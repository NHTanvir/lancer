<script>
  import { onMount, onDestroy } from "svelte";

  let subtab = "intercept";

  // Intercept state
  let interceptOn = false;
  let interceptQueue = [];  // paused requests from the API
  let selectedPaused = null;
  let actionMenuOpen = false;

  function pausedWire() { return editedWire || selectedPaused?.wire || selectedPaused?.raw_request || ""; }
  function actionSend(tab) {
    const raw = pausedWire();
    if (tab === "comparer") {
      const existing = JSON.parse(localStorage.getItem("lancer.send.comparer") || "{}");
      if (!existing.item1) existing.item1 = raw; else existing.item2 = raw;
      localStorage.setItem("lancer.send.comparer", JSON.stringify(existing));
    } else {
      localStorage.setItem(`lancer.send.${tab}`, JSON.stringify({ raw }));
    }
    window.dispatchEvent(new CustomEvent("lancer:navigate", { detail: tab }));
    actionMenuOpen = false;
  }
  function pausedUrl() {
    const raw = pausedWire();
    const line = raw.split("\r\n")[0] || raw.split("\n")[0] || "";
    const [, path = "/"] = line.split(" ");
    const host = (raw.match(/host:\s*(.+)/i) || [])[1]?.trim() || selectedPaused?.host || "target";
    return `https://${host}${path}`;
  }
  function actionCopy(fmt) {
    const raw = pausedWire();
    const line = raw.split("\r\n")[0] || raw.split("\n")[0] || "";
    const [method = "GET"] = line.split(" ");
    const url = pausedUrl();
    let out;
    if (fmt === "curl") out = `curl -X ${method} '${url}'`;
    else if (fmt === "powershell") out = `Invoke-WebRequest -Method ${method} -Uri '${url}'`;
    else out = `fetch('${url}', { method: '${method}' })`;
    navigator.clipboard.writeText(out).catch(() => {});
    actionMenuOpen = false;
  }
  function actionCopyUrl() {
    navigator.clipboard.writeText(pausedUrl()).catch(() => {});
    actionMenuOpen = false;
  }
  async function actionSendToScanner() {
    try {
      await fetch("/api/v1/scan/full", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ url: pausedUrl() }),
      });
    } catch {}
    actionMenuOpen = false;
  }
  function actionSendToDecoder() {
    localStorage.setItem("lancer.send.decoder", JSON.stringify({ input: pausedWire() }));
    window.dispatchEvent(new CustomEvent("lancer:navigate", { detail: "decoder" }));
    actionMenuOpen = false;
  }
  let editedWire = "";
  let listenAddr = "127.0.0.1:8080";
  let proxyStatus = null;
  let pollTimer = null;

  // History state
  let rows = [];
  let filter = "";
  let selected = null;
  let reqSubtab = "raw";
  let respSubtab = "raw";

  // Match & Replace rules
  let rules = [];
  let editRuleIdx = -1;
  let editRule = null;

  function statusClass(s) {
    if (!s) return "dim";
    if (s >= 500) return "status-5";
    if (s >= 400) return "status-4";
    if (s >= 300) return "status-3";
    if (s >= 200) return "status-2";
    return "dim";
  }
  function methodClass(m) { return "method-" + (m || "GET"); }

  function bytesToText(b) {
    if (b == null) return "";
    if (typeof b === "string") return b;
    if (Array.isArray(b) || b instanceof Uint8Array) {
      try { return new TextDecoder("utf-8", { fatal: false }).decode(new Uint8Array(b)); }
      catch { return ""; }
    }
    return String(b);
  }

  function formatRequest(row) {
    const r = row.request;
    if (!r) {
      return `${row.method || "GET"} ${row.path || "/"} HTTP/1.1\nHost: ${row.host || ""}\n`;
    }
    const method = r.method || row.method || "GET";
    const path = r.path || row.path || "/";
    const ver = r.version === "Http2" ? "HTTP/2" : r.version === "Http3" ? "HTTP/3" : "HTTP/1.1";
    const hdrs = (r.headers || []).map(h => `${h.name}: ${h.value}`).join("\n");
    const body = bytesToText(r.body);
    return `${method} ${path} ${ver}\n${hdrs}\n\n${body}`;
  }

  function formatResponse(row) {
    const r = row.response;
    if (!r) {
      return `HTTP/1.1 ${row.status || "?"}\n\n(no response captured)`;
    }
    const ver = r.version === "Http2" ? "HTTP/2" : r.version === "Http3" ? "HTTP/3" : "HTTP/1.1";
    const reason = r.reason || "";
    const hdrs = (r.headers || []).map(h => `${h.name}: ${h.value}`).join("\n");
    const body = bytesToText(r.body);
    return `${ver} ${r.status} ${reason}\n${hdrs}\n\n${body}`;
  }

  // ── WebSockets history ──────────────────────────────
  let wsRows = [];
  let wsFilter = "";
  let selectedWs = null;
  $: filteredWs = wsRows.filter(m =>
    !wsFilter ||
    (m.host || "").includes(wsFilter) ||
    (m.direction || "").includes(wsFilter) ||
    (m.frame_type || "").includes(wsFilter)
  );
  async function loadWsHistory() {
    try {
      const r = await fetch("/api/v1/ws-history");
      if (r.ok) wsRows = await r.json();
    } catch {}
  }

  // WS right-click context menu
  let wsCtxMenu = null;
  function onWsContextMenu(event, m) {
    event.preventDefault();
    selectedWs = m;
    wsCtxMenu = { x: event.clientX, y: event.clientY, msg: m };
  }
  function closeWsCtxMenu() { wsCtxMenu = null; }
  function wsSendToComparer() {
    if (!wsCtxMenu) return;
    const item = wsCtxMenu.msg.payload_text || "";
    const existing = JSON.parse(localStorage.getItem("lancer.send.comparer") || "{}");
    if (!existing.item1) existing.item1 = item;
    else existing.item2 = item;
    localStorage.setItem("lancer.send.comparer", JSON.stringify(existing));
    window.dispatchEvent(new CustomEvent("lancer:navigate", { detail: "comparer" }));
    closeWsCtxMenu();
  }
  function wsSendToDecoder() {
    if (!wsCtxMenu) return;
    localStorage.setItem("lancer.send.decoder", JSON.stringify({ input: wsCtxMenu.msg.payload_text || "" }));
    window.dispatchEvent(new CustomEvent("lancer:navigate", { detail: "decoder" }));
    closeWsCtxMenu();
  }
  function wsCopyPayload() {
    if (!wsCtxMenu) return;
    navigator.clipboard.writeText(wsCtxMenu.msg.payload_text || "").catch(() => {});
    closeWsCtxMenu();
  }

  // ── Right-click context menu state ──────────────────
  let ctxMenu = null;
  function onRowContextMenu(event, row) {
    event.preventDefault();
    selected = row;
    ctxMenu = { x: event.clientX, y: event.clientY, row };
  }
  function closeCtxMenu() { ctxMenu = null; actionMenuOpen = false; highlightMenuOpen = false; mimeGroupsOpen = false; wsCtxMenu = null; }

  function payloadFromRow(row) {
    return {
      method: row.method || "GET",
      scheme: row.scheme || "http",
      host: row.host || "",
      port: row.port || (row.scheme === "https" ? 443 : 80),
      path: row.path || "/",
      raw: formatRequest(row),
    };
  }

  function ctxSendToRepeater() {
    if (!ctxMenu) return;
    const payload = payloadFromRow(ctxMenu.row);
    localStorage.setItem("repeater_prefill", JSON.stringify(payload));
    localStorage.setItem("lancer.send.repeater", JSON.stringify(payload));
    window.dispatchEvent(new CustomEvent("lancer:navigate", { detail: "repeater" }));
    closeCtxMenu();
  }
  function ctxSendToIntruder() {
    if (!ctxMenu) return;
    localStorage.setItem("lancer.send.intruder", JSON.stringify(payloadFromRow(ctxMenu.row)));
    window.dispatchEvent(new CustomEvent("lancer:navigate", { detail: "intruder" }));
    closeCtxMenu();
  }
  function ctxSendToComparer(role) {
    if (!ctxMenu) return;
    const item = role === "response" ? formatResponse(ctxMenu.row) : formatRequest(ctxMenu.row);
    const existing = JSON.parse(localStorage.getItem("lancer.send.comparer") || "{}");
    if (!existing.item1) existing.item1 = item;
    else existing.item2 = item;
    localStorage.setItem("lancer.send.comparer", JSON.stringify(existing));
    window.dispatchEvent(new CustomEvent("lancer:navigate", { detail: "comparer" }));
    closeCtxMenu();
  }
  function ctxSendToDecoder() {
    if (!ctxMenu) return;
    const text = bytesToText(ctxMenu.row.response?.body) || formatResponse(ctxMenu.row);
    localStorage.setItem("lancer.send.decoder", JSON.stringify({ input: text }));
    window.dispatchEvent(new CustomEvent("lancer:navigate", { detail: "decoder" }));
    closeCtxMenu();
  }
  async function ctxSendToScanner() {
    if (!ctxMenu) return;
    const row = ctxMenu.row;
    const url = `${row.scheme || "http"}://${row.host}${row.path || "/"}`;
    try {
      await fetch("/api/v1/scan/full", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ url }) });
    } catch {}
    closeCtxMenu();
  }
  async function ctxAddToScope() {
    if (!ctxMenu) return;
    const row = ctxMenu.row;
    try {
      const r = await fetch("/api/v1/scope");
      let rules = r.ok ? await r.json() : [];
      if (!Array.isArray(rules)) rules = [];
      rules.push({ kind: "Include", protocol: row.scheme || null, host: row.host, port: row.port || null, path: null, enabled: true, regex: false });
      await fetch("/api/v1/scope", { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify(rules) });
    } catch {}
    closeCtxMenu();
  }
  function ctxCopyUrl() {
    if (!ctxMenu) return;
    const r = ctxMenu.row;
    navigator.clipboard.writeText(`${r.scheme || "http"}://${r.host}${r.path || "/"}`).catch(() => {});
    closeCtxMenu();
  }
  function ctxCopyAsCurl() {
    if (!ctxMenu) return;
    const r = ctxMenu.row;
    const url = `${r.scheme || "http"}://${r.host}${r.path || "/"}`;
    let curl = `curl -X ${r.method || "GET"} '${url}'`;
    for (const h of (r.request?.headers || [])) {
      if (["host","content-length","accept-encoding","proxy-connection"].includes(h.name.toLowerCase())) continue;
      curl += ` \\\n  -H '${h.name}: ${h.value.replace(/'/g,"'\\''")}'`;
    }
    navigator.clipboard.writeText(curl).catch(() => {});
    closeCtxMenu();
  }

  // ── Copy as PowerShell / fetch (history context menu) ──
  function ctxCopyAs(fmt) {
    if (!ctxMenu) return;
    const r = ctxMenu.row;
    const url = `${r.scheme || "http"}://${r.host}${r.path || "/"}`;
    const method = r.method || "GET";
    let out;
    if (fmt === "powershell") out = `Invoke-WebRequest -Method ${method} -Uri '${url}'`;
    else out = `fetch('${url}', { method: '${method}' })`;
    navigator.clipboard.writeText(out).catch(() => {});
    closeCtxMenu();
  }

  // ── Send to Decoder (history context menu) ──
  function ctxSendToDecoderReq() {
    if (!ctxMenu) return;
    localStorage.setItem("lancer.send.decoder", JSON.stringify({ input: formatRequest(ctxMenu.row) }));
    window.dispatchEvent(new CustomEvent("lancer:navigate", { detail: "decoder" }));
    closeCtxMenu();
  }

  // ── Save entire history (export rows JSON) ──
  function saveEntireHistory() {
    const blob = new Blob([JSON.stringify(filteredRows, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "lancer-http-history.json";
    a.click();
    closeCtxMenu();
  }

  // ── Highlight colors (Burp 7-color palette) ──
  const HIGHLIGHT_COLORS = [
    { name: "Red",    value: "#ffd5d5" },
    { name: "Orange", value: "#ffe2c2" },
    { name: "Yellow", value: "#fff6c2" },
    { name: "Green",  value: "#d6f5d6" },
    { name: "Cyan",   value: "#cdefff" },
    { name: "Blue",   value: "#d6e0ff" },
    { name: "Purple", value: "#ecd6ff" },
  ];
  let highlightMenuOpen = false;
  async function patchHistory(id, body) {
    try {
      await fetch(`/api/v1/history/${id}`, {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      });
    } catch {}
  }
  async function setRowColor(color) {
    if (!ctxMenu) return;
    const row = ctxMenu.row;
    row.color = color;
    rows = rows;
    await patchHistory(row.id, { color: color || "" });
    closeCtxMenu();
  }

  // ── Inline comment editing ──
  let commentEditId = null;
  let commentDraft = "";
  function startEditComment(row, e) {
    if (e) e.stopPropagation();
    commentEditId = row.id;
    commentDraft = row.comment || "";
  }
  async function saveComment(row) {
    row.comment = commentDraft;
    rows = rows;
    commentEditId = null;
    await patchHistory(row.id, { comment: commentDraft });
  }
  function ctxAddComment() {
    if (!ctxMenu) return;
    startEditComment(ctxMenu.row);
    closeCtxMenu();
  }
  function focusOnMount(node) {
    node.focus();
    if (node.select) node.select();
    return {};
  }

  // ── History filters (client-side) ──
  let onlyInScope = false;
  let onlyWithComments = false;
  let onlyParametrized = false;
  let hide4xx = false;
  let hide5xx = false;
  let extFilter = "";
  let mimeGroupsOpen = false;
  const MIME_GROUPS = ["HTML", "Script", "CSS", "XML", "JSON", "Image", "Text", "Other"];
  let mimeGroupSel = {};

  function mimeGroupOf(mime) {
    const m = (mime || "").toLowerCase();
    if (!m) return "Other";
    if (m.includes("html")) return "HTML";
    if (m.includes("javascript") || m.includes("ecmascript") || m === "script") return "Script";
    if (m.includes("css")) return "CSS";
    if (m.includes("json")) return "JSON";
    if (m.includes("xml")) return "XML";
    if (m.includes("image")) return "Image";
    if (m.startsWith("text") || m.includes("plain")) return "Text";
    return "Other";
  }
  function extOf(path) {
    const clean = (path || "").split("?")[0].split("#")[0];
    const seg = clean.split("/").pop() || "";
    const dot = seg.lastIndexOf(".");
    return dot > 0 ? seg.slice(dot + 1).toLowerCase() : "";
  }
  function isParametrized(row) {
    return (row.path || "").includes("?") || !!(row.request && (row.request.body && bytesToText(row.request.body).length > 0));
  }
  $: anyMimeSelected = MIME_GROUPS.some(g => mimeGroupSel[g]);

  async function loadProxyStatus() {
    try {
      const r = await fetch("/api/v1/proxy/status");
      if (r.ok) {
        proxyStatus = await r.json();
        interceptOn = proxyStatus.intercept_requests;
        listenAddr = proxyStatus.addr || "127.0.0.1:8080";
      }
    } catch {}
  }

  async function toggleIntercept() {
    const newState = !interceptOn;
    try {
      const r = await fetch("/api/v1/proxy/intercept/toggle", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ requests: newState, responses: false }),
      });
      if (r.ok) {
        const d = await r.json();
        interceptOn = d.intercept_requests;
        if (!interceptOn) { interceptQueue = []; selectedPaused = null; }
      }
    } catch { interceptOn = newState; }
  }

  async function pollIntercept() {
    if (!interceptOn) return;
    try {
      const r = await fetch("/api/v1/proxy/intercept/queue");
      if (r.ok) {
        const q = await r.json();
        interceptQueue = q || [];
        // Auto-select first item if nothing selected
        if (!selectedPaused && interceptQueue.length > 0) {
          selectPaused(interceptQueue[0]);
        }
        // Clear selection if item was resolved
        if (selectedPaused && !interceptQueue.find(p => p.id === selectedPaused.id)) {
          if (interceptQueue.length > 0) selectPaused(interceptQueue[0]);
          else { selectedPaused = null; editedWire = ""; }
        }
      }
    } catch {}
  }

  function selectPaused(item) {
    selectedPaused = item;
    editedWire = item.wire || "";
  }

  async function forwardRequest() {
    if (!selectedPaused) return;
    try {
      await fetch("/api/v1/proxy/intercept/forward", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ id: selectedPaused.id, wire: editedWire }),
      });
      selectedPaused = null; editedWire = "";
      await pollIntercept();
    } catch {}
  }

  async function dropRequest() {
    if (!selectedPaused) return;
    try {
      await fetch("/api/v1/proxy/intercept/drop", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ id: selectedPaused.id }),
      });
      selectedPaused = null; editedWire = "";
      await pollIntercept();
    } catch {}
  }

  async function forwardAll() {
    for (const item of [...interceptQueue]) {
      await fetch("/api/v1/proxy/intercept/forward", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ id: item.id }),
      });
    }
    interceptQueue = []; selectedPaused = null; editedWire = "";
  }

  async function refreshHistory() {
    try {
      const r = await fetch("/api/v1/history?limit=500");
      if (r.ok) rows = await r.json();
    } catch { rows = []; }
  }

  async function deleteHistoryItem(id, e) {
    e.stopPropagation();
    try {
      await fetch(`/api/v1/history/${id}`, { method: "DELETE" });
      rows = rows.filter(r => r.id !== id);
      if (selected && selected.id === id) selected = null;
    } catch {}
  }

  // Match & Replace
  async function loadRules() {
    try {
      const r = await fetch("/api/v1/proxy/rules");
      if (r.ok) rules = await r.json();
    } catch {}
  }

  async function saveRules() {
    try {
      await fetch("/api/v1/proxy/rules", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(rules),
      });
    } catch {}
  }

  async function toggleRule(i) {
    rules[i].enabled = !rules[i].enabled;
    rules = rules;
    await saveRules();
  }

  const MR_TARGETS = ["RequestHeader", "RequestBody", "RequestFirstLine", "ResponseHeader", "ResponseBody", "ResponseFirstLine"];

  function addRule() {
    rules = [...rules, { name: "New rule", enabled: true, target: "RequestHeader", pattern: "", replacement: "", is_regex: false, only_in_scope: false }];
    saveRules();
  }

  function removeRule(i) {
    rules = rules.filter((_, idx) => idx !== i);
    saveRules();
  }

  function moveRule(i, dir) {
    const t = i + dir;
    if (t < 0 || t >= rules.length) return;
    const a = [...rules];
    [a[i], a[t]] = [a[t], a[i]];
    rules = a;
    saveRules();
  }

  function exportRules() {
    const blob = new Blob([JSON.stringify(rules, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "lancer-match-replace.json";
    a.click();
  }

  function importRules() {
    const input = document.createElement("input");
    input.type = "file"; input.accept = "application/json";
    input.onchange = async () => {
      const file = input.files && input.files[0];
      if (!file) return;
      try {
        const imported = JSON.parse(await file.text());
        if (Array.isArray(imported)) { rules = imported; await saveRules(); }
      } catch {}
    };
    input.click();
  }

  async function downloadCert(fmt) {
    window.open(`/api/v1/proxy/ca-cert.${fmt}`, "_blank");
  }

  onMount(async () => {
    await loadProxyStatus();
    if (subtab === "history") await refreshHistory();
    if (subtab === "matchreplace") await loadRules();
    if (subtab === "ws") await loadWsHistory();

    // Poll intercept queue every 500ms when intercept is on, ws every 5s when on ws tab
    pollTimer = setInterval(async () => {
      if (subtab === "intercept" && interceptOn) await pollIntercept();
      if (subtab === "ws") await loadWsHistory();
    }, 500);

    window.addEventListener("click", closeCtxMenu);
  });

  $: if (subtab === "ws") loadWsHistory();

  onDestroy(() => {
    if (pollTimer) clearInterval(pollTimer);
    window.removeEventListener("click", closeCtxMenu);
  });

  $: filteredRows = rows.filter(r => {
    const textMatch = !filter ||
      (r.host && r.host.includes(filter)) ||
      (r.path && r.path.includes(filter)) ||
      String(r.status || "").includes(filter) ||
      (r.method && r.method.includes(filter.toUpperCase()));
    if (!textMatch) return false;
    if (onlyInScope && !r.in_scope) return false;
    if (onlyWithComments && !(r.comment && r.comment.trim())) return false;
    if (onlyParametrized && !isParametrized(r)) return false;
    const s = Number(r.status) || 0;
    if (hide4xx && s >= 400 && s < 500) return false;
    if (hide5xx && s >= 500 && s < 600) return false;
    if (extFilter && !extOf(r.path).includes(extFilter.toLowerCase().replace(/^\./, ""))) return false;
    if (anyMimeSelected && !mimeGroupSel[mimeGroupOf(r.mime)]) return false;
    return true;
  });

  $: if (subtab === "history") refreshHistory();
  $: if (subtab === "matchreplace") loadRules();
  $: if (subtab === "intercept" && interceptOn) pollIntercept();
</script>

<div class="view">
  <div class="subtabs">
    <button class="subtab" class:active={subtab==="intercept"}    on:click={() => subtab="intercept"}>Intercept</button>
    <button class="subtab" class:active={subtab==="history"}      on:click={() => subtab="history"}>HTTP history</button>
    <button class="subtab" class:active={subtab==="ws"}           on:click={() => subtab="ws"}>WebSockets history</button>
    <button class="subtab" class:active={subtab==="matchreplace"} on:click={() => subtab="matchreplace"}>Match and replace</button>
    <button class="subtab" class:active={subtab==="settings"}     on:click={() => subtab="settings"}>Proxy settings</button>
  </div>

  <!-- ─── INTERCEPT ─── -->
  {#if subtab === "intercept"}
    <div class="intercept-toolbar">
      <button
        class="intercept-toggle-btn"
        class:intercept-off={!interceptOn}
        class:intercept-on={interceptOn}
        on:click={toggleIntercept}
      >
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
          <ellipse cx="7" cy="7" rx="6" ry="4" stroke="currentColor" stroke-width="1.3"/>
          <circle cx="7" cy="7" r="2" fill="currentColor"/>
        </svg>
        {interceptOn ? "Intercept on" : "Intercept off"}
      </button>
      <button class="toolbar-btn" disabled={!selectedPaused} on:click={forwardRequest}>
        Forward <span class="dd-arrow">▼</span>
      </button>
      <button class="toolbar-btn" disabled={!selectedPaused} on:click={dropRequest}>
        Drop <span class="dd-arrow">▼</span>
      </button>
      <button class="toolbar-btn" disabled={interceptQueue.length === 0} on:click={forwardAll}>
        Forward all
      </button>
      <div class="action-wrap">
        <button class="toolbar-btn" disabled={!selectedPaused} on:click|stopPropagation={() => actionMenuOpen = !actionMenuOpen}>Action ▼</button>
        {#if actionMenuOpen && selectedPaused}
          <div class="action-menu" on:click|stopPropagation>
            <div class="ctx-item" on:click={() => actionSend("repeater")}>Send to Repeater</div>
            <div class="ctx-item" on:click={() => actionSend("intruder")}>Send to Intruder</div>
            <div class="ctx-item" on:click={actionSendToScanner}>Send to Scanner</div>
            <div class="ctx-item" on:click={() => actionSend("comparer")}>Send to Comparer</div>
            <div class="ctx-item" on:click={actionSendToDecoder}>Send to Decoder</div>
            <div class="ctx-sep"></div>
            <div class="ctx-item" on:click={actionCopyUrl}>Copy URL</div>
            <div class="ctx-item" on:click={() => actionCopy("curl")}>Copy as curl</div>
            <div class="ctx-item" on:click={() => actionCopy("powershell")}>Copy as PowerShell</div>
            <div class="ctx-item" on:click={() => actionCopy("fetch")}>Copy as fetch</div>
          </div>
        {/if}
      </div>
      <button class="toolbar-btn" on:click={async () => { try { await fetch("/api/browser/open", {method:"POST"}); } catch {} }}>Open browser</button>
      {#if interceptQueue.length > 0}
        <span class="queue-badge">{interceptQueue.length} paused</span>
      {/if}
    </div>

    <div class="intercept-body">
      {#if interceptOn && (interceptQueue.length > 0 || selectedPaused)}
        <!-- Queue sidebar + editor -->
        <div class="intercept-split">
          {#if interceptQueue.length > 1}
            <div class="queue-list">
              {#each interceptQueue as item}
                <div
                  class="queue-item"
                  class:queue-item-active={selectedPaused && selectedPaused.id === item.id}
                  on:click={() => selectPaused(item)}
                  role="button"
                  tabindex="0"
                  on:keydown={e => e.key === "Enter" && selectPaused(item)}
                >
                  <span class="queue-method">{item.request?.method || "?"}</span>
                  <span class="queue-host dim">{item.request?.meta?.host || "?"}</span>
                </div>
              {/each}
            </div>
          {/if}
          <div class="intercept-editor-wrap">
            <div class="editor-toolbar">
              <span class="editor-label">
                {#if selectedPaused}
                  {selectedPaused.request?.method || ""} {selectedPaused.request?.meta?.host || ""}{selectedPaused.request?.path || ""}
                {:else}
                  Request
                {/if}
              </span>
              <div class="inline-tabs">
                <button class="itab itab-active">Raw</button>
                <button class="itab">Pretty</button>
                <button class="itab">Hex</button>
              </div>
            </div>
            <textarea
              class="intercept-area"
              bind:value={editedWire}
              spellcheck="false"
            ></textarea>
          </div>
        </div>
      {:else if interceptOn}
        <div class="intercept-waiting">
          <div class="spinner"></div>
          <p class="intercept-off-title">Waiting for traffic...</p>
          <p class="dim" style="font-size:12px;max-width:340px;text-align:center">
            Intercept is on. Browse a site through the proxy at <code>{listenAddr}</code>.
          </p>
        </div>
      {:else}
        <div class="intercept-off-state">
          <svg width="80" height="80" viewBox="0 0 80 80" fill="none">
            <rect x="28" y="8" width="24" height="64" rx="8" fill="#434a54" opacity="0.1"/>
            <circle cx="40" cy="24" r="9" fill="#d42c2c" opacity="0.4"/>
            <circle cx="40" cy="40" r="9" fill="#c98a00" opacity="0.4"/>
            <circle cx="40" cy="56" r="9" fill="#1b8c1b" opacity="1"/>
          </svg>
          <p class="intercept-off-title">Intercept is off</p>
          <p class="dim" style="font-size:12px;max-width:340px;text-align:center;line-height:1.6">
            Requests are forwarded directly. Turn intercept on to pause and inspect requests.
          </p>
          <div class="intercept-off-actions">
            <button class="btn-secondary">Learn more</button>
            <button class="btn-orange" on:click={async () => { try { await fetch("/api/browser/open", {method:"POST"}); } catch {} }}>Open browser</button>
          </div>
        </div>
      {/if}
    </div>
  {/if}

  <!-- ─── HTTP HISTORY ─── -->
  {#if subtab === "history"}
    <div class="toolbar">
      <input style="flex:1;max-width:380px" placeholder="Filter host / path / status / method..." bind:value={filter} />
      <button on:click={refreshHistory} class="toolbar-btn">Reload</button>
      <span class="dim" style="margin-left:auto;font-size:12px">{filteredRows.length} requests</span>
    </div>
    <div class="toolbar history-filter-bar">
      <label class="filter-chk"><input type="checkbox" bind:checked={onlyInScope} />In scope only</label>
      <label class="filter-chk"><input type="checkbox" bind:checked={onlyWithComments} />With comments</label>
      <label class="filter-chk"><input type="checkbox" bind:checked={onlyParametrized} />Parametrized</label>
      <label class="filter-chk"><input type="checkbox" bind:checked={hide4xx} />Hide 4xx</label>
      <label class="filter-chk"><input type="checkbox" bind:checked={hide5xx} />Hide 5xx</label>
      <input class="ext-filter" placeholder="ext (e.g. js)" bind:value={extFilter} title="Show only this file extension" />
      <div class="action-wrap">
        <button class="toolbar-btn" on:click|stopPropagation={() => mimeGroupsOpen = !mimeGroupsOpen}>
          MIME {anyMimeSelected ? `(${MIME_GROUPS.filter(g => mimeGroupSel[g]).length})` : ""} ▼
        </button>
        {#if mimeGroupsOpen}
          <div class="action-menu" on:click|stopPropagation>
            {#each MIME_GROUPS as g}
              <label class="ctx-item filter-chk"><input type="checkbox" bind:checked={mimeGroupSel[g]} />{g}</label>
            {/each}
          </div>
        {/if}
      </div>
    </div>

    <div class="history-body">
      <div class="table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th>#</th><th>Host</th><th>Method</th><th>URL</th>
              <th>Status</th><th>Length</th><th>MIME</th><th>Ext</th><th>Params</th>
              <th>TLS</th><th>Time (ms)</th><th>Comment</th><th></th>
            </tr>
          </thead>
          <tbody>
            {#each filteredRows as row, i}
              <tr
                class:row-selected={selected === row}
                class:row-even={i % 2 === 0}
                style={row.color ? `background:${row.color}` : ""}
                on:click={() => selected = selected === row ? null : row}
                on:contextmenu={(e) => onRowContextMenu(e, row)}
              >
                <td class="dim">{i + 1}</td>
                <td>{row.host || "-"}</td>
                <td class={methodClass(row.method)}>{row.method || "-"}</td>
                <td class="path-cell" title={row.path}>{(row.path||"/").length > 60 ? (row.path||"/").slice(0,60)+"..." : (row.path||"/")}</td>
                <td class={statusClass(row.status)}>{row.status || "-"}</td>
                <td class="dim">{row.response_length ?? "-"}</td>
                <td class="dim">{row.mime || "-"}</td>
                <td class="dim">{extOf(row.path) || "-"}</td>
                <td class="dim" style="text-align:center">{isParametrized(row) ? "✓" : ""}</td>
                <td class="dim" style="text-align:center" title={row.scheme}>{row.scheme === "https" ? "🔒" : ""}</td>
                <td class="dim">{row.elapsed_ms ?? "-"}</td>
                <td class="comment-cell" on:click|stopPropagation>
                  {#if commentEditId === row.id}
                    <input
                      class="comment-input"
                      bind:value={commentDraft}
                      use:focusOnMount
                      on:blur={() => saveComment(row)}
                      on:keydown={(e) => { if (e.key === "Enter") saveComment(row); else if (e.key === "Escape") commentEditId = null; }}
                    />
                  {:else}
                    <span class="comment-text" title="Click to edit comment" on:click={(e) => startEditComment(row, e)}>
                      {row.comment || "+"}
                    </span>
                  {/if}
                </td>
                <td>
                  <button class="del-btn dim" title="Delete" on:click={e => deleteHistoryItem(row.id, e)}>×</button>
                </td>
              </tr>
            {/each}
            {#if filteredRows.length === 0}
              <tr><td colspan="13" class="empty-cell">No requests yet. Browse through <code>{listenAddr}</code>.</td></tr>
            {/if}
          </tbody>
        </table>
      </div>

      {#if selected}
        <div class="detail-pane split-h">
          <div class="pane">
            <div class="pane-header">
              Request
              <div class="inline-tabs">
                <button class="itab" class:itab-active={reqSubtab==="pretty"} on:click={() => reqSubtab="pretty"}>Pretty</button>
                <button class="itab" class:itab-active={reqSubtab==="raw"}    on:click={() => reqSubtab="raw"}>Raw</button>
                <button class="itab" class:itab-active={reqSubtab==="hex"}    on:click={() => reqSubtab="hex"}>Hex</button>
              </div>
            </div>
            <textarea class="raw-area" readonly value={formatRequest(selected)}></textarea>
          </div>
          <div class="pane">
            <div class="pane-header">
              Response
              <div class="inline-tabs">
                <button class="itab" class:itab-active={respSubtab==="pretty"} on:click={() => respSubtab="pretty"}>Pretty</button>
                <button class="itab" class:itab-active={respSubtab==="raw"}    on:click={() => respSubtab="raw"}>Raw</button>
                <button class="itab" class:itab-active={respSubtab==="hex"}    on:click={() => respSubtab="hex"}>Hex</button>
              </div>
            </div>
            <textarea class="raw-area" readonly value={formatResponse(selected)}></textarea>
          </div>
        </div>
      {/if}
    </div>
  {/if}

  <!-- ─── WEBSOCKETS ─── -->
  {#if subtab === "ws"}
    <div class="toolbar">
      <input style="flex:1;max-width:380px" placeholder="Filter host / direction / type..." bind:value={wsFilter} />
      <button class="toolbar-btn" on:click={loadWsHistory}>Reload</button>
      <span class="dim" style="font-size:12px;margin-left:auto">{filteredWs.length} / {wsRows.length} messages</span>
    </div>
    <div class="ws-body">
      <div class="table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th>#</th>
              <th>Time</th>
              <th>Host</th>
              <th>Dir</th>
              <th>Type</th>
              <th>Length</th>
              <th>Payload (preview)</th>
            </tr>
          </thead>
          <tbody>
            {#each filteredWs as m, i}
              <tr
                class:row-selected={selectedWs === m}
                class:row-even={i % 2 === 0}
                on:click={() => selectedWs = selectedWs === m ? null : m}
                on:contextmenu={(e) => onWsContextMenu(e, m)}
              >
                <td class="dim mono">{i + 1}</td>
                <td class="dim small">{(m.captured_at || "").slice(11, 19)}</td>
                <td>{m.host}</td>
                <td class={m.direction === "c2s" ? "dir-c2s" : "dir-s2c"}>{m.direction === "c2s" ? "→ server" : "← client"}</td>
                <td>{m.frame_type}</td>
                <td class="dim">{m.length}</td>
                <td class="ws-preview mono small">{(m.payload_text || "").slice(0, 80)}</td>
              </tr>
            {/each}
            {#if filteredWs.length === 0}
              <tr><td colspan="7" class="empty-cell">No WebSocket messages captured yet. Browse a WebSocket-using site through <code>{listenAddr}</code>.</td></tr>
            {/if}
          </tbody>
        </table>
      </div>
      {#if selectedWs}
        <div class="ws-detail">
          <div class="pane-header">Payload ({selectedWs.length} bytes, {selectedWs.frame_type})</div>
          <textarea class="raw-area" readonly value={selectedWs.payload_text || ""}></textarea>
        </div>
      {/if}
    </div>
  {/if}

  <!-- ─── MATCH AND REPLACE ─── -->
  {#if subtab === "matchreplace"}
    <div class="toolbar">
      <button class="btn-orange" on:click={addRule}>Add</button>
      <button class="toolbar-btn" on:click={exportRules}>Export</button>
      <button class="toolbar-btn" on:click={importRules}>Import</button>
      <span class="dim" style="font-size:12px;margin-left:4px">{rules.length} rules</span>
    </div>
    <div class="table-wrap" style="flex:1;overflow-y:auto">
      <table class="data-table">
        <thead>
          <tr>
            <th style="width:36px">On</th>
            <th>Name</th>
            <th>Target</th>
            <th>Match (regex/literal)</th>
            <th>Replace</th>
            <th style="width:48px">Regex</th>
            <th style="width:70px">Order</th>
            <th style="width:36px"></th>
          </tr>
        </thead>
        <tbody>
          {#each rules as rule, i}
            <tr class:row-even={i % 2 === 0}>
              <td><input type="checkbox" bind:checked={rule.enabled} on:change={saveRules} /></td>
              <td><input class="mr-in" bind:value={rule.name} on:change={saveRules} /></td>
              <td>
                <select class="mr-sel" bind:value={rule.target} on:change={saveRules}>
                  {#each MR_TARGETS as t}<option value={t}>{t}</option>{/each}
                </select>
              </td>
              <td><input class="mr-in mono" bind:value={rule.pattern} on:change={saveRules} /></td>
              <td><input class="mr-in mono" bind:value={rule.replacement} on:change={saveRules} /></td>
              <td style="text-align:center"><input type="checkbox" bind:checked={rule.is_regex} on:change={saveRules} /></td>
              <td style="white-space:nowrap">
                <button class="ord-btn" on:click={() => moveRule(i, -1)} disabled={i === 0}>▲</button>
                <button class="ord-btn" on:click={() => moveRule(i, 1)} disabled={i === rules.length - 1}>▼</button>
              </td>
              <td><button class="del-btn dim" on:click={() => removeRule(i)}>×</button></td>
            </tr>
          {/each}
          {#if rules.length === 0}
            <tr><td colspan="8" class="empty-cell">No match/replace rules. Click Add to create one.</td></tr>
          {/if}
        </tbody>
      </table>
    </div>
  {/if}

  <!-- ─── PROXY SETTINGS ─── -->
  {#if subtab === "settings"}
    <div class="panel">
      <div class="settings-section">
        <div class="settings-title">Proxy Listeners</div>
        <div class="settings-card">
          <div class="settings-row">
            <label class="settings-label" for="bind-addr">Bind address</label>
            <input id="bind-addr" bind:value={listenAddr} style="width:180px" readonly />
            {#if proxyStatus?.running}
              <span style="color:#1b8c1b;font-size:12px">● Listening on {listenAddr}</span>
            {:else}
              <span class="dim" style="font-size:12px">● Stopped</span>
            {/if}
          </div>
        </div>
      </div>

      <div class="settings-section" style="margin-top:16px">
        <div class="settings-title">CA Certificate</div>
        <div class="settings-card">
          <p class="settings-desc">
            To intercept HTTPS traffic, install the Lancer CA certificate in your browser or OS trust store.
            Configure your browser to use <code>{listenAddr}</code> as HTTP/HTTPS proxy.
          </p>
          <div style="display:flex;gap:8px;margin-top:10px">
            <button class="toolbar-btn" on:click={() => downloadCert("der")}>Export DER (browser)</button>
            <button class="toolbar-btn" on:click={() => downloadCert("pem")}>Export PEM</button>
          </div>
          <p class="settings-desc" style="margin-top:8px;font-size:12px;color:#69707b">
            To install in Chrome/Edge: Settings → Security → Manage certificates → Authorities → Import → select lancer-ca.der
          </p>
        </div>
      </div>
    </div>
  {/if}
</div>

{#if ctxMenu}
  <div class="ctx-menu" style="left:{ctxMenu.x}px;top:{ctxMenu.y}px" on:click|stopPropagation>
    <div class="ctx-item" on:click={ctxSendToRepeater}>Send to Repeater <span class="ctx-shortcut">Ctrl+R</span></div>
    <div class="ctx-item" on:click={ctxSendToIntruder}>Send to Intruder <span class="ctx-shortcut">Ctrl+I</span></div>
    <div class="ctx-item" on:click={() => ctxSendToComparer("request")}>Send request to Comparer</div>
    <div class="ctx-item" on:click={() => ctxSendToComparer("response")}>Send response to Comparer</div>
    <div class="ctx-item" on:click={ctxSendToDecoder}>Send response to Decoder</div>
    <div class="ctx-item" on:click={ctxSendToDecoderReq}>Send request to Decoder</div>
    <div class="ctx-item" on:click={ctxSendToScanner}>Send to Scanner</div>
    <div class="ctx-sep"></div>
    <div class="ctx-item ctx-submenu" on:click|stopPropagation={() => highlightMenuOpen = !highlightMenuOpen}>
      Highlight <span class="ctx-shortcut">▸</span>
      {#if highlightMenuOpen}
        <div class="ctx-flyout" on:click|stopPropagation>
          {#each HIGHLIGHT_COLORS as c}
            <div class="ctx-item color-item" on:click={() => setRowColor(c.value)}>
              <span class="color-swatch" style="background:{c.value}"></span>{c.name}
            </div>
          {/each}
          <div class="ctx-sep"></div>
          <div class="ctx-item" on:click={() => setRowColor(null)}>None</div>
        </div>
      {/if}
    </div>
    <div class="ctx-item" on:click={ctxAddComment}>Add comment</div>
    <div class="ctx-sep"></div>
    <div class="ctx-item" on:click={ctxAddToScope}>Add host to scope</div>
    <div class="ctx-item" on:click={ctxCopyUrl}>Copy URL</div>
    <div class="ctx-item" on:click={ctxCopyAsCurl}>Copy as curl</div>
    <div class="ctx-item" on:click={() => ctxCopyAs("powershell")}>Copy as PowerShell</div>
    <div class="ctx-item" on:click={() => ctxCopyAs("fetch")}>Copy as fetch</div>
    <div class="ctx-sep"></div>
    <div class="ctx-item" on:click={saveEntireHistory}>Save entire history</div>
  </div>
{/if}

{#if wsCtxMenu}
  <div class="ctx-menu" style="left:{wsCtxMenu.x}px;top:{wsCtxMenu.y}px" on:click|stopPropagation>
    <div class="ctx-item" on:click={wsSendToComparer}>Send to Comparer</div>
    <div class="ctx-item" on:click={wsSendToDecoder}>Send to Decoder</div>
    <div class="ctx-item" on:click={wsCopyPayload}>Copy payload</div>
  </div>
{/if}

<style>
  .ws-body { flex: 1; display: flex; flex-direction: column; overflow: hidden; min-height: 0; }
  .ws-body .table-wrap { flex: 1; overflow-y: auto; min-height: 0; }
  .ws-detail { height: 220px; flex-shrink: 0; border-top: 2px solid var(--border); display: flex; flex-direction: column; }
  .ws-detail .raw-area { flex: 1; resize: none; border: none; padding: 8px 10px; font-size: 11px; font-family: ui-monospace, Consolas, monospace; outline: none; background: #ffffff; }
  .ws-preview { max-width: 380px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .dir-c2s { color: #1a75c4; font-weight: 600; }
  .dir-s2c { color: #1b8c1b; font-weight: 600; }
  .small { font-size: 11px; }

  .ctx-menu {
    position: fixed; z-index: 9999;
    background: #ffffff;
    border: 1px solid var(--border-strong);
    border-radius: 4px;
    box-shadow: 0 6px 18px rgba(0,0,0,0.18);
    padding: 4px 0;
    min-width: 220px;
    font-size: 12px;
  }
  .ctx-item {
    padding: 6px 14px;
    cursor: pointer;
    color: var(--text);
    user-select: none;
  }
  .ctx-item:hover { background: var(--row-hover); }
  .ctx-sep { height: 1px; background: var(--border); margin: 4px 0; }
  .ctx-shortcut { float: right; color: var(--text-muted); font-size: 11px; padding-left: 14px; }

  .intercept-toolbar {
    display: flex; align-items: center; gap: 4px;
    padding: 6px 10px;
    background: var(--surface-2);
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
    flex-wrap: wrap;
  }
  .intercept-toggle-btn {
    display: flex; align-items: center; gap: 5px;
    padding: 4px 12px;
    font-size: 13px; font-weight: 500;
    border-radius: 3px; cursor: pointer;
  }
  .intercept-off { background: var(--surface-2); color: var(--text-2); border: 1px solid var(--border-strong); }
  .intercept-on  { background: var(--accent); color: #fff; border: 1px solid var(--accent-hover); }
  .intercept-off:hover { background: var(--surface-3); }
  .intercept-on:hover  { background: var(--accent-hover); }
  .toolbar-btn {
    padding: 4px 10px; font-size: 13px;
    background: var(--surface-2); color: var(--text);
    border: 1px solid var(--border-strong); border-radius: 3px; cursor: pointer;
    display: flex; align-items: center; gap: 4px;
  }
  .toolbar-btn:hover:not(:disabled) { background: var(--surface-3); }
  .toolbar-btn:disabled { opacity: 0.45; cursor: not-allowed; }
  .dd-arrow { font-size: 10px; }
  .queue-badge {
    font-size: 11px; font-weight: 600;
    background: var(--accent); color: #fff;
    padding: 2px 8px; border-radius: 10px;
    margin-left: 4px;
  }

  .intercept-body {
    flex: 1; display: flex; flex-direction: column; overflow: hidden; min-height: 0;
  }
  .intercept-split {
    flex: 1; display: flex; overflow: hidden; min-height: 0;
  }
  .queue-list {
    width: 180px; flex-shrink: 0;
    overflow-y: auto;
    border-right: 1px solid var(--border);
    background: var(--surface-1);
  }
  .queue-item {
    display: flex; flex-direction: column; gap: 1px;
    padding: 6px 10px; cursor: pointer;
    border-bottom: 1px solid var(--border);
    font-size: 12px;
  }
  .queue-item:hover { background: var(--row-hover); }
  .queue-item-active { background: var(--row-active) !important; }
  .queue-method { font-weight: 600; font-size: 11px; color: var(--accent); }
  .queue-host { font-size: 11px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

  .intercept-editor-wrap {
    flex: 1; display: flex; flex-direction: column; overflow: hidden;
  }
  .editor-toolbar {
    display: flex; align-items: center; justify-content: space-between;
    padding: 5px 10px;
    background: var(--surface-2);
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
    font-size: 12px;
  }
  .editor-label { font-weight: 600; color: var(--text-2); font-family: ui-monospace, Consolas, monospace; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 60%; }
  .intercept-area {
    flex: 1; resize: none;
    border: none; border-radius: 0;
    background: #ffffff; color: var(--text);
    font-size: 12px;
    font-family: ui-monospace, "Cascadia Code", Consolas, monospace;
    padding: 10px 12px; min-height: 0;
    outline: none; width: 100%;
  }

  .intercept-off-state, .intercept-waiting {
    flex: 1; display: flex; flex-direction: column;
    align-items: center; justify-content: center;
    gap: 12px; padding: 40px;
  }
  .intercept-off-title {
    font-size: 16px; font-weight: 700; color: var(--text); margin: 0;
  }
  .intercept-off-actions { display: flex; gap: 8px; margin-top: 6px; }
  .btn-orange {
    background: var(--accent); color: #fff; border: none; border-radius: 3px;
    padding: 5px 14px; font-size: 13px; cursor: pointer;
  }
  .btn-orange:hover { background: var(--accent-hover); }
  .btn-secondary {
    background: var(--surface-2); color: var(--text); border: 1px solid var(--border-strong); border-radius: 3px;
    padding: 5px 14px; font-size: 13px; cursor: pointer;
  }
  .btn-secondary:hover { background: var(--surface-3); }

  /* Spinner */
  .spinner {
    width: 32px; height: 32px; border-radius: 50%;
    border: 3px solid var(--border); border-top-color: var(--accent);
    animation: spin 0.8s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* History */
  .history-body { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
  .table-wrap { flex: 1; overflow-y: auto; min-height: 0; }
  .data-table { width: 100%; border-collapse: collapse; font-size: 12px; }
  .data-table th, .data-table td { text-align: left; padding: 5px 10px; border-bottom: 1px solid var(--border); white-space: nowrap; }
  .data-table thead th { background: var(--surface-2); color: var(--text-muted); font-size: 11px; font-weight: 600; position: sticky; top: 0; z-index: 1; border-bottom: 1px solid var(--border); }
  .data-table tbody tr { cursor: pointer; }
  .data-table tbody tr:hover { background: var(--row-hover); }
  .row-selected { background: var(--row-active) !important; }
  .row-even { background: var(--surface-1); }
  .path-cell { max-width: 280px; overflow: hidden; text-overflow: ellipsis; }
  .empty-cell { text-align: center; padding: 40px; color: var(--text-muted); }
  .mono-cell { font-family: ui-monospace, Consolas, monospace; font-size: 11px; }
  .del-btn { padding: 1px 6px; font-size: 13px; background: transparent; border: none; cursor: pointer; color: var(--text-muted); }
  .del-btn:hover { color: #d42c2c; }
  .mr-in { width: 100%; box-sizing: border-box; padding: 3px 6px; border: 1px solid #d8d8d8; border-radius: 3px; font-size: 12px; }
  .mr-in.mono { font-family: ui-monospace, Consolas, monospace; }
  .mr-sel { padding: 3px 4px; border: 1px solid #d8d8d8; border-radius: 3px; font-size: 11px; }
  .ord-btn { padding: 0 4px; font-size: 10px; background: var(--surface-2); border: 1px solid var(--border-strong); border-radius: 2px; cursor: pointer; }
  .ord-btn:disabled { opacity: 0.35; cursor: default; }
  .action-wrap { position: relative; display: inline-block; }
  .action-menu { position: absolute; top: 100%; left: 0; background: #fff; border: 1px solid var(--border-strong); border-radius: 4px; box-shadow: 0 4px 16px rgba(0,0,0,0.18); z-index: 50; min-width: 200px; padding: 4px 0; }
  .action-menu .ctx-item { padding: 5px 14px; font-size: 12px; cursor: pointer; }
  .action-menu .ctx-item:hover { background: var(--row-hover); }

  .detail-pane { height: 260px; flex-shrink: 0; border-top: 2px solid var(--border); }
  .pane-header { display: flex !important; align-items: center !important; justify-content: space-between !important; }
  .inline-tabs { display: flex; gap: 2px; }
  .itab { padding: 2px 8px; font-size: 11px; background: transparent; border: 1px solid transparent; border-radius: 3px; color: var(--text-muted); cursor: pointer; }
  .itab:hover { color: var(--text); background: var(--surface-2); }
  .itab-active { color: var(--accent) !important; border-color: var(--accent) !important; background: transparent !important; }
  .raw-area { flex: 1; resize: none; min-height: 0; border: none; border-radius: 0; background: #ffffff; color: var(--text); font-size: 11px; padding: 10px; height: 100%; outline: none; font-family: ui-monospace, Consolas, monospace; }

  /* Match & Replace */
  .empty-state { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 12px; padding: 40px; }

  /* Settings */
  .settings-section { display: flex; flex-direction: column; gap: 8px; }
  .settings-title { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-muted); margin-bottom: 6px; }
  .settings-card { background: var(--surface-1); border: 1px solid var(--border); border-radius: 4px; padding: 14px; }
  .settings-row { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
  .settings-label { font-size: 13px; color: var(--text-2); white-space: nowrap; }
  .settings-desc { font-size: 13px; color: var(--text-2); margin: 4px 0; line-height: 1.5; }
  code { background: var(--surface-2); color: var(--text); padding: 1px 5px; border-radius: 3px; font-family: ui-monospace, Consolas, monospace; font-size: 12px; }

  /* History filter bar */
  .history-filter-bar { padding-top: 0; gap: 12px; flex-wrap: wrap; }
  .filter-chk { display: flex; align-items: center; gap: 5px; font-size: 12px; color: var(--text-2); cursor: pointer; white-space: nowrap; user-select: none; }
  .filter-chk input { cursor: pointer; }
  .ext-filter { width: 110px; padding: 3px 6px; font-size: 12px; border: 1px solid var(--border-strong); border-radius: 3px; background: var(--surface-1); color: var(--text); }

  /* Inline comment editing */
  .comment-cell { max-width: 180px; }
  .comment-text { display: inline-block; max-width: 170px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; vertical-align: bottom; color: var(--text-2); cursor: text; padding: 0 2px; }
  .comment-text:hover { color: var(--accent); }
  .comment-input { width: 160px; padding: 2px 5px; font-size: 12px; border: 1px solid var(--accent); border-radius: 3px; background: var(--surface-1); color: var(--text); }

  /* Highlight submenu / flyout */
  .ctx-submenu { position: relative; }
  .ctx-flyout { position: absolute; left: 100%; top: -5px; background: #ffffff; border: 1px solid var(--border-strong); border-radius: 4px; box-shadow: 0 6px 18px rgba(0,0,0,0.18); padding: 4px 0; min-width: 140px; z-index: 10000; }
  .color-item { display: flex; align-items: center; gap: 8px; }
  .color-swatch { display: inline-block; width: 13px; height: 13px; border-radius: 3px; border: 1px solid var(--border-strong); flex-shrink: 0; }
</style>
