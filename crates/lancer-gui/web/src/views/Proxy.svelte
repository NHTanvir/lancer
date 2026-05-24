<script>
  import { onMount, onDestroy } from "svelte";

  let subtab = "intercept";

  // Intercept state
  let interceptOn = false;
  let interceptQueue = [];  // paused requests from the API
  let selectedPaused = null;
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

  function addRule() {
    rules = [...rules, { name: "New rule", enabled: true, target: "RequestHeader", pattern: "", replacement: "", is_regex: false, only_in_scope: false }];
    saveRules();
  }

  function removeRule(i) {
    rules = rules.filter((_, idx) => idx !== i);
    saveRules();
  }

  async function downloadCert(fmt) {
    window.open(`/api/v1/proxy/ca-cert.${fmt}`, "_blank");
  }

  onMount(async () => {
    await loadProxyStatus();
    if (subtab === "history") await refreshHistory();
    if (subtab === "matchreplace") await loadRules();

    // Poll intercept queue every 500ms when intercept is on
    pollTimer = setInterval(async () => {
      if (subtab === "intercept" && interceptOn) await pollIntercept();
    }, 500);
  });

  onDestroy(() => { if (pollTimer) clearInterval(pollTimer); });

  $: filteredRows = rows.filter(r =>
    !filter ||
    (r.host && r.host.includes(filter)) ||
    (r.path && r.path.includes(filter)) ||
    String(r.status || "").includes(filter) ||
    (r.method && r.method.includes(filter.toUpperCase()))
  );

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
        Drop
      </button>
      <button class="toolbar-btn" disabled={interceptQueue.length === 0} on:click={forwardAll}>
        Forward all
      </button>
      <button class="toolbar-btn" disabled={!selectedPaused}>Action ▼</button>
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
            <rect x="28" y="8" width="24" height="64" rx="8" fill="#444" opacity="0.1"/>
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

    <div class="history-body">
      <div class="table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th>#</th><th>Host</th><th>Method</th><th>URL</th>
              <th>Status</th><th>Length</th><th>MIME</th><th>Time (ms)</th><th></th>
            </tr>
          </thead>
          <tbody>
            {#each filteredRows as row, i}
              <tr
                class:row-selected={selected === row}
                class:row-even={i % 2 === 0}
                on:click={() => selected = selected === row ? null : row}
              >
                <td class="dim">{i + 1}</td>
                <td>{row.host || "-"}</td>
                <td class={methodClass(row.method)}>{row.method || "-"}</td>
                <td class="path-cell" title={row.path}>{(row.path||"/").length > 60 ? (row.path||"/").slice(0,60)+"..." : (row.path||"/")}</td>
                <td class={statusClass(row.status)}>{row.status || "-"}</td>
                <td class="dim">{row.response_length ?? "-"}</td>
                <td class="dim">{row.mime || "-"}</td>
                <td class="dim">{row.elapsed_ms ?? "-"}</td>
                <td>
                  <button class="del-btn dim" title="Delete" on:click={e => deleteHistoryItem(row.id, e)}>×</button>
                </td>
              </tr>
            {/each}
            {#if filteredRows.length === 0}
              <tr><td colspan="9" class="empty-cell">No requests yet. Browse through <code>{listenAddr}</code>.</td></tr>
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
    <div class="empty-state">
      <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
        <path d="M8 24 Q16 12 24 24 Q32 36 40 24" stroke="#c8c8c8" stroke-width="2" fill="none" stroke-linecap="round"/>
        <circle cx="8"  cy="24" r="3" fill="#c8c8c8"/>
        <circle cx="40" cy="24" r="3" fill="#c8c8c8"/>
      </svg>
      <span class="dim" style="font-size:13px">No WebSocket messages captured yet.</span>
    </div>
  {/if}

  <!-- ─── MATCH AND REPLACE ─── -->
  {#if subtab === "matchreplace"}
    <div class="toolbar">
      <button class="btn-orange" on:click={addRule}>Add</button>
      <span class="dim" style="font-size:12px;margin-left:4px">{rules.length} rules</span>
    </div>
    <div class="table-wrap" style="flex:1;overflow-y:auto">
      <table class="data-table">
        <thead>
          <tr>
            <th style="width:36px">On</th>
            <th>Name</th>
            <th>Target</th>
            <th>Match</th>
            <th>Replace</th>
            <th style="width:40px"></th>
          </tr>
        </thead>
        <tbody>
          {#each rules as rule, i}
            <tr class:row-even={i % 2 === 0}>
              <td><input type="checkbox" checked={rule.enabled} on:change={() => toggleRule(i)} /></td>
              <td>{rule.name}</td>
              <td>{rule.target}</td>
              <td class="mono-cell">{rule.pattern}</td>
              <td class="mono-cell">{rule.replacement}</td>
              <td><button class="del-btn dim" on:click={() => removeRule(i)}>×</button></td>
            </tr>
          {/each}
          {#if rules.length === 0}
            <tr><td colspan="6" class="empty-cell">No match/replace rules. Click Add to create one.</td></tr>
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
          <p class="settings-desc" style="margin-top:8px;font-size:12px;color:#767676">
            To install in Chrome/Edge: Settings → Security → Manage certificates → Authorities → Import → select lancer-ca.der
          </p>
        </div>
      </div>
    </div>
  {/if}
</div>

<style>
  .intercept-toolbar {
    display: flex; align-items: center; gap: 4px;
    padding: 6px 10px;
    background: #f5f5f5;
    border-bottom: 1px solid #dedede;
    flex-shrink: 0;
    flex-wrap: wrap;
  }
  .intercept-toggle-btn {
    display: flex; align-items: center; gap: 5px;
    padding: 4px 12px;
    font-size: 13px; font-weight: 500;
    border-radius: 3px; cursor: pointer;
  }
  .intercept-off { background: #f0f0f0; color: #444; border: 1px solid #c8c8c8; }
  .intercept-on  { background: #e03a00; color: #fff; border: 1px solid #c73400; }
  .intercept-off:hover { background: #e4e4e4; }
  .intercept-on:hover  { background: #c73400; }
  .toolbar-btn {
    padding: 4px 10px; font-size: 13px;
    background: #f0f0f0; color: #333;
    border: 1px solid #c8c8c8; border-radius: 3px; cursor: pointer;
    display: flex; align-items: center; gap: 4px;
  }
  .toolbar-btn:hover:not(:disabled) { background: #e4e4e4; }
  .toolbar-btn:disabled { opacity: 0.45; cursor: not-allowed; }
  .dd-arrow { font-size: 10px; }
  .queue-badge {
    font-size: 11px; font-weight: 600;
    background: #e03a00; color: #fff;
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
    border-right: 1px solid #dedede;
    background: #fafafa;
  }
  .queue-item {
    display: flex; flex-direction: column; gap: 1px;
    padding: 6px 10px; cursor: pointer;
    border-bottom: 1px solid #e8e8e8;
    font-size: 12px;
  }
  .queue-item:hover { background: #f0f7ff; }
  .queue-item-active { background: #daeeff !important; }
  .queue-method { font-weight: 600; font-size: 11px; color: #e03a00; }
  .queue-host { font-size: 11px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

  .intercept-editor-wrap {
    flex: 1; display: flex; flex-direction: column; overflow: hidden;
  }
  .editor-toolbar {
    display: flex; align-items: center; justify-content: space-between;
    padding: 5px 10px;
    background: #f5f5f5;
    border-bottom: 1px solid #dedede;
    flex-shrink: 0;
    font-size: 12px;
  }
  .editor-label { font-weight: 600; color: #444; font-family: ui-monospace, Consolas, monospace; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 60%; }
  .intercept-area {
    flex: 1; resize: none;
    border: none; border-radius: 0;
    background: #ffffff; color: #212121;
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
    font-size: 16px; font-weight: 700; color: #212121; margin: 0;
  }
  .intercept-off-actions { display: flex; gap: 8px; margin-top: 6px; }
  .btn-orange {
    background: #e03a00; color: #fff; border: none; border-radius: 3px;
    padding: 5px 14px; font-size: 13px; cursor: pointer;
  }
  .btn-orange:hover { background: #c73400; }
  .btn-secondary {
    background: #f0f0f0; color: #333; border: 1px solid #c8c8c8; border-radius: 3px;
    padding: 5px 14px; font-size: 13px; cursor: pointer;
  }
  .btn-secondary:hover { background: #e4e4e4; }

  /* Spinner */
  .spinner {
    width: 32px; height: 32px; border-radius: 50%;
    border: 3px solid #dedede; border-top-color: #e03a00;
    animation: spin 0.8s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* History */
  .history-body { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
  .table-wrap { flex: 1; overflow-y: auto; min-height: 0; }
  .data-table { width: 100%; border-collapse: collapse; font-size: 12px; }
  .data-table th, .data-table td { text-align: left; padding: 5px 10px; border-bottom: 1px solid #e8e8e8; white-space: nowrap; }
  .data-table thead th { background: #f5f5f5; color: #767676; font-size: 11px; font-weight: 600; position: sticky; top: 0; z-index: 1; border-bottom: 1px solid #dedede; }
  .data-table tbody tr { cursor: pointer; }
  .data-table tbody tr:hover { background: #f0f7ff; }
  .row-selected { background: #daeeff !important; }
  .row-even { background: #fafafa; }
  .path-cell { max-width: 280px; overflow: hidden; text-overflow: ellipsis; }
  .empty-cell { text-align: center; padding: 40px; color: #767676; }
  .mono-cell { font-family: ui-monospace, Consolas, monospace; font-size: 11px; }
  .del-btn { padding: 1px 6px; font-size: 13px; background: transparent; border: none; cursor: pointer; color: #767676; }
  .del-btn:hover { color: #d42c2c; }

  .detail-pane { height: 260px; flex-shrink: 0; border-top: 2px solid #dedede; }
  .pane-header { display: flex !important; align-items: center !important; justify-content: space-between !important; }
  .inline-tabs { display: flex; gap: 2px; }
  .itab { padding: 2px 8px; font-size: 11px; background: transparent; border: 1px solid transparent; border-radius: 3px; color: #767676; cursor: pointer; }
  .itab:hover { color: #212121; background: #f0f0f0; }
  .itab-active { color: #e03a00 !important; border-color: #e03a00 !important; background: transparent !important; }
  .raw-area { flex: 1; resize: none; min-height: 0; border: none; border-radius: 0; background: #ffffff; color: #212121; font-size: 11px; padding: 10px; height: 100%; outline: none; font-family: ui-monospace, Consolas, monospace; }

  /* Match & Replace */
  .empty-state { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 12px; padding: 40px; }

  /* Settings */
  .settings-section { display: flex; flex-direction: column; gap: 8px; }
  .settings-title { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; color: #767676; margin-bottom: 6px; }
  .settings-card { background: #fafafa; border: 1px solid #dedede; border-radius: 4px; padding: 14px; }
  .settings-row { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
  .settings-label { font-size: 13px; color: #444; white-space: nowrap; }
  .settings-desc { font-size: 13px; color: #444; margin: 4px 0; line-height: 1.5; }
  code { background: #f0f0f0; color: #212121; padding: 1px 5px; border-radius: 3px; font-family: ui-monospace, Consolas, monospace; font-size: 12px; }
</style>
