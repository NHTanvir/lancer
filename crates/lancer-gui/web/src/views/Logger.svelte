<script>
  import { onMount, onDestroy } from "svelte";

  let rows = [];
  let filter = "";
  let selected = null;
  let pollInterval = null;
  let sourceFilter = "all"; // all | proxy | tool
  // §12 per-tool capture toggles (client-side view filter; persisted).
  let capture = { proxy: true, tool: true };
  try { const s = localStorage.getItem("lancer.logger.capture"); if (s) capture = JSON.parse(s); } catch {}
  $: try { localStorage.setItem("lancer.logger.capture", JSON.stringify(capture)); } catch {}

  function sourceOf(r) { return r.tool_generated ? "tool" : "proxy"; }

  // §12 advanced capture filter (client-side expression). When enabled, only
  // rows for which the boolean expression is true are shown. Field bindings:
  // host, method, status, path, mime, scheme, length, params, comment, tool.
  let captureFilterOn = false;
  let captureFilter = "";
  try {
    const s = localStorage.getItem("lancer.logger.captureFilter");
    if (s) { const v = JSON.parse(s); captureFilterOn = !!v.on; captureFilter = v.expr || ""; }
  } catch {}
  $: try { localStorage.setItem("lancer.logger.captureFilter", JSON.stringify({ on: captureFilterOn, expr: captureFilter })); } catch {}

  let captureFilterErr = "";
  // Compile once per expression change; null when empty/invalid.
  $: captureFn = (() => {
    captureFilterErr = "";
    if (!captureFilterOn || !captureFilter.trim()) return null;
    try {
      // Sandboxed-ish: expression sees only the named bindings we pass in.
      // eslint-disable-next-line no-new-func
      return new Function(
        "host", "method", "status", "path", "mime", "scheme", "length", "params", "comment", "tool",
        `"use strict"; return (${captureFilter});`
      );
    } catch (e) {
      captureFilterErr = e.message;
      return null;
    }
  })();

  function passesCapture(r) {
    if (!captureFn) return true;
    try {
      return !!captureFn(
        (r.host || "").toLowerCase(),
        (r.method || "").toUpperCase(),
        Number(r.status) || 0,
        (r.path || "").toLowerCase(),
        (r.mime || "").toLowerCase(),
        (r.scheme || "http").toLowerCase(),
        Number(r.response_length) || 0,
        hasParams(r),
        (r.comment || "").toLowerCase(),
        sourceOf(r)
      );
    } catch (e) {
      captureFilterErr = e.message;
      return true;
    }
  }

  $: filteredRows = rows.filter(r => {
    const src = sourceOf(r);
    if (!capture[src]) return false;
    if (sourceFilter !== "all" && src !== sourceFilter) return false;
    if (!passesCapture(r)) return false;
    return !filter ||
      (r.host && r.host.toLowerCase().includes(filter.toLowerCase())) ||
      (r.path && r.path.toLowerCase().includes(filter.toLowerCase())) ||
      (r.method && r.method.toLowerCase().includes(filter.toLowerCase())) ||
      String(r.status || "").includes(filter) ||
      (r.scheme && r.scheme.toLowerCase().includes(filter.toLowerCase()));
  });

  function protocolLabel(r) {
    const s = (r.scheme || "http").toUpperCase();
    return s;
  }
  function hasParams(r) {
    if (typeof r.has_params === "boolean") return r.has_params;
    return (r.path || "").includes("?");
  }

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
    if (!r) return `${row.method || "GET"} ${row.path || "/"} HTTP/1.1\nHost: ${row.host || ""}\n`;
    const method = r.method || row.method || "GET";
    const path = r.path || row.path || "/";
    const ver = r.version === "Http2" ? "HTTP/2" : r.version === "Http3" ? "HTTP/3" : "HTTP/1.1";
    const hdrs = (r.headers || []).map(h => `${h.name}: ${h.value}`).join("\n");
    const body = bytesToText(r.body);
    return `${method} ${path} ${ver}\n${hdrs}\n\n${body}`;
  }
  function formatResponse(row) {
    const r = row.response;
    if (!r) return `HTTP/1.1 ${row.status || "?"}\n\n(no body captured)`;
    const ver = r.version === "Http2" ? "HTTP/2" : r.version === "Http3" ? "HTTP/3" : "HTTP/1.1";
    const reason = r.reason || "";
    const hdrs = (r.headers || []).map(h => `${h.name}: ${h.value}`).join("\n");
    const body = bytesToText(r.body);
    return `${ver} ${r.status} ${reason}\n${hdrs}\n\n${body}`;
  }

  // Right-click context menu
  let ctxMenu = null;
  function onRowContextMenu(event, row) {
    event.preventDefault();
    selected = row;
    ctxMenu = { x: event.clientX, y: event.clientY, row };
  }
  function closeCtxMenu() { ctxMenu = null; }
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
  function ctxCopyUrl() {
    if (!ctxMenu) return;
    const r = ctxMenu.row;
    navigator.clipboard.writeText(`${r.scheme || "http"}://${r.host}${r.path || "/"}`).catch(() => {});
    closeCtxMenu();
  }

  // ── Annotation: inline comment + highlight color ─────────────────────
  // Persists via the existing PATCH /api/v1/history/{id} {comment,color}.
  const HIGHLIGHT_COLORS = [
    { name: "Red",    value: "#ffd5d5" },
    { name: "Orange", value: "#ffe2c2" },
    { name: "Yellow", value: "#fff7bf" },
    { name: "Green",  value: "#d6f5d6" },
    { name: "Cyan",   value: "#cdeff5" },
    { name: "Blue",   value: "#d5e3ff" },
    { name: "Purple", value: "#e8d9ff" },
  ];
  let editingCommentId = null;

  async function patchHistory(row, patch) {
    if (!row || row.id == null) return false;
    try {
      const r = await fetch(`/api/v1/history/${encodeURIComponent(row.id)}`, {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(patch),
      });
      return r.ok;
    } catch { return false; }
  }

  async function setComment(row, value) {
    const next = value == null ? "" : value;
    if ((row.comment || "") === next) return;
    const ok = await patchHistory(row, { comment: next });
    if (ok) { row.comment = next; rows = rows; }
  }

  async function setColor(row, value) {
    const ok = await patchHistory(row, { color: value || "" });
    if (ok) { row.color = value || null; rows = rows; }
  }

  function startCommentEdit(row) {
    editingCommentId = row.id;
  }
  function commitCommentEdit(row, value) {
    editingCommentId = null;
    setComment(row, value);
  }

  function ctxSetHighlight(value) {
    if (!ctxMenu) return;
    setColor(ctxMenu.row, value);
    closeCtxMenu();
  }
  function ctxAddComment() {
    if (!ctxMenu) return;
    startCommentEdit(ctxMenu.row);
    closeCtxMenu();
  }

  function statusClass(s) {
    if (!s) return "dim";
    if (s >= 500) return "status-5";
    if (s >= 400) return "status-4";
    if (s >= 300) return "status-3";
    if (s >= 200) return "status-2";
    return "dim";
  }

  function methodClass(m) { return "method-" + (m || "GET"); }

  function formatTime(ts) {
    if (!ts) return "-";
    try { return new Date(ts).toLocaleTimeString(); }
    catch { return String(ts); }
  }

  async function load() {
    try {
      const r = await fetch("/api/v1/history?limit=500");
      if (r.ok) rows = await r.json();
    } catch { rows = []; }
  }

  onMount(() => {
    load();
    pollInterval = setInterval(load, 5000);
    window.addEventListener("click", closeCtxMenu);
  });

  onDestroy(() => {
    if (pollInterval) clearInterval(pollInterval);
    window.removeEventListener("click", closeCtxMenu);
  });
</script>

<div class="view">
  <!-- Filter toolbar -->
  <div class="toolbar">
    <input
      style="flex:1;max-width:380px"
      placeholder="Filter host / path / method / status..."
      bind:value={filter}
    />
    <button class="toolbar-btn" on:click={load}>Reload</button>
    <button class="toolbar-btn" on:click={() => { rows = []; selected = null; }}>Clear</button>
    <select class="src-sel" bind:value={sourceFilter} title="Filter by source tool">
      <option value="all">All sources</option>
      <option value="proxy">Proxy only</option>
      <option value="tool">Tool only</option>
    </select>
    <label class="cap-tog" title="Capture proxy traffic"><input type="checkbox" bind:checked={capture.proxy} /> Proxy</label>
    <label class="cap-tog" title="Capture tool-generated traffic"><input type="checkbox" bind:checked={capture.tool} /> Tools</label>
    <label class="cap-tog" title="Enable advanced capture-filter expression"><input type="checkbox" bind:checked={captureFilterOn} /> Capture filter</label>
    <span class="dim" style="font-size:12px;margin-left:auto">{filteredRows.length} entries</span>
  </div>
  {#if captureFilterOn}
    <div class="capfilter-bar">
      <input
        class="capfilter-input"
        class:cap-err={!!captureFilterErr}
        placeholder="e.g.  status >= 400 && host.includes('api')  —  fields: host, method, status, path, mime, scheme, length, params, comment, tool"
        bind:value={captureFilter}
      />
      {#if captureFilterErr}
        <span class="capfilter-err" title={captureFilterErr}>expression error</span>
      {/if}
    </div>
  {/if}

  <div class="logger-body">
    <div class="table-wrap">
      <table class="data-table">
        <thead>
          <tr>
            <th>#</th>
            <th>Tool</th>
            <th>Protocol</th>
            <th>Host</th>
            <th>Method</th>
            <th>URL</th>
            <th>Params</th>
            <th>Status</th>
            <th>Length</th>
            <th>MIME</th>
            <th>Time</th>
            <th>Comment</th>
          </tr>
        </thead>
        <tbody>
          {#each filteredRows as row, i}
            <tr
              class:row-selected={selected === row}
              class:row-even={i % 2 === 0}
              class:has-color={!!row.color}
              style={row.color ? `background:${row.color}` : ""}
              on:click={() => selected = selected === row ? null : row}
              on:contextmenu={(e) => onRowContextMenu(e, row)}
            >
              <td class="dim mono">{i + 1}</td>
              <td><span class="src-badge src-{sourceOf(row)}">{row.tool_generated ? "Tool" : "Proxy"}</span></td>
              <td class="dim">{protocolLabel(row)}</td>
              <td>{row.host || "-"}</td>
              <td class={methodClass(row.method)}>{row.method || "-"}</td>
              <td class="url-cell" title={row.path}>{row.path && row.path.length > 60 ? row.path.slice(0, 60) + "..." : (row.path || "/")}</td>
              <td class="dim">{hasParams(row) ? "Y" : ""}</td>
              <td class={statusClass(row.status)}>{row.status || "-"}</td>
              <td class="dim">{row.response_length ?? "-"}</td>
              <td class="dim">{row.mime || "-"}</td>
              <td class="dim mono time-cell">{formatTime(row.captured_at)}</td>
              <td class="comment-cell" on:click|stopPropagation on:dblclick={() => startCommentEdit(row)} title="Double-click to edit comment">
                {#if editingCommentId === row.id}
                  <!-- svelte-ignore a11y-autofocus -->
                  <input
                    class="comment-input"
                    autofocus
                    value={row.comment || ""}
                    on:blur={(e) => commitCommentEdit(row, e.target.value)}
                    on:keydown={(e) => { if (e.key === "Enter") e.target.blur(); else if (e.key === "Escape") { editingCommentId = null; } }}
                  />
                {:else}
                  <span class="dim comment-text">{row.comment || ""}</span>
                {/if}
              </td>
            </tr>
          {/each}
          {#if filteredRows.length === 0}
            <tr>
              <td colspan="12" class="empty-cell">
                {rows.length === 0
                  ? "No requests logged yet. Browse via the proxy to populate this log."
                  : "No entries match the current filter."}
              </td>
            </tr>
          {/if}
        </tbody>
      </table>
    </div>

    {#if selected}
      <div class="detail-pane split-h">
        <div class="pane">
          <div class="pane-header">Request</div>
          <textarea
            class="raw-area"
            readonly
            value={formatRequest(selected)}
          ></textarea>
        </div>
        <div class="pane">
          <div class="pane-header">Response</div>
          <textarea
            class="raw-area"
            readonly
            value={formatResponse(selected)}
          ></textarea>
        </div>
      </div>
    {/if}
  </div>
</div>

{#if ctxMenu}
  <div class="ctx-menu" style="left:{ctxMenu.x}px;top:{ctxMenu.y}px" on:click|stopPropagation>
    <div class="ctx-item" on:click={ctxSendToRepeater}>Send to Repeater <span class="ctx-shortcut">Ctrl+R</span></div>
    <div class="ctx-item" on:click={ctxSendToIntruder}>Send to Intruder <span class="ctx-shortcut">Ctrl+I</span></div>
    <div class="ctx-item" on:click={() => ctxSendToComparer("request")}>Send request to Comparer</div>
    <div class="ctx-item" on:click={() => ctxSendToComparer("response")}>Send response to Comparer</div>
    <div class="ctx-item" on:click={ctxSendToDecoder}>Send to Decoder</div>
    <div class="ctx-sep"></div>
    <div class="ctx-item" on:click={ctxAddComment}>Add comment</div>
    <div class="ctx-item ctx-submenu">
      Set highlight
      <span class="ctx-shortcut">▸</span>
      <div class="ctx-flyout">
        <div class="ctx-item ctx-color" on:click={() => ctxSetHighlight("")}>
          <span class="color-swatch swatch-none"></span> None
        </div>
        {#each HIGHLIGHT_COLORS as c}
          <div class="ctx-item ctx-color" on:click={() => ctxSetHighlight(c.value)}>
            <span class="color-swatch" style="background:{c.value}"></span> {c.name}
          </div>
        {/each}
      </div>
    </div>
    <div class="ctx-sep"></div>
    <div class="ctx-item" on:click={ctxCopyUrl}>Copy URL</div>
  </div>
{/if}

<style>
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

  /* Highlight submenu */
  .ctx-submenu { position: relative; }
  .ctx-flyout {
    position: absolute; left: 100%; top: -4px;
    display: none;
    background: #ffffff;
    border: 1px solid var(--border-strong);
    border-radius: 4px;
    box-shadow: 0 6px 18px rgba(0,0,0,0.18);
    padding: 4px 0; min-width: 140px;
  }
  .ctx-submenu:hover .ctx-flyout { display: block; }
  .ctx-color { display: flex; align-items: center; gap: 8px; }
  .color-swatch {
    width: 12px; height: 12px; border-radius: 3px;
    border: 1px solid var(--border-strong); flex-shrink: 0;
  }
  .swatch-none { background: repeating-linear-gradient(45deg, #fff, #fff 3px, var(--border) 3px, var(--border) 4px); }

  /* Inline comment editing */
  .comment-input {
    width: 100%; box-sizing: border-box;
    font-size: 12px; padding: 1px 4px; font-style: normal;
    border: 1px solid var(--accent); border-radius: 2px;
    background: #fff; color: var(--text); outline: none;
  }
  .comment-text { display: block; overflow: hidden; text-overflow: ellipsis; }
  /* Colored rows: keep hover/selection legible by letting them win */
  .data-table tbody tr.has-color:hover { filter: brightness(0.96); }
  .data-table tbody tr.has-color.row-selected { box-shadow: inset 3px 0 0 var(--accent); }

  .toolbar {
    display: flex; align-items: center; gap: 6px;
    padding: 6px 12px;
    background: var(--surface-2);
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }
  .toolbar-btn {
    padding: 4px 10px; font-size: 13px;
    background: var(--surface-2); color: var(--text);
    border: 1px solid var(--border-strong); border-radius: 3px;
    cursor: pointer;
  }
  .src-sel { padding: 4px 6px; font-size: 12px; border: 1px solid var(--border-strong); border-radius: 3px; }
  .cap-tog { display: flex; align-items: center; gap: 3px; font-size: 12px; color: var(--text-2); }
  .src-badge { font-size: 10px; font-weight: 700; padding: 1px 6px; border-radius: 3px; }
  .src-proxy { background: #e6f0fb; color: #2e6fae; }
  .src-tool { background: #fff1e6; color: #c2620a; }
  .toolbar-btn:hover { background: var(--surface-3); }

  .capfilter-bar {
    display: flex; align-items: center; gap: 8px;
    padding: 5px 12px;
    background: var(--surface-1);
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }
  .capfilter-input {
    flex: 1; font-size: 12px; padding: 4px 8px;
    border: 1px solid var(--border-strong); border-radius: 3px;
    background: #fff; color: var(--text);
    font-family: ui-monospace, Consolas, monospace;
  }
  .capfilter-input.cap-err { border-color: #d42c2c; }
  .capfilter-err { font-size: 11px; color: #d42c2c; white-space: nowrap; }

  .logger-body {
    flex: 1; display: flex; flex-direction: column;
    overflow: hidden; min-height: 0;
  }
  .table-wrap { flex: 1; overflow-y: auto; min-height: 0; }
  .data-table {
    width: 100%; border-collapse: collapse; font-size: 12px;
  }
  .data-table th, .data-table td {
    text-align: left;
    padding: 5px 10px;
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }
  .data-table thead th {
    background: var(--surface-2);
    color: var(--text-muted);
    font-size: 11px; font-weight: 600;
    position: sticky; top: 0; z-index: 1;
    border-bottom: 1px solid var(--border);
  }
  .data-table tbody tr { cursor: pointer; }
  .data-table tbody tr:hover { background: var(--row-hover); }
  .row-selected { background: var(--row-active) !important; }
  .row-even { background: var(--surface-1); }
  .url-cell    { max-width: 280px; overflow: hidden; text-overflow: ellipsis; }
  .time-cell   { font-size: 11px; }
  .comment-cell{ max-width: 120px; overflow: hidden; text-overflow: ellipsis; font-style: italic; }
  .mono { font-family: ui-monospace, Consolas, monospace; }
  .empty-cell { text-align: center; padding: 40px; color: var(--text-muted); }

  .detail-pane {
    height: 260px; flex-shrink: 0;
    border-top: 2px solid var(--border);
  }
  .pane-header {
    padding: 5px 10px;
    background: var(--surface-2);
    border-bottom: 1px solid var(--border);
    font-size: 12px; font-weight: 600; color: var(--text-2);
    flex-shrink: 0;
  }
  .raw-area {
    flex: 1; resize: none; min-height: 0;
    border: none; border-radius: 0;
    background: #ffffff; color: var(--text);
    font-size: 11px; padding: 10px; height: 100%;
    outline: none;
    font-family: ui-monospace, Consolas, monospace;
  }
</style>
