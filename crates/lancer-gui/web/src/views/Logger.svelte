<script>
  import { onMount, onDestroy } from "svelte";

  let rows = [];
  let filter = "";
  let selected = null;
  let pollInterval = null;

  $: filteredRows = rows.filter(r =>
    !filter ||
    (r.host && r.host.toLowerCase().includes(filter.toLowerCase())) ||
    (r.path && r.path.toLowerCase().includes(filter.toLowerCase())) ||
    (r.method && r.method.toLowerCase().includes(filter.toLowerCase())) ||
    String(r.status || "").includes(filter) ||
    (r.scheme && r.scheme.toLowerCase().includes(filter.toLowerCase()))
  );

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
  });

  onDestroy(() => {
    if (pollInterval) clearInterval(pollInterval);
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
    <span class="dim" style="font-size:12px;margin-left:auto">{filteredRows.length} entries</span>
  </div>

  <div class="logger-body">
    <div class="table-wrap">
      <table class="data-table">
        <thead>
          <tr>
            <th>#</th>
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
              on:click={() => selected = selected === row ? null : row}
            >
              <td class="dim mono">{i + 1}</td>
              <td class="dim">{protocolLabel(row)}</td>
              <td>{row.host || "-"}</td>
              <td class={methodClass(row.method)}>{row.method || "-"}</td>
              <td class="url-cell" title={row.path}>{row.path && row.path.length > 60 ? row.path.slice(0, 60) + "..." : (row.path || "/")}</td>
              <td class="dim">{hasParams(row) ? "Y" : ""}</td>
              <td class={statusClass(row.status)}>{row.status || "-"}</td>
              <td class="dim">{row.response_length ?? "-"}</td>
              <td class="dim">{row.mime || "-"}</td>
              <td class="dim mono time-cell">{formatTime(row.captured_at)}</td>
              <td class="dim comment-cell">{row.comment || ""}</td>
            </tr>
          {/each}
          {#if filteredRows.length === 0}
            <tr>
              <td colspan="11" class="empty-cell">
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

<style>
  .toolbar {
    display: flex; align-items: center; gap: 6px;
    padding: 6px 12px;
    background: #f5f5f5;
    border-bottom: 1px solid #dedede;
    flex-shrink: 0;
  }
  .toolbar-btn {
    padding: 4px 10px; font-size: 13px;
    background: #f0f0f0; color: #333;
    border: 1px solid #c8c8c8; border-radius: 3px;
    cursor: pointer;
  }
  .toolbar-btn:hover { background: #e4e4e4; }

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
    border-bottom: 1px solid #e8e8e8;
    white-space: nowrap;
  }
  .data-table thead th {
    background: #f5f5f5;
    color: #767676;
    font-size: 11px; font-weight: 600;
    position: sticky; top: 0; z-index: 1;
    border-bottom: 1px solid #dedede;
  }
  .data-table tbody tr { cursor: pointer; }
  .data-table tbody tr:hover { background: #f0f7ff; }
  .row-selected { background: #daeeff !important; }
  .row-even { background: #fafafa; }
  .url-cell    { max-width: 280px; overflow: hidden; text-overflow: ellipsis; }
  .time-cell   { font-size: 11px; }
  .comment-cell{ max-width: 120px; overflow: hidden; text-overflow: ellipsis; font-style: italic; }
  .mono { font-family: ui-monospace, Consolas, monospace; }
  .empty-cell { text-align: center; padding: 40px; color: #767676; }

  .detail-pane {
    height: 260px; flex-shrink: 0;
    border-top: 2px solid #dedede;
  }
  .pane-header {
    padding: 5px 10px;
    background: #f5f5f5;
    border-bottom: 1px solid #dedede;
    font-size: 12px; font-weight: 600; color: #444;
    flex-shrink: 0;
  }
  .raw-area {
    flex: 1; resize: none; min-height: 0;
    border: none; border-radius: 0;
    background: #ffffff; color: #212121;
    font-size: 11px; padding: 10px; height: 100%;
    outline: none;
    font-family: ui-monospace, Consolas, monospace;
  }
</style>
