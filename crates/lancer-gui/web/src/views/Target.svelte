<script>
  import { onMount, onDestroy } from "svelte";

  let subtab = "sitemap";
  let issues = [];

  // Site map state
  let history = [];
  let selectedEntry = null;
  let expandedHosts = {};
  let reqTab = "pretty";
  let respTab = "pretty";
  let ctxMenu = null; // { x, y, entry }
  let pollTimer;

  // Group history by host
  $: siteTree = buildTree(history);

  function buildTree(entries) {
    const hosts = {};
    for (const e of entries) {
      const host = e.host || e.url?.replace(/https?:\/\//, "").split("/")[0] || "unknown";
      if (!hosts[host]) hosts[host] = [];
      hosts[host].push(e);
    }
    return Object.entries(hosts).map(([host, items]) => ({ host, items }));
  }

  function toggleHost(host) {
    expandedHosts = { ...expandedHosts, [host]: !expandedHosts[host] };
  }

  function selectEntry(e) {
    selectedEntry = e;
    ctxMenu = null;
  }

  function onRightClick(event, entry) {
    event.preventDefault();
    ctxMenu = { x: event.clientX, y: event.clientY, entry };
  }

  function closeCtx() { ctxMenu = null; }

  function ctxSendToRepeater() {
    if (!ctxMenu) return;
    const e = ctxMenu.entry;
    const raw = e.raw_request || e.request || "";
    localStorage.setItem("repeater_prefill", JSON.stringify({
      method: e.method || "GET",
      host: e.host || "",
      path: e.path || e.url || "/",
      raw
    }));
    window.dispatchEvent(new CustomEvent("lancer:navigate", { detail: "repeater" }));
    closeCtx();
  }

  function ctxCopyUrl() {
    if (!ctxMenu) return;
    const url = ctxMenu.entry.url || `${ctxMenu.entry.host}${ctxMenu.entry.path || ""}`;
    navigator.clipboard.writeText(url).catch(() => {});
    closeCtx();
  }

  function ctxAddScope() { closeCtx(); }
  function ctxDelete() {
    if (!ctxMenu) return;
    history = history.filter(h => h !== ctxMenu.entry);
    if (selectedEntry === ctxMenu.entry) selectedEntry = null;
    closeCtx();
  }

  function formatRequest(e) {
    if (e.raw_request) return e.raw_request;
    const method = e.method || "GET";
    const path = e.path || "/";
    const host = e.host || "";
    return `${method} ${path} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: Lancer/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n`;
  }

  function formatResponse(e) {
    if (e.raw_response) return e.raw_response;
    const status = e.status || "?";
    const body = e.body || e.response_body || "";
    return `HTTP/1.1 ${status}\r\n\r\n${body}`;
  }

  function hexDump(str) {
    return str.split("").map((c, i) => {
      const h = c.charCodeAt(0).toString(16).padStart(2, "0");
      return (i > 0 && i % 16 === 0 ? "\n" : "") + h + " ";
    }).join("");
  }

  function severityClass(s) {
    const m = { Critical: "badge-Critical", High: "badge-High", Medium: "badge-Medium", Low: "badge-Low", Info: "badge-Info" };
    return m[s] || "badge-Info";
  }

  async function fetchHistory() {
    try {
      const r = await fetch("/api/v1/history");
      if (r.ok) {
        const d = await r.json();
        history = Array.isArray(d) ? d : (d.entries || d.history || []);
      }
    } catch {}
  }

  async function fetchIssues() {
    try {
      const r = await fetch("/api/v1/issues");
      if (r.ok) {
        const d = await r.json();
        issues = Array.isArray(d) ? d : (d.issues || []);
      }
    } catch {}
  }

  onMount(() => {
    fetchHistory();
    fetchIssues();
    pollTimer = setInterval(fetchHistory, 4000);
    window.addEventListener("click", closeCtx);
  });

  onDestroy(() => {
    clearInterval(pollTimer);
    window.removeEventListener("click", closeCtx);
  });
</script>

<div class="view">
  <div class="subtabs">
    <button class="subtab" class:active={subtab==="sitemap"} on:click={() => subtab="sitemap"}>Site map</button>
    <button class="subtab" class:active={subtab==="scope"}   on:click={() => subtab="scope"}>Scope</button>
    <button class="subtab" class:active={subtab==="issues"}  on:click={() => subtab="issues"}>Issues</button>
  </div>

  <!-- ── SITE MAP ── -->
  {#if subtab === "sitemap"}
    {#if history.length === 0}
      <div class="empty-state">
        <svg width="56" height="56" viewBox="0 0 56 56" fill="none">
          <rect x="6" y="28" width="44" height="22" rx="3" stroke="#c8c8c8" stroke-width="1.5" fill="#f5f5f5"/>
          <rect x="12" y="18" width="32" height="12" rx="3" stroke="#c8c8c8" stroke-width="1.5" fill="#f5f5f5"/>
          <rect x="18" y="8"  width="20" height="12" rx="3" stroke="#c8c8c8" stroke-width="1.5" fill="#f5f5f5"/>
        </svg>
        <p class="empty-title">Site map URL view is empty</p>
        <p class="empty-desc dim">
          Browse through Lancer's proxy to populate the site map.<br>
          All observed hosts and URLs will appear here.
        </p>
        <div class="empty-actions">
          <button class="btn-secondary">Learn more</button>
          <button class="btn-orange" on:click={async () => { try { await fetch("/api/browser/open", {method:"POST"}); } catch {} }}>Open browser</button>
        </div>
      </div>
    {:else}
      <!-- 3-column layout matching Burp Site map -->
      <div class="sitemap-layout">

        <!-- LEFT: site tree -->
        <div class="tree-panel">
          <div class="tree-toolbar">
            <span class="tree-label">Site map filter:</span>
            <span class="tree-count dim">{history.length} items</span>
          </div>
          <div class="tree-scroll">
            {#each siteTree as node}
              <!-- Host row -->
              <div
                class="tree-host"
                on:click={() => toggleHost(node.host)}
                on:contextmenu={(e) => onRightClick(e, node.items[0])}
              >
                <span class="tree-arrow">{expandedHosts[node.host] !== false ? '▾' : '▸'}</span>
                <svg width="14" height="14" viewBox="0 0 14 14" fill="none" style="flex-shrink:0">
                  <circle cx="7" cy="7" r="6" stroke="#767676" stroke-width="1.2"/>
                  <ellipse cx="7" cy="7" rx="2.5" ry="6" stroke="#767676" stroke-width="1"/>
                  <path d="M1 7h12" stroke="#767676" stroke-width="1" stroke-dasharray="2 1"/>
                </svg>
                <span class="tree-host-name">{node.host}</span>
                <span class="tree-badge dim">{node.items.length}</span>
              </div>
              <!-- URL rows under host -->
              {#if expandedHosts[node.host] !== false}
                {#each node.items as item}
                  <div
                    class="tree-url"
                    class:selected={selectedEntry === item}
                    on:click={() => selectEntry(item)}
                    on:contextmenu={(e) => onRightClick(e, item)}
                  >
                    <span class="method-dot method-{item.method || 'GET'}">{item.method || "GET"}</span>
                    <span class="url-path dim">{item.path || item.url || "/"}</span>
                    {#if item.status}
                      <span class="status-chip status-{String(item.status)[0]}">{item.status}</span>
                    {/if}
                  </div>
                {/each}
              {/if}
            {/each}
          </div>
        </div>

        <!-- CENTER: Request pane -->
        <div class="req-pane">
          <div class="pane-title">Request</div>
          <div class="subtabs inner-tabs">
            {#each ["pretty","raw","hex"] as t}
              <button class="subtab" class:active={reqTab===t} on:click={() => reqTab=t}>
                {t.charAt(0).toUpperCase()+t.slice(1)}
              </button>
            {/each}
          </div>
          <div class="editor-scroll">
            {#if !selectedEntry}
              <p class="dim" style="padding:14px;font-size:12px">Select a request from the site map.</p>
            {:else if reqTab === "hex"}
              <pre class="editor hex">{hexDump(formatRequest(selectedEntry))}</pre>
            {:else}
              <pre class="editor">{formatRequest(selectedEntry)}</pre>
            {/if}
          </div>
        </div>

        <!-- RIGHT: Response pane -->
        <div class="resp-pane">
          <div class="pane-title">Response</div>
          <div class="subtabs inner-tabs">
            {#each ["pretty","raw","hex"] as t}
              <button class="subtab" class:active={respTab===t} on:click={() => respTab=t}>
                {t.charAt(0).toUpperCase()+t.slice(1)}
              </button>
            {/each}
          </div>
          <div class="editor-scroll">
            {#if !selectedEntry}
              <p class="dim" style="padding:14px;font-size:12px">Select a request to see the response.</p>
            {:else if respTab === "hex"}
              <pre class="editor hex">{hexDump(formatResponse(selectedEntry))}</pre>
            {:else}
              <pre class="editor">{formatResponse(selectedEntry)}</pre>
            {/if}
          </div>
        </div>

      </div>
    {/if}
  {/if}

  <!-- ── SCOPE ── -->
  {#if subtab === "scope"}
    <div class="panel">
      <div class="scope-notice">
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none" style="flex-shrink:0;margin-top:1px">
          <circle cx="8" cy="8" r="7" stroke="#767676" stroke-width="1.2"/>
          <path d="M8 5v4" stroke="#767676" stroke-width="1.4" stroke-linecap="round"/>
          <circle cx="8" cy="11.5" r="0.7" fill="#767676"/>
        </svg>
        <p>Scope is empty. Add items by right-clicking in Proxy history or Target site map.</p>
      </div>
    </div>
  {/if}

  <!-- ── ISSUES ── -->
  {#if subtab === "issues"}
    {#if issues.length === 0}
      <div class="empty-state">
        <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
          <circle cx="24" cy="24" r="20" stroke="#c8c8c8" stroke-width="1.5" fill="#f5f5f5"/>
          <path d="M24 16v12" stroke="#c8c8c8" stroke-width="2" stroke-linecap="round"/>
          <circle cx="24" cy="33" r="1.2" fill="#c8c8c8"/>
        </svg>
        <span class="empty-title">No issues found</span>
        <span class="dim" style="font-size:12px">Run a scan to discover vulnerabilities</span>
      </div>
    {:else}
      <div class="table-scroll">
        <table class="data-table">
          <thead>
            <tr><th>Severity</th><th>Issue type</th><th>Host</th><th>Path</th></tr>
          </thead>
          <tbody>
            {#each issues as iss, i}
              <tr class:row-even={i % 2 === 0}>
                <td><span class="badge {severityClass(iss.severity)}">{iss.severity}</span></td>
                <td>{iss.name || iss.type || "-"}</td>
                <td class="dim">{iss.host || "-"}</td>
                <td class="dim url-cell">{iss.path || "-"}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  {/if}
</div>

<!-- RIGHT-CLICK CONTEXT MENU -->
{#if ctxMenu}
  <div class="ctx-menu" style="left:{ctxMenu.x}px;top:{ctxMenu.y}px" on:click|stopPropagation>
    <div class="ctx-item" on:click={ctxAddScope}>Add to scope</div>
    <div class="ctx-sep"></div>
    <div class="ctx-item" on:click={ctxSendToRepeater}>Send to Repeater</div>
    <div class="ctx-item ctx-disabled">Send to Intruder</div>
    <div class="ctx-item ctx-disabled">Send to Sequencer</div>
    <div class="ctx-item ctx-disabled">Send to Comparer</div>
    <div class="ctx-sep"></div>
    <div class="ctx-item" on:click={ctxCopyUrl}>Copy URL</div>
    <div class="ctx-sep"></div>
    <div class="ctx-item ctx-danger" on:click={ctxDelete}>Delete item</div>
  </div>
{/if}

<style>
  /* Empty state */
  .empty-state {
    flex: 1; display: flex; flex-direction: column;
    align-items: center; justify-content: center;
    gap: 10px; padding: 40px; text-align: center;
  }
  .empty-title { font-size: 14px; font-weight: 600; color: #212121; margin: 0; }
  .empty-desc { font-size: 13px; color: #767676; line-height: 1.6; max-width: 440px; margin: 0; }
  .empty-actions { display: flex; gap: 8px; margin-top: 8px; }
  .btn-orange { background: #e03a00; color: #fff; border: none; border-radius: 3px; padding: 5px 14px; font-size: 13px; cursor: pointer; }
  .btn-orange:hover { background: #c73400; }
  .btn-secondary { background: #f0f0f0; color: #333; border: 1px solid #c8c8c8; border-radius: 3px; padding: 5px 14px; font-size: 13px; cursor: pointer; }
  .btn-secondary:hover { background: #e4e4e4; }

  /* 3-column site map layout */
  .sitemap-layout {
    display: grid;
    grid-template-columns: 230px 1fr 1fr;
    flex: 1; overflow: hidden;
    border-top: 1px solid #dedede;
  }

  /* Tree panel */
  .tree-panel {
    border-right: 1px solid #dedede;
    display: flex; flex-direction: column;
    overflow: hidden;
  }
  .tree-toolbar {
    display: flex; align-items: center; justify-content: space-between;
    padding: 5px 10px;
    background: #f5f5f5;
    border-bottom: 1px solid #dedede;
    font-size: 11px; flex-shrink: 0;
  }
  .tree-label { color: #444; font-weight: 500; }
  .tree-count { font-size: 11px; }
  .tree-scroll { flex: 1; overflow-y: auto; }

  .tree-host {
    display: flex; align-items: center; gap: 5px;
    padding: 5px 8px;
    cursor: pointer;
    font-size: 12px; font-weight: 600; color: #212121;
    border-bottom: 1px solid #f0f0f0;
    user-select: none;
  }
  .tree-host:hover { background: #f0f7ff; }
  .tree-arrow { font-size: 10px; color: #767676; width: 10px; }
  .tree-host-name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .tree-badge { font-size: 10px; background: #e8e8e8; padding: 1px 5px; border-radius: 8px; }

  .tree-url {
    display: flex; align-items: center; gap: 6px;
    padding: 3px 8px 3px 26px;
    cursor: pointer;
    font-size: 12px; color: #444;
    border-bottom: 1px solid #f5f5f5;
    user-select: none;
  }
  .tree-url:hover { background: #f0f7ff; }
  .tree-url.selected { background: #daeeff; }
  .url-path { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: ui-monospace, Consolas, monospace; font-size: 11px; }
  .status-chip { font-size: 10px; padding: 1px 4px; border-radius: 2px; flex-shrink: 0; }
  .status-2 { background: #eaf5ea; color: #1b8c1b; }
  .status-3 { background: #e6f0fb; color: #1a75c4; }
  .status-4 { background: #fef8e6; color: #c98a00; }
  .status-5 { background: #fde8e8; color: #d42c2c; }
  .method-dot { font-size: 10px; font-weight: 700; flex-shrink: 0; width: 32px; }
  .method-GET    { color: #1b8c1b; }
  .method-POST   { color: #e86c00; }
  .method-PUT    { color: #1a75c4; }
  .method-DELETE { color: #d42c2c; }
  .method-PATCH  { color: #7b5ea7; }

  /* Request/Response panes */
  .req-pane, .resp-pane {
    display: flex; flex-direction: column;
    overflow: hidden;
    border-right: 1px solid #dedede;
  }
  .resp-pane { border-right: none; }
  .pane-title {
    padding: 4px 10px;
    background: #f5f5f5;
    border-bottom: 1px solid #dedede;
    font-size: 12px; font-weight: 600; color: #444;
    flex-shrink: 0;
  }
  .inner-tabs { height: 30px; }
  .editor-scroll { flex: 1; overflow: auto; }
  .editor {
    margin: 0; padding: 10px 12px;
    font-size: 11.5px;
    font-family: ui-monospace, "Cascadia Code", Consolas, monospace;
    white-space: pre-wrap; word-break: break-all;
    color: #212121; line-height: 1.6;
  }
  .editor.hex { color: #555; }

  /* Scope notice */
  .scope-notice {
    display: flex; gap: 10px; align-items: flex-start;
    background: #f5f5f5; border: 1px solid #dedede; border-radius: 4px;
    padding: 12px 14px; font-size: 13px; color: #444; max-width: 600px;
  }
  .scope-notice p { margin: 0; }

  /* Issues table */
  .table-scroll { flex: 1; overflow-y: auto; }
  .data-table { width: 100%; border-collapse: collapse; font-size: 13px; }
  .data-table th, .data-table td { text-align: left; padding: 6px 12px; border-bottom: 1px solid #e8e8e8; white-space: nowrap; }
  .data-table thead th { background: #f5f5f5; color: #767676; font-size: 11px; font-weight: 600; position: sticky; top: 0; z-index: 1; border-bottom: 1px solid #dedede; }
  .data-table tbody tr:hover { background: #f0f7ff; }
  .row-even { background: #fafafa; }
  .url-cell { max-width: 280px; overflow: hidden; text-overflow: ellipsis; }

  /* Context menu */
  .ctx-menu {
    position: fixed; z-index: 9999;
    background: #ffffff;
    border: 1px solid #c8c8c8;
    border-radius: 4px;
    box-shadow: 0 4px 16px rgba(0,0,0,0.15);
    min-width: 200px;
    padding: 4px 0;
    font-size: 13px;
  }
  .ctx-item {
    padding: 6px 16px;
    cursor: pointer;
    color: #212121;
    white-space: nowrap;
  }
  .ctx-item:hover { background: #f0f7ff; }
  .ctx-item.ctx-disabled { color: #aaa; cursor: default; }
  .ctx-item.ctx-disabled:hover { background: none; }
  .ctx-item.ctx-danger { color: #d42c2c; }
  .ctx-item.ctx-danger:hover { background: #fde8e8; }
  .ctx-sep { height: 1px; background: #e8e8e8; margin: 3px 0; }
</style>
