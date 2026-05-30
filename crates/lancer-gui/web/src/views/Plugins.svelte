<script>
  import { onMount, onDestroy } from "svelte";

  // ── Subtab state ──
  let subtab = "installed";

  // ── Plugin list state ──
  let plugins = [];
  let selectedIndex = -1;
  let pollTimer;

  // ── Bottom panel state ──
  let bottomTab = "details";

  // ── Add/upload state ──
  let fileInput;

  // ── Derived: selected plugin ──
  $: selectedPlugin = selectedIndex >= 0 && selectedIndex < plugins.length
    ? plugins[selectedIndex]
    : null;

  // ── System impact estimate ──
  $: systemImpactPct = plugins.length === 0 ? 0
    : Math.min(100, plugins.filter(p => p.enabled).length * 18 + 6);
  $: systemImpactLabel = systemImpactPct < 25 ? "Low"
    : systemImpactPct < 55 ? "Medium"
    : systemImpactPct < 80 ? "High"
    : "Critical";

  // ── API calls ──
  async function load() {
    try {
      const r = await fetch("/api/v1/plugins");
      if (r.ok) {
        const data = await r.json();
        plugins = Array.isArray(data) ? data : (data.plugins || []);
        // clamp selection
        if (selectedIndex >= plugins.length) selectedIndex = plugins.length - 1;
      }
    } catch {}
  }

  async function toggleEnabled(idx) {
    const p = plugins[idx];
    if (!p) return;
    const next = !p.enabled;
    try {
      const id = p.manifest?.id || p.id || "";
      await fetch(`/api/v1/plugins/${encodeURIComponent(id)}/toggle`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ enabled: next }),
      });
    } catch {}
    plugins = plugins.map((x, i) => i === idx ? { ...x, enabled: next } : x);
  }

  async function removePlugin() {
    if (selectedIndex < 0) return;
    const p = plugins[selectedIndex];
    const id = p.manifest?.id || p.id || "";
    try {
      await fetch(`/api/v1/plugins/${encodeURIComponent(id)}`, { method: "DELETE" });
    } catch {}
    plugins = plugins.filter((_, i) => i !== selectedIndex);
    selectedIndex = Math.min(selectedIndex, plugins.length - 1);
  }

  function moveUp() {
    if (selectedIndex <= 0) return;
    const arr = [...plugins];
    [arr[selectedIndex - 1], arr[selectedIndex]] = [arr[selectedIndex], arr[selectedIndex - 1]];
    plugins = arr;
    selectedIndex = selectedIndex - 1;
  }

  function moveDown() {
    if (selectedIndex < 0 || selectedIndex >= plugins.length - 1) return;
    const arr = [...plugins];
    [arr[selectedIndex], arr[selectedIndex + 1]] = [arr[selectedIndex + 1], arr[selectedIndex]];
    plugins = arr;
    selectedIndex = selectedIndex + 1;
  }

  function triggerAdd() {
    if (fileInput) fileInput.click();
  }

  async function onFileSelected(e) {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const content = await file.text();
      await fetch("/api/v1/plugins/upload", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name: file.name, content }),
      });
      await load();
    } catch {}
    e.target.value = "";
  }

  // ── Kind badge class ──
  function kindBadge(k) {
    const m = {
      Rhai: "badge-rhai", Wasm: "badge-wasm", Lua: "badge-lua",
      Python: "badge-py", Native: "badge-native", Jvm: "badge-jvm",
    };
    return m[k] || "badge-default";
  }

  // ── BApp Store placeholder cards ──
  const bappCards = [
    { name: "Active Scan++",        desc: "Extends Lancer's active scanner with 20+ additional checks." },
    { name: "Autorize",             desc: "Automatic authorization enforcement detection tool." },
    { name: "Param Miner",          desc: "Finds hidden, unlinked parameters in HTTP requests." },
    { name: "Turbo Intruder",       desc: "High-speed, scriptable HTTP request sending." },
    { name: "HTTP Request Smuggler",desc: "Detects HTTP request smuggling / desync vulnerabilities." },
    { name: "Logger++",             desc: "Advanced logging with powerful filtering capabilities." },
    { name: "CSRF Scanner",         desc: "Passive CSRF detection across all traffic." },
    { name: "JS Miner",             desc: "Mines JS files for secrets, endpoints, and comments." },
    { name: "Retire.js",            desc: "Identifies JavaScript libraries with known vulnerabilities." },
    { name: "GAP",                  desc: "Gets All Parameters from target scope." },
    { name: "Software Vulnerability Scanner", desc: "Scans for known CVEs in detected software." },
    { name: "Upload Scanner",       desc: "Checks file upload endpoints for dangerous file types." },
  ];

  // ── Extension APIs ──
  const apiList = [
    { name: "HTTP listener",         desc: "Intercept and modify all HTTP/S requests and responses in real time." },
    { name: "Proxy listener",        desc: "Hook into the proxy to view, intercept and modify proxy traffic." },
    { name: "Scanner checks",        desc: "Add custom passive and active scan checks to the scanner." },
    { name: "Intruder payloads",     desc: "Supply custom payload lists and generators for Intruder attacks." },
    { name: "Session handling",      desc: "Implement custom session token handlers and CSRF token macros." },
    { name: "Context menu items",    desc: "Add custom entries to right-click context menus across all tools." },
    { name: "Tab contents",          desc: "Render custom tabs and panels within the main Lancer UI." },
    { name: "Message editor tabs",   desc: "Add custom tabs to the request/response editor panels." },
    { name: "HTTP message highlight",desc: "Highlight rows in the HTTP history based on custom logic." },
    { name: "Persistence provider",  desc: "Store and retrieve custom data in the Lancer project file." },
    { name: "Collaborator",          desc: "Use Lancer Collaborator interactions in custom scanner checks." },
    { name: "Decoder codec",         desc: "Register custom encode/decode transforms in the Decoder tab." },
  ];

  // ── Custom scan checks ──
  let scanChecks = [];

  // ── Bambda scripts ──
  let bambdaScripts = [
    { name: "Exclude 304 responses",   desc: "Filter out all HTTP 304 Not Modified responses." },
    { name: "In-scope only",           desc: "Show only requests that match the current target scope." },
    { name: "Has response body",       desc: "Filter to requests that have a non-empty response body." },
    { name: "Params with SQLi chars",  desc: "Flag requests whose parameters contain SQL injection metacharacters." },
  ];

  // ── Extension settings ──
  let extSettings = {
    autoReload: true,
    loadOnStartup: true,
    errorNotify: true,
    aiEnabled: false,
  };

  onMount(() => {
    load();
    pollTimer = setInterval(load, 8000);
  });
  onDestroy(() => { if (pollTimer) clearInterval(pollTimer); });
</script>

<div class="view">

  <!-- ── Top subtab bar ── -->
  <div class="subtabs">
    <button class="subtab" class:active={subtab === "installed"}      on:click={() => subtab = "installed"}>Installed</button>
    <button class="subtab" class:active={subtab === "bapp"}           on:click={() => subtab = "bapp"}>BApp Store</button>
    <button class="subtab" class:active={subtab === "apis"}           on:click={() => subtab = "apis"}>APIs</button>
    <button class="subtab" class:active={subtab === "scan-checks"}    on:click={() => subtab = "scan-checks"}>Custom scan checks</button>
    <button class="subtab" class:active={subtab === "bambda"}         on:click={() => subtab = "bambda"}>Bambda library</button>
    <button class="subtab" class:active={subtab === "ext-settings"}   on:click={() => subtab = "ext-settings"}>&#9881; Extensions settings</button>
  </div>

  <!-- ══════════════════════════════════════════════════════════ INSTALLED ══ -->
  {#if subtab === "installed"}
    <div class="installed-root">

      <!-- Impact banner -->
      <div class="impact-bar">
        <span class="impact-icon">&#9432;</span>
        <span class="impact-label">Total estimated system impact:</span>
        <span class="impact-value" class:impact-low={systemImpactLabel==="Low"} class:impact-med={systemImpactLabel==="Medium"} class:impact-high={systemImpactLabel==="High" || systemImpactLabel==="Critical"}>{systemImpactLabel}</span>
        <div class="impact-track">
          <div class="impact-fill" class:fill-low={systemImpactLabel==="Low"} class:fill-med={systemImpactLabel==="Medium"} class:fill-high={systemImpactLabel==="High" || systemImpactLabel==="Critical"} style="width:{systemImpactPct}%"></div>
        </div>
      </div>

      <!-- Section header -->
      <div class="section-header">
        <strong>Lancer extensions</strong>
        <span class="dim"> — Extensions let you customize Lancer's behavior using your own or third-party code.</span>
      </div>

      <!-- Main body: side buttons + table -->
      <div class="installed-body">

        <!-- Left action buttons -->
        <div class="side-btns">
          <button class="side-btn" on:click={triggerAdd}>Add</button>
          <button class="side-btn" on:click={removePlugin} disabled={selectedIndex < 0}>Remove</button>
          <button class="side-btn" on:click={moveUp}   disabled={selectedIndex <= 0}>Up</button>
          <button class="side-btn" on:click={moveDown} disabled={selectedIndex < 0 || selectedIndex >= plugins.length - 1}>Down</button>
        </div>

        <!-- Plugin table -->
        <div class="table-wrap">
          {#if plugins.length === 0}
            <div class="empty-state">
              <svg width="40" height="40" viewBox="0 0 40 40" fill="none">
                <rect x="6" y="6" width="28" height="28" rx="4" stroke="#c8c8c8" stroke-width="1.5" fill="#f5f5f5"/>
                <path d="M13 20 h14" stroke="#c8c8c8" stroke-width="1.3" stroke-linecap="round"/>
                <path d="M20 13 v14" stroke="#c8c8c8" stroke-width="1.3" stroke-linecap="round"/>
              </svg>
              <span style="font-weight:500;color:#444">No extensions installed</span>
              <span class="dim" style="font-size:12px">Click <strong>Add</strong> to load a Rhai, WASM, Lua, Python, Native, or JVM extension.</span>
            </div>
          {:else}
            <table class="ext-table">
              <thead>
                <tr>
                  <th class="col-loaded">Loaded</th>
                  <th class="col-type">Type</th>
                  <th class="col-name">Name</th>
                  <th class="col-ai">AI enabled</th>
                  <th class="col-credits">AI credits used</th>
                  <th class="col-impact">System impact</th>
                  <th class="col-reload">Auto-reload</th>
                </tr>
              </thead>
              <tbody>
                {#each plugins as p, i}
                  <tr
                    class:row-selected={selectedIndex === i}
                    on:click={() => { selectedIndex = i; bottomTab = "details"; }}
                  >
                    <td class="col-loaded">
                      <input
                        type="checkbox"
                        checked={!!p.enabled}
                        on:click|stopPropagation
                        on:change={() => toggleEnabled(i)}
                        title="Toggle extension"
                        style="accent-color:#e03a00;cursor:pointer"
                      />
                    </td>
                    <td class="col-type">
                      <span class={"badge " + kindBadge(p.manifest?.kind || p.kind)}>
                        {p.manifest?.kind || p.kind || "?"}
                      </span>
                    </td>
                    <td class="col-name">{p.manifest?.name || p.name || "Unnamed"}</td>
                    <td class="col-ai"><span class="dim">—</span></td>
                    <td class="col-credits"><span class="dim">0</span></td>
                    <td class="col-impact">
                      <span class="impact-pill impact-pill-med">Medium</span>
                    </td>
                    <td class="col-reload">
                      <input
                        type="checkbox"
                        checked={false}
                        on:click|stopPropagation
                        style="accent-color:#e03a00;cursor:pointer"
                      />
                    </td>
                  </tr>
                {/each}
              </tbody>
            </table>
          {/if}
        </div>
      </div>

      <!-- Bottom detail panel -->
      <div class="bottom-panel">
        <div class="bottom-tabs">
          <button class="bottom-tab" class:active={bottomTab === "details"} on:click={() => bottomTab = "details"}>Details</button>
          <button class="bottom-tab" class:active={bottomTab === "output"}  on:click={() => bottomTab = "output"}>Output</button>
          <button class="bottom-tab" class:active={bottomTab === "errors"}  on:click={() => bottomTab = "errors"}>Errors</button>
        </div>

        <div class="bottom-content">
          {#if bottomTab === "details"}
            {#if selectedPlugin}
              <div class="details-row">
                <label class="check-label">
                  <input type="checkbox" checked={!!selectedPlugin.enabled} style="accent-color:#e03a00" on:change={() => toggleEnabled(selectedIndex)} />
                  Extension loaded
                </label>
              </div>
              <table class="detail-table">
                <thead>
                  <tr><th>Item</th><th>Detail</th></tr>
                </thead>
                <tbody>
                  <tr>
                    <td>Name</td>
                    <td>{selectedPlugin.manifest?.name || selectedPlugin.name || "—"}</td>
                  </tr>
                  <tr>
                    <td>Extension type</td>
                    <td>
                      <span class={"badge " + kindBadge(selectedPlugin.manifest?.kind || selectedPlugin.kind)}>
                        {selectedPlugin.manifest?.kind || selectedPlugin.kind || "Unknown"}
                      </span>
                    </td>
                  </tr>
                  <tr>
                    <td>Version</td>
                    <td>{selectedPlugin.manifest?.version || selectedPlugin.version || "—"}</td>
                  </tr>
                  <tr>
                    <td>Author</td>
                    <td>{selectedPlugin.manifest?.author || selectedPlugin.author || "—"}</td>
                  </tr>
                  <tr>
                    <td>ID</td>
                    <td><code>{selectedPlugin.manifest?.id || selectedPlugin.id || "—"}</code></td>
                  </tr>
                  <tr>
                    <td>Filename / path</td>
                    <td><code class="mono">{selectedPlugin.path || "—"}</code></td>
                  </tr>
                  {#if selectedPlugin.manifest?.description || selectedPlugin.description}
                    <tr>
                      <td>Description</td>
                      <td>{selectedPlugin.manifest?.description || selectedPlugin.description}</td>
                    </tr>
                  {/if}
                </tbody>
              </table>
            {:else}
              <div class="no-selection dim">Select an extension to view its details.</div>
            {/if}

          {:else if bottomTab === "output"}
            <textarea
              class="log-area"
              readonly
              placeholder="Extension stdout will appear here..."
              value={selectedPlugin?.output || ""}
            ></textarea>

          {:else if bottomTab === "errors"}
            <textarea
              class="log-area log-area-errors"
              readonly
              placeholder="Extension stderr / errors will appear here..."
              value={selectedPlugin?.errors || ""}
            ></textarea>
          {/if}
        </div>
      </div>
    </div>

  <!-- ══════════════════════════════════════════════════════════ BAPP STORE ══ -->
  {:else if subtab === "bapp"}
    <div class="panel">
      <div class="bapp-notice">
        <svg width="18" height="18" viewBox="0 0 18 18" fill="none" style="flex-shrink:0">
          <circle cx="9" cy="9" r="7.5" stroke="#1a75c4" stroke-width="1.4" fill="#e6f0fb"/>
          <path d="M9 8 v5" stroke="#1a75c4" stroke-width="1.5" stroke-linecap="round"/>
          <circle cx="9" cy="5.5" r="0.9" fill="#1a75c4"/>
        </svg>
        <span>BApp Store requires an internet connection. The cards below are available extensions.</span>
      </div>

      <div class="bapp-grid">
        {#each bappCards as card}
          <div class="bapp-card">
            <div class="bapp-card-name">{card.name}</div>
            <div class="bapp-card-desc dim">{card.desc}</div>
            <button class="bapp-install-btn">Install</button>
          </div>
        {/each}
      </div>
    </div>

  <!-- ══════════════════════════════════════════════════════════════ APIS ══ -->
  {:else if subtab === "apis"}
    <div class="panel">
      <div class="apis-header">
        <strong>Extension APIs</strong>
        <span class="dim"> — Use these APIs in your extensions to interact with Lancer's internals.</span>
      </div>
      <table class="api-table">
        <thead>
          <tr><th>API</th><th>Description</th></tr>
        </thead>
        <tbody>
          {#each apiList as api}
            <tr>
              <td class="api-name">{api.name}</td>
              <td class="dim">{api.desc}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>

  <!-- ════════════════════════════════════════════════ CUSTOM SCAN CHECKS ══ -->
  {:else if subtab === "scan-checks"}
    <div class="panel">
      <div class="toolbar" style="margin-bottom:10px">
        <button class="side-btn" style="width:auto;padding:4px 12px">Add check</button>
        <button class="side-btn" style="width:auto;padding:4px 12px" disabled={scanChecks.length === 0}>Remove</button>
      </div>
      {#if scanChecks.length === 0}
        <div class="empty-state">
          <svg width="40" height="40" viewBox="0 0 40 40" fill="none">
            <rect x="6" y="6" width="28" height="28" rx="4" stroke="#c8c8c8" stroke-width="1.5" fill="#f5f5f5"/>
            <path d="M13 20 h14" stroke="#dedede" stroke-width="1.3" stroke-linecap="round"/>
          </svg>
          <span style="font-weight:500;color:#444">No custom scan checks</span>
          <span class="dim" style="font-size:12px">Add a Rhai or Python script to define a passive or active scan check.</span>
        </div>
      {:else}
        <table class="ext-table">
          <thead>
            <tr>
              <th>Enabled</th><th>Name</th><th>Type</th><th>File</th>
            </tr>
          </thead>
          <tbody>
            {#each scanChecks as c}
              <tr>
                <td><input type="checkbox" checked={c.enabled} style="accent-color:#e03a00"/></td>
                <td>{c.name}</td>
                <td>{c.type}</td>
                <td><code class="mono">{c.file}</code></td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </div>

  <!-- ══════════════════════════════════════════════════ BAMBDA LIBRARY ══ -->
  {:else if subtab === "bambda"}
    <div class="panel">
      <div class="apis-header">
        <strong>Bambda library</strong>
        <span class="dim"> — Lambda filter scripts for HTTP history, proxy, and logger views.</span>
      </div>
      <table class="api-table">
        <thead>
          <tr><th>Name</th><th>Description</th><th></th></tr>
        </thead>
        <tbody>
          {#each bambdaScripts as b}
            <tr>
              <td class="api-name">{b.name}</td>
              <td class="dim">{b.desc}</td>
              <td><button class="bapp-install-btn" style="width:auto;padding:3px 10px">Use</button></td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>

  <!-- ══════════════════════════════════════════════ EXTENSION SETTINGS ══ -->
  {:else if subtab === "ext-settings"}
    <div class="panel">
      <div class="settings-card-ext">
        <div class="card-title-ext">Extension behavior</div>

        <div class="setting-row-ext">
          <label class="check-label-ext">
            <input type="checkbox" bind:checked={extSettings.autoReload} style="accent-color:#e03a00" />
            Auto-reload extensions on file change
          </label>
          <span class="dim" style="font-size:11px;margin-left:24px">Watch extension files and reload automatically when they are modified.</span>
        </div>

        <div class="setting-row-ext">
          <label class="check-label-ext">
            <input type="checkbox" bind:checked={extSettings.loadOnStartup} style="accent-color:#e03a00" />
            Load extensions on startup
          </label>
          <span class="dim" style="font-size:11px;margin-left:24px">Automatically load all enabled extensions when Lancer starts.</span>
        </div>

        <div class="setting-row-ext">
          <label class="check-label-ext">
            <input type="checkbox" bind:checked={extSettings.errorNotify} style="accent-color:#e03a00" />
            Notify on extension errors
          </label>
          <span class="dim" style="font-size:11px;margin-left:24px">Show a notification in the status bar when an extension produces an error.</span>
        </div>

        <div class="setting-row-ext">
          <label class="check-label-ext">
            <input type="checkbox" bind:checked={extSettings.aiEnabled} style="accent-color:#e03a00" />
            Enable AI features for extensions
          </label>
          <span class="dim" style="font-size:11px;margin-left:24px">Allow extensions to use Lancer AI APIs (consumes AI credits).</span>
        </div>
      </div>

      <div class="settings-card-ext" style="margin-top:12px">
        <div class="card-title-ext">Plugin directory</div>
        <div class="setting-row-ext">
          <span style="font-size:13px;color:#444;min-width:130px;flex-shrink:0">Plugins dir</span>
          <code class="mono" style="font-size:12px;background:#f5f5f5;border:1px solid #dedede;padding:3px 8px;border-radius:3px">%LOCALAPPDATA%\Lancer\plugins\</code>
          <span class="dim" style="font-size:11px;margin-left:8px">Override with <code>LANCER_PLUGINS_DIR</code> env var</span>
        </div>
        <div class="setting-row-ext" style="margin-top:8px">
          <span style="font-size:13px;color:#444;min-width:130px;flex-shrink:0">Supported runtimes</span>
          <div style="display:flex;gap:6px;flex-wrap:wrap">
            <span class="badge badge-rhai">Rhai</span>
            <span class="badge badge-wasm">WASM</span>
            <span class="badge badge-lua">Lua</span>
            <span class="badge badge-py">Python</span>
            <span class="badge badge-native">Native</span>
            <span class="badge badge-jvm">JVM</span>
          </div>
        </div>
      </div>
    </div>
  {/if}

</div>

<!-- Hidden file input for Add -->
<input
  bind:this={fileInput}
  type="file"
  style="display:none"
  accept=".rhai,.wasm,.lua,.py,.dll,.so,.dylib,.jar,.zip"
  on:change={onFileSelected}
/>

<style>
  /* ── Installed layout ── */
  .installed-root {
    display: flex;
    flex-direction: column;
    flex: 1;
    overflow: hidden;
    height: 100%;
  }

  /* Impact banner */
  .impact-bar {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 5px 14px;
    background: #fafafa;
    border-bottom: 1px solid #dedede;
    flex-shrink: 0;
    font-size: 12px;
    color: #444;
  }
  .impact-icon { font-size: 14px; color: #1a75c4; line-height: 1; }
  .impact-label { font-size: 12px; color: #444; }
  .impact-value { font-weight: 600; font-size: 12px; }
  .impact-low  { color: #1b8c1b; }
  .impact-med  { color: #c98a00; }
  .impact-high { color: #d42c2c; }
  .impact-track {
    width: 120px;
    height: 8px;
    background: #e8e8e8;
    border-radius: 4px;
    overflow: hidden;
    flex-shrink: 0;
  }
  .impact-fill {
    height: 100%;
    border-radius: 4px;
    transition: width 0.3s ease;
  }
  .fill-low  { background: #1b8c1b; }
  .fill-med  { background: #c98a00; }
  .fill-high { background: #d42c2c; }

  /* Section header */
  .section-header {
    padding: 6px 14px;
    font-size: 12px;
    border-bottom: 1px solid #dedede;
    background: #ffffff;
    flex-shrink: 0;
    color: #212121;
  }

  /* Body: side buttons + table */
  .installed-body {
    display: flex;
    flex-direction: row;
    flex: 1;
    overflow: hidden;
    min-height: 0;
  }

  /* Side action buttons */
  .side-btns {
    display: flex;
    flex-direction: column;
    gap: 3px;
    padding: 8px 6px;
    width: 80px;
    flex-shrink: 0;
    background: #f5f5f5;
    border-right: 1px solid #dedede;
    align-items: stretch;
  }
  .side-btn {
    width: 100%;
    padding: 4px 0;
    font-size: 12px;
    background: #ffffff;
    color: #333;
    border: 1px solid #c8c8c8;
    border-radius: 3px;
    cursor: pointer;
    text-align: center;
  }
  .side-btn:hover:not(:disabled) { background: #f0f0f0; border-color: #aaa; }
  .side-btn:disabled { opacity: 0.45; cursor: not-allowed; }

  /* Table wrapper */
  .table-wrap {
    flex: 1;
    overflow-y: auto;
    overflow-x: auto;
  }

  /* Extension table */
  .ext-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
    table-layout: fixed;
  }
  .ext-table th {
    padding: 5px 10px;
    background: #f5f5f5;
    border-bottom: 1px solid #dedede;
    font-size: 11px;
    font-weight: 600;
    color: #767676;
    text-align: left;
    position: sticky;
    top: 0;
    z-index: 1;
    white-space: nowrap;
  }
  .ext-table td {
    padding: 5px 10px;
    border-bottom: 1px solid #f0f0f0;
    color: #212121;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .ext-table tbody tr { cursor: pointer; }
  .ext-table tbody tr:hover { background: #fafafa; }
  .row-selected td { background: #fce8e2 !important; }

  /* Column widths */
  .col-loaded  { width: 62px;  }
  .col-type    { width: 80px;  }
  .col-name    { width: auto;  }
  .col-ai      { width: 88px;  }
  .col-credits { width: 110px; }
  .col-impact  { width: 108px; }
  .col-reload  { width: 90px;  }

  /* System impact pill in table */
  .impact-pill {
    font-size: 10px;
    font-weight: 600;
    padding: 1px 7px;
    border-radius: 3px;
    text-transform: uppercase;
  }
  .impact-pill-med { background: #fef8e6; color: #c98a00; border: 1px solid #f5dfa0; }
  .impact-pill-low { background: #eaf5ea; color: #1b8c1b; border: 1px solid #a8d8a8; }
  .impact-pill-high{ background: #fde8e8; color: #d42c2c; border: 1px solid #f5b8b8; }

  /* ── Bottom panel ── */
  .bottom-panel {
    display: flex;
    flex-direction: column;
    flex-shrink: 0;
    height: 180px;
    border-top: 2px solid #dedede;
    background: #ffffff;
  }
  .bottom-tabs {
    display: flex;
    align-items: stretch;
    background: #f5f5f5;
    border-bottom: 1px solid #dedede;
    height: 30px;
    flex-shrink: 0;
  }
  .bottom-tab {
    padding: 0 14px;
    background: transparent;
    border: none;
    border-bottom: 2px solid transparent;
    border-radius: 0;
    font-size: 12px;
    color: #444;
    cursor: pointer;
    height: 100%;
  }
  .bottom-tab:hover { color: #212121; background: rgba(0,0,0,0.04); }
  .bottom-tab.active {
    color: #e03a00;
    border-bottom-color: #e03a00;
    font-weight: 600;
    background: transparent;
  }
  .bottom-content {
    flex: 1;
    overflow-y: auto;
    padding: 8px 12px;
    background: #ffffff;
  }

  /* Details tab */
  .details-row {
    margin-bottom: 8px;
  }
  .check-label {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    font-size: 12px;
    color: #212121;
    cursor: pointer;
  }
  .detail-table {
    border-collapse: collapse;
    font-size: 12px;
    width: 100%;
    max-width: 640px;
  }
  .detail-table th {
    background: #f5f5f5;
    color: #767676;
    font-size: 11px;
    font-weight: 600;
    padding: 4px 10px;
    text-align: left;
    border-bottom: 1px solid #dedede;
  }
  .detail-table td {
    padding: 4px 10px;
    border-bottom: 1px solid #f0f0f0;
    color: #212121;
    vertical-align: top;
  }
  .detail-table td:first-child { color: #767676; width: 140px; font-weight: 500; }
  .no-selection {
    padding: 16px 4px;
    font-size: 12px;
  }

  /* Output / Errors textareas */
  .log-area {
    width: 100%;
    height: 110px;
    font-size: 11px;
    font-family: ui-monospace, "Cascadia Code", Consolas, monospace;
    resize: none;
    background: #fafafa;
    border: 1px solid #e8e8e8;
    border-radius: 3px;
    padding: 6px 8px;
    color: #444;
    outline: none;
  }
  .log-area-errors { color: #d42c2c; background: #fff8f8; border-color: #f5c0c0; }

  /* ── BApp Store ── */
  .bapp-notice {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    background: #e6f0fb;
    border: 1px solid #9dc3e8;
    border-radius: 4px;
    padding: 10px 14px;
    font-size: 12px;
    color: #1a3a5c;
    margin-bottom: 16px;
    max-width: 700px;
  }
  .bapp-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(210px, 1fr));
    gap: 10px;
  }
  .bapp-card {
    background: #ffffff;
    border: 1px solid #dedede;
    border-radius: 4px;
    padding: 12px 14px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .bapp-card:hover { border-color: #e03a00; }
  .bapp-card-name {
    font-size: 13px;
    font-weight: 600;
    color: #212121;
  }
  .bapp-card-desc {
    font-size: 11px;
    line-height: 1.5;
    flex: 1;
  }
  .bapp-install-btn {
    align-self: flex-start;
    background: #e03a00;
    color: #ffffff;
    border: none;
    border-radius: 3px;
    padding: 4px 12px;
    font-size: 11px;
    cursor: pointer;
    margin-top: 2px;
  }
  .bapp-install-btn:hover { background: #c73400; }

  /* ── APIs & Bambda tables ── */
  .apis-header {
    padding: 0 0 10px 0;
    font-size: 12px;
    color: #212121;
    border-bottom: 1px solid #dedede;
    margin-bottom: 10px;
  }
  .api-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }
  .api-table th {
    background: #f5f5f5;
    color: #767676;
    font-size: 11px;
    font-weight: 600;
    padding: 5px 12px;
    text-align: left;
    border-bottom: 1px solid #dedede;
  }
  .api-table td {
    padding: 6px 12px;
    border-bottom: 1px solid #f0f0f0;
    color: #212121;
  }
  .api-name {
    font-weight: 500;
    color: #212121;
    white-space: nowrap;
    width: 220px;
  }

  /* ── Extension settings ── */
  .settings-card-ext {
    background: #fafafa;
    border: 1px solid #dedede;
    border-radius: 4px;
    padding: 14px 18px;
    max-width: 680px;
  }
  .card-title-ext {
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: #767676;
    margin-bottom: 12px;
    padding-bottom: 8px;
    border-bottom: 1px solid #e8e8e8;
  }
  .setting-row-ext {
    display: flex;
    flex-direction: column;
    gap: 2px;
    margin-bottom: 12px;
  }
  .setting-row-ext:last-child { margin-bottom: 0; }
  .check-label-ext {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    font-size: 13px;
    color: #212121;
    cursor: pointer;
  }

  /* ── Badge colors ── */
  .badge { display: inline-block; font-size: 10px; font-weight: 600; text-transform: uppercase; padding: 1px 6px; border-radius: 2px; letter-spacing: 0.03em; }
  .badge-rhai    { background: #fce8e2; color: #e03a00; }
  .badge-wasm    { background: #e6f0fb; color: #1a75c4; }
  .badge-lua     { background: #eaf5ea; color: #1b8c1b; }
  .badge-py      { background: #fef0e6; color: #e86c00; }
  .badge-native  { background: #fef8e6; color: #c98a00; }
  .badge-jvm     { background: #f3eaf5; color: #7b3fa0; }
  .badge-default { background: #eeeeee; color: #444444; }

  /* ── Code ── */
  code, .mono {
    font-family: ui-monospace, "Cascadia Code", Consolas, monospace;
    font-size: 11px;
  }
  code {
    background: #f5f5f5;
    border: 1px solid #dedede;
    padding: 0 5px;
    border-radius: 2px;
  }
</style>
