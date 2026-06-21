<script>
  import { onMount } from "svelte";

  let subtab = "findings";
  let findings = [];
  let files = [];
  let loading = false;
  let rescanning = false;
  let selected = null;

  // Filters
  let filterType = "";
  let filterSev  = "";
  let filterFile = "";
  let filterSearch = "";

  const TYPES = ["secret","endpoint","sink","source_map"];
  const SEVS  = ["Critical","High","Medium","Low","Info"];

  const TYPE_COLOR = {
    secret:     "#d42c2c",
    endpoint:   "#1a75c4",
    sink:       "#e86c00",
    source_map: "#7b5ea7",
  };
  const TYPE_BG = {
    secret:     "#fde8e8",
    endpoint:   "#e6f0fb",
    sink:       "#fef0e6",
    source_map: "#f0ebfb",
  };

  function sevClass(s) {
    return { Critical:"badge-Critical", High:"badge-High", Medium:"badge-Medium", Low:"badge-Low", Info:"badge-Info" }[s] || "badge-Info";
  }

  $: filtered = findings.filter(f => {
    if (filterType   && f.type     !== filterType)   return false;
    if (filterSev    && f.severity !== filterSev)    return false;
    if (filterFile   && !(f.file||"").toLowerCase().includes(filterFile.toLowerCase())) return false;
    if (filterSearch && !JSON.stringify(f).toLowerCase().includes(filterSearch.toLowerCase())) return false;
    return true;
  });

  $: secretCount   = findings.filter(f => f.type === "secret").length;
  $: endpointCount = findings.filter(f => f.type === "endpoint").length;
  $: sinkCount     = findings.filter(f => f.type === "sink").length;

  async function loadFindings() {
    loading = true;
    try {
      const [fr, ff] = await Promise.all([
        fetch("/api/v1/jsmining/findings"),
        fetch("/api/v1/jsmining/files"),
      ]);
      if (fr.ok) findings = await fr.json();
      if (ff.ok) files    = await ff.json();
    } catch {
      // Demo data when backend not yet wired
      findings = [
        { id:"j1", type:"secret",    severity:"Critical", file:"https://target.com/static/app.bundle.js", line:1847, snippet:'const AWS_KEY = "AKIAIOSFODNN7EXAMPLE"', secret_type:"AWS Access Key", confidence:0.99, found_at: new Date(Date.now()-60000*5).toISOString() },
        { id:"j2", type:"secret",    severity:"High",     file:"https://target.com/static/chunk.3f8a.js",  line:342,  snippet:'Authorization: Bearer eyJhbGciOiJIUzI1NiIs…', secret_type:"JWT Token", confidence:0.95, found_at: new Date(Date.now()-60000*4).toISOString() },
        { id:"j3", type:"endpoint",  severity:"Info",     file:"https://target.com/static/app.bundle.js", line:2103, snippet:'fetch("/api/v2/admin/users",{method:"GET"…', endpoint:"/api/v2/admin/users", method:"GET", found_at: new Date(Date.now()-60000*3).toISOString() },
        { id:"j4", type:"endpoint",  severity:"Info",     file:"https://target.com/static/app.bundle.js", line:2140, snippet:'axios.post("/api/internal/payments",p)', endpoint:"/api/internal/payments", method:"POST", found_at: new Date(Date.now()-60000*2).toISOString() },
        { id:"j5", type:"sink",      severity:"High",     file:"https://target.com/static/app.bundle.js", line:987,  snippet:'document.getElementById("msg").innerHTML=u', sink:"innerHTML", source:"url param", found_at: new Date(Date.now()-60000).toISOString() },
        { id:"j6", type:"sink",      severity:"Medium",   file:"https://target.com/static/chunk.3f8a.js",  line:128,  snippet:'eval(data.userScript)', sink:"eval", source:"response data", found_at: new Date().toISOString() },
        { id:"j7", type:"source_map",severity:"Info",     file:"https://target.com/static/app.bundle.js.map", line:1, snippet:"webpack source map — 2847 modules recovered", found_at: new Date().toISOString() },
        { id:"j8", type:"secret",    severity:"High",     file:"https://target.com/static/chunk.9d2b.js",  line:56,  snippet:'const STRIPE_KEY = "pk_live_51Abc…"', secret_type:"Stripe API Key", confidence:0.97, found_at: new Date().toISOString() },
      ];
      files = [
        { url:"https://target.com/static/app.bundle.js", size_kb:1284, findings:5, last_seen: new Date().toISOString() },
        { url:"https://target.com/static/chunk.3f8a.js",  size_kb:432,  findings:2, last_seen: new Date().toISOString() },
        { url:"https://target.com/static/chunk.9d2b.js",  size_kb:98,   findings:1, last_seen: new Date().toISOString() },
        { url:"https://target.com/static/app.bundle.js.map", size_kb:6400, findings:1, last_seen: new Date().toISOString() },
      ];
    } finally { loading = false; }
  }

  async function rescan() {
    rescanning = true;
    try {
      await fetch("/api/v1/jsmining/rescan", { method:"POST" });
      await loadFindings();
    } catch { await loadFindings(); }
    finally { rescanning = false; }
  }

  function sendToRepeater(f) {
    if (f.type !== "endpoint") return;
    const raw = `${f.method || "GET"} ${f.endpoint} HTTP/1.1\r\nHost: target.com\r\n\r\n`;
    try {
      localStorage.setItem("lancer.send.repeater", JSON.stringify({ raw }));
      window.dispatchEvent(new CustomEvent("lancer:navigate", { detail: "repeater" }));
    } catch {}
  }

  function sendToScanner(f) {
    if (!f.endpoint) return;
    try {
      localStorage.setItem("lancer.send.scanner", JSON.stringify({ url: "https://target.com" + f.endpoint }));
      window.dispatchEvent(new CustomEvent("lancer:navigate", { detail: "scanner" }));
    } catch {}
  }

  function fmtDate(iso) {
    if (!iso) return "—";
    const d = new Date(iso);
    return d.toLocaleTimeString(undefined,{hour:"2-digit",minute:"2-digit",second:"2-digit"}) + " " + d.toLocaleDateString(undefined,{month:"short",day:"numeric"});
  }

  onMount(loadFindings);
</script>

<div class="view jsmining-root">
  <!-- Subtab bar -->
  <div class="subtabs">
    <button class="subtab" class:active={subtab==="findings"} on:click={() => subtab="findings"}>
      Findings <span class="cnt-badge total">{findings.length}</span>
    </button>
    <button class="subtab" class:active={subtab==="files"} on:click={() => subtab="files"}>
      JS Files <span class="cnt-badge">{files.length}</span>
    </button>
    <div class="subtab-spacer"></div>
    <div class="legend">
      <span class="leg-dot" style="background:{TYPE_COLOR.secret}"></span><span>Secrets {secretCount}</span>
      <span class="leg-dot" style="background:{TYPE_COLOR.endpoint}"></span><span>Endpoints {endpointCount}</span>
      <span class="leg-dot" style="background:{TYPE_COLOR.sink}"></span><span>Sinks {sinkCount}</span>
    </div>
    <button class="btn-rescan" on:click={rescan} disabled={rescanning}>
      {rescanning ? "Scanning…" : "↺ Rescan"}
    </button>
  </div>

  {#if subtab === "findings"}
  <div class="main-layout">
    <!-- Left: list -->
    <div class="list-col">
      <!-- Filter bar -->
      <div class="filter-bar">
        <input class="filter-input" placeholder="Search snippets, files…" bind:value={filterSearch} />
        <select bind:value={filterType}>
          <option value="">All types</option>
          {#each TYPES as t}<option value={t}>{t}</option>{/each}
        </select>
        <select bind:value={filterSev}>
          <option value="">All severities</option>
          {#each SEVS as s}<option value={s}>{s}</option>{/each}
        </select>
        <input class="filter-input" placeholder="Filter by file…" bind:value={filterFile} style="max-width:200px" />
      </div>

      {#if loading}
        <div class="empty-state"><span class="dim">Analysing JS files…</span></div>
      {:else if filtered.length === 0}
        <div class="empty-state">
          <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
            <rect x="6" y="4" width="36" height="40" rx="3" stroke="#d5dae1" stroke-width="1.5" fill="#f1f3f6"/>
            <path d="M14 14 L20 20 L14 26" stroke="#e5481d" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            <path d="M24 26 L34 26" stroke="#d5dae1" stroke-width="1.2" stroke-linecap="round"/>
          </svg>
          <span style="font-weight:500;color:#434a54">No findings</span>
          <span class="dim" style="font-size:12px">JS Miner passively analyses every JS file flowing through the proxy.<br/>Browse your target to populate findings.</span>
        </div>
      {:else}
        <div class="findings-list">
          {#each filtered as f}
          <div class="finding-item" class:selected={selected?.id === f.id} on:click={() => selected = f}>
            <div class="fi-left">
              <span class="type-tag" style="background:{TYPE_BG[f.type]};color:{TYPE_COLOR[f.type]}">{f.type}</span>
              <span class="badge {sevClass(f.severity)}">{f.severity}</span>
            </div>
            <div class="fi-body">
              <div class="fi-snippet">{f.snippet}</div>
              <div class="fi-file dim">{f.file} : {f.line}</div>
            </div>
            <div class="fi-time dim">{fmtDate(f.found_at)}</div>
          </div>
          {/each}
        </div>
      {/if}
    </div>

    <!-- Right: detail -->
    {#if selected}
    <div class="detail-col">
      <div class="detail-header">
        <span class="type-tag big" style="background:{TYPE_BG[selected.type]};color:{TYPE_COLOR[selected.type]}">{selected.type}</span>
        <span class="badge {sevClass(selected.severity)}">{selected.severity}</span>
        <div class="detail-actions">
          {#if selected.type === "endpoint"}
          <button class="act-btn" on:click={() => sendToRepeater(selected)}>→ Repeater</button>
          <button class="act-btn" on:click={() => sendToScanner(selected)}>→ Scanner</button>
          {/if}
          <button class="act-btn" on:click={() => { try { navigator.clipboard.writeText(selected.snippet); } catch {} }}>Copy</button>
        </div>
        <button class="close-btn" on:click={() => selected=null}>×</button>
      </div>
      <div class="detail-body">
        <!-- Meta -->
        <div class="meta-grid">
          <div class="meta-row"><span class="ml">File</span><span class="mv mono">{selected.file}</span></div>
          <div class="meta-row"><span class="ml">Line</span><span class="mv">{selected.line}</span></div>
          {#if selected.secret_type}
          <div class="meta-row"><span class="ml">Secret type</span><span class="mv">{selected.secret_type}</span></div>
          {/if}
          {#if selected.confidence !== undefined}
          <div class="meta-row"><span class="ml">Confidence</span><span class="mv">{(selected.confidence*100).toFixed(0)}%</span></div>
          {/if}
          {#if selected.endpoint}
          <div class="meta-row"><span class="ml">Endpoint</span><span class="mv mono">{selected.endpoint}</span></div>
          {/if}
          {#if selected.method}
          <div class="meta-row"><span class="ml">Method</span><span class="mv">{selected.method}</span></div>
          {/if}
          {#if selected.sink}
          <div class="meta-row"><span class="ml">Sink</span><span class="mv mono">{selected.sink}</span></div>
          {/if}
          {#if selected.source}
          <div class="meta-row"><span class="ml">Data source</span><span class="mv">{selected.source}</span></div>
          {/if}
          <div class="meta-row"><span class="ml">Found at</span><span class="mv dim">{fmtDate(selected.found_at)}</span></div>
        </div>

        <!-- Snippet -->
        <div class="section-title">Code Snippet</div>
        <pre class="snippet-pre">{selected.snippet}</pre>

        <!-- Guidance -->
        <div class="section-title">Guidance</div>
        <div class="guidance">
          {#if selected.type === "secret"}
            <p>This appears to be a hardcoded secret embedded in client-side JS. Verify if it is live using the auto-validation hook (Settings → JS Miner → Auto-validate). Rotate the credential immediately if confirmed live. Consider reporting to the program's responsible disclosure channel even if outside scope.</p>
          {:else if selected.type === "endpoint"}
            <p>An API endpoint was extracted from JS call sites. Send to Scanner to test for authentication, authorization, and injection vulnerabilities. Check if the endpoint is in scope before testing.</p>
          {:else if selected.type === "sink"}
            <p>A dangerous DOM sink was detected. Trace the data source to determine if user-controlled input can reach this sink. If so, this is a potential DOM XSS. Use DOM Invader to confirm.</p>
          {:else if selected.type === "source_map"}
            <p>A source map was detected and parsed. The recovered source code may reveal additional endpoints, secrets, and logic not visible in the minified bundle. Review the recovered sources carefully.</p>
          {/if}
        </div>
      </div>
    </div>
    {/if}
  </div>

  {:else}
  <!-- FILES TAB -->
  <div class="panel">
    {#if files.length === 0}
      <div class="empty-state">
        <span class="dim">No JS files captured yet. Browse your target through the proxy.</span>
      </div>
    {:else}
      <div class="files-table-wrap">
        <table class="files-table">
          <thead>
            <tr>
              <th>URL</th>
              <th>Size</th>
              <th>Findings</th>
              <th>Last seen</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {#each files as f}
            <tr>
              <td class="file-url mono">{f.url}</td>
              <td class="dim">{f.size_kb} KB</td>
              <td>
                {#if f.findings > 0}
                  <span class="findings-count">{f.findings}</span>
                {:else}
                  <span class="dim">0</span>
                {/if}
              </td>
              <td class="dim" style="white-space:nowrap">{fmtDate(f.last_seen)}</td>
              <td>
                <button class="act-btn" on:click={() => { filterFile=f.url; subtab="findings"; }}>View findings</button>
              </td>
            </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </div>
  {/if}
</div>

<style>
  .jsmining-root { display:flex; flex-direction:column; height:100%; overflow:hidden; }

  .subtabs { display:flex; align-items:center; background:var(--surface-2); border-bottom:1px solid var(--border); flex-shrink:0; height:36px; padding-right:8px; gap:0; }
  .subtab-spacer { flex:1; }
  .cnt-badge { display:inline-block; background:var(--accent); color:#fff; border-radius:8px; font-size:10px; padding:0 5px; margin-left:4px; }
  .cnt-badge.total { background:var(--text-2); }

  .legend { display:flex; align-items:center; gap:10px; font-size:11px; color:var(--text-muted); padding:0 10px; flex-shrink:0; }
  .leg-dot { width:8px; height:8px; border-radius:50%; display:inline-block; margin-right:3px; }

  .btn-rescan { background:var(--surface-2); border:1px solid var(--border-strong); border-radius:3px; padding:4px 12px; font-size:12px; cursor:pointer; flex-shrink:0; margin-left:8px; }
  .btn-rescan:hover:not(:disabled) { background:var(--surface-3); }
  .btn-rescan:disabled { opacity:0.5; cursor:not-allowed; }

  .main-layout { display:flex; flex:1; overflow:hidden; }
  .list-col { display:flex; flex-direction:column; flex:1; min-width:0; border-right:1px solid var(--border); overflow:hidden; }
  .detail-col { width:380px; flex-shrink:0; display:flex; flex-direction:column; overflow:hidden; }

  .filter-bar { display:flex; align-items:center; gap:6px; padding:6px 10px; background:var(--surface-1); border-bottom:1px solid var(--border); flex-shrink:0; flex-wrap:wrap; }
  .filter-input { flex:1; min-width:100px; max-width:220px; padding:4px 8px; font-size:12px; }
  .filter-bar select { padding:4px 6px; font-size:12px; }

  .findings-list { flex:1; overflow-y:auto; }
  .finding-item { display:flex; align-items:flex-start; gap:8px; padding:8px 12px; border-bottom:1px solid var(--surface-2); cursor:pointer; }
  .finding-item:hover { background:var(--surface-1); }
  .finding-item.selected { background:var(--accent-soft); }
  .fi-left { display:flex; flex-direction:column; gap:4px; flex-shrink:0; width:100px; }
  .type-tag { font-size:10px; font-weight:700; text-transform:uppercase; padding:2px 6px; border-radius:3px; letter-spacing:0.03em; }
  .type-tag.big { font-size:12px; padding:3px 8px; }
  .fi-body { flex:1; min-width:0; }
  .fi-snippet { font-family:ui-monospace,Consolas,monospace; font-size:11px; color:var(--text); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .fi-file { font-size:10px; margin-top:2px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .fi-time { font-size:10px; white-space:nowrap; flex-shrink:0; }

  .detail-header { display:flex; align-items:center; gap:6px; padding:8px 12px; background:var(--surface-2); border-bottom:1px solid var(--border); flex-shrink:0; flex-wrap:wrap; }
  .detail-actions { display:flex; gap:4px; margin-left:auto; }
  .act-btn { padding:3px 8px; font-size:11px; cursor:pointer; border:1px solid var(--border-strong); border-radius:3px; background:var(--surface-2); }
  .act-btn:hover { background:var(--surface-3); }
  .close-btn { background:transparent; border:none; font-size:16px; color:var(--text-muted); cursor:pointer; padding:0 4px; }
  .detail-body { flex:1; overflow-y:auto; padding:12px; display:flex; flex-direction:column; gap:10px; }

  .meta-grid { display:flex; flex-direction:column; gap:4px; background:var(--surface-1); border:1px solid var(--border); border-radius:3px; padding:10px 12px; }
  .meta-row { display:flex; gap:8px; font-size:12px; }
  .ml { color:var(--text-muted); width:90px; flex-shrink:0; font-size:11px; font-weight:600; text-transform:uppercase; letter-spacing:0.04em; }
  .mv { flex:1; color:var(--text); word-break:break-all; }
  .mv.mono { font-family:ui-monospace,Consolas,monospace; font-size:11px; }

  .section-title { font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:0.06em; color:var(--text-muted); }
  .snippet-pre { background:#1e1f22; color:#d6d6d6; border:none; border-radius:3px; padding:10px 12px; font-size:11px; font-family:ui-monospace,Consolas,monospace; overflow-x:auto; white-space:pre-wrap; word-break:break-all; margin:0; }
  .guidance { font-size:12px; color:var(--text-2); line-height:1.6; background:var(--surface-1); border:1px solid var(--border); border-radius:3px; padding:10px 12px; }
  .guidance p { margin:0; }

  /* Files table */
  .files-table-wrap { overflow-y:auto; }
  .files-table { width:100%; border-collapse:collapse; font-size:12px; }
  .files-table thead th { background:var(--surface-2); border-bottom:1px solid var(--border); padding:6px 10px; text-align:left; font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:0.05em; color:var(--text-muted); white-space:nowrap; position:sticky; top:0; z-index:1; }
  .files-table tbody tr { border-bottom:1px solid var(--surface-2); }
  .files-table td { padding:7px 10px; }
  .file-url { font-family:ui-monospace,Consolas,monospace; font-size:11px; max-width:400px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .findings-count { display:inline-block; background:#fde8e8; color:#d42c2c; border-radius:8px; font-size:11px; font-weight:700; padding:1px 7px; }

  .empty-state { flex:1; display:flex; flex-direction:column; align-items:center; justify-content:center; gap:10px; color:var(--text-muted); font-size:13px; text-align:center; padding:40px; }
</style>
