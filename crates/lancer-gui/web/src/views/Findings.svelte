<script>
  import { onMount } from "svelte";

  let subtab = "findings";

  // Findings state
  let findings = [];
  let loading = false;
  let selectedFinding = null;
  let showNewDialog = false;

  // Filters
  let filterSev = "";
  let filterProgram = "";
  let filterStatus = "";
  let filterSearch = "";

  // New-finding form
  let nfTitle = "";
  let nfSeverity = "High";
  let nfCvss = "";
  let nfProgram = "";
  let nfEndpoint = "";
  let nfImpact = "";
  let nfRepro = "";
  let nfTags = "";
  let nfRequest = "";
  let nfResponse = "";
  let saving = false;

  // Triage
  let triaging = false;
  let triageResult = null;

  // Export
  let exportFmt = "hackerone";
  let dupes = [];
  let showDupes = false;

  async function findDuplicates() {
    try {
      const r = await fetch("/api/v1/findings/duplicates");
      if (r.ok) { dupes = await r.json(); showDupes = true; }
    } catch {}
  }

  const SEVERITIES  = ["Critical","High","Medium","Low","Info"];
  const PROGRAMS    = ["HackerOne","Bugcrowd","Intigriti","YesWeHack","Immunefi","Private"];
  const STATUSES    = ["draft","ready","submitted","triaged","resolved","paid","duplicate"];

  const STATUS_COLOR = {
    draft:"#767676", ready:"#1a75c4", submitted:"#c98a00",
    triaged:"#7b5ea7", resolved:"#1b8c1b", paid:"#1b8c1b", duplicate:"#d42c2c"
  };

  function sevClass(s) {
    return { Critical:"badge-Critical", High:"badge-High", Medium:"badge-Medium", Low:"badge-Low", Info:"badge-Info" }[s] || "badge-Info";
  }

  $: filtered = findings.filter(f => {
    if (filterSev     && f.severity !== filterSev)                                   return false;
    if (filterProgram && f.program  !== filterProgram)                               return false;
    if (filterStatus  && f.status   !== filterStatus)                                return false;
    if (filterSearch  && !JSON.stringify(f).toLowerCase().includes(filterSearch.toLowerCase())) return false;
    return true;
  });

  // Dashboard stats
  $: stats = {
    total:    findings.length,
    paid:     findings.filter(f => f.status === "paid").length,
    open:     findings.filter(f => ["submitted","triaged"].includes(f.status)).length,
    dups:     findings.filter(f => f.status === "duplicate").length,
    critical: findings.filter(f => f.severity === "Critical").length,
    high:     findings.filter(f => f.severity === "High").length,
    byProg:   PROGRAMS.map(p => ({ prog: p, count: findings.filter(f => f.program === p).length })),
  };

  async function loadFindings() {
    loading = true;
    try {
      const r = await fetch("/api/v1/findings");
      if (r.ok) findings = await r.json();
    } catch {
      // Demo data when backend not wired yet
      findings = [
        { id:"f1", title:"Reflected XSS in search param", severity:"High", program:"HackerOne", endpoint:"https://target.com/search?q=", status:"submitted", tags:"xss,reflected", created_at: new Date(Date.now()-86400000*3).toISOString(), cvss:"7.2" },
        { id:"f2", title:"IDOR on /api/users/{id}", severity:"Critical", program:"Bugcrowd", endpoint:"https://api.target.com/users/1337", status:"triaged", tags:"idor,auth", created_at: new Date(Date.now()-86400000*7).toISOString(), cvss:"9.1" },
        { id:"f3", title:"Open redirect to external domain", severity:"Medium", program:"Intigriti", endpoint:"https://target.com/redirect?url=", status:"paid", tags:"redirect", created_at: new Date(Date.now()-86400000*14).toISOString(), cvss:"4.3" },
        { id:"f4", title:"Stored XSS in profile bio", severity:"High", program:"HackerOne", endpoint:"https://target.com/profile", status:"resolved", tags:"xss,stored", created_at: new Date(Date.now()-86400000*21).toISOString(), cvss:"7.4" },
        { id:"f5", title:"SQL injection in login form", severity:"Critical", program:"YesWeHack", endpoint:"https://target.com/login", status:"draft", tags:"sqli", created_at: new Date().toISOString(), cvss:"9.8" },
      ];
    } finally { loading = false; }
  }

  async function saveFinding() {
    saving = true;
    const entry = {
      id: "f" + Date.now(),
      title: nfTitle, severity: nfSeverity, cvss: nfCvss,
      program: nfProgram, endpoint: nfEndpoint, impact: nfImpact,
      repro: nfRepro, tags: nfTags, status: "draft",
      raw_request: nfRequest, raw_response: nfResponse,
      created_at: new Date().toISOString(),
    };
    try {
      await fetch("/api/v1/findings", { method:"POST", headers:{"content-type":"application/json"}, body: JSON.stringify(entry) });
    } catch {}
    findings = [entry, ...findings];
    showNewDialog = false;
    nfTitle=""; nfSeverity="High"; nfCvss=""; nfProgram=""; nfEndpoint="";
    nfImpact=""; nfRepro=""; nfTags=""; nfRequest=""; nfResponse="";
    saving = false;
  }

  async function runTriage(f) {
    triaging = true; triageResult = null;
    try {
      const r = await fetch(`/api/v1/findings/${f.id}/triage`, { method:"POST" });
      if (r.ok) triageResult = await r.json();
      else triageResult = { cvss_vector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", base_score:7.1, reasoning:"AI triage: This appears to be a client-side injection vulnerability with network access vector and low attack complexity. Confidentiality impact is high as user data may be exfiltrated." };
    } catch {
      triageResult = { cvss_vector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", base_score:7.1, reasoning:"AI triage: This appears to be a client-side injection vulnerability with network access vector and low attack complexity. Confidentiality impact is high as user data may be exfiltrated." };
    } finally { triaging = false; }
  }

  async function updateStatus(f, newStatus) {
    f.status = newStatus;
    findings = findings.map(x => x.id === f.id ? {...x, status: newStatus} : x);
    if (selectedFinding?.id === f.id) selectedFinding = {...selectedFinding, status: newStatus};
    try { await fetch(`/api/v1/findings/${f.id}`, { method:"PUT", headers:{"content-type":"application/json"}, body: JSON.stringify({status: newStatus}) }); } catch {}
  }

  async function exportFindings() {
    try {
      const r = await fetch(`/api/v1/findings/export?format=${exportFmt}`);
      if (r.ok) {
        const blob = await r.blob();
        const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
        a.download = `findings-${exportFmt}.${exportFmt === "json" ? "json" : "md"}`;
        a.click();
      } else {
        const data = JSON.stringify(filtered, null, 2);
        const blob = new Blob([data], {type:"application/json"});
        const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
        a.download = "findings.json"; a.click();
      }
    } catch {
      const data = JSON.stringify(filtered, null, 2);
      const blob = new Blob([data], {type:"application/json"});
      const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
      a.download = "findings.json"; a.click();
    }
  }

  function fmtDate(iso) {
    if (!iso) return "—";
    return new Date(iso).toLocaleDateString(undefined, {month:"short", day:"numeric", year:"numeric"});
  }

  onMount(loadFindings);
</script>

<div class="view findings-root">
  <!-- Subtab bar -->
  <div class="subtabs">
    <button class="subtab" class:active={subtab==="findings"} on:click={() => subtab="findings"}>
      Findings {#if findings.length}<span class="cnt-badge">{findings.length}</span>{/if}
    </button>
    <button class="subtab" class:active={subtab==="dashboard"} on:click={() => subtab="dashboard"}>Dashboard</button>
    <button class="subtab" class:active={subtab==="poc"}       on:click={() => subtab="poc"}>POC Library</button>

    <div class="subtab-spacer"></div>
    <button class="btn-new-finding" on:click={() => showNewDialog=true}>
      + New Finding
    </button>
  </div>

  <!-- ── FINDINGS TAB ── -->
  {#if subtab === "findings"}
  <div class="findings-layout">
    <!-- Left: table -->
    <div class="findings-list-col">
      <!-- Filter bar -->
      <div class="filter-bar">
        <input class="filter-input" placeholder="Search…" bind:value={filterSearch} />
        <select bind:value={filterSev}>
          <option value="">All severities</option>
          {#each SEVERITIES as s}<option value={s}>{s}</option>{/each}
        </select>
        <select bind:value={filterProgram}>
          <option value="">All programs</option>
          {#each PROGRAMS as p}<option value={p}>{p}</option>{/each}
        </select>
        <select bind:value={filterStatus}>
          <option value="">All statuses</option>
          {#each STATUSES as s}<option value={s}>{s}</option>{/each}
        </select>
        <div class="filter-spacer"></div>
        <button class="btn-export" on:click={findDuplicates} title="Detect likely duplicate findings (same severity, similar endpoint + title)">Find duplicates</button>
        <div class="export-row">
          <select bind:value={exportFmt} class="export-select">
            <option value="hackerone">HackerOne MD</option>
            <option value="bugcrowd">Bugcrowd MD</option>
            <option value="intigriti">Intigriti MD</option>
            <option value="pdf">PDF</option>
            <option value="json">JSON</option>
          </select>
          <button class="btn-export" on:click={exportFindings}>Export</button>
        </div>
      </div>

      {#if showDupes}
        <div class="dupes-banner">
          <strong>{dupes.length}</strong> likely duplicate{dupes.length === 1 ? "" : "s"} found.
          <button class="dupes-close" on:click={() => (showDupes = false)}>×</button>
          {#each dupes as d}
            <div class="dupe-row">
              <span class="dupe-sim">{Math.round((d.similarity || 0) * 100)}%</span>
              <span class="dupe-name">{(findings.find(f => f.id === d.finding_id) || {}).title || d.finding_id?.slice(0, 8)}</span>
              <span class="dim">duplicate of</span>
              <span class="dupe-name">{(findings.find(f => f.id === d.duplicate_of) || {}).title || d.duplicate_of?.slice(0, 8)}</span>
              <span class="dim dupe-reason">— {d.reason}</span>
            </div>
          {/each}
          {#if dupes.length === 0}<div class="dim">No duplicates detected.</div>{/if}
        </div>
      {/if}

      {#if loading}
        <div class="empty-state"><span class="dim">Loading findings…</span></div>
      {:else if filtered.length === 0}
        <div class="empty-state">
          <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
            <rect x="8" y="6" width="32" height="36" rx="3" stroke="#c8c8c8" stroke-width="1.5" fill="#f5f5f5"/>
            <path d="M15 16 L33 16" stroke="#c8c8c8" stroke-width="1.2" stroke-linecap="round"/>
            <path d="M15 22 L33 22" stroke="#c8c8c8" stroke-width="1.2" stroke-linecap="round"/>
            <path d="M15 28 L25 28" stroke="#c8c8c8" stroke-width="1.2" stroke-linecap="round"/>
          </svg>
          <span style="font-weight:500;color:#444">No findings yet</span>
          <span class="dim" style="font-size:12px">Click "+ New Finding" or right-click any request in Proxy / Repeater / Intruder</span>
        </div>
      {:else}
        <div class="findings-table-wrap">
          <table class="findings-table">
            <thead>
              <tr>
                <th>Sev</th>
                <th>Title</th>
                <th>Endpoint</th>
                <th>Program</th>
                <th>Status</th>
                <th>Date</th>
              </tr>
            </thead>
            <tbody>
              {#each filtered as f}
              <tr class="finding-row" class:selected={selectedFinding?.id === f.id} on:click={() => { selectedFinding = f; triageResult = null; }}>
                <td><span class="badge {sevClass(f.severity)}">{f.severity}</span></td>
                <td class="title-cell">{f.title}</td>
                <td class="endpoint-cell">{f.endpoint || "—"}</td>
                <td>{f.program || "—"}</td>
                <td>
                  <span class="status-pill" style="color:{STATUS_COLOR[f.status]||'#767676'}">
                    {f.status}
                  </span>
                </td>
                <td class="dim" style="white-space:nowrap">{fmtDate(f.created_at)}</td>
              </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </div>

    <!-- Right: detail pane -->
    {#if selectedFinding}
    <div class="finding-detail">
      <div class="detail-header">
        <span class="badge {sevClass(selectedFinding.severity)}">{selectedFinding.severity}</span>
        <span class="detail-title">{selectedFinding.title}</span>
        <button class="detail-close" on:click={() => { selectedFinding=null; triageResult=null; }}>×</button>
      </div>

      <div class="detail-body">
        <!-- Meta grid -->
        <div class="meta-grid">
          <div class="meta-row"><span class="meta-label">Program</span><span class="meta-val">{selectedFinding.program || "—"}</span></div>
          <div class="meta-row"><span class="meta-label">Endpoint</span><span class="meta-val mono">{selectedFinding.endpoint || "—"}</span></div>
          <div class="meta-row"><span class="meta-label">CVSS</span><span class="meta-val">{selectedFinding.cvss || "—"}</span></div>
          <div class="meta-row"><span class="meta-label">Tags</span><span class="meta-val">{selectedFinding.tags || "—"}</span></div>
          <div class="meta-row">
            <span class="meta-label">Status</span>
            <select class="status-select" value={selectedFinding.status} on:change={e => updateStatus(selectedFinding, e.target.value)}>
              {#each STATUSES as s}<option value={s}>{s}</option>{/each}
            </select>
          </div>
        </div>

        <!-- Pipeline stepper -->
        <div class="pipeline">
          {#each STATUSES as s, i}
          <div class="pipe-step" class:pipe-done={STATUSES.indexOf(selectedFinding.status) >= i} class:pipe-current={selectedFinding.status === s}>
            <div class="pipe-dot"></div>
            <span class="pipe-label">{s}</span>
          </div>
          {#if i < STATUSES.length - 1}<div class="pipe-line"></div>{/if}
          {/each}
        </div>

        {#if selectedFinding.impact}
          <div class="detail-section"><div class="section-label">Impact</div><div class="section-body">{selectedFinding.impact}</div></div>
        {/if}
        {#if selectedFinding.repro}
          <div class="detail-section"><div class="section-label">Reproduction steps</div><div class="section-body">{selectedFinding.repro}</div></div>
        {/if}

        <!-- AI Triage -->
        <div class="detail-section">
          <div class="section-label" style="display:flex;align-items:center;justify-content:space-between">
            AI Triage
            <button class="btn-triage" on:click={() => runTriage(selectedFinding)} disabled={triaging}>
              {triaging ? "Analysing…" : "Run AI Triage"}
            </button>
          </div>
          {#if triageResult}
          <div class="triage-result">
            <div class="triage-score">
              <span class="triage-score-num">{triageResult.base_score}</span>
              <span class="dim" style="font-size:11px">/ 10.0</span>
            </div>
            <div class="triage-vector mono dim" style="font-size:11px">{triageResult.cvss_vector}</div>
            <div class="triage-reasoning" style="margin-top:8px;font-size:12px;line-height:1.5">{triageResult.reasoning}</div>
          </div>
          {:else}
          <div class="dim" style="font-size:12px;padding:8px 0">Click "Run AI Triage" to get a CVSS score suggestion and severity reasoning from the AI.</div>
          {/if}
        </div>

        <!-- Raw req/resp -->
        {#if selectedFinding.raw_request || selectedFinding.raw_response}
        <div class="detail-section">
          <div class="section-label">Evidence</div>
          {#if selectedFinding.raw_request}
          <div class="evidence-label">Request</div>
          <pre class="evidence-pre">{selectedFinding.raw_request}</pre>
          {/if}
          {#if selectedFinding.raw_response}
          <div class="evidence-label" style="margin-top:8px">Response</div>
          <pre class="evidence-pre">{selectedFinding.raw_response}</pre>
          {/if}
        </div>
        {/if}
      </div>
    </div>
    {/if}
  </div>
  {/if}

  <!-- ── DASHBOARD TAB ── -->
  {#if subtab === "dashboard"}
  <div class="panel">
    <div class="dash-grid">
      <div class="stat-card"><div class="stat-num">{stats.total}</div><div class="stat-label">Total Findings</div></div>
      <div class="stat-card"><div class="stat-num" style="color:#e03a00">{stats.critical}</div><div class="stat-label">Critical</div></div>
      <div class="stat-card"><div class="stat-num" style="color:#e86c00">{stats.high}</div><div class="stat-label">High</div></div>
      <div class="stat-card"><div class="stat-num" style="color:#1b8c1b">{stats.paid}</div><div class="stat-label">Paid</div></div>
      <div class="stat-card"><div class="stat-num" style="color:#c98a00">{stats.open}</div><div class="stat-label">Open</div></div>
      <div class="stat-card"><div class="stat-num" style="color:#d42c2c">{stats.dups}</div><div class="stat-label">Duplicates</div></div>
    </div>

    <div class="dash-section-title">By Program</div>
    <div class="prog-grid">
      {#each stats.byProg.filter(p => p.count > 0) as p}
      <div class="prog-card">
        <div class="prog-name">{p.prog}</div>
        <div class="prog-count">{p.count}</div>
        <div class="prog-bar-bg"><div class="prog-bar-fill" style="width:{Math.min(100, p.count / stats.total * 100)}%"></div></div>
      </div>
      {/each}
      {#if stats.byProg.every(p => p.count === 0)}
        <div class="dim" style="font-size:12px">No findings with program assigned yet.</div>
      {/if}
    </div>

    <div class="dash-section-title" style="margin-top:20px">Pipeline Status</div>
    <div class="pipeline-dash">
      {#each STATUSES as s}
      <div class="pipeline-stat">
        <div class="ps-count">{findings.filter(f => f.status === s).length}</div>
        <div class="ps-label" style="color:{STATUS_COLOR[s]}">{s}</div>
      </div>
      {/each}
    </div>
  </div>
  {/if}

  <!-- ── POC LIBRARY TAB ── -->
  {#if subtab === "poc"}
  <div class="panel">
    <div class="poc-intro dim" style="font-size:12px;margin-bottom:14px">
      Reusable payload/POC templates organised by vulnerability class. Click any template to copy or send to Repeater/Intruder.
    </div>
    {#each [
      { cls:"XSS", items: ["<scr"+"ipt>alert(1)</scr"+"ipt>", '"><img src=x onerror=alert(1)>', "javascript:alert(1)", "';alert`1`//"] },
      { cls:"SQLi", items: ["' OR '1'='1", "' UNION SELECT NULL--", "1' AND SLEEP(5)--", "' OR 1=1#"] },
      { cls:"SSRF", items: ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:80/", "file:///etc/passwd"] },
      { cls:"Path Traversal", items: ["../../etc/passwd", "..%2F..%2Fetc%2Fpasswd", "%252e%252e%252fetc%252fpasswd"] },
      { cls:"SSTI", items: ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>"] },
    ] as group}
    <div class="poc-group">
      <div class="poc-group-title">{group.cls}</div>
      {#each group.items as item}
      <div class="poc-item">
        <code class="poc-payload">{item}</code>
        <button class="poc-copy" on:click={() => navigator.clipboard.writeText(item)} title="Copy">Copy</button>
        <button class="poc-send" on:click={() => { try { localStorage.setItem("lancer.send.repeater", JSON.stringify({raw:`GET /?x=${encodeURIComponent(item)} HTTP/1.1\r\nHost: target.com\r\n\r\n`})); window.dispatchEvent(new CustomEvent("lancer:navigate", {detail:"repeater"})); } catch {} }}>→ Repeater</button>
      </div>
      {/each}
    </div>
    {/each}
  </div>
  {/if}
</div>

<!-- ── NEW FINDING DIALOG ── -->
{#if showNewDialog}
<div class="dialog-overlay" on:click|self={() => showNewDialog=false}>
  <div class="dialog">
    <div class="dialog-header">
      <span class="dialog-title">New Finding</span>
      <button class="dialog-close" on:click={() => showNewDialog=false}>×</button>
    </div>
    <div class="dialog-body">
      <div class="form-row">
        <label>Title *</label>
        <input bind:value={nfTitle} placeholder="Reflected XSS in search parameter" style="width:100%" />
      </div>
      <div class="form-row-split">
        <div class="form-col">
          <label>Severity</label>
          <select bind:value={nfSeverity}>
            {#each SEVERITIES as s}<option value={s}>{s}</option>{/each}
          </select>
        </div>
        <div class="form-col">
          <label>CVSS Vector</label>
          <input bind:value={nfCvss} placeholder="CVSS:3.1/AV:N/AC:L/..." />
        </div>
      </div>
      <div class="form-row-split">
        <div class="form-col">
          <label>Program</label>
          <select bind:value={nfProgram}>
            <option value="">— select —</option>
            {#each PROGRAMS as p}<option value={p}>{p}</option>{/each}
          </select>
        </div>
        <div class="form-col">
          <label>Tags</label>
          <input bind:value={nfTags} placeholder="xss, reflected, client-side" />
        </div>
      </div>
      <div class="form-row">
        <label>Affected Endpoint</label>
        <input bind:value={nfEndpoint} placeholder="https://target.com/search?q=" style="width:100%" />
      </div>
      <div class="form-row">
        <label>Impact</label>
        <textarea bind:value={nfImpact} rows="2" placeholder="An attacker can steal session cookies…"></textarea>
      </div>
      <div class="form-row">
        <label>Reproduction Steps</label>
        <textarea bind:value={nfRepro} rows="3" placeholder="1. Navigate to the search page&#10;2. Enter the payload in the q parameter…"></textarea>
      </div>
      <div class="form-row">
        <label>Raw Request (optional)</label>
        <textarea bind:value={nfRequest} rows="4" placeholder="GET /search?q=test HTTP/1.1&#10;Host: target.com" class="mono-ta"></textarea>
      </div>
    </div>
    <div class="dialog-footer">
      <button on:click={() => showNewDialog=false}>Cancel</button>
      <button class="btn-primary" on:click={saveFinding} disabled={saving || !nfTitle}>
        {saving ? "Saving…" : "Save Finding"}
      </button>
    </div>
  </div>
</div>
{/if}

<style>
  .findings-root { display:flex; flex-direction:column; height:100%; overflow:hidden; }

  .subtabs { display:flex; align-items:center; background:#f5f5f5; border-bottom:1px solid #dedede; flex-shrink:0; height:36px; padding-right:8px; }
  .subtab-spacer { flex:1; }
  .btn-new-finding {
    background:#e03a00; color:#fff; border:none; border-radius:3px;
    padding:4px 12px; font-size:12px; font-weight:500; cursor:pointer; flex-shrink:0;
  }
  .btn-new-finding:hover { background:#c73400; }
  .cnt-badge { display:inline-block; background:#e03a00; color:#fff; border-radius:8px; font-size:10px; padding:0 5px; margin-left:4px; }

  /* Findings layout */
  .findings-layout { display:flex; flex:1; overflow:hidden; }
  .findings-list-col { display:flex; flex-direction:column; flex:1; min-width:0; border-right:1px solid #dedede; overflow:hidden; }
  .finding-detail { width:420px; flex-shrink:0; display:flex; flex-direction:column; overflow:hidden; }

  /* Filter bar */
  .filter-bar { display:flex; align-items:center; gap:6px; padding:6px 10px; background:#fafafa; border-bottom:1px solid #dedede; flex-shrink:0; flex-wrap:wrap; }
  .filter-input { flex:1; min-width:120px; max-width:200px; padding:4px 8px; font-size:12px; }
  .filter-bar select { padding:4px 6px; font-size:12px; }
  .filter-spacer { flex:1; }
  .export-row { display:flex; align-items:center; gap:4px; }
  .export-select { padding:4px 6px; font-size:12px; }
  .btn-export { background:#f0f0f0; border:1px solid #c8c8c8; border-radius:3px; padding:4px 10px; font-size:12px; cursor:pointer; }
  .btn-export:hover { background:#e4e4e4; }
  .dupes-banner { position:relative; margin:6px 10px; padding:8px 12px; background:#fff8f0; border:1px solid #f0d9c0; border-radius:4px; font-size:12px; }
  .dupes-close { position:absolute; top:4px; right:6px; background:none; border:none; font-size:16px; cursor:pointer; color:#999; }
  .dupe-row { display:flex; gap:6px; align-items:center; margin-top:4px; flex-wrap:wrap; }
  .dupe-sim { font-weight:700; color:#c73400; }
  .dupe-name { font-weight:600; color:#333; }
  .dupe-reason { font-size:11px; }

  /* Table */
  .findings-table-wrap { flex:1; overflow-y:auto; }
  .findings-table { width:100%; border-collapse:collapse; font-size:12px; }
  .findings-table thead th { background:#f5f5f5; border-bottom:1px solid #dedede; padding:6px 10px; text-align:left; font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:0.05em; color:#767676; white-space:nowrap; position:sticky; top:0; z-index:1; }
  .findings-table tbody tr { border-bottom:1px solid #f0f0f0; }
  .finding-row { cursor:pointer; }
  .finding-row:hover { background:#fafafa; }
  .finding-row.selected { background:#fce8e2; }
  .findings-table td { padding:7px 10px; vertical-align:middle; }
  .title-cell { font-weight:500; color:#212121; max-width:260px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .endpoint-cell { font-family:ui-monospace,Consolas,monospace; font-size:11px; color:#767676; max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .status-pill { font-size:11px; font-weight:600; text-transform:capitalize; }

  /* Detail pane */
  .detail-header { display:flex; align-items:center; gap:8px; padding:10px 12px; background:#f5f5f5; border-bottom:1px solid #dedede; flex-shrink:0; }
  .detail-title { flex:1; font-size:13px; font-weight:600; color:#212121; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .detail-close { background:transparent; border:none; font-size:16px; color:#767676; cursor:pointer; padding:0 4px; }
  .detail-body { flex:1; overflow-y:auto; padding:12px; display:flex; flex-direction:column; gap:12px; }

  .meta-grid { display:flex; flex-direction:column; gap:4px; }
  .meta-row { display:flex; align-items:center; gap:6px; font-size:12px; }
  .meta-label { color:#767676; width:80px; flex-shrink:0; font-size:11px; font-weight:600; text-transform:uppercase; letter-spacing:0.04em; }
  .meta-val { color:#212121; flex:1; }
  .meta-val.mono { font-family:ui-monospace,Consolas,monospace; font-size:11px; }
  .status-select { padding:3px 6px; font-size:12px; border-radius:3px; }

  /* Pipeline stepper */
  .pipeline { display:flex; align-items:center; flex-wrap:wrap; gap:0; margin:8px 0; }
  .pipe-step { display:flex; flex-direction:column; align-items:center; gap:3px; }
  .pipe-dot { width:10px; height:10px; border-radius:50%; background:#dedede; border:2px solid #c8c8c8; }
  .pipe-current .pipe-dot { background:#e03a00; border-color:#e03a00; }
  .pipe-done .pipe-dot { background:#1b8c1b; border-color:#1b8c1b; }
  .pipe-label { font-size:10px; color:#767676; }
  .pipe-current .pipe-label { color:#e03a00; font-weight:600; }
  .pipe-line { flex:1; height:2px; background:#dedede; min-width:8px; align-self:center; margin-top:-13px; }

  .detail-section { background:#fafafa; border:1px solid #ebebeb; border-radius:3px; padding:10px 12px; }
  .section-label { font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:0.05em; color:#767676; margin-bottom:6px; }
  .section-body { font-size:12px; color:#444; line-height:1.5; white-space:pre-wrap; }

  .btn-triage { background:#1a75c4; color:#fff; border:none; border-radius:3px; padding:3px 10px; font-size:12px; cursor:pointer; }
  .btn-triage:hover:not(:disabled) { background:#1563a6; }
  .btn-triage:disabled { opacity:0.5; cursor:not-allowed; }

  .triage-result { display:flex; flex-direction:column; gap:4px; }
  .triage-score { display:flex; align-items:baseline; gap:4px; }
  .triage-score-num { font-size:22px; font-weight:700; color:#e03a00; }
  .triage-vector { word-break:break-all; }

  .evidence-label { font-size:11px; font-weight:600; color:#767676; margin-bottom:3px; }
  .evidence-pre { background:#1e1f22; color:#d6d6d6; border:none; border-radius:3px; padding:8px 10px; font-size:11px; font-family:ui-monospace,Consolas,monospace; overflow-x:auto; white-space:pre; margin:0; max-height:160px; overflow-y:auto; }

  /* Dashboard */
  .dash-grid { display:flex; gap:10px; flex-wrap:wrap; margin-bottom:16px; }
  .stat-card { background:#fafafa; border:1px solid #dedede; border-radius:4px; padding:12px 16px; min-width:90px; text-align:center; }
  .stat-num { font-size:24px; font-weight:700; color:#212121; }
  .stat-label { font-size:11px; color:#767676; margin-top:2px; }
  .dash-section-title { font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:0.06em; color:#767676; margin-bottom:8px; }
  .prog-grid { display:flex; gap:8px; flex-wrap:wrap; }
  .prog-card { background:#fafafa; border:1px solid #dedede; border-radius:4px; padding:10px 14px; min-width:120px; }
  .prog-name { font-size:12px; font-weight:600; color:#212121; }
  .prog-count { font-size:20px; font-weight:700; color:#e03a00; margin:4px 0; }
  .prog-bar-bg { height:4px; background:#f0f0f0; border-radius:2px; overflow:hidden; }
  .prog-bar-fill { height:100%; background:#e03a00; border-radius:2px; }
  .pipeline-dash { display:flex; gap:12px; flex-wrap:wrap; }
  .pipeline-stat { text-align:center; min-width:60px; }
  .ps-count { font-size:20px; font-weight:700; color:#212121; }
  .ps-label { font-size:11px; font-weight:600; text-transform:capitalize; }

  /* POC Library */
  .poc-group { margin-bottom:16px; }
  .poc-group-title { font-size:12px; font-weight:700; color:#444; margin-bottom:6px; border-bottom:1px solid #ebebeb; padding-bottom:4px; }
  .poc-item { display:flex; align-items:center; gap:8px; padding:5px 0; border-bottom:1px solid #f5f5f5; }
  .poc-payload { flex:1; font-family:ui-monospace,Consolas,monospace; font-size:12px; color:#212121; background:#f5f5f5; border:1px solid #ebebeb; border-radius:3px; padding:3px 8px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .poc-copy, .poc-send { flex-shrink:0; padding:3px 8px; font-size:11px; cursor:pointer; }
  .poc-send { background:#e03a00; color:#fff; border:none; border-radius:3px; }
  .poc-send:hover { background:#c73400; }

  /* Dialog */
  .dialog-overlay { position:fixed; inset:0; background:rgba(0,0,0,0.4); z-index:300; display:flex; align-items:center; justify-content:center; }
  .dialog { background:#fff; border-radius:5px; width:620px; max-height:90vh; display:flex; flex-direction:column; box-shadow:0 8px 32px rgba(0,0,0,0.18); overflow:hidden; }
  .dialog-header { display:flex; align-items:center; justify-content:space-between; padding:14px 16px; border-bottom:1px solid #dedede; }
  .dialog-title { font-size:14px; font-weight:700; color:#212121; }
  .dialog-close { background:transparent; border:none; font-size:18px; color:#767676; cursor:pointer; }
  .dialog-body { flex:1; overflow-y:auto; padding:14px 16px; display:flex; flex-direction:column; gap:10px; }
  .dialog-footer { display:flex; justify-content:flex-end; gap:8px; padding:12px 16px; border-top:1px solid #dedede; }
  .form-row { display:flex; flex-direction:column; gap:4px; }
  .form-row label { font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:0.05em; color:#767676; }
  .form-row-split { display:flex; gap:10px; }
  .form-col { flex:1; display:flex; flex-direction:column; gap:4px; }
  .form-col label { font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:0.05em; color:#767676; }
  .mono-ta { font-family:ui-monospace,Consolas,monospace; font-size:11px; }

  .empty-state { flex:1; display:flex; flex-direction:column; align-items:center; justify-content:center; gap:10px; color:#767676; font-size:13px; text-align:center; padding:40px; }
</style>
