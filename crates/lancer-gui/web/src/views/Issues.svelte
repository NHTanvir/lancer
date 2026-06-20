<script>
  import { onMount } from "svelte";

  let issues = [];
  let filter = "All";
  let expanded = {};
  let hideFp = true;
  let showAdd = false;
  let newIssue = { host: "", url: "", name: "", severity: "Medium", confidence: "Firm", description: "", remediation: "" };

  const severities = ["All", "Critical", "High", "Medium", "Low", "Info"];
  const SEV_OPTS = ["Critical", "High", "Medium", "Low", "Info"];
  const CONF_OPTS = ["Certain", "Firm", "Tentative"];

  async function reload() {
    try { const r = await fetch("/api/v1/issues"); if (r.ok) issues = await r.json(); }
    catch { issues = []; }
  }

  async function addIssue() {
    if (!newIssue.name || !newIssue.host) return;
    try {
      const r = await fetch("/api/v1/issues", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(newIssue) });
      if (r.ok) { showAdd = false; newIssue = { host: "", url: "", name: "", severity: "Medium", confidence: "Firm", description: "", remediation: "" }; await reload(); }
      else alert("Add failed — is a project open? " + (await r.text()));
    } catch {}
  }

  async function patchIssue(issue, body) {
    try { await fetch(`/api/v1/issues/${issue.id}`, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }); await reload(); }
    catch {}
  }
  const markFp = (issue) => patchIssue(issue, { false_positive: !issue.false_positive });
  const setSeverity = (issue, severity) => patchIssue(issue, { severity });
  const setConfidence = (issue, confidence) => patchIssue(issue, { confidence });

  const severityColor = {
    Critical: "#f38ba8",
    High:     "#fab387",
    Medium:   "#f9e2af",
    Low:      "#a6e3a1",
    Info:     "#89b4fa",
  };

  onMount(reload);

  $: visible = issues.filter(i => !(hideFp && i.false_positive));
  $: counts = severities.reduce((acc, s) => {
    acc[s] = s === "All" ? visible.length : visible.filter(i => i.severity === s).length;
    return acc;
  }, {});

  $: filtered = filter === "All" ? visible : visible.filter(i => i.severity === filter);

  function toggle(id) {
    expanded[id] = !expanded[id];
    expanded = expanded;
  }

  function borderColor(sev) {
    return severityColor[sev] || "#45475a";
  }
</script>

<div class="view">
  <div class="toolbar" style="flex-wrap:wrap;gap:6px">
    {#each severities as s}
      <button
        class="filter-btn"
        class:active={filter === s}
        on:click={() => filter = s}
        style={filter === s ? `border-color:${s === "All" ? "#89b4fa" : (severityColor[s] || "#89b4fa")}` : ""}
      >
        {s}
        {#if counts[s] > 0}
          <span class="count">{counts[s]}</span>
        {/if}
      </button>
    {/each}
    <label class="fp-toggle dim" style="margin-left:auto"><input type="checkbox" bind:checked={hideFp} /> Hide false positives</label>
    <button class="filter-btn" on:click={() => (showAdd = !showAdd)}>+ Add issue</button>
    <span class="dim" style="font-size:11px">{filtered.length} issue{filtered.length !== 1 ? "s" : ""}</span>
  </div>

  {#if showAdd}
    <div class="add-form">
      <input placeholder="Name *" bind:value={newIssue.name} />
      <input placeholder="Host *" bind:value={newIssue.host} />
      <input placeholder="URL" bind:value={newIssue.url} />
      <select bind:value={newIssue.severity}>{#each SEV_OPTS as s}<option>{s}</option>{/each}</select>
      <select bind:value={newIssue.confidence}>{#each CONF_OPTS as c}<option>{c}</option>{/each}</select>
      <input class="grow" placeholder="Description" bind:value={newIssue.description} />
      <button class="filter-btn primary" on:click={addIssue}>Create</button>
      <button class="filter-btn" on:click={() => (showAdd = false)}>Cancel</button>
    </div>
  {/if}

  <div class="panel">
    {#if filtered.length === 0}
      <div class="empty-state">
        <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
          <circle cx="24" cy="24" r="22" stroke="#313244" stroke-width="2"/>
          <path d="M24 14 L24 26" stroke="#45475a" stroke-width="3" stroke-linecap="round"/>
          <circle cx="24" cy="33" r="2" fill="#45475a"/>
        </svg>
        <span>{filter === "All" ? "No issues found yet" : `No ${filter} issues`}</span>
        <span class="dim" style="font-size:11px">Run a scan to discover vulnerabilities</span>
      </div>
    {:else}
      <div class="issue-list">
        {#each filtered as issue, i}
          <div class="issue-item" class:is-fp={issue.false_positive} style="border-left-color:{borderColor(issue.severity)}">
            <div class="issue-header" on:click={() => toggle(i)} role="button" tabindex="0" on:keydown={e => e.key === "Enter" && toggle(i)}>
              <span class="badge {('badge-' + issue.severity)}">{issue.severity}</span>
              <span class="issue-name">{issue.name}</span>
              {#if issue.false_positive}<span class="fp-badge">FALSE POSITIVE</span>{/if}
              <span class="issue-meta dim">{issue.host}</span>
              {#if issue.confidence}
                <span class="confidence dim">· {issue.confidence}</span>
              {/if}
              <span class="expand-icon">{expanded[i] ? "▲" : "▼"}</span>
            </div>

            {#if expanded[i]}
              <div class="issue-body">
                <div class="override-bar">
                  <label class="ov dim">Severity
                    <select value={issue.severity} on:change={e => setSeverity(issue, e.target.value)}>{#each SEV_OPTS as s}<option>{s}</option>{/each}</select>
                  </label>
                  <label class="ov dim">Confidence
                    <select value={issue.confidence} on:change={e => setConfidence(issue, e.target.value)}>{#each CONF_OPTS as c}<option>{c}</option>{/each}</select>
                  </label>
                  <button class="fp-btn" on:click={() => markFp(issue)}>{issue.false_positive ? "Unmark false positive" : "Mark as false positive"}</button>
                </div>
                {#if issue.description}
                  <div class="issue-section">
                    <div class="section-label">Description</div>
                    <div class="section-text">{issue.description}</div>
                  </div>
                {/if}
                {#if issue.remediation}
                  <div class="issue-section">
                    <div class="section-label">Remediation</div>
                    <div class="section-text remediation">{issue.remediation}</div>
                  </div>
                {/if}
                {#if issue.request}
                  <div class="issue-section">
                    <div class="section-label">Evidence</div>
                    <pre class="evidence">{issue.request}</pre>
                  </div>
                {/if}
              </div>
            {/if}
          </div>
        {/each}
      </div>
    {/if}
  </div>
</div>

<style>
  .filter-btn {
    font-size: 12px; padding: 4px 10px;
    border-color: #45475a;
  }
  .filter-btn.active {
    background: #313244; color: #cdd6f4;
  }
  .count {
    display: inline-block;
    background: #313244; color: #a6adc8;
    border-radius: 8px; font-size: 10px;
    padding: 0 5px; margin-left: 4px;
  }

  .issue-list {
    display: flex; flex-direction: column; gap: 8px;
  }
  .issue-item {
    background: #181825;
    border: 1px solid #313244;
    border-left-width: 3px;
    border-radius: 6px;
    overflow: hidden;
  }
  .issue-header {
    display: flex; align-items: center; gap: 8px;
    padding: 10px 14px;
    cursor: pointer;
    user-select: none;
    flex-wrap: wrap;
  }
  .issue-header:hover { background: #1e1e2e; }
  .issue-name {
    font-size: 13px; font-weight: 500;
    color: #cdd6f4; flex: 1;
  }
  .issue-meta { font-size: 11px; }
  .confidence { font-size: 11px; }
  .expand-icon { color: #45475a; font-size: 10px; flex-shrink: 0; }

  .issue-body {
    border-top: 1px solid #313244;
    padding: 12px 14px;
    display: flex; flex-direction: column; gap: 10px;
  }
  .issue-section { display: flex; flex-direction: column; gap: 4px; }
  .section-label {
    font-size: 10px; font-weight: 600;
    text-transform: uppercase; letter-spacing: 0.06em;
    color: #6c7086;
  }
  .section-text { font-size: 12px; color: #a6adc8; line-height: 1.5; }
  .remediation { color: #a6e3a1; }
  .fp-toggle { display: flex; align-items: center; gap: 5px; font-size: 11px; }
  .filter-btn.primary { background: var(--accent); color: #fff; border-color: var(--accent); }
  .add-form { display: flex; flex-wrap: wrap; gap: 6px; padding: 8px 12px; background: #1e1e2e; border-bottom: 1px solid #313244; align-items: center; }
  .add-form input, .add-form select { background: #11111b; border: 1px solid #313244; color: #cdd6f4; border-radius: 3px; padding: 4px 7px; font-size: 12px; }
  .add-form input.grow { flex: 1; min-width: 160px; }
  .is-fp { opacity: 0.6; }
  .fp-badge { font-size: 9px; font-weight: 700; background: #45475a; color: #f38ba8; padding: 1px 6px; border-radius: 3px; letter-spacing: 0.04em; }
  .override-bar { display: flex; align-items: flex-end; gap: 14px; padding-bottom: 4px; border-bottom: 1px solid #313244; }
  .ov { display: flex; flex-direction: column; gap: 3px; font-size: 10px; text-transform: uppercase; letter-spacing: 0.04em; }
  .ov select { background: #11111b; border: 1px solid #313244; color: #cdd6f4; border-radius: 3px; padding: 3px 6px; font-size: 12px; }
  .fp-btn { background: #313244; color: #f38ba8; border: 1px solid #45475a; border-radius: 3px; padding: 4px 10px; font-size: 12px; cursor: pointer; }
  .fp-btn:hover { background: #45475a; }
  .evidence {
    background: #11111b; border: 1px solid #313244;
    border-radius: 4px; padding: 8px;
    font-size: 11px; color: #a6adc8;
    margin: 0; overflow-x: auto;
    font-family: ui-monospace, Menlo, Consolas, monospace;
  }
</style>
