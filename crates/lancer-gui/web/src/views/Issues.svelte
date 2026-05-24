<script>
  import { onMount } from "svelte";

  let issues = [];
  let filter = "All";
  let expanded = {};

  const severities = ["All", "Critical", "High", "Medium", "Low", "Info"];

  const severityColor = {
    Critical: "#f38ba8",
    High:     "#fab387",
    Medium:   "#f9e2af",
    Low:      "#a6e3a1",
    Info:     "#89b4fa",
  };

  onMount(async () => {
    try {
      const r = await fetch("/api/v1/issues");
      if (r.ok) issues = await r.json();
    } catch {
      issues = [];
    }
  });

  $: counts = severities.reduce((acc, s) => {
    acc[s] = s === "All" ? issues.length : issues.filter(i => i.severity === s).length;
    return acc;
  }, {});

  $: filtered = filter === "All" ? issues : issues.filter(i => i.severity === filter);

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
    <span class="dim" style="margin-left:auto;font-size:11px">{filtered.length} issue{filtered.length !== 1 ? "s" : ""}</span>
  </div>

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
          <div class="issue-item" style="border-left-color:{borderColor(issue.severity)}">
            <div class="issue-header" on:click={() => toggle(i)} role="button" tabindex="0" on:keydown={e => e.key === "Enter" && toggle(i)}>
              <span class="badge {('badge-' + issue.severity)}">{issue.severity}</span>
              <span class="issue-name">{issue.name}</span>
              <span class="issue-meta dim">{issue.host}</span>
              {#if issue.confidence}
                <span class="confidence dim">· {issue.confidence}</span>
              {/if}
              <span class="expand-icon">{expanded[i] ? "▲" : "▼"}</span>
            </div>

            {#if expanded[i]}
              <div class="issue-body">
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
  .evidence {
    background: #11111b; border: 1px solid #313244;
    border-radius: 4px; padding: 8px;
    font-size: 11px; color: #a6adc8;
    margin: 0; overflow-x: auto;
    font-family: ui-monospace, Menlo, Consolas, monospace;
  }
</style>
