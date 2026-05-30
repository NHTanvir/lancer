<script>
  import { onMount } from "svelte";

  let target = "";
  let enumeratePlugins = false;
  let results = [];
  let selected = null;
  let running = false;

  function sevClass(s) {
    return { critical: "s-crit", high: "s-high", medium: "s-med", low: "s-low", info: "s-info" }[s] || "s-info";
  }

  async function load() {
    try {
      const r = await fetch("/api/v1/cms-scan");
      if (r.ok) results = await r.json();
    } catch {}
  }

  async function run() {
    if (!target) return;
    running = true;
    await fetch("/api/v1/cms-scan/run", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ target, enumerate_plugins: enumeratePlugins }),
    });
    for (let i = 0; i < 30; i++) {
      await new Promise(r => setTimeout(r, 1500));
      await load();
    }
    running = false;
  }

  async function clearAll() {
    await fetch("/api/v1/cms-scan", { method: "DELETE" });
    results = []; selected = null;
  }

  onMount(load);
</script>

<div class="cms">
  <div class="cm-bar">
    <input type="url" bind:value={target} placeholder="https://target.example.com" />
    <label class="toggle">
      <input type="checkbox" bind:checked={enumeratePlugins} /> Enumerate plugins (noisy)
    </label>
    <button on:click={run} disabled={running || !target} class="run">{running ? "Scanning…" : "Scan"}</button>
    <button on:click={clearAll} class="btn-danger">Clear</button>
  </div>

  <div class="cm-body">
    <div class="results-list">
      {#each results as r (r.target)}
        <div class="result-row" class:selected={selected === r} on:click={() => selected = r}>
          <strong>{r.cms}</strong>
          {#if r.version}<span class="badge">v{r.version}</span>{/if}
          <span class="dim">{r.findings.length} findings</span>
          <span class="dim url">{r.target}</span>
        </div>
      {/each}
    </div>

    {#if selected}
      <div class="cm-detail">
        <h3>{selected.cms} {#if selected.version}<small>v{selected.version}</small>{/if}</h3>
        <p class="url-line">{selected.target}</p>

        {#if selected.plugins?.length}
          <h4>Plugins detected</h4>
          <div class="chips">
            {#each selected.plugins as p}<span class="chip">{p}</span>{/each}
          </div>
        {/if}

        <h4>Findings</h4>
        {#each selected.findings as f}
          <div class="finding">
            <div class="finding-head">
              <strong>{f.title}</strong>
              <span class="sev {sevClass(f.severity)}">{f.severity}</span>
              {#if f.cve}<a href="https://nvd.nist.gov/vuln/detail/{f.cve}" target="_blank" class="cve">{f.cve}</a>{/if}
            </div>
            <p>{f.detail}</p>
            {#if f.evidence_url}<code class="evidence">{f.evidence_url}</code>{/if}
          </div>
        {/each}
        {#if selected.findings.length === 0}
          <div class="empty">No findings — CMS not detected or hardened.</div>
        {/if}
      </div>
    {/if}
  </div>
</div>

<style>
  .cms{display:flex;flex-direction:column;height:100%;font-size:13px}
  .cm-bar{padding:8px 12px;border-bottom:1px solid var(--border);display:flex;gap:8px;align-items:center}
  .cm-bar input{flex:1;padding:4px 8px}
  .toggle{display:flex;gap:4px;align-items:center;font-size:11px}
  .run{background:#e03a00;color:white;border:none;padding:5px 14px;border-radius:4px;cursor:pointer;font-weight:600}
  .btn-danger{background:#fde8e8;color:#c0392b;border:1px solid #e74c3c;padding:5px 10px;border-radius:4px;cursor:pointer}
  .cm-body{flex:1;display:flex;overflow:hidden}
  .results-list{width:240px;border-right:1px solid var(--border);overflow-y:auto}
  .result-row{padding:8px;border-bottom:1px solid var(--border);cursor:pointer;display:flex;flex-direction:column;gap:2px}
  .result-row.selected{background:#e8f0fe}
  .badge{background:#eaf4fb;color:#2980b9;padding:1px 6px;border-radius:8px;font-size:10px;font-weight:700}
  .dim{color:var(--text-muted);font-size:11px}
  .url{font-family:monospace;font-size:10px;text-overflow:ellipsis;overflow:hidden;white-space:nowrap}
  .cm-detail{flex:1;padding:14px;overflow-y:auto}
  .cm-detail h4{margin:14px 0 6px;color:var(--text-muted);font-size:12px}
  .url-line{margin:0 0 8px;font-family:monospace;font-size:11px;color:var(--text-muted)}
  .chips{display:flex;flex-wrap:wrap;gap:4px}
  .chip{background:#fef0e6;color:#d35400;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600}
  .finding{padding:8px;border:1px solid var(--border);border-radius:6px;margin-bottom:6px}
  .finding-head{display:flex;gap:6px;align-items:center;margin-bottom:4px;flex-wrap:wrap}
  .sev{padding:1px 6px;border-radius:8px;font-size:10px;font-weight:700}
  .s-crit{background:#fde8e8;color:#c0392b}
  .s-high{background:#fef0e6;color:#d35400}
  .s-med{background:#fef9e6;color:#b7770d}
  .s-low{background:#eafaf1;color:#27ae60}
  .s-info{background:#eaf4fb;color:#2980b9}
  .cve{padding:1px 6px;border-radius:8px;font-size:10px;font-weight:700;background:#222;color:#fff;text-decoration:none}
  .finding p{margin:4px 0;font-size:12px}
  .evidence{font-family:monospace;font-size:10px;background:var(--bg-hover);padding:2px 6px;border-radius:4px;display:inline-block;word-break:break-all}
  .empty{padding:30px;text-align:center;color:var(--text-muted);font-style:italic}
</style>
