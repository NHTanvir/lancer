<script>
  import { onMount } from "svelte";

  let server = "";
  let transport = "http";
  let results = [];
  let selected = null;
  let running = false;

  async function load() {
    try {
      const r = await fetch("/api/v1/mcp-scan/results");
      if (r.ok) results = await r.json();
    } catch {}
  }

  async function run() {
    if (!server) return;
    running = true;
    await fetch("/api/v1/mcp-scan/run", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ transport, server, depth: "full" }),
    });
    for (let i = 0; i < 30; i++) {
      await new Promise(r => setTimeout(r, 1500));
      await load();
    }
    running = false;
  }

  async function clearAll() {
    await fetch("/api/v1/mcp-scan/results", { method: "DELETE" });
    results = []; selected = null;
  }

  function sevClass(s) {
    return { critical: "s-crit", high: "s-high", medium: "s-med", low: "s-low", info: "s-info" }[s] || "s-info";
  }

  onMount(load);
</script>

<div class="mcp-scan">
  <div class="ms-bar">
    <select bind:value={transport}>
      <option value="http">HTTP</option>
      <option value="sse">SSE</option>
      <option value="stdio">stdio</option>
      <option value="web_socket">WebSocket</option>
    </select>
    <input type="text" bind:value={server} placeholder="https://mcp.example.com or ./my-mcp-server" />
    <button on:click={run} disabled={running || !server} class="run">{running ? "Scanning…" : "Scan"}</button>
    <button on:click={clearAll} class="btn-danger">Clear</button>
  </div>

  <div class="ms-body">
    <div class="results-list">
      {#each results as r (r.id)}
        <div class="result-row" class:selected={selected?.id === r.id} on:click={() => selected = r}>
          <strong>{r.server}</strong>
          <span class="dim">{r.tools.length} tools · {r.findings.length} findings</span>
        </div>
      {/each}
    </div>

    {#if selected}
      <div class="ms-detail">
        <h3>{selected.server}</h3>

        <h4>Tools ({selected.tools.length})</h4>
        <table>
          <thead><tr><th>Name</th><th>Description</th><th>Hash</th></tr></thead>
          <tbody>
            {#each selected.tools as t}
              <tr>
                <td><code>{t.name}</code></td>
                <td class="desc">{t.description}</td>
                <td><code class="hash">{t.description_hash}</code></td>
              </tr>
            {/each}
          </tbody>
        </table>

        <h4>Findings ({selected.findings.length})</h4>
        <div class="findings">
          {#each selected.findings as f}
            <div class="finding">
              <div class="finding-head">
                <span class="cat-badge">{f.category}</span>
                <span class="sev {sevClass(f.severity)}">{f.severity}</span>
                {#if f.tool}<span class="tool-badge">{f.tool}</span>{/if}
              </div>
              <p>{f.message}</p>
              {#if f.evidence}<pre class="evidence">{f.evidence}</pre>{/if}
            </div>
          {/each}
        </div>
      </div>
    {/if}
  </div>
</div>

<style>
  .mcp-scan{display:flex;flex-direction:column;height:100%;font-size:13px}
  .ms-bar{padding:8px 12px;border-bottom:1px solid var(--border);display:flex;gap:6px;align-items:center}
  .ms-bar select{padding:4px 8px}
  .ms-bar input{flex:1;padding:4px 8px}
  .run{background:var(--accent);color:white;border:none;padding:5px 14px;border-radius:4px;cursor:pointer;font-weight:600}
  .run:disabled{opacity:0.5}
  .btn-danger{background:#fde8e8;color:#c0392b;border:1px solid #e74c3c;padding:5px 10px;border-radius:4px;cursor:pointer}
  .ms-body{flex:1;display:flex;overflow:hidden}
  .results-list{width:240px;border-right:1px solid var(--border);overflow-y:auto}
  .result-row{padding:8px;border-bottom:1px solid var(--border);cursor:pointer;display:flex;flex-direction:column;gap:2px}
  .result-row.selected{background:#e8f0fe}
  .dim{color:var(--text-muted);font-size:11px}
  .ms-detail{flex:1;padding:14px;overflow-y:auto}
  .ms-detail h4{margin:12px 0 6px;color:var(--text-muted);font-size:12px}
  table{width:100%;border-collapse:collapse;margin-bottom:6px}
  th{background:var(--bg-hover);padding:5px;border-bottom:1px solid var(--border);text-align:left;font-size:11px}
  td{padding:4px 6px;border-bottom:1px solid var(--border-light, var(--border));vertical-align:top}
  .desc{font-size:11px;color:var(--text-muted);max-width:380px}
  .hash{font-size:10px}
  .findings{display:flex;flex-direction:column;gap:8px}
  .finding{padding:8px;border:1px solid var(--border);border-radius:6px}
  .finding-head{display:flex;gap:6px;align-items:center;margin-bottom:4px}
  .cat-badge{background:#fef0e6;color:#d35400;padding:1px 6px;border-radius:8px;font-size:10px;font-weight:700}
  .tool-badge{background:#eaf4fb;color:#2980b9;padding:1px 6px;border-radius:8px;font-size:10px;font-weight:700}
  .sev{padding:1px 6px;border-radius:8px;font-size:10px;font-weight:700}
  .s-crit{background:#fde8e8;color:#c0392b}
  .s-high{background:#fef0e6;color:#d35400}
  .s-med{background:#fef9e6;color:#b7770d}
  .s-low{background:#eafaf1;color:#27ae60}
  .s-info{background:#eaf4fb;color:#2980b9}
  .evidence{background:#23272e;color:#dcdcdc;padding:6px;border-radius:4px;font-size:10px;overflow:auto;max-height:120px;white-space:pre-wrap;margin:4px 0 0}
  .finding p{margin:4px 0;font-size:12px}
</style>
