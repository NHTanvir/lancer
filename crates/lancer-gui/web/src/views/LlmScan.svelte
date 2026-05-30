<script>
  import { onMount } from "svelte";

  let target = "";
  let apiKey = "";
  let model = "gpt-4o-mini";
  let categories = [];
  let running = false;
  let results = [];
  let estimate = null;
  let filterVerdict = "";

  const CATEGORIES = [
    "prompt_injection", "jailbreak", "data_leakage", "hallucination",
    "toxicity", "bias", "code_generation", "tool_misuse",
    "prompt_extraction", "xml_injection",
  ];

  $: filtered = results.filter(r => !filterVerdict || r.verdict === filterVerdict);
  $: failCount = results.filter(r => r.verdict === "fail").length;
  $: passCount = results.filter(r => r.verdict === "pass").length;

  function verdictClass(v) {
    return { pass: "v-pass", fail: "v-fail", inconclusive: "v-inc" }[v] || "v-inc";
  }
  function sevClass(s) {
    return { critical: "s-crit", high: "s-high", medium: "s-med", low: "s-low", info: "s-info" }[s] || "s-info";
  }

  async function load() {
    try {
      const r = await fetch("/api/v1/llm-scan/results");
      if (r.ok) results = await r.json();
    } catch {}
  }

  async function estimateCost() {
    const req = { target, api_key: apiKey, model, categories };
    try {
      const r = await fetch("/api/v1/llm-scan/estimate", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify(req),
      });
      if (r.ok) estimate = await r.json();
    } catch {}
  }

  async function run() {
    if (!target) return;
    running = true;
    try { await fetch("/api/v1/llm-scan/results", { method: "DELETE" }); } catch {}
    const req = { target, api_key: apiKey, model, categories, concurrency: 4 };
    try {
      await fetch("/api/v1/llm-scan/run", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify(req),
      });
      for (let i = 0; i < 60; i++) {
        await new Promise(r => setTimeout(r, 2000));
        await load();
      }
    } catch {}
    running = false;
  }

  function toggle(c) {
    if (categories.includes(c)) categories = categories.filter(x => x !== c);
    else categories = [...categories, c];
  }

  onMount(load);
</script>

<div class="llm-scan">
  <div class="lp-config">
    <h3>LLM vulnerability scan</h3>
    <div class="row"><label>Target endpoint</label>
      <input type="url" bind:value={target} placeholder="https://api.openai.com/v1/chat/completions" /></div>
    <div class="row"><label>API key</label>
      <input type="password" bind:value={apiKey} placeholder="sk-…" /></div>
    <div class="row"><label>Model</label>
      <input bind:value={model} /></div>
    <div class="row"><label>Categories</label>
      <div class="cats">
        {#each CATEGORIES as c}
          <label class="cat-chip">
            <input type="checkbox" checked={categories.includes(c)} on:change={() => toggle(c)} />
            {c.replace(/_/g, " ")}
          </label>
        {/each}
      </div>
    </div>
    <div class="row actions">
      <button on:click={estimateCost}>Estimate cost</button>
      <button on:click={run} disabled={running || !target} class="primary">{running ? "Running…" : "Run scan"}</button>
      {#if estimate}
        <span class="estimate">~{estimate.tokens} tokens, ≈${estimate.cost_usd.toFixed(4)}</span>
      {/if}
    </div>
  </div>

  <div class="lp-summary">
    <span class="sum-badge fail">{failCount} fail</span>
    <span class="sum-badge pass">{passCount} pass</span>
    <span class="sum-badge total">{results.length} total</span>
    <select bind:value={filterVerdict}>
      <option value="">All verdicts</option>
      <option value="pass">Pass</option>
      <option value="fail">Fail</option>
      <option value="inconclusive">Inconclusive</option>
    </select>
  </div>

  <div class="lp-results">
    <table>
      <thead><tr><th>Category</th><th>Probe</th><th>Verdict</th><th>Severity</th><th>Reason</th></tr></thead>
      <tbody>
        {#each filtered as r (r.id)}
          <tr>
            <td>{r.category.replace(/_/g, " ")}</td>
            <td><code>{r.probe_name}</code></td>
            <td><span class="verdict {verdictClass(r.verdict)}">{r.verdict}</span></td>
            <td><span class="sev {sevClass(r.severity)}">{r.severity}</span></td>
            <td class="reason">{r.reason}</td>
          </tr>
        {/each}
      </tbody>
    </table>
    {#if filtered.length === 0 && !running}
      <div class="empty">No results yet. Configure target and run scan.</div>
    {/if}
  </div>
</div>

<style>
  .llm-scan{display:flex;flex-direction:column;height:100%;font-size:13px}
  .lp-config{padding:10px 12px;background:var(--bg-hover);border-bottom:1px solid var(--border)}
  .row{display:flex;align-items:center;gap:8px;margin-bottom:6px}
  .row label{width:120px;font-size:11px;font-weight:600;color:var(--text-muted)}
  .row input{flex:1;padding:4px 8px}
  .cats{display:flex;gap:6px;flex-wrap:wrap;flex:1}
  .cat-chip{display:flex;gap:4px;align-items:center;font-size:11px;background:var(--bg);padding:2px 8px;border-radius:10px;border:1px solid var(--border)}
  .actions{justify-content:flex-end;margin-top:8px}
  .primary{background:#e03a00;color:white;border:none;padding:5px 14px;border-radius:4px;font-weight:600;cursor:pointer}
  .estimate{font-size:11px;color:var(--text-muted);margin-left:8px}
  .lp-summary{display:flex;gap:8px;align-items:center;padding:6px 12px;border-bottom:1px solid var(--border)}
  .sum-badge{padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700}
  .sum-badge.fail{background:#fde8e8;color:#c0392b}
  .sum-badge.pass{background:#eafaf1;color:#27ae60}
  .sum-badge.total{background:var(--bg-hover);color:var(--text-muted)}
  .lp-results{flex:1;overflow:auto;padding:0 12px}
  table{width:100%;border-collapse:collapse}
  th{position:sticky;top:0;background:var(--bg-hover);padding:5px;border-bottom:1px solid var(--border);text-align:left;font-size:11px}
  td{padding:4px 5px;border-bottom:1px solid var(--border-light, #eee)}
  .verdict{padding:1px 6px;border-radius:8px;font-size:10px;font-weight:700}
  .v-pass{background:#eafaf1;color:#27ae60}
  .v-fail{background:#fde8e8;color:#c0392b}
  .v-inc{background:#fef9e6;color:#b7770d}
  .sev{padding:1px 6px;border-radius:8px;font-size:10px;font-weight:700}
  .s-crit{background:#fde8e8;color:#c0392b}
  .s-high{background:#fef0e6;color:#d35400}
  .s-med{background:#fef9e6;color:#b7770d}
  .s-low{background:#eafaf1;color:#27ae60}
  .s-info{background:#eaf4fb;color:#2980b9}
  .reason{font-size:11px;color:var(--text-muted)}
  .empty{padding:40px;text-align:center;color:var(--text-muted);font-style:italic}
</style>
