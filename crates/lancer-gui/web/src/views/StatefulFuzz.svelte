<script>
  import { onMount } from "svelte";

  let spec = "";
  let baseUrl = "";
  let authToken = "";
  let mode = "sequence";
  let maxSequences = 50;
  let sessions = [];
  let selected = null;
  let running = false;

  function sevClass(s) {
    return { critical: "s-crit", high: "s-high", medium: "s-med", low: "s-low", info: "s-info" }[s] || "s-info";
  }

  async function load() {
    try {
      const r = await fetch("/api/v1/stateful-fuzz/sessions");
      if (r.ok) sessions = await r.json();
    } catch {}
  }

  async function start() {
    if (!spec || !baseUrl) return;
    running = true;
    await fetch("/api/v1/stateful-fuzz/start", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({
        spec, base_url: baseUrl, auth_token: authToken || null,
        mode, max_sequences: maxSequences,
      }),
    });
    for (let i = 0; i < 60; i++) {
      await new Promise(r => setTimeout(r, 2000));
      await load();
    }
    running = false;
  }

  async function loadSpecFile(e) {
    const file = e.target.files[0];
    if (file) spec = await file.text();
  }

  onMount(load);
</script>

<div class="stateful">
  <div class="config">
    <h3>Stateful API fuzzer (RESTler-style)</h3>
    <div class="row">
      <label>OpenAPI / Swagger</label>
      <input type="file" on:change={loadSpecFile} accept=".json,.yaml,.yml" />
      <span class="dim">{spec ? `${spec.length.toLocaleString()} bytes loaded` : "no spec"}</span>
    </div>
    <div class="row">
      <label>Base URL</label>
      <input type="url" bind:value={baseUrl} placeholder="https://api.example.com" />
    </div>
    <div class="row">
      <label>Auth token</label>
      <input type="text" bind:value={authToken} placeholder="Bearer …" />
    </div>
    <div class="row">
      <label>Mode</label>
      <select bind:value={mode}>
        <option value="production_safe">Production-safe (GET-only)</option>
        <option value="sequence">Sequence</option>
        <option value="cluster_bomb">Cluster bomb</option>
        <option value="mutate_mid_sequence">Mutate mid-sequence</option>
      </select>
      <label>Max sequences <input type="number" bind:value={maxSequences} min="1" max="500" /></label>
    </div>
    <button on:click={start} disabled={!spec || !baseUrl || running} class="run">{running ? "Fuzzing…" : "Start fuzz"}</button>
  </div>

  <div class="results">
    <div class="sessions">
      <h4>Sessions ({sessions.length})</h4>
      {#each sessions as s (s.id)}
        <div class="sess-row" class:selected={selected?.id === s.id} on:click={() => selected = s}>
          <strong>{s.sequences_run} seqs</strong>
          <span class="dim">{s.ops.length} ops · {s.flaws.length} flaws</span>
          <span class="ts">{new Date(s.started_at).toLocaleTimeString()}</span>
        </div>
      {/each}
    </div>
    {#if selected}
      <div class="flaws">
        <h4>Flaws ({selected.flaws.length})</h4>
        {#each selected.flaws as f}
          <div class="flaw">
            <div class="flaw-head">
              <span class="kind">{f.kind}</span>
              <span class="sev {sevClass(f.severity)}">{f.severity}</span>
              <span class="dim">step {f.at_step}</span>
            </div>
            <p>{f.message}</p>
            <details>
              <summary>Sequence ({f.sequence.ops.length} steps)</summary>
              <ol>
                {#each f.sequence.ops as op}
                  <li><code>{op.method} {op.path}</code></li>
                {/each}
              </ol>
            </details>
          </div>
        {/each}
        {#if selected.flaws.length === 0}
          <div class="empty">No flaws found.</div>
        {/if}
      </div>
    {/if}
  </div>
</div>

<style>
  .stateful{display:flex;height:100%;font-size:13px}
  .config{width:380px;padding:12px;border-right:1px solid var(--border);overflow-y:auto;background:var(--bg-hover)}
  .config h3{margin:0 0 10px}
  .row{display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap}
  .row label{width:90px;font-size:11px;font-weight:600;color:var(--text-muted)}
  .row input,.row select{flex:1;padding:4px 8px}
  .row input[type="number"]{width:80px}
  .dim{color:var(--text-muted);font-size:11px}
  .run{background:var(--accent);color:white;border:none;border-radius:4px;padding:6px 14px;cursor:pointer;font-weight:600;width:100%;margin-top:6px}
  .run:disabled{opacity:0.5}
  .results{flex:1;display:flex;overflow:hidden}
  .sessions{width:240px;border-right:1px solid var(--border);overflow-y:auto;padding:8px}
  .sessions h4{margin:0 0 6px;color:var(--text-muted);font-size:12px}
  .sess-row{padding:6px;border:1px solid var(--border);border-radius:4px;margin-bottom:4px;cursor:pointer}
  .sess-row.selected{background:#e8f0fe;border-color:#1976d2}
  .ts{display:block;font-size:10px;color:var(--text-muted)}
  .flaws{flex:1;padding:10px;overflow-y:auto}
  .flaws h4{margin:0 0 8px;color:var(--text-muted);font-size:12px}
  .flaw{padding:8px;border:1px solid var(--border);border-radius:6px;margin-bottom:8px}
  .flaw-head{display:flex;gap:6px;align-items:center;margin-bottom:4px}
  .kind{background:#fde8e8;color:#c0392b;padding:1px 6px;border-radius:8px;font-size:10px;font-weight:700}
  .sev{padding:1px 6px;border-radius:8px;font-size:10px;font-weight:700}
  .s-crit{background:#fde8e8;color:#c0392b}
  .s-high{background:#fef0e6;color:#d35400}
  .s-med{background:#fef9e6;color:#b7770d}
  .s-low{background:#eafaf1;color:#27ae60}
  .s-info{background:#eaf4fb;color:#2980b9}
  .flaw p{margin:4px 0;font-size:12px}
  details{font-size:11px}
  ol{margin:4px 0 0 18px;padding:0}
  .empty{padding:30px;text-align:center;color:var(--text-muted);font-style:italic}
</style>
