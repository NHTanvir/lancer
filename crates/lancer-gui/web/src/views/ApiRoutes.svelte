<script>
  import { onMount } from "svelte";

  let baseUrl = "";
  let authHeader = "";
  let concurrency = 50;
  let running = false;
  let results = [];
  let filter = "";
  let onlyInteresting = false;

  $: filtered = results.filter(r => {
    if (onlyInteresting && !r.interesting) return false;
    if (filter && !JSON.stringify(r).toLowerCase().includes(filter.toLowerCase())) return false;
    return true;
  });

  $: discoveredCount = results.filter(r => r.interesting).length;

  function statusClass(s) {
    if (!s) return "s-none";
    if (s < 300) return "s-2xx";
    if (s < 400) return "s-3xx";
    if (s < 500) return "s-4xx";
    return "s-5xx";
  }

  async function load() {
    try {
      const r = await fetch("/api/v1/api-routes");
      if (r.ok) results = await r.json();
    } catch {}
  }

  async function run() {
    if (!baseUrl) return;
    running = true;
    try { await fetch("/api/v1/api-routes", { method: "DELETE" }); } catch {}
    const body = {
      base_url: baseUrl,
      concurrency,
      methods: ["GET", "POST", "PUT", "DELETE"],
    };
    if (authHeader) body.auth_header = authHeader;
    try {
      await fetch("/api/v1/api-routes", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      });
      for (let i = 0; i < 30; i++) {
        await new Promise(r => setTimeout(r, 1500));
        await load();
      }
    } catch {}
    running = false;
  }

  async function clearAll() {
    await fetch("/api/v1/api-routes", { method: "DELETE" });
    results = [];
  }

  onMount(load);
</script>

<div class="api-routes">
  <div class="ar-toolbar">
    <input type="url" bind:value={baseUrl} placeholder="https://api.example.com" class="url-input" />
    <input type="text" bind:value={authHeader} placeholder="Authorization: Bearer …" class="auth-input" />
    <input type="number" bind:value={concurrency} min="1" max="500" class="num-input" />
    <button on:click={run} disabled={running || !baseUrl} class="run-btn">{running ? "Running…" : "Discover"}</button>
    <label class="toggle">
      <input type="checkbox" bind:checked={onlyInteresting} /> Interesting only
    </label>
    <input type="search" bind:value={filter} placeholder="Filter…" class="filter-input" />
    <span class="stat-badge">{discoveredCount} / {results.length}</span>
    <button on:click={clearAll} class="btn-danger">Clear</button>
  </div>

  <div class="ar-body">
    <table class="ar-table">
      <thead>
        <tr><th>Method</th><th>URL</th><th>Status</th><th>Length</th><th>Content-Type</th><th>Found</th></tr>
      </thead>
      <tbody>
        {#each filtered as r (r.id)}
          <tr class:hit={r.interesting}>
            <td><code class="method">{r.method}</code></td>
            <td class="url-cell">{r.url}</td>
            <td><span class="status {statusClass(r.status)}">{r.status}</span></td>
            <td>{r.length || 0}</td>
            <td><code>{r.content_type || "—"}</code></td>
            <td>{new Date(r.discovered_at).toLocaleTimeString()}</td>
          </tr>
        {/each}
      </tbody>
    </table>
    {#if filtered.length === 0 && !running}
      <div class="empty">No routes yet. Enter a base URL and click Discover.</div>
    {/if}
  </div>
</div>

<style>
  .api-routes{display:flex;flex-direction:column;height:100%;font-size:13px}
  .ar-toolbar{padding:8px 12px;border-bottom:1px solid var(--border);display:flex;gap:6px;align-items:center;flex-wrap:wrap}
  .url-input{flex:1;min-width:220px;padding:4px 8px}
  .auth-input{flex:0.6;min-width:140px}
  .num-input{width:70px}
  .run-btn{background:var(--accent);color:white;padding:5px 14px;border:none;border-radius:4px;cursor:pointer;font-weight:600}
  .run-btn:disabled{opacity:0.5}
  .toggle{display:flex;align-items:center;gap:4px;font-size:11px}
  .filter-input{width:160px}
  .stat-badge{padding:2px 8px;border-radius:10px;background:var(--bg-hover);font-size:11px;font-weight:600}
  .btn-danger{background:#fde8e8;color:#c0392b;border:1px solid #e74c3c}
  .ar-body{flex:1;overflow:auto}
  .ar-table{width:100%;border-collapse:collapse}
  .ar-table th{background:var(--bg-hover);text-align:left;padding:5px 8px;border-bottom:1px solid var(--border);font-size:11px;position:sticky;top:0;z-index:1}
  .ar-table td{padding:4px 8px;border-bottom:1px solid var(--border-light, var(--border))}
  .ar-table tr:hover td{background:var(--bg-hover)}
  .ar-table tr.hit td{background:#fff7e6}
  .method{font-weight:600;color:var(--accent)}
  .url-cell{max-width:380px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:monospace}
  .status{padding:1px 6px;border-radius:8px;font-size:10px;font-weight:700}
  .s-2xx{background:#eafaf1;color:#27ae60}
  .s-3xx{background:#eaf4fb;color:#2980b9}
  .s-4xx{background:#fef9e6;color:#b7770d}
  .s-5xx{background:#fde8e8;color:#c0392b}
  .s-none{background:var(--border);color:#666}
  .empty{padding:40px;text-align:center;color:var(--text-muted);font-style:italic}
</style>
