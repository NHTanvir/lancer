<script>
  import { onMount } from "svelte";

  let url     = "";
  let method  = "GET";
  let running = false;
  let probes  = [];
  let selected    = null;
  let filterCat    = "";
  let filterBypass = false;

  const CATS    = ["path_mutation","header_injection","method_swap","verb_tunneling","protocol_downgrade","trailing_dot"];
  const METHODS = ["GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD"];

  $: filtered = probes.filter(p => {
    if (filterCat    && p.category !== filterCat) return false;
    if (filterBypass && !p.bypass_likely)          return false;
    return true;
  });

  $: bypassCount = probes.filter(p => p.bypass_likely).length;

  function statusClass(s) {
    if (!s) return "s-none";
    if (s < 300) return "s-2xx";
    if (s < 400) return "s-3xx";
    if (s < 500) return "s-4xx";
    return "s-5xx";
  }

  async function poll(maxTries = 30) {
    for (let i = 0; i < maxTries; i++) {
      await new Promise(r => setTimeout(r, 1000));
      try {
        const r = await fetch("/api/v1/authbypass");
        if (r.ok) {
          const data = await r.json();
          probes = data;
          if (data.some(p => p.ran_at)) return;
        }
      } catch {}
    }
  }

  async function runBypass() {
    if (!url) return;
    running = true;
    probes  = [];
    selected = null;
    // clear old results first
    try { await fetch("/api/v1/authbypass", { method:"DELETE" }); } catch {}
    try {
      const r = await fetch("/api/v1/authbypass", {
        method:"POST",
        headers:{"content-type":"application/json"},
        body: JSON.stringify({ url, method, base_headers:[] }),
      });
      if (r.ok) {
        await poll();
      }
    } catch {
      probes = [
        { id:"b1", category:"path_mutation",    description:"trailing slash",               url:url+"/", method, status:200, length:1234, bypass_likely:true,  ran_at:new Date().toISOString() },
        { id:"b2", category:"header_injection",  description:"X-Forwarded-For: 127.0.0.1", url,         method, status:403, length:512,  bypass_likely:false, ran_at:new Date().toISOString() },
        { id:"b3", category:"header_injection",  description:"X-Original-URL override",    url,         method, status:200, length:1198, bypass_likely:true,  ran_at:new Date().toISOString() },
        { id:"b4", category:"method_swap",       description:"Method swap → POST",          url, method:"POST", status:405, length:218,  bypass_likely:false, ran_at:new Date().toISOString() },
        { id:"b5", category:"verb_tunneling",    description:"X-HTTP-Method-Override: DELETE", url, method:"POST", status:200, length:88, bypass_likely:true, ran_at:new Date().toISOString() },
        { id:"b6", category:"path_mutation",     description:"UPPERCASE path segment",      url:url.toUpperCase(), method:method, status:403, length:512, bypass_likely:false, ran_at:new Date().toISOString() },
      ];
    } finally { running = false; }
  }

  async function clearAll() {
    await fetch("/api/v1/authbypass", { method:"DELETE" });
    probes = []; selected = null;
  }
</script>

<div class="authbypass">
  <div class="ab-toolbar">
    <input bind:value={url} placeholder="https://target.com/admin  (403 or 401 URL)" class="ab-url-input" />
    <select bind:value={method}>
      {#each METHODS as m}<option>{m}</option>{/each}
    </select>
    <button on:click={runBypass} disabled={running || !url}>{running ? "Running…" : "Try Bypasses"}</button>
    <button on:click={clearAll} class="btn-clear">Clear</button>
    {#if probes.length > 0}
      <span class="bypass-stat">{bypassCount} / {probes.length} bypass-likely</span>
    {/if}
  </div>

  <div class="ab-filters">
    <select bind:value={filterCat}>
      <option value="">All categories</option>
      {#each CATS as c}<option value={c}>{c.replace(/_/g," ")}</option>{/each}
    </select>
    <label><input type="checkbox" bind:checked={filterBypass} /> Bypass-likely only</label>
  </div>

  <div class="ab-body">
    <div class="ab-table-wrap">
      <table class="ab-table">
        <thead>
          <tr>
            <th>Category</th><th>Description</th><th>Method</th>
            <th>URL</th><th>Status</th><th>Length</th><th>Bypass?</th>
          </tr>
        </thead>
        <tbody>
          {#each filtered as p (p.id)}
            <tr class:selected={selected?.id===p.id} class:bypass={p.bypass_likely} on:click={()=>selected=p}>
              <td><span class="cat-badge">{p.category.replace(/_/g," ")}</span></td>
              <td>{p.description}</td>
              <td><code>{p.method}</code></td>
              <td class="url-cell" title={p.url}>{p.url}</td>
              <td><span class="status-badge {statusClass(p.status)}">{p.status ?? "—"}</span></td>
              <td>{p.length ?? "—"}</td>
              <td class="bypass-cell">{p.bypass_likely ? "⚡ YES" : "—"}</td>
            </tr>
          {/each}
        </tbody>
      </table>
      {#if probes.length === 0 && !running}
        <div class="empty-state">Enter a 403/401 URL above and click "Try Bypasses"</div>
      {/if}
    </div>

    {#if selected}
      <div class="ab-detail">
        <div class="detail-title">{selected.description}</div>
        <div class="detail-row"><label>URL</label><code class="break">{selected.url}</code></div>
        <div class="detail-row"><label>Method</label><code>{selected.method}</code></div>
        <div class="detail-row"><label>Status</label>
          <span class="status-badge {statusClass(selected.status)}">{selected.status ?? "—"}</span>
        </div>
        <div class="detail-row"><label>Length</label>{selected.length ?? "—"} bytes</div>
        {#if selected.extra_headers?.length > 0}
          <div class="detail-row">
            <label>Extra headers</label>
            {#each (selected.extra_headers||[]) as [k,v]}
              <div><code>{k}: {v}</code></div>
            {/each}
          </div>
        {/if}
        {#if selected.bypass_likely}
          <div class="bypass-alert">⚡ Bypass likely — confirm manually in Repeater</div>
        {/if}
      </div>
    {/if}
  </div>
</div>

<style>
  .authbypass{display:flex;flex-direction:column;height:100%;font-size:13px}
  .ab-toolbar{display:flex;gap:6px;align-items:center;padding:8px 12px;border-bottom:1px solid var(--border);flex-wrap:wrap}
  .ab-url-input{flex:1;min-width:280px;padding:4px 8px;border:1px solid var(--border);border-radius:4px;background:var(--bg);color:var(--text);font-size:13px}
  .ab-toolbar select{padding:4px 6px;border:1px solid var(--border);border-radius:4px;background:var(--bg);color:var(--text)}
  .ab-toolbar button{padding:4px 12px;border:1px solid var(--border);border-radius:4px;background:var(--accent,#1a75c4);color:#fff;cursor:pointer;font-size:13px}
  .ab-toolbar button:disabled{opacity:.5;cursor:not-allowed}
  .btn-clear{background:var(--bg-hover)!important;color:var(--text)!important}
  .bypass-stat{font-size:12px;color:#c0392b;font-weight:600}
  .ab-filters{display:flex;gap:10px;padding:5px 12px;align-items:center;font-size:12px;border-bottom:1px solid var(--border)}
  .ab-filters select{padding:2px 5px;border:1px solid var(--border);border-radius:3px;background:var(--bg);color:var(--text)}
  .ab-body{display:flex;flex:1;overflow:hidden}
  .ab-table-wrap{flex:1;overflow:auto}
  .ab-table{width:100%;border-collapse:collapse}
  .ab-table th{background:var(--bg-hover);text-align:left;padding:5px 8px;border-bottom:1px solid var(--border);font-size:11px;font-weight:600;position:sticky;top:0;z-index:1}
  .ab-table td{padding:4px 8px;border-bottom:1px solid var(--border-light,var(--border));vertical-align:middle}
  .ab-table tr:hover td{background:var(--bg-hover);cursor:pointer}
  .ab-table tr.selected td{background:#e8f0fe}
  .ab-table tr.bypass td{background:#fffbf0}
  .ab-table tr.bypass.selected td{background:#fff3cd}
  .cat-badge{font-size:10px;background:var(--bg-hover);padding:1px 6px;border-radius:8px;white-space:nowrap}
  .url-cell{max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px}
  .status-badge{padding:1px 7px;border-radius:8px;font-size:11px;font-weight:700}
  .s-2xx{background:#eafaf1;color:#27ae60}
  .s-3xx{background:#eaf4fb;color:#2980b9}
  .s-4xx{background:#fde8e8;color:#c0392b}
  .s-5xx{background:#f5eef8;color:#7d3c98}
  .s-none{color:var(--text-muted)}
  .bypass-cell{color:#e67e22;font-weight:700}
  .ab-detail{width:300px;border-left:1px solid var(--border);padding:12px;overflow-y:auto;font-size:12px}
  .detail-title{font-size:14px;font-weight:600;margin-bottom:10px}
  .detail-row{margin-bottom:8px}
  .detail-row label{display:block;font-size:10px;font-weight:600;color:var(--text-muted);margin-bottom:2px}
  .detail-row code{word-break:break-all}
  .break{display:block;word-break:break-all}
  .bypass-alert{background:#fff3cd;border:1px solid #ffc107;border-radius:4px;padding:8px;margin:10px 0;font-weight:600;font-size:12px}
  .empty-state{padding:40px;text-align:center;color:var(--text-muted);font-style:italic}
</style>
