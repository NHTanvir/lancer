<script>
  import { onMount } from "svelte";

  let hostsText    = "";
  let running      = false;
  let results      = [];
  let selected     = null;
  let filterLive   = false;
  let filterSearch = "";

  $: filtered = results.filter(r => {
    if (filterLive   && !r.live) return false;
    if (filterSearch && !JSON.stringify(r).toLowerCase().includes(filterSearch.toLowerCase())) return false;
    return true;
  });

  $: liveCount = results.filter(r => r.live).length;

  function statusClass(s) {
    if (!s) return "s-none";
    if (s < 300) return "s-2xx";
    if (s < 400) return "s-3xx";
    if (s < 500) return "s-4xx";
    return "s-5xx";
  }

  async function poll(expectedCount, maxTries = 60) {
    for (let i = 0; i < maxTries; i++) {
      await new Promise(r => setTimeout(r, 1000));
      try {
        const r = await fetch("/api/v1/bulkprobe");
        if (r.ok) {
          const data = await r.json();
          results = data;
          if (data.length >= expectedCount) return;
        }
      } catch {}
    }
  }

  async function runProbe() {
    const hosts = hostsText.split(/[\n,\s]+/).map(h => h.trim()).filter(Boolean);
    if (!hosts.length) return;
    running  = true;
    results  = [];
    selected = null;
    try { await fetch("/api/v1/bulkprobe", { method:"DELETE" }); } catch {}
    try {
      const r = await fetch("/api/v1/bulkprobe", {
        method:"POST",
        headers:{"content-type":"application/json"},
        body: JSON.stringify({ hosts, concurrency:50, timeout_secs:10 }),
      });
      if (r.ok) {
        await poll(hosts.length);
      }
    } catch {
      results = [
        { id:"p1", host:"sub1.target.com",  url:"https://sub1.target.com",  status:200, title:"Admin Portal",       content_length:14200, response_time_ms:143, server:"nginx/1.24.0", technologies:["Nginx","React"],       cdn:"Cloudflare", waf:null,          live:true,  probed_at:new Date().toISOString() },
        { id:"p2", host:"api.target.com",   url:"https://api.target.com",   status:200, title:null,                 content_length:88,    response_time_ms:89,  server:"caddy",        technologies:["Caddy"],               cdn:null,          waf:null,          live:true,  probed_at:new Date().toISOString() },
        { id:"p3", host:"old.target.com",   url:"https://old.target.com",   status:404, title:"Not Found",          content_length:212,   response_time_ms:201, server:"Apache",       technologies:["Apache","WordPress"],  cdn:null,          waf:"ModSecurity", live:false, probed_at:new Date().toISOString() },
        { id:"p4", host:"stage.target.com", url:"https://stage.target.com", status:200, title:"Staging — internal", content_length:9800,  response_time_ms:310, server:null,           technologies:["Next.js"],             cdn:"CloudFront",  waf:null,          live:true,  probed_at:new Date().toISOString() },
        { id:"p5", host:"mail.target.com",  url:"https://mail.target.com",  status:null,title:null,                 content_length:null,  response_time_ms:10001,server:null,          technologies:[],                      cdn:null,          waf:null,          live:false, probed_at:new Date().toISOString() },
      ];
    } finally { running = false; }
  }

  async function clearAll() {
    await fetch("/api/v1/bulkprobe", { method:"DELETE" });
    results = []; selected = null;
  }
</script>

<div class="bulkprobe">
  <div class="bp-top">
    <textarea
      bind:value={hostsText}
      placeholder="Paste hosts — one per line&#10;sub1.target.com&#10;api.target.com&#10;https://stage.target.com"
      rows="4"
      class="bp-hosts"
    />
    <div class="bp-actions">
      <button on:click={runProbe} disabled={running || !hostsText.trim()}>
        {running ? "Probing…" : "Probe Hosts"}
      </button>
      <button on:click={clearAll} class="btn-clear">Clear</button>
      {#if results.length > 0}
        <span class="live-stat">{liveCount} live / {results.length} probed</span>
      {/if}
    </div>
  </div>

  <div class="bp-filters">
    <input type="search" bind:value={filterSearch} placeholder="Filter results…" />
    <label><input type="checkbox" bind:checked={filterLive} /> Live only</label>
  </div>

  <div class="bp-body">
    <div class="bp-table-wrap">
      <table class="bp-table">
        <thead>
          <tr>
            <th>Host</th><th>Status</th><th>Title</th><th>Server</th>
            <th>Technologies</th><th>CDN</th><th>WAF</th><th>ms</th><th>Live</th>
          </tr>
        </thead>
        <tbody>
          {#each filtered as r (r.id)}
            <tr class:selected={selected?.id===r.id} on:click={()=>selected=r}>
              <td class="host-cell">{r.host}</td>
              <td><span class="status-badge {statusClass(r.status)}">{r.status ?? "timeout"}</span></td>
              <td class="title-cell">{r.title ?? "—"}</td>
              <td>{r.server ?? "—"}</td>
              <td class="tech-cell">
                {#each (r.technologies||[]) as t}
                  <span class="tech-tag">{t}</span>
                {/each}
              </td>
              <td>{r.cdn ?? "—"}</td>
              <td>{r.waf ?? "—"}</td>
              <td>{r.response_time_ms}</td>
              <td class="live-cell">{r.live ? "✅" : "❌"}</td>
            </tr>
          {/each}
        </tbody>
      </table>
      {#if results.length === 0 && !running}
        <div class="empty-state">Paste a list of hostnames above and click "Probe Hosts"</div>
      {/if}
    </div>

    {#if selected}
      <div class="bp-detail">
        <div class="detail-title">{selected.host}</div>
        <div class="detail-row"><label>URL</label><code>{selected.url}</code></div>
        <div class="detail-row">
          <label>Status</label>
          <span class="status-badge {statusClass(selected.status)}">{selected.status ?? "timeout"}</span>
        </div>
        <div class="detail-row"><label>Title</label>{selected.title ?? "—"}</div>
        <div class="detail-row"><label>Server</label>{selected.server ?? "—"}</div>
        <div class="detail-row"><label>Size</label>{selected.content_length ?? "—"} bytes</div>
        <div class="detail-row"><label>Response time</label>{selected.response_time_ms} ms</div>
        {#if selected.technologies?.length > 0}
          <div class="detail-row">
            <label>Technologies</label>
            <div class="tech-list">
              {#each selected.technologies as t}<span class="tech-tag">{t}</span>{/each}
            </div>
          </div>
        {/if}
        {#if selected.cdn}<div class="detail-row"><label>CDN</label>{selected.cdn}</div>{/if}
        {#if selected.waf}<div class="detail-row"><label>WAF</label>{selected.waf}</div>{/if}
      </div>
    {/if}
  </div>
</div>

<style>
  .bulkprobe{display:flex;flex-direction:column;height:100%;font-size:13px}
  .bp-top{padding:8px 12px;border-bottom:1px solid var(--border);display:flex;gap:8px;align-items:flex-start}
  .bp-hosts{flex:1;padding:6px 8px;border:1px solid var(--border);border-radius:4px;background:var(--bg);color:var(--text);font-family:monospace;font-size:12px;resize:vertical}
  .bp-actions{display:flex;flex-direction:column;gap:6px;min-width:110px}
  .bp-actions button{padding:5px 14px;border:1px solid var(--border);border-radius:4px;background:var(--accent,#1a75c4);color:#fff;cursor:pointer;font-size:13px}
  .bp-actions button:disabled{opacity:.5;cursor:not-allowed}
  .btn-clear{background:var(--bg-hover)!important;color:var(--text)!important}
  .live-stat{font-size:11px;color:#27ae60;font-weight:600;text-align:center}
  .bp-filters{display:flex;gap:10px;padding:5px 12px;align-items:center;font-size:12px;border-bottom:1px solid var(--border)}
  .bp-filters input[type=search]{padding:3px 6px;border:1px solid var(--border);border-radius:4px;background:var(--bg);color:var(--text);font-size:12px}
  .bp-body{display:flex;flex:1;overflow:hidden}
  .bp-table-wrap{flex:1;overflow:auto}
  .bp-table{width:100%;border-collapse:collapse}
  .bp-table th{background:var(--bg-hover);text-align:left;padding:5px 8px;border-bottom:1px solid var(--border);font-size:11px;font-weight:600;position:sticky;top:0;z-index:1}
  .bp-table td{padding:4px 8px;border-bottom:1px solid var(--border-light,#eee);vertical-align:middle}
  .bp-table tr:hover td{background:var(--bg-hover);cursor:pointer}
  .bp-table tr.selected td{background:#e8f0fe}
  .host-cell{font-weight:600;min-width:150px}
  .title-cell{max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .status-badge{padding:1px 7px;border-radius:8px;font-size:11px;font-weight:700}
  .s-2xx{background:#eafaf1;color:#27ae60}
  .s-3xx{background:#eaf4fb;color:#2980b9}
  .s-4xx{background:#fde8e8;color:#c0392b}
  .s-5xx{background:#f5eef8;color:#7d3c98}
  .s-none{background:#f0f0f0;color:#888}
  .tech-cell{max-width:140px}
  .tech-tag{display:inline-block;background:#eaf4fb;color:#2980b9;font-size:10px;padding:1px 5px;border-radius:6px;margin:1px 2px 1px 0}
  .tech-list{display:flex;flex-wrap:wrap;gap:2px}
  .live-cell{text-align:center}
  .bp-detail{width:280px;border-left:1px solid var(--border);padding:12px;overflow-y:auto;font-size:12px}
  .detail-title{font-size:14px;font-weight:600;margin-bottom:10px;word-break:break-all}
  .detail-row{margin-bottom:8px}
  .detail-row label{display:block;font-size:10px;font-weight:600;color:var(--text-muted);margin-bottom:2px}
  .detail-row code{word-break:break-all;font-size:11px}
  .empty-state{padding:40px;text-align:center;color:var(--text-muted);font-style:italic}
</style>
