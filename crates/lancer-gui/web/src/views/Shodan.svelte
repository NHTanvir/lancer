<script>
  let ip = "";
  let cve = "";
  let hostInfo = null;
  let cveInfo = null;
  let loading = false;

  async function lookupHost() {
    if (!ip) return;
    loading = true;
    try {
      const r = await fetch(`/api/v1/shodan/host/${encodeURIComponent(ip)}`);
      if (r.ok) hostInfo = await r.json();
      else hostInfo = { error: await r.text() };
    } catch (e) { hostInfo = { error: e.message }; }
    loading = false;
  }

  async function lookupCve() {
    if (!cve) return;
    loading = true;
    try {
      const r = await fetch(`/api/v1/shodan/cve/${encodeURIComponent(cve)}`);
      if (r.ok) cveInfo = await r.json();
      else cveInfo = { error: await r.text() };
    } catch (e) { cveInfo = { error: e.message }; }
    loading = false;
  }
</script>

<div class="shodan">
  <div class="lookup-card">
    <h3>Host lookup</h3>
    <div class="row">
      <input type="text" bind:value={ip} placeholder="1.1.1.1 or example.com" on:keydown={e => e.key === "Enter" && lookupHost()} />
      <button on:click={lookupHost} disabled={loading || !ip}>Lookup</button>
    </div>
    {#if hostInfo}
      {#if hostInfo.error}
        <pre class="err">{hostInfo.error}</pre>
      {:else}
        <div class="info">
          <div><strong>IP:</strong> {hostInfo.ip} <span class="src">via {hostInfo.source}</span></div>
          {#if hostInfo.org}<div><strong>Org:</strong> {hostInfo.org}</div>{/if}
          {#if hostInfo.country}<div><strong>Country:</strong> {hostInfo.country}</div>{/if}
          {#if hostInfo.os}<div><strong>OS:</strong> {hostInfo.os}</div>{/if}
          <div><strong>Hostnames:</strong> {hostInfo.hostnames.join(", ") || "—"}</div>
          <div><strong>Ports:</strong>
            {#each hostInfo.ports as p}<span class="port">{p}</span>{/each}
          </div>
          <div><strong>Tags:</strong>
            {#each hostInfo.tags as t}<span class="tag">{t}</span>{/each}
          </div>
          {#if hostInfo.vulns?.length}
            <div><strong>Vulns:</strong></div>
            <ul>
              {#each hostInfo.vulns as v}<li><code>{v}</code></li>{/each}
            </ul>
          {/if}
        </div>
      {/if}
    {/if}
  </div>

  <div class="lookup-card">
    <h3>CVE lookup</h3>
    <div class="row">
      <input type="text" bind:value={cve} placeholder="CVE-2021-44228" on:keydown={e => e.key === "Enter" && lookupCve()} />
      <button on:click={lookupCve} disabled={loading || !cve}>Lookup</button>
    </div>
    {#if cveInfo}
      {#if cveInfo.error}
        <pre class="err">{cveInfo.error}</pre>
      {:else}
        <div class="info">
          <div><strong>{cveInfo.cve}</strong>
            {#if cveInfo.kev}<span class="kev">KEV</span>{/if}
          </div>
          {#if cveInfo.summary}<p>{cveInfo.summary}</p>{/if}
          {#if cveInfo.cvss}<div><strong>CVSS:</strong> {cveInfo.cvss}</div>{/if}
          {#if cveInfo.cvss_v3}<div><strong>CVSS v3:</strong> {cveInfo.cvss_v3}</div>{/if}
          {#if cveInfo.epss}<div><strong>EPSS:</strong> {(cveInfo.epss * 100).toFixed(1)}%</div>{/if}
          {#if cveInfo.references?.length}
            <div><strong>References:</strong></div>
            <ul>
              {#each cveInfo.references.slice(0, 8) as r}
                <li><a href={r} target="_blank">{r}</a></li>
              {/each}
            </ul>
          {/if}
        </div>
      {/if}
    {/if}
  </div>
</div>

<style>
  .shodan{padding:14px;display:grid;grid-template-columns:1fr 1fr;gap:14px;height:100%;overflow:auto;font-size:13px}
  .lookup-card{background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:12px}
  .lookup-card h3{margin:0 0 8px;font-size:14px}
  .row{display:flex;gap:6px;margin-bottom:8px}
  .row input{flex:1;padding:5px 8px}
  .row button{background:#e03a00;color:white;border:none;padding:5px 12px;border-radius:4px;cursor:pointer;font-weight:600}
  .row button:disabled{opacity:0.5}
  .info > div{margin-bottom:4px}
  .info ul{margin:4px 0 0 18px;padding:0}
  .src{font-size:10px;background:#eaf4fb;color:#2980b9;padding:1px 6px;border-radius:8px;font-weight:700;margin-left:6px}
  .port{background:#fef0e6;color:#d35400;padding:1px 6px;border-radius:8px;font-size:10px;font-weight:700;margin-right:4px}
  .tag{background:#eaf4fb;color:#2980b9;padding:1px 6px;border-radius:8px;font-size:10px;font-weight:700;margin-right:4px}
  .kev{background:#c0392b;color:white;padding:1px 6px;border-radius:8px;font-size:10px;font-weight:700;margin-left:6px}
  .err{background:#fde8e8;color:#c0392b;padding:6px;border-radius:4px;font-size:11px}
</style>
