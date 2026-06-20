<script>
  import { onMount } from "svelte";

  let findings = [];
  let loading   = false;
  let selected  = null;
  let filterSev    = "";
  let filterKind   = "";
  let filterSearch = "";

  const KINDS = [
    "aws_access_key","aws_secret_key","gcp_service_account","azure_token",
    "git_hub_pat","git_lab_token","slack_token","stripe_live_key","twilio_sid",
    "send_grid_key","mailgun_key","open_ai_key","anthropic_key","jwt",
    "pem_private_key","ssh_private_key","generic_high_entropy",
  ];
  const SEVS = ["Critical","High","Medium","Low","Info"];

  function sevClass(s) {
    return {Critical:"sev-critical",High:"sev-high",Medium:"sev-medium",Low:"sev-low",Info:"sev-info"}[s] || "sev-info";
  }

  $: filtered = findings.filter(f => {
    if (filterSev    && f.severity !== filterSev)  return false;
    if (filterKind   && f.kind     !== filterKind) return false;
    if (filterSearch && !JSON.stringify(f).toLowerCase().includes(filterSearch.toLowerCase())) return false;
    return true;
  });

  $: critCount     = findings.filter(f => f.severity === "Critical").length;
  $: highCount     = findings.filter(f => f.severity === "High").length;
  $: verifiedCount = findings.filter(f => f.verified).length;

  function mask(v) {
    if (!v || v.length <= 8) return v;
    return v.slice(0, 4) + "••••••••" + v.slice(-4);
  }

  async function load() {
    loading = true;
    try {
      const r = await fetch("/api/v1/secrets");
      if (r.ok) findings = await r.json();
    } catch {
      findings = [
        { id:"s1", kind:"aws_access_key",       severity:"Critical", confidence:0.99, url:"https://target.com/js/app.bundle.js", snippet:'const KEY = "AKIAIOSFODNN7EXAMPLE"', raw_value:"AKIAIOSFODNN7EXAMPLE", verified:false, found_at:new Date().toISOString() },
        { id:"s2", kind:"anthropic_key",         severity:"Critical", confidence:0.99, url:"https://target.com/api/config",        snippet:'sk-ant-api03-XXXXXXXXXXXXX',           raw_value:"sk-ant-api03-XXXX",         verified:true,  found_at:new Date().toISOString() },
        { id:"s3", kind:"jwt",                   severity:"High",     confidence:0.97, url:"https://target.com/dashboard",         snippet:'Bearer eyJhbGciOiJIUzI1NiIs…',       raw_value:"eyJhbGci…",                 verified:false, found_at:new Date().toISOString() },
        { id:"s4", kind:"generic_high_entropy",  severity:"Medium",   confidence:0.61, url:"https://target.com/static/config.js", snippet:'"api_token":"dK9mN3pQ7rS1vX2wZ4"', raw_value:"dK9mN3pQ7rS1vX2wZ4",       verified:false, found_at:new Date().toISOString() },
      ];
    } finally { loading = false; }
  }

  async function clearAll() {
    await fetch("/api/v1/secrets", { method:"DELETE" });
    findings = []; selected = null;
  }

  onMount(load);
</script>

<div class="secret-scanner">
  <div class="ss-header">
    <div class="ss-stats">
      <span class="stat-badge critical">{critCount} Critical</span>
      <span class="stat-badge high">{highCount} High</span>
      <span class="stat-badge verified">{verifiedCount} Verified live</span>
      <span class="stat-badge total">{findings.length} Total</span>
    </div>
    <div class="ss-toolbar">
      <select bind:value={filterSev}>
        <option value="">All severities</option>
        {#each SEVS as s}<option>{s}</option>{/each}
      </select>
      <select bind:value={filterKind}>
        <option value="">All types</option>
        {#each KINDS as k}<option value={k}>{k.replace(/_/g," ")}</option>{/each}
      </select>
      <input type="search" bind:value={filterSearch} placeholder="Search…" />
      <button on:click={load} disabled={loading}>Refresh</button>
      <button on:click={clearAll} class="btn-danger">Clear all</button>
    </div>
  </div>

  <div class="ss-body">
    <div class="ss-table-wrap">
      <table class="ss-table">
        <thead>
          <tr>
            <th>Type</th><th>Severity</th><th>Conf.</th>
            <th>URL</th><th>Snippet</th><th>Verified</th><th>Found</th>
          </tr>
        </thead>
        <tbody>
          {#each filtered as f (f.id)}
            <tr class:selected={selected?.id===f.id} on:click={()=>selected=f}>
              <td><code>{f.kind.replace(/_/g," ")}</code></td>
              <td><span class="sev-badge {sevClass(f.severity)}">{f.severity}</span></td>
              <td>{Math.round((f.confidence||0)*100)}%</td>
              <td class="url-cell" title={f.url}>{f.url}</td>
              <td class="snippet-cell"><code>{(f.snippet||"").slice(0,60)}</code></td>
              <td>{f.verified ? "✅ live" : "—"}</td>
              <td>{f.found_at ? new Date(f.found_at).toLocaleTimeString() : ""}</td>
            </tr>
          {/each}
        </tbody>
      </table>
      {#if filtered.length === 0 && !loading}
        <div class="empty-state">No secrets found yet — detected automatically from proxy traffic.</div>
      {/if}
    </div>

    {#if selected}
      <div class="ss-detail">
        <div class="detail-header">
          <strong>{selected.kind.replace(/_/g," ")}</strong>
          <span class="sev-badge {sevClass(selected.severity)}">{selected.severity}</span>
          {#if selected.verified}<span class="verified-badge">✅ VERIFIED LIVE</span>{/if}
        </div>
        <div class="detail-row"><label>URL</label><code>{selected.url}</code></div>
        <div class="detail-row"><label>Value (masked)</label><code>{mask(selected.raw_value)}</code></div>
        <div class="detail-row"><label>Confidence</label>{Math.round((selected.confidence||0)*100)}%</div>
        <div class="detail-row"><label>Snippet</label><pre>{selected.snippet}</pre></div>
        <div class="detail-actions">
          <button on:click={()=>navigator.clipboard?.writeText(selected.raw_value)}>Copy raw value</button>
        </div>
      </div>
    {/if}
  </div>
</div>

<style>
  .secret-scanner{display:flex;flex-direction:column;height:100%;font-size:13px}
  .ss-header{padding:8px 12px;border-bottom:1px solid var(--border);display:flex;flex-direction:column;gap:6px}
  .ss-stats{display:flex;gap:8px;flex-wrap:wrap}
  .stat-badge{padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600}
  .stat-badge.critical{background:#fde8e8;color:#c0392b}
  .stat-badge.high{background:#fef3e6;color:#d35400}
  .stat-badge.verified{background:#eafaf1;color:#27ae60}
  .stat-badge.total{background:var(--bg-hover);color:var(--text-muted)}
  .ss-toolbar{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
  .ss-toolbar select,.ss-toolbar input{padding:3px 6px;border:1px solid var(--border);border-radius:4px;background:var(--bg);color:var(--text);font-size:12px}
  .ss-toolbar button{padding:3px 10px;border:1px solid var(--border);border-radius:4px;background:var(--bg-hover);color:var(--text);cursor:pointer;font-size:12px}
  .btn-danger{background:#fde8e8!important;color:#c0392b!important;border-color:#e74c3c!important}
  .ss-body{display:flex;flex:1;overflow:hidden}
  .ss-table-wrap{flex:1;overflow:auto}
  .ss-table{width:100%;border-collapse:collapse}
  .ss-table th{background:var(--bg-hover);text-align:left;padding:5px 8px;border-bottom:1px solid var(--border);font-size:11px;font-weight:600;position:sticky;top:0;z-index:1}
  .ss-table td{padding:4px 8px;border-bottom:1px solid var(--border-light,var(--border));vertical-align:top}
  .ss-table tr:hover td{background:var(--bg-hover);cursor:pointer}
  .ss-table tr.selected td{background:#e8f0fe}
  .url-cell{max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .snippet-cell{max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .sev-badge{padding:1px 6px;border-radius:8px;font-size:10px;font-weight:700;white-space:nowrap}
  .sev-critical{background:#fde8e8;color:#c0392b}
  .sev-high{background:#fef0e6;color:#d35400}
  .sev-medium{background:#fef9e6;color:#b7770d}
  .sev-low{background:#eafaf1;color:#27ae60}
  .sev-info{background:#eaf4fb;color:#2980b9}
  .verified-badge{background:#eafaf1;color:#27ae60;font-size:11px;padding:2px 8px;border-radius:8px;font-weight:600}
  .ss-detail{width:320px;border-left:1px solid var(--border);padding:12px;overflow-y:auto}
  .detail-header{display:flex;gap:8px;align-items:center;margin-bottom:12px;font-size:14px;flex-wrap:wrap}
  .detail-row{margin-bottom:8px}
  .detail-row label{display:block;font-size:10px;font-weight:600;color:var(--text-muted);margin-bottom:2px}
  .detail-row code{word-break:break-all;font-size:12px}
  .detail-row pre{margin:0;background:var(--bg-hover);padding:6px;border-radius:4px;overflow:auto;max-height:150px;font-size:11px;white-space:pre-wrap;word-break:break-all}
  .detail-actions{display:flex;gap:6px;margin-top:10px}
  .detail-actions button{padding:4px 10px;border:1px solid var(--border);border-radius:4px;background:var(--bg-hover);color:var(--text);cursor:pointer;font-size:12px}
  .empty-state{padding:40px;text-align:center;color:var(--text-muted);font-style:italic}
</style>
