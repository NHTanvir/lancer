<script>
  import { onMount, onDestroy } from "svelte";

  let status = { running: false, domain: "", dns: null, http: null, smtp: null, interaction_count: 0, payload_count: 0 };
  let config = { domain: "oast.lancer.local", bind_ip: "0.0.0.0", dns_port: 15353, http_port: 8088, smtp_port: 1825, answer_ip: "127.0.0.1", enable_dns: true, enable_http: true, enable_smtp: false };
  let interactions = [];
  let payloads = [];
  let lastPayload = null;
  let filter = "all"; // all | dns | http | smtp
  let autoPoll = true;
  let pollTimer;
  let busy = false;
  let showConfig = false;

  $: filtered = interactions.filter(i => filter === "all" || i.kind === filter);

  async function loadStatus() {
    try {
      const r = await fetch("/api/v1/collaborator/status");
      if (r.ok) status = await r.json();
    } catch {}
  }

  async function loadConfig() {
    try {
      const r = await fetch("/api/v1/collaborator/config");
      if (r.ok) config = await r.json();
    } catch {}
  }

  async function loadInteractions() {
    try {
      const r = await fetch("/api/v1/collaborator/interactions");
      if (r.ok) interactions = (await r.json()).slice().reverse();
    } catch {}
  }

  async function loadPayloads() {
    try {
      const r = await fetch("/api/v1/collaborator/payloads");
      if (r.ok) payloads = await r.json();
    } catch {}
  }

  async function refresh() {
    await loadStatus();
    if (status.running || interactions.length) await loadInteractions();
  }

  async function saveConfig() {
    busy = true;
    try {
      await fetch("/api/v1/collaborator/config", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          ...config,
          dns_port: +config.dns_port, http_port: +config.http_port, smtp_port: +config.smtp_port,
        }),
      });
      await loadStatus();
    } catch {}
    busy = false;
  }

  async function startServer() {
    busy = true;
    await saveConfig();
    try {
      const r = await fetch("/api/v1/collaborator/server/start", { method: "POST" });
      status = await r.json();
    } catch {}
    busy = false;
  }

  async function stopServer() {
    busy = true;
    try {
      const r = await fetch("/api/v1/collaborator/server/stop", { method: "POST" });
      status = await r.json();
    } catch {}
    busy = false;
  }

  async function generate() {
    try {
      const r = await fetch("/api/v1/collaborator/generate", { method: "POST" });
      if (r.ok) {
        lastPayload = await r.json();
        navigator.clipboard.writeText(lastPayload.host).catch(() => {});
        await loadPayloads();
        await loadStatus();
      }
    } catch {}
  }

  async function clearInteractions() {
    if (!confirm("Clear all recorded interactions?")) return;
    try {
      await fetch("/api/v1/collaborator/interactions", { method: "DELETE" });
      interactions = [];
      await loadStatus();
    } catch {}
  }

  // §6 OOB/SSRF scan correlated through the OAST server.
  let oobOpen = false;
  let oobRequest = `GET /fetch?url=https://example.com HTTP/1.1\r\nHost: target.example\r\n\r\n`;
  let oobScheme = "https", oobHost = "target.example", oobPort = 443;
  let oobResult = null, oobBusy = false;
  async function runOob() {
    oobBusy = true; oobResult = null;
    try {
      const r = await fetch("/api/v1/scan/oob", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ request: oobRequest, scheme: oobScheme, host: oobHost, port: +oobPort }),
      });
      oobResult = await r.json();
      await refresh();
    } catch (e) { oobResult = { ok: false, error: String(e) }; }
    finally { oobBusy = false; }
  }

  function copy(text) { navigator.clipboard.writeText(text || "").catch(() => {}); }
  function fmtTime(t) { try { return new Date(t).toLocaleTimeString(); } catch { return t; } }
  function rawSummary(i) {
    const r = i.raw || {};
    if (i.kind === "dns") return `qtype=${r.qtype}`;
    if (i.kind === "http") return `${r.method || ""} ${r.path || ""}`;
    if (i.kind === "smtp") return (r.recipients || []).join(", ");
    return "";
  }

  onMount(() => {
    loadStatus(); loadConfig(); loadInteractions(); loadPayloads();
    pollTimer = setInterval(() => { if (autoPoll) refresh(); }, 3000);
  });
  onDestroy(() => { if (pollTimer) clearInterval(pollTimer); });
</script>

<div class="view">
  <div class="toolbar">
    <span class="dot" class:on={status.running} class:off={!status.running}></span>
    <strong>{status.running ? "OAST running" : "OAST stopped"}</strong>
    {#if status.running}
      <span class="dim listeners">
        {#if status.dns}DNS :{status.dns}{/if}
        {#if status.http} · HTTP :{status.http}{/if}
        {#if status.smtp} · SMTP :{status.smtp}{/if}
      </span>
    {/if}
    {#if status.running}
      <button class="toolbar-btn danger" on:click={stopServer} disabled={busy}>Stop server</button>
    {:else}
      <button class="toolbar-btn primary" on:click={startServer} disabled={busy}>Start server</button>
    {/if}
    <button class="toolbar-btn" on:click={() => (showConfig = !showConfig)}>{showConfig ? "Hide" : "Configure"}</button>
    <button class="toolbar-btn primary" on:click={generate}>Generate payload</button>
    <button class="toolbar-btn" on:click={() => (oobOpen = !oobOpen)}>OOB scan</button>
    <span class="dim" style="margin-left:auto;font-size:12px">{status.payload_count} payloads · {status.interaction_count} hits</span>
  </div>

  {#if oobOpen}
    <div class="config-pane">
      <div class="pane-title">OOB / SSRF scan — injects a correlated payload into every query param + SSRF header of a request, then reports which sink called back</div>
      <textarea bind:value={oobRequest} style="width:100%;box-sizing:border-box;min-height:90px;font-family:ui-monospace,Consolas,monospace;font-size:12px;padding:8px;border:1px solid #d5dae1;border-radius:4px"></textarea>
      <div class="cfg-grid" style="margin-top:6px">
        <label>Scheme<input bind:value={oobScheme} /></label>
        <label>Host<input bind:value={oobHost} /></label>
        <label>Port<input type="number" bind:value={oobPort} /></label>
        <button class="btn-primary" on:click={runOob} disabled={oobBusy} style="align-self:flex-end">{oobBusy ? "Scanning…" : "Run OOB scan"}</button>
      </div>
      {#if oobResult}
        {#if !oobResult.ok}
          <div class="dim" style="color:#d42c2c;margin-top:8px">{oobResult.error}</div>
        {:else if (oobResult.confirmed || []).length === 0}
          <div class="dim" style="margin-top:8px">Tested {oobResult.tested_sinks} sinks — no out-of-band callbacks within the window.</div>
        {:else}
          <div style="margin-top:8px">
            <strong style="color:#c0392b">⚠ {oobResult.confirmed.length} confirmed OOB sink(s)</strong> of {oobResult.tested_sinks} tested:
            {#each oobResult.confirmed as c}
              <div class="dupe-row" style="font-size:12px"><code class="corr">{c.sink}</code> — {(c.interactions || []).map(i => i.kind).join(", ")}</div>
            {/each}
          </div>
        {/if}
      {/if}
    </div>
  {/if}

  {#if showConfig}
    <div class="config-pane">
      <div class="pane-title">OAST server configuration</div>
      <div class="cfg-grid">
        <label>Domain<input bind:value={config.domain} placeholder="oast.lancer.local" /></label>
        <label>Bind IP<input bind:value={config.bind_ip} placeholder="0.0.0.0" /></label>
        <label>Answer A-record<input bind:value={config.answer_ip} placeholder="127.0.0.1" /></label>
        <label>DNS port<input type="number" bind:value={config.dns_port} /></label>
        <label>HTTP port<input type="number" bind:value={config.http_port} /></label>
        <label>SMTP port<input type="number" bind:value={config.smtp_port} /></label>
        <label class="check"><input type="checkbox" bind:checked={config.enable_dns} /> DNS listener</label>
        <label class="check"><input type="checkbox" bind:checked={config.enable_http} /> HTTP listener</label>
        <label class="check"><input type="checkbox" bind:checked={config.enable_smtp} /> SMTP listener</label>
      </div>
      <div class="cfg-actions">
        <button class="btn-primary" on:click={saveConfig} disabled={busy}>Save config</button>
        <span class="dim hint">Point real <code>*.{config.domain}</code> NS/A records (or a port-forward) at this host for public callbacks. Defaults use unprivileged ports so no root is required.</span>
      </div>
    </div>
  {/if}

  {#if lastPayload}
    <div class="payload-banner">
      <span class="pb-label">Latest payload (copied to clipboard):</span>
      <code class="pb-host">{lastPayload.host}</code>
      <button class="sm-btn" on:click={() => copy(lastPayload.host)}>⎘ Copy</button>
      <span class="dim">Inject into any target's SSRF / XXE / deserialization / log sink, then watch for a hit below.</span>
    </div>
  {/if}

  <div class="filter-bar">
    {#each ["all", "dns", "http", "smtp"] as f}
      <button class="chip" class:active={filter === f} on:click={() => (filter = f)}>{f.toUpperCase()}</button>
    {/each}
    <label class="check-inline"><input type="checkbox" bind:checked={autoPoll} /> Auto-poll</label>
    <button class="toolbar-btn" on:click={refresh}>Poll now</button>
    <button class="toolbar-btn danger" on:click={clearInteractions}>Clear</button>
    <span class="dim" style="margin-left:auto;font-size:12px">{filtered.length} interactions</span>
  </div>

  <div class="table-wrap">
    <table class="data-table">
      <thead>
        <tr>
          <th>Time</th>
          <th>Type</th>
          <th>Correlated payload</th>
          <th>Remote IP</th>
          <th>Query</th>
          <th>Detail</th>
        </tr>
      </thead>
      <tbody>
        {#each filtered as i, idx}
          <tr class:row-even={idx % 2 === 0}>
            <td class="dim">{fmtTime(i.timestamp)}</td>
            <td><span class="kind kind-{i.kind}">{i.kind.toUpperCase()}</span></td>
            <td>{#if i.payload_id}<code class="corr">{i.payload_id.slice(0, 12)}</code>{:else}<span class="dim">uncorrelated</span>{/if}</td>
            <td class="dim">{i.remote_ip || ""}</td>
            <td class="value-cell" title={i.query}>{i.query}</td>
            <td class="dim">{rawSummary(i)}</td>
          </tr>
        {/each}
        {#if filtered.length === 0}
          <tr><td colspan="6" class="empty-cell">
            {status.running
              ? "No interactions yet. Generate a payload, inject it into a target, and out-of-band callbacks will appear here."
              : "Start the OAST server, then generate a payload to begin catching out-of-band callbacks."}
          </td></tr>
        {/if}
      </tbody>
    </table>
  </div>
</div>

<style>
  .toolbar { display: flex; align-items: center; gap: 8px; padding: 6px 12px; background: var(--surface-2); border-bottom: 1px solid var(--border); flex-shrink: 0; }
  .toolbar-btn { padding: 4px 10px; font-size: 13px; background: var(--surface-2); color: var(--text); border: 1px solid var(--border-strong); border-radius: 3px; cursor: pointer; }
  .toolbar-btn:hover { background: var(--surface-3); }
  .toolbar-btn.primary { background: var(--accent); color: #fff; border-color: var(--accent); }
  .toolbar-btn.primary:hover { background: var(--accent-hover); }
  .toolbar-btn.danger { color: #d42c2c; border-color: #f5b8b8; }
  .toolbar-btn.danger:hover { background: #fde8e8; }
  .dot { width: 9px; height: 9px; border-radius: 50%; display: inline-block; }
  .dot.on { background: #2e9e3f; box-shadow: 0 0 4px #2e9e3f; }
  .dot.off { background: #b8b8b8; }
  .listeners { font-size: 12px; }

  .config-pane { padding: 12px 14px; background: var(--surface-1); border-bottom: 2px solid var(--border); }
  .pane-title { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-muted); margin-bottom: 10px; }
  .cfg-grid { display: flex; flex-wrap: wrap; gap: 10px; }
  .cfg-grid label { display: flex; flex-direction: column; gap: 4px; font-size: 11px; color: var(--text-muted); min-width: 140px; }
  .cfg-grid label.check { flex-direction: row; align-items: center; gap: 5px; min-width: auto; }
  .cfg-actions { margin-top: 12px; display: flex; align-items: center; gap: 12px; }
  .hint { font-size: 11px; }

  .payload-banner { display: flex; align-items: center; gap: 10px; padding: 8px 14px; background: #fff8f0; border-bottom: 1px solid #f0d9c0; flex-wrap: wrap; }
  .pb-label { font-size: 11px; font-weight: 600; color: #a05000; }
  .pb-host { font-size: 13px; font-weight: 700; color: var(--accent-hover); }

  .filter-bar { display: flex; align-items: center; gap: 6px; padding: 6px 12px; background: #fbfbfb; border-bottom: 1px solid #ededed; }
  .chip { font-size: 11px; padding: 3px 10px; border: 1px solid #d0d0d0; border-radius: 12px; background: #fff; color: var(--text-2); cursor: pointer; }
  .chip.active { background: var(--accent); color: #fff; border-color: var(--accent); }
  .check-inline { display: flex; align-items: center; gap: 4px; font-size: 12px; color: var(--text-2); margin-left: 8px; }

  .table-wrap { flex: 1; overflow-y: auto; min-height: 0; }
  .data-table { width: 100%; border-collapse: collapse; font-size: 12px; }
  .data-table th, .data-table td { text-align: left; padding: 5px 10px; border-bottom: 1px solid var(--border); white-space: nowrap; }
  .data-table thead th { background: var(--surface-2); color: var(--text-muted); font-size: 11px; font-weight: 600; position: sticky; top: 0; z-index: 1; }
  .row-even { background: var(--surface-1); }
  .value-cell { max-width: 360px; overflow: hidden; text-overflow: ellipsis; font-family: ui-monospace, Consolas, monospace; }
  .empty-cell { text-align: center; padding: 30px; color: var(--text-muted); }
  code { font-family: ui-monospace, Consolas, monospace; }
  .corr { color: #2e6fae; }
  .kind { font-size: 10px; font-weight: 700; padding: 1px 6px; border-radius: 3px; }
  .kind-dns { background: #e6f0fb; color: #2e6fae; }
  .kind-http { background: #e9f7ec; color: #2e9e3f; }
  .kind-smtp { background: #f3ecfb; color: #7a4fb0; }
  .sm-btn { font-size: 12px; padding: 2px 8px; background: var(--surface-2); color: var(--text); border: 1px solid var(--border-strong); border-radius: 3px; cursor: pointer; }
  .sm-btn:hover { background: var(--surface-3); }
  .btn-primary { background: var(--accent); color: #fff; border: none; border-radius: 3px; padding: 5px 14px; font-size: 13px; cursor: pointer; }
  .btn-primary:hover { background: var(--accent-hover); }
  .view { display: flex; flex-direction: column; height: 100%; overflow: hidden; }
</style>
