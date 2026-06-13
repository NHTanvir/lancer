<script>
  import { onMount } from "svelte";

  let subtab = "new";
  let url = "https://example.com/";
  let scanType = "full";
  let scanning = false;
  let queue = [];

  // §5.4 scan config library
  const PRESETS = ["Lightweight", "Balanced", "Deep", "AuditOnly", "CrawlOnly", "PassiveOnly", "OwaspTop10"];
  let cfg = { preset: "Balanced", enabled_checks: null, disabled_checks: [], max_concurrency_per_host: 8, throttle_ms: 0, follow_redirects_on_audit: true };
  let available = { active: [], passive: [] };
  let cfgSaved = false;

  async function loadConfig() {
    try {
      const r = await fetch("/api/v1/scan/config");
      if (r.ok) { const d = await r.json(); cfg = d.config; available = d.available; }
    } catch {}
  }
  function checkOn(id) { return !(cfg.disabled_checks || []).includes(id); }
  function toggleCheck(id) {
    const dis = new Set(cfg.disabled_checks || []);
    if (dis.has(id)) dis.delete(id); else dis.add(id);
    cfg.disabled_checks = [...dis];
  }
  // §5.5 API spec import (OpenAPI / Postman / GraphQL introspection)
  let showImport = false;
  let importSpec = "";
  let importBase = "";
  let importResults = [];
  let importError = "";
  let importing = false;

  async function doImport() {
    importError = ""; importResults = []; importing = true;
    try {
      const r = await fetch("/api/v1/scan/import-spec", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ spec: importSpec, base: importBase || null }),
      });
      if (r.ok) { const d = await r.json(); importResults = d.requests || []; }
      else importError = `Import failed: ${await r.text()}`;
    } catch (e) { importError = `Could not reach API (${e})`; }
    finally { importing = false; }
  }
  // §5.1.1 Deep JS-rendering crawl (headless Chromium; needs lancer-api built --features chromium)
  let showCrawl = false;
  let crawlUrl = "https://example.com/";
  let crawlWait = 800;
  let crawlResult = null;
  let crawlError = "";
  let crawling = false;
  async function doDeepCrawl() {
    crawlError = ""; crawlResult = null; crawling = true;
    try {
      const r = await fetch("/api/v1/crawl/deep", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ url: crawlUrl, wait_ms: +crawlWait }),
      });
      const d = await r.json();
      if (d.ok === false) crawlError = d.error || "crawl failed";
      else crawlResult = d;
    } catch (e) { crawlError = `Could not reach API (${e})`; }
    finally { crawling = false; }
  }

  async function scanImported() {
    for (const req of importResults) {
      try { await fetch("/api/v1/scan/full", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ url: req.url }) }); } catch {}
    }
    alert(`Queued ${importResults.length} imported request(s) for scanning.`);
  }

  async function saveConfig() {
    try {
      await fetch("/api/v1/scan/config", {
        method: "PUT", headers: { "content-type": "application/json" },
        body: JSON.stringify({ ...cfg, max_concurrency_per_host: +cfg.max_concurrency_per_host, throttle_ms: +cfg.throttle_ms }),
      });
      cfgSaved = true; setTimeout(() => (cfgSaved = false), 1500);
    } catch {}
  }

  function severityClass(s) {
    const m = { Critical: "badge-Critical", High: "badge-High", Medium: "badge-Medium", Low: "badge-Low", Info: "badge-Info" };
    return m[s] || "badge-Info";
  }

  async function startScan() {
    scanning = true;
    const endpoint = scanType === "full" ? "full" : scanType === "passive" ? "passive" : "active";
    try {
      const r = await fetch(`/api/v1/scan/${endpoint}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data = await r.json();
      queue = [
        {
          id: queue.length + 1, url, type: endpoint,
          status: "running",
          issues: Array.isArray(data) ? data : (data.issues || data || []),
          started: new Date().toLocaleTimeString(),
        },
        ...queue,
      ];
    } catch {
      queue = [
        { id: queue.length + 1, url, type: endpoint, status: "error", issues: [], started: new Date().toLocaleTimeString() },
        ...queue,
      ];
    } finally {
      scanning = false;
      setTimeout(() => {
        queue = queue.map((q, i) => i === 0 ? { ...q, status: "done" } : q);
      }, 2000);
    }
  }

  onMount(async () => {
    try {
      const r = await fetch("/api/v1/scan/queue");
      if (r.ok) queue = await r.json();
    } catch {}
  });
</script>

<div class="view">
  <div class="subtabs">
    <button class="subtab" class:active={subtab==="new"}   on:click={() => subtab="new"}>New scan</button>
    <button class="subtab" class:active={subtab==="queue"} on:click={() => subtab="queue"}>
      Scan queue {#if queue.length}<span class="tab-badge">{queue.length}</span>{/if}
    </button>
    <button class="subtab" class:active={subtab==="config"} on:click={() => { subtab="config"; if(!available.active.length) loadConfig(); }}>Configuration</button>
  </div>

  <div class="panel">
    {#if subtab === "new"}
      <div class="card">
        <div class="card-title">Target URL</div>
        <div class="url-row">
          <input bind:value={url} placeholder="https://target.example/" style="flex:1;max-width:500px" />
        </div>

        <div class="card-title" style="margin-top:18px">Scan type</div>
        <div class="scan-types">
          <button
            class="scan-btn"
            class:scan-active={scanType==="full"}
            on:click={() => scanType="full"}
          >
            <svg width="22" height="22" viewBox="0 0 22 22" fill="none" style="margin-bottom:4px">
              <circle cx="11" cy="11" r="9" stroke="#e03a00" stroke-width="1.5" fill="none"/>
              <path d="M7 11 L10 14 L15 8" stroke="#e03a00" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
            <span class="scan-label">Full scan</span>
            <span class="scan-desc dim">Passive + Active checks</span>
          </button>
          <button
            class="scan-btn"
            class:scan-active={scanType==="passive"}
            on:click={() => scanType="passive"}
          >
            <svg width="22" height="22" viewBox="0 0 22 22" fill="none" style="margin-bottom:4px">
              <ellipse cx="11" cy="11" rx="9" ry="6" stroke="#767676" stroke-width="1.5" fill="none"/>
              <circle cx="11" cy="11" r="3" fill="#767676" opacity="0.4"/>
            </svg>
            <span class="scan-label">Passive only</span>
            <span class="scan-desc dim">Non-intrusive analysis</span>
          </button>
          <button
            class="scan-btn"
            class:scan-active={scanType==="active"}
            on:click={() => scanType="active"}
          >
            <svg width="22" height="22" viewBox="0 0 22 22" fill="none" style="margin-bottom:4px">
              <path d="M11 3 L14 10 L20 10 L15 14 L17 21 L11 17 L5 21 L7 14 L2 10 L8 10 Z" stroke="#767676" stroke-width="1.3" fill="none"/>
            </svg>
            <span class="scan-label">Active only</span>
            <span class="scan-desc dim">Inject and probe</span>
          </button>
        </div>

        <div style="margin-top:18px">
          <button class="btn-orange" on:click={startScan} disabled={scanning || !url}>
            {scanning ? "Starting..." : "New scan"}
          </button>
          <button class="btn-import" on:click={() => (showImport = !showImport)}>{showImport ? "Hide import" : "Import API spec ▾"}</button>
          <button class="btn-import" on:click={() => (showCrawl = !showCrawl)}>{showCrawl ? "Hide deep crawl" : "Deep JS crawl ▾"}</button>
        </div>
      </div>

      {#if showCrawl}
        <div class="card" style="margin-top:12px;max-width:820px">
          <div class="card-title">Deep JS-rendering crawl — headless Chromium (renders client-side JS, then extracts links / scripts / fetch endpoints)</div>
          <div class="import-row">
            <input bind:value={crawlUrl} placeholder="https://target/" style="flex:1" />
            <label class="dim" style="font-size:11px">wait ms<input type="number" bind:value={crawlWait} style="width:80px;margin-left:4px" /></label>
            <button class="btn-orange" on:click={doDeepCrawl} disabled={crawling}>{crawling ? "Rendering…" : "Crawl"}</button>
          </div>
          <div class="dim" style="font-size:11px;margin-top:4px">Requires lancer-api built with <code>--features chromium</code> + a Chrome/Chromium binary.</div>
          {#if crawlError}<div class="imp-err">{crawlError}</div>{/if}
          {#if crawlResult}
            <div class="imp-results" style="margin-top:8px">
              <div class="imp-req"><strong>{crawlResult.title || crawlResult.url}</strong></div>
              {#each [...(crawlResult.links||[]), ...(crawlResult.endpoints||[]), ...(crawlResult.scripts||[])] as u}
                <div class="imp-req"><code class="imp-url">{u}</code></div>
              {/each}
            </div>
          {/if}
        </div>
      {/if}

      {#if showImport}
        <div class="card" style="margin-top:12px;max-width:820px">
          <div class="card-title">Import API spec — OpenAPI / Postman / GraphQL introspection (auto-detected)</div>
          <textarea class="spec-area" bind:value={importSpec} placeholder="Paste an OpenAPI 3.x doc (JSON/YAML), a Postman v2.1 collection, or a GraphQL introspection result…"></textarea>
          <div class="import-row">
            <input bind:value={importBase} placeholder="Base URL (optional, e.g. https://api.example.com)" style="flex:1" />
            <button class="btn-orange" on:click={doImport} disabled={importing || !importSpec.trim()}>{importing ? "Importing…" : "Import"}</button>
            {#if importResults.length}<button class="btn-import" on:click={scanImported}>Scan all {importResults.length}</button>{/if}
          </div>
          {#if importError}<div class="imp-err">{importError}</div>{/if}
          {#if importResults.length}
            <div class="imp-results">
              {#each importResults as req}
                <div class="imp-req"><span class="imp-method">{req.method}</span><code class="imp-url">{req.url}</code><span class="imp-tags dim">{(req.tags || []).join(", ")}</span></div>
              {/each}
            </div>
          {/if}
        </div>
      {/if}

    {:else if subtab === "config"}
      <div class="card" style="max-width:820px">
        <div class="card-title">Scan preset</div>
        <select bind:value={cfg.preset} class="preset-sel">
          {#each PRESETS as p}<option value={p}>{p}</option>{/each}
        </select>

        <div class="cfg-row" style="margin-top:16px">
          <label>Max concurrency / host<input type="number" bind:value={cfg.max_concurrency_per_host} min="1" /></label>
          <label>Throttle (ms)<input type="number" bind:value={cfg.throttle_ms} min="0" /></label>
          <label class="check"><input type="checkbox" bind:checked={cfg.follow_redirects_on_audit} /> Follow redirects on audit</label>
        </div>

        <div class="card-title" style="margin-top:18px">Active checks ({available.active.length})</div>
        <div class="check-grid">
          {#each available.active as c}
            <label class="check-item"><input type="checkbox" checked={checkOn(c.id)} on:change={() => toggleCheck(c.id)} /> {c.name}</label>
          {/each}
        </div>

        <div class="card-title" style="margin-top:18px">Passive checks ({available.passive.length})</div>
        <div class="check-grid">
          {#each available.passive as c}
            <label class="check-item"><input type="checkbox" checked={checkOn(c.id)} on:change={() => toggleCheck(c.id)} /> {c.name}</label>
          {/each}
        </div>

        <div style="margin-top:18px">
          <button class="btn-orange" on:click={saveConfig}>Save configuration</button>
          {#if cfgSaved}<span class="dim" style="margin-left:10px;color:#1b8c1b">✓ Saved — applies to subsequent scans</span>{/if}
        </div>
      </div>
    {:else}
      {#if queue.length === 0}
        <div class="empty-state">
          <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
            <rect x="8" y="10" width="32" height="30" rx="3" stroke="#c8c8c8" stroke-width="1.5" fill="#f5f5f5"/>
            <path d="M14 20 L34 20" stroke="#c8c8c8" stroke-width="1.2" stroke-linecap="round"/>
            <path d="M14 26 L34 26" stroke="#c8c8c8" stroke-width="1.2" stroke-linecap="round"/>
            <path d="M14 32 L26 32" stroke="#c8c8c8" stroke-width="1.2" stroke-linecap="round"/>
          </svg>
          <span style="font-weight:500;color:#444">No scans in queue</span>
          <span class="dim" style="font-size:12px">Go to "New scan" to start a scan</span>
        </div>
      {:else}
        {#each queue as scan}
          <div class="scan-card">
            <div class="scan-header">
              <span class="scan-url">{scan.url}</span>
              <span class="scan-type-badge">{scan.type}</span>
              <span class="scan-status"
                class:status-done={scan.status==="done"}
                class:status-running={scan.status==="running"}
                class:status-error={scan.status==="error"}
              >{scan.status}</span>
              <span class="dim" style="font-size:11px;margin-left:6px">{scan.started}</span>
            </div>
            {#if scan.issues.length > 0}
              <div class="scan-issues">
                {#each scan.issues as iss}
                  <span class="badge {severityClass(iss.severity)}">{iss.severity}</span>
                  <span class="iss-name">{iss.name}</span>
                {/each}
              </div>
            {:else}
              <div class="dim" style="font-size:12px;margin-top:4px">
                {scan.status === "running" ? "Scanning..." : "No issues found"}
              </div>
            {/if}
          </div>
        {/each}
      {/if}
    {/if}
  </div>
</div>

<style>
  .card {
    background: #fafafa; border: 1px solid #dedede;
    border-radius: 4px; padding: 16px;
    max-width: 700px;
  }
  .card-title {
    font-size: 11px; font-weight: 700;
    text-transform: uppercase; letter-spacing: 0.06em;
    color: #767676; margin-bottom: 10px;
  }
  .url-row { display: flex; gap: 8px; }

  .scan-types { display: flex; gap: 10px; }
  .scan-btn {
    flex: 1; display: flex; flex-direction: column; align-items: center;
    gap: 2px; padding: 14px 10px;
    background: #ffffff; border: 1px solid #c8c8c8;
    border-radius: 4px; cursor: pointer;
    transition: border-color 0.1s, background 0.1s;
    text-align: center;
  }
  .scan-btn:hover { background: #f5f5f5; border-color: #aaa; }
  .scan-active { border-color: #e03a00 !important; background: #fce8e2 !important; }
  .scan-label { font-size: 13px; font-weight: 600; color: #212121; }
  .scan-desc  { font-size: 11px; }

  .btn-orange {
    background: #e03a00; color: #fff;
    border: none; border-radius: 3px;
    padding: 5px 16px; font-size: 13px; cursor: pointer;
  }
  .btn-orange:hover:not(:disabled) { background: #c73400; }
  .btn-orange:disabled { opacity: 0.5; cursor: not-allowed; }

  .tab-badge {
    display: inline-block;
    background: #e03a00; color: #fff;
    border-radius: 8px; font-size: 10px;
    padding: 0 5px; margin-left: 4px;
  }

  .scan-card {
    background: #fafafa; border: 1px solid #dedede;
    border-radius: 4px; padding: 12px 14px;
    margin-bottom: 8px;
  }
  .scan-header {
    display: flex; align-items: center; gap: 8px;
    flex-wrap: wrap; margin-bottom: 6px;
  }
  .scan-url { font-size: 13px; color: #212121; flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .scan-type-badge {
    font-size: 10px; text-transform: uppercase;
    background: #f0f0f0; color: #767676;
    padding: 2px 6px; border-radius: 3px;
    border: 1px solid #c8c8c8;
  }
  .scan-status { font-size: 12px; font-weight: 600; }
  .status-done    { color: #1b8c1b; }
  .status-running { color: #c98a00; }
  .status-error   { color: #d42c2c; }
  .scan-issues { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; font-size: 12px; }
  .iss-name { color: #444; }

  .empty-state {
    flex: 1; display: flex; flex-direction: column;
    align-items: center; justify-content: center;
    gap: 10px; padding: 60px; text-align: center;
  }

  .preset-sel { padding: 5px 8px; border: 1px solid #c8c8c8; border-radius: 3px; font-size: 13px; min-width: 200px; }
  .cfg-row { display: flex; flex-wrap: wrap; gap: 16px; align-items: flex-end; }
  .cfg-row label { display: flex; flex-direction: column; gap: 4px; font-size: 11px; color: #767676; }
  .cfg-row label.check { flex-direction: row; align-items: center; gap: 5px; }
  .cfg-row input[type="number"] { width: 100px; padding: 4px 6px; border: 1px solid #c8c8c8; border-radius: 3px; }
  .check-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 4px 14px; }
  .check-item { display: flex; align-items: center; gap: 6px; font-size: 12px; color: #444; }
  .btn-import { background: #f0f0f0; color: #333; border: 1px solid #c8c8c8; border-radius: 3px; padding: 5px 14px; font-size: 13px; cursor: pointer; margin-left: 8px; }
  .btn-import:hover { background: #e4e4e4; }
  .spec-area { width: 100%; box-sizing: border-box; min-height: 120px; font-family: ui-monospace, Consolas, monospace; font-size: 12px; padding: 8px; border: 1px solid #c8c8c8; border-radius: 3px; resize: vertical; }
  .import-row { display: flex; gap: 8px; align-items: center; margin-top: 8px; }
  .import-row input { padding: 5px 9px; border: 1px solid #c8c8c8; border-radius: 3px; font-size: 13px; }
  .imp-err { color: #d42c2c; font-size: 12px; margin-top: 6px; }
  .imp-results { margin-top: 10px; max-height: 240px; overflow: auto; border: 1px solid #eee; border-radius: 4px; }
  .imp-req { display: flex; gap: 8px; align-items: center; padding: 3px 8px; border-bottom: 1px solid #f2f2f2; font-size: 12px; }
  .imp-method { font-weight: 700; color: #2e6fae; min-width: 52px; }
  .imp-url { font-family: ui-monospace, Consolas, monospace; color: #333; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .imp-tags { font-size: 11px; }
</style>
