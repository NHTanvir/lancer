<script>
  import { onMount } from "svelte";

  let subtab = "new";
  let url = "https://example.com/";
  let scanType = "full";
  let scanning = false;
  let queue = [];

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
</style>
