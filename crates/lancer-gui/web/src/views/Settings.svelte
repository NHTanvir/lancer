<script>
  import { onMount } from "svelte";

  let category = "proxy";
  let saved = false;

  // Proxy settings
  let bindAddr = "127.0.0.1:8080";
  let interceptReq = true;
  let interceptResp = false;
  let interceptOnlyInScope = false;

  // Scanner settings
  let maxThreads = 10;
  let scanTimeout = 30;

  // Repeater settings
  let followRedirects = true;
  let processBody = true;

  // About
  let version = "loading...";

  const categories = [
    { id: "proxy",    label: "Proxy" },
    { id: "scanner",  label: "Scanner" },
    { id: "repeater", label: "Repeater" },
    { id: "misc",     label: "Misc / About" },
  ];

  onMount(async () => {
    try {
      const r = await fetch("/api/v1/status");
      const d = await r.json();
      version = d.version || "unknown";
    } catch {
      version = "offline";
    }
    try {
      const r = await fetch("/api/v1/proxy/status");
      if (r.ok) {
        const d = await r.json();
        if (d.addr) bindAddr = d.addr;
        interceptReq = !!d.intercept_requests;
        interceptResp = !!d.intercept_responses;
      }
    } catch {}
  });

  function save() {
    saved = true;
    setTimeout(() => saved = false, 1800);
  }
</script>

<div class="view settings-view">
  <!-- Left: categories -->
  <div class="settings-left">
    <div class="settings-left-title">Settings</div>
    {#each categories as cat}
      <button
        class="cat-item"
        class:cat-active={category === cat.id}
        on:click={() => category = cat.id}
      >{cat.label}</button>
    {/each}
  </div>

  <!-- Right: settings panel -->
  <div class="settings-right">
    <div class="settings-header">
      <span class="settings-page-title">
        {categories.find(c => c.id === category)?.label || ""}
      </span>
      <button class="btn-save" on:click={save}>
        {saved ? "Saved" : "Save changes"}
      </button>
    </div>

    <div class="settings-body">
      {#if category === "proxy"}
        <div class="settings-card">
          <div class="card-title">Proxy listeners</div>
          <div class="setting-row">
            <label class="setting-label" for="bind-addr">Bind address</label>
            <div class="setting-controls">
              <input id="bind-addr" bind:value={bindAddr} style="width:200px" placeholder="127.0.0.1:8080" />
              <span class="setting-hint">Address and port the proxy listens on</span>
            </div>
          </div>
          <div class="setting-row">
            <span class="setting-label">Intercept</span>
            <div class="setting-controls">
              <label class="check-label">
                <input type="checkbox" bind:checked={interceptReq} />
                Intercept requests
              </label>
              <label class="check-label">
                <input type="checkbox" bind:checked={interceptResp} />
                Intercept responses
              </label>
              <label class="check-label">
                <input type="checkbox" bind:checked={interceptOnlyInScope} />
                Only in-scope traffic
              </label>
            </div>
          </div>
        </div>

      {:else if category === "scanner"}
        <div class="settings-card">
          <div class="card-title">Scanner options</div>
          <div class="setting-row">
            <label class="setting-label" for="max-threads">Threads</label>
            <div class="setting-controls">
              <input id="max-threads" type="number" bind:value={maxThreads} style="width:80px" min="1" max="50" />
              <span class="setting-hint">Max concurrent scan threads</span>
            </div>
          </div>
          <div class="setting-row">
            <label class="setting-label" for="scan-timeout">Timeout (s)</label>
            <div class="setting-controls">
              <input id="scan-timeout" type="number" bind:value={scanTimeout} style="width:80px" min="5" max="300" />
              <span class="setting-hint">Per-request timeout in seconds</span>
            </div>
          </div>
        </div>

      {:else if category === "repeater"}
        <div class="settings-card">
          <div class="card-title">Repeater options</div>
          <div class="setting-row">
            <span class="setting-label">Redirects</span>
            <div class="setting-controls">
              <label class="check-label">
                <input type="checkbox" bind:checked={followRedirects} />
                Follow redirects
              </label>
            </div>
          </div>
          <div class="setting-row">
            <span class="setting-label">Body</span>
            <div class="setting-controls">
              <label class="check-label">
                <input type="checkbox" bind:checked={processBody} />
                Process response body
              </label>
            </div>
          </div>
        </div>

      {:else if category === "misc"}
        <div class="settings-card">
          <div class="card-title">About Lancer</div>
          <div class="about-row">
            <svg width="40" height="40" viewBox="0 0 40 40" fill="none">
              <polygon points="20,4 8,22 17,22 17,36 32,18 22,18" fill="#e03a00"/>
            </svg>
            <div class="about-info">
              <div class="about-name">Lancer</div>
              <div class="about-version dim">Version {version}</div>
              <div class="about-desc dim">
                A web security testing toolkit — Burp Suite-compatible proxy, scanner, intruder, and more.
              </div>
            </div>
          </div>
          <div class="about-actions">
            <button class="btn-secondary">Documentation</button>
            <button class="btn-secondary">GitHub</button>
            <button class="btn-secondary">Check for updates</button>
          </div>
        </div>
      {/if}
    </div>
  </div>
</div>

<style>
  .settings-view {
    flex-direction: row !important;
  }

  /* Left nav */
  .settings-left {
    width: 180px; flex-shrink: 0;
    background: #f5f5f5;
    border-right: 1px solid #dedede;
    display: flex; flex-direction: column;
    overflow-y: auto;
  }
  .settings-left-title {
    font-size: 11px; font-weight: 700;
    text-transform: uppercase; letter-spacing: 0.07em;
    color: #767676;
    padding: 12px 14px 8px;
    border-bottom: 1px solid #dedede;
  }
  .cat-item {
    padding: 9px 14px;
    background: transparent;
    border: none; border-radius: 0;
    border-bottom: 1px solid #ebebeb;
    color: #444; font-size: 13px;
    text-align: left; cursor: pointer;
    transition: background 0.1s, color 0.1s;
  }
  .cat-item:hover { background: #ebebeb; }
  .cat-active {
    background: #ffffff !important;
    color: #e03a00 !important;
    font-weight: 600;
    border-left: 3px solid #e03a00;
    padding-left: 11px;
  }

  /* Right panel */
  .settings-right {
    flex: 1; display: flex; flex-direction: column;
    overflow: hidden; background: #ffffff;
  }
  .settings-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 10px 18px;
    background: #f5f5f5;
    border-bottom: 1px solid #dedede;
    flex-shrink: 0;
  }
  .settings-page-title {
    font-size: 14px; font-weight: 600; color: #212121;
  }
  .btn-save {
    background: #e03a00; color: #fff;
    border: none; border-radius: 3px;
    padding: 5px 14px; font-size: 13px; cursor: pointer;
  }
  .btn-save:hover { background: #c73400; }

  .settings-body {
    flex: 1; overflow-y: auto;
    padding: 16px 18px;
  }

  .settings-card {
    background: #fafafa;
    border: 1px solid #dedede;
    border-radius: 4px;
    padding: 16px 18px;
    margin-bottom: 14px;
  }
  .card-title {
    font-size: 11px; font-weight: 700;
    text-transform: uppercase; letter-spacing: 0.06em;
    color: #767676; margin-bottom: 14px;
    padding-bottom: 8px;
    border-bottom: 1px solid #e8e8e8;
  }
  .setting-row {
    display: flex; align-items: flex-start; gap: 16px;
    margin-bottom: 12px; flex-wrap: wrap;
  }
  .setting-row:last-child { margin-bottom: 0; }
  .setting-label {
    font-size: 13px; color: #444;
    min-width: 120px; padding-top: 5px; flex-shrink: 0;
    font-weight: 500;
  }
  .setting-controls {
    display: flex; flex-direction: column; gap: 6px;
  }
  .setting-hint { font-size: 11px; color: #767676; }
  .check-label {
    display: flex; align-items: center; gap: 7px;
    font-size: 13px; color: #444; cursor: pointer;
  }
  .check-label input { cursor: pointer; accent-color: #e03a00; }

  /* About */
  .about-row {
    display: flex; gap: 16px; align-items: flex-start; margin-bottom: 14px;
  }
  .about-name { font-size: 18px; font-weight: 700; color: #212121; margin-bottom: 2px; }
  .about-version { font-size: 12px; margin-bottom: 6px; }
  .about-desc { font-size: 13px; line-height: 1.5; max-width: 420px; }
  .about-info { display: flex; flex-direction: column; }
  .about-actions { display: flex; gap: 8px; }
  .btn-secondary {
    background: #f0f0f0; color: #333;
    border: 1px solid #c8c8c8; border-radius: 3px;
    padding: 5px 12px; font-size: 13px; cursor: pointer;
  }
  .btn-secondary:hover { background: #e4e4e4; }
</style>
