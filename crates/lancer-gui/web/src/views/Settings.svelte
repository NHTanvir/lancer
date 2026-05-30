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

  // ── §23 Network / proxy settings ───────────────────────────────────────
  // Full ProxySettings object loaded from /api/v1/proxy/settings.
  let proxyCfg = null;
  let netLoading = false;
  let netError = "";
  let netNote = "";
  // Derived editable mirrors of the proxy config:
  let upstreamEnabled = false;
  let upstreamKind = "Http";       // Http | Socks5 (serde PascalCase)
  let upstreamHost = "";
  let upstreamPort = 8080;
  let upstreamUser = "";
  let upstreamPass = "";
  let tlsPassthroughText = "";      // textarea, one host per line
  let dnsOverrides = [];            // [{ host, ip }]
  let platformAuth = [];            // [{ host_pattern, scheme, username, password }]

  // ── §16/§27 AI (BYO-LLM) ───────────────────────────────────────────────
  let aiProvider = "ollama";        // ollama | openai | anthropic
  let aiModel = "";
  let aiKey = "";

  // ── Display ─────────────────────────────────────────────────────────────
  let theme = "light";              // light | dark
  let fontSize = "13px";

  // ── Updates ───────────────────────────────────────────────────────────────
  let autoCheckUpdates = false;
  let updateStatus = "";

  const categories = [
    { id: "proxy",    label: "Proxy" },
    { id: "network",  label: "Network" },
    { id: "scanner",  label: "Scanner" },
    { id: "repeater", label: "Repeater" },
    { id: "ai",       label: "AI" },
    { id: "display",  label: "Display" },
    { id: "updates",  label: "Updates" },
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
    try {
      const ls = JSON.parse(localStorage.getItem("lancer.settings") || "{}");
      if (typeof ls.maxThreads === "number") maxThreads = ls.maxThreads;
      if (typeof ls.scanTimeout === "number") scanTimeout = ls.scanTimeout;
      if (typeof ls.followRedirects === "boolean") followRedirects = ls.followRedirects;
      if (typeof ls.processBody === "boolean") processBody = ls.processBody;
      if (typeof ls.interceptOnlyInScope === "boolean") interceptOnlyInScope = ls.interceptOnlyInScope;
    } catch {}

    // AI config (read by Repeater's AI buttons)
    try {
      aiProvider = localStorage.getItem("lancer.ai.provider") || "ollama";
      aiModel = localStorage.getItem("lancer.ai.model") || "";
      aiKey = localStorage.getItem("lancer.ai.key") || "";
    } catch {}

    // Display
    try {
      theme = localStorage.getItem("lancer.theme") || "light";
      fontSize = localStorage.getItem("lancer.fontSize") || "13px";
    } catch {}

    // Updates
    try {
      autoCheckUpdates = localStorage.getItem("lancer.autoCheckUpdates") === "true";
    } catch {}

    await loadNetwork();
  });

  async function loadNetwork() {
    netLoading = true;
    netError = "";
    try {
      const r = await fetch("/api/v1/proxy/settings");
      if (!r.ok) { netError = await r.text(); netLoading = false; return; }
      const d = await r.json();
      proxyCfg = d || {};
      // Defensive: backend may omit/null any field.
      const up = proxyCfg.upstream;
      upstreamEnabled = !!up;
      upstreamKind = up?.kind || "Http";
      upstreamHost = up?.host || "";
      upstreamPort = typeof up?.port === "number" ? up.port : 8080;
      upstreamUser = up?.username || "";
      upstreamPass = up?.password || "";
      tlsPassthroughText = Array.isArray(proxyCfg.tls_passthrough)
        ? proxyCfg.tls_passthrough.join("\n") : "";
      dnsOverrides = Array.isArray(proxyCfg.dns_overrides)
        ? proxyCfg.dns_overrides.map(o => ({ host: o?.host || "", ip: o?.ip || "" })) : [];
      platformAuth = Array.isArray(proxyCfg.platform_auth)
        ? proxyCfg.platform_auth.map(a => ({
            host_pattern: a?.host_pattern || "",
            scheme: a?.scheme || "Basic",
            username: a?.username || "",
            password: a?.password || "",
            domain: a?.domain ?? null,
          }))
        : [];
    } catch (e) {
      netError = e.message || String(e);
    }
    netLoading = false;
  }

  function addDnsOverride() { dnsOverrides = [...dnsOverrides, { host: "", ip: "" }]; }
  function removeDnsOverride(i) { dnsOverrides = dnsOverrides.filter((_, idx) => idx !== i); }
  function addPlatformAuth() {
    platformAuth = [...platformAuth, { host_pattern: "", scheme: "Basic", username: "", password: "", domain: null }];
  }
  function removePlatformAuth(i) { platformAuth = platformAuth.filter((_, idx) => idx !== i); }

  async function saveNetwork() {
    netError = "";
    netNote = "";
    // Start from the loaded object so we preserve listeners / timeouts / ca_dir etc.
    const out = { ...(proxyCfg || {}) };
    out.upstream = upstreamEnabled
      ? {
          kind: upstreamKind,
          host: upstreamHost,
          port: Number(upstreamPort) || 0,
          username: upstreamUser ? upstreamUser : null,
          password: upstreamPass ? upstreamPass : null,
        }
      : null;
    out.tls_passthrough = tlsPassthroughText
      .split("\n").map(s => s.trim()).filter(Boolean);
    out.dns_overrides = dnsOverrides
      .filter(o => o.host.trim() && o.ip.trim())
      .map(o => ({ host: o.host.trim(), ip: o.ip.trim() }));
    out.platform_auth = platformAuth
      .filter(a => a.host_pattern.trim())
      .map(a => ({
        host_pattern: a.host_pattern.trim(),
        scheme: a.scheme,
        username: a.username,
        password: a.password,
        domain: a.domain ? a.domain : null,
      }));
    try {
      const r = await fetch("/api/v1/proxy/settings", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(out),
      });
      if (!r.ok) { netError = await r.text(); return; }
      const d = await r.json();
      netNote = d?.note || "saved";
      proxyCfg = out;
      setTimeout(() => netNote = "", 4000);
    } catch (e) {
      netError = e.message || String(e);
    }
  }

  function saveAi() {
    try {
      localStorage.setItem("lancer.ai.provider", aiProvider);
      localStorage.setItem("lancer.ai.model", aiModel);
      localStorage.setItem("lancer.ai.key", aiKey);
    } catch {}
  }

  function applyTheme() {
    try {
      document.body.setAttribute("data-theme", theme);
      localStorage.setItem("lancer.theme", theme);
    } catch {}
  }

  function applyFontSize() {
    try {
      document.documentElement.style.fontSize = fontSize;
      localStorage.setItem("lancer.fontSize", fontSize);
    } catch {}
  }

  async function checkForUpdates() {
    updateStatus = "Checking...";
    try {
      const r = await fetch("/api/v1/status");
      if (!r.ok) { updateStatus = "Could not reach server"; return; }
      const d = await r.json();
      version = d.version || version;
      updateStatus = `You are on version ${version}. No newer version available.`;
    } catch (e) {
      updateStatus = "Offline — " + (e.message || String(e));
    }
  }

  function saveAutoCheck() {
    try { localStorage.setItem("lancer.autoCheckUpdates", String(autoCheckUpdates)); } catch {}
  }

  async function save() {
    // Network category routes its own save (full ProxySettings PUT).
    if (category === "network") { await saveNetwork(); flashSaved(); return; }
    if (category === "ai")      { saveAi(); flashSaved(); return; }
    if (category === "display") { applyTheme(); applyFontSize(); flashSaved(); return; }
    if (category === "updates") { saveAutoCheck(); flashSaved(); return; }
    try {
      const r = await fetch("/api/v1/settings", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          intercept_requests: interceptReq,
          intercept_responses: interceptResp,
        }),
      });
      if (r.ok) {
        flashSaved();
        try { localStorage.setItem("lancer.settings", JSON.stringify({
          maxThreads, scanTimeout, followRedirects, processBody, interceptOnlyInScope,
        })); } catch {}
      }
    } catch {}
  }

  function flashSaved() {
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

      {:else if category === "network"}
        {#if netLoading}
          <div class="dim" style="padding:8px 2px;">Loading network settings…</div>
        {/if}
        {#if netError}
          <div class="net-error">{netError}</div>
        {/if}
        {#if netNote}
          <div class="net-note">{netNote}</div>
        {/if}

        <div class="settings-card">
          <div class="card-title">Upstream proxy</div>
          <div class="setting-row">
            <span class="setting-label">Enable</span>
            <div class="setting-controls">
              <label class="check-label">
                <input type="checkbox" bind:checked={upstreamEnabled} />
                Route traffic through an upstream proxy
              </label>
            </div>
          </div>
          {#if upstreamEnabled}
            <div class="setting-row">
              <label class="setting-label" for="up-kind">Type</label>
              <div class="setting-controls">
                <select id="up-kind" bind:value={upstreamKind} style="width:140px">
                  <option value="Http">HTTP</option>
                  <option value="Socks5">SOCKS5</option>
                </select>
              </div>
            </div>
            <div class="setting-row">
              <label class="setting-label" for="up-host">Host / port</label>
              <div class="setting-controls">
                <div style="display:flex;gap:6px;">
                  <input id="up-host" bind:value={upstreamHost} style="width:200px" placeholder="proxy.example.com" />
                  <input type="number" bind:value={upstreamPort} style="width:90px" min="1" max="65535" placeholder="8080" />
                </div>
              </div>
            </div>
            <div class="setting-row">
              <label class="setting-label" for="up-user">Auth (optional)</label>
              <div class="setting-controls">
                <div style="display:flex;gap:6px;">
                  <input id="up-user" bind:value={upstreamUser} style="width:150px" placeholder="username" autocomplete="off" />
                  <input type="password" bind:value={upstreamPass} style="width:150px" placeholder="password" autocomplete="off" />
                </div>
                <span class="setting-hint">Leave blank for no upstream authentication</span>
              </div>
            </div>
          {/if}
        </div>

        <div class="settings-card">
          <div class="card-title">TLS pass-through</div>
          <div class="setting-row">
            <label class="setting-label" for="tls-pt">Hosts</label>
            <div class="setting-controls">
              <textarea id="tls-pt" bind:value={tlsPassthroughText} rows="4" style="width:320px"
                placeholder={"example.com\nsecure.internal"}></textarea>
              <span class="setting-hint">One host per line — these hosts are not intercepted (TLS passes through untouched)</span>
            </div>
          </div>
        </div>

        <div class="settings-card">
          <div class="card-title">DNS overrides</div>
          {#each dnsOverrides as o, i}
            <div class="setting-row">
              <span class="setting-label">{i === 0 ? "Host → IP" : ""}</span>
              <div class="setting-controls">
                <div style="display:flex;gap:6px;align-items:center;">
                  <input bind:value={o.host} style="width:180px" placeholder="host (e.g. app.local)" />
                  <span class="dim">→</span>
                  <input bind:value={o.ip} style="width:130px" placeholder="93.184.216.34" />
                  <button class="btn-row-remove" type="button" on:click={() => removeDnsOverride(i)}>Remove</button>
                </div>
              </div>
            </div>
          {/each}
          {#if dnsOverrides.length === 0}
            <div class="dim" style="font-size:12px;margin-bottom:10px;">No DNS overrides configured.</div>
          {/if}
          <button class="btn-secondary" type="button" on:click={addDnsOverride}>+ Add override</button>
        </div>

        <div class="settings-card">
          <div class="card-title">Platform authentication</div>
          {#each platformAuth as a, i}
            <div class="setting-row">
              <span class="setting-label">{i === 0 ? "Credentials" : ""}</span>
              <div class="setting-controls">
                <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap;">
                  <input bind:value={a.host_pattern} style="width:160px" placeholder="host or *.example.com" />
                  <select bind:value={a.scheme} style="width:110px">
                    <option value="Basic">Basic</option>
                    <option value="Digest">Digest</option>
                    <option value="Ntlm">NTLM</option>
                    <option value="Negotiate">Negotiate</option>
                  </select>
                  <input bind:value={a.username} style="width:130px" placeholder="username" autocomplete="off" />
                  <input type="password" bind:value={a.password} style="width:130px" placeholder="password" autocomplete="off" />
                  <button class="btn-row-remove" type="button" on:click={() => removePlatformAuth(i)}>Remove</button>
                </div>
              </div>
            </div>
          {/each}
          {#if platformAuth.length === 0}
            <div class="dim" style="font-size:12px;margin-bottom:10px;">No platform credentials configured.</div>
          {/if}
          <button class="btn-secondary" type="button" on:click={addPlatformAuth}>+ Add credential</button>
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

      {:else if category === "ai"}
        <div class="settings-card">
          <div class="card-title">BYO-LLM (AI assistant)</div>
          <div class="setting-row">
            <label class="setting-label" for="ai-provider">Provider</label>
            <div class="setting-controls">
              <select id="ai-provider" bind:value={aiProvider} style="width:160px">
                <option value="ollama">Ollama (local)</option>
                <option value="openai">OpenAI</option>
                <option value="anthropic">Anthropic</option>
              </select>
              <span class="setting-hint">Used by the AI buttons in Repeater and triage</span>
            </div>
          </div>
          <div class="setting-row">
            <label class="setting-label" for="ai-model">Model</label>
            <div class="setting-controls">
              <input id="ai-model" bind:value={aiModel} style="width:240px"
                placeholder={aiProvider === "ollama" ? "llama3" : aiProvider === "anthropic" ? "claude-3-5-sonnet" : "gpt-4o"} />
            </div>
          </div>
          <div class="setting-row">
            <label class="setting-label" for="ai-key">API key</label>
            <div class="setting-controls">
              <input id="ai-key" type="password" bind:value={aiKey} style="width:300px"
                placeholder={aiProvider === "ollama" ? "(not required for local Ollama)" : "sk-…"} autocomplete="off" />
              <span class="setting-hint">Stored locally in this browser only — never sent anywhere except your chosen provider</span>
            </div>
          </div>
        </div>

      {:else if category === "display"}
        <div class="settings-card">
          <div class="card-title">Appearance</div>
          <div class="setting-row">
            <label class="setting-label" for="theme-sel">Theme</label>
            <div class="setting-controls">
              <select id="theme-sel" bind:value={theme} on:change={applyTheme} style="width:140px">
                <option value="light">Light</option>
                <option value="dark">Dark</option>
              </select>
              <span class="setting-hint">Applies immediately</span>
            </div>
          </div>
          <div class="setting-row">
            <label class="setting-label" for="font-sel">Font size</label>
            <div class="setting-controls">
              <select id="font-sel" bind:value={fontSize} on:change={applyFontSize} style="width:140px">
                <option value="12px">Small</option>
                <option value="13px">Default</option>
                <option value="14px">Large</option>
                <option value="16px">Extra large</option>
              </select>
            </div>
          </div>
        </div>

      {:else if category === "updates"}
        <div class="settings-card">
          <div class="card-title">Updates</div>
          <div class="setting-row">
            <span class="setting-label">Current version</span>
            <div class="setting-controls">
              <div style="display:flex;gap:10px;align-items:center;">
                <button class="btn-secondary" type="button" on:click={checkForUpdates}>Check for updates</button>
                <span class="dim">v{version}</span>
              </div>
              {#if updateStatus}
                <span class="setting-hint">{updateStatus}</span>
              {/if}
            </div>
          </div>
          <div class="setting-row">
            <span class="setting-label">Startup</span>
            <div class="setting-controls">
              <label class="check-label">
                <input type="checkbox" bind:checked={autoCheckUpdates} on:change={saveAutoCheck} />
                Auto-check for updates on startup
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

  /* Network category */
  .net-error {
    background: #fde8e8; color: #c0392b;
    border: 1px solid #f5c6c6; border-radius: 4px;
    padding: 8px 10px; font-size: 12px; margin-bottom: 12px;
  }
  .net-note {
    background: #e8f6ec; color: #1e7a3a;
    border: 1px solid #bfe5c9; border-radius: 4px;
    padding: 8px 10px; font-size: 12px; margin-bottom: 12px;
  }
  .btn-row-remove {
    background: #f0f0f0; color: #c0392b;
    border: 1px solid #d8c0c0; border-radius: 3px;
    padding: 4px 9px; font-size: 12px; cursor: pointer;
  }
  .btn-row-remove:hover { background: #f7e0e0; }

  .settings-card textarea,
  .settings-card select {
    font: inherit; font-size: 13px;
    border: 1px solid #c8c8c8; border-radius: 3px;
    padding: 4px 6px; color: #212121; background: #fff;
  }
  .settings-card textarea { resize: vertical; }
</style>
