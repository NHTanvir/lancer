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
  let upstreamRules = [];           // [{ host_pattern, kind, host, port, username, password }]
  let clientTls = [];               // [{ host_pattern, cert_pem_path, key_pem_path }]
  let connectTimeoutMs = 30000;
  let readTimeoutMs = 30000;

  // ── §16/§27 AI (BYO-LLM) ───────────────────────────────────────────────
  let aiProvider = "ollama";        // ollama | openai | anthropic
  let aiModel = "";
  let aiKey = "";

  // ── Display ─────────────────────────────────────────────────────────────
  let theme = "light";              // light | dark | system
  let fontSize = "13px";
  let fontFamily = "system";        // system | mono | serif
  let density = "comfortable";      // compact | comfortable | spacious
  // HTTP message display (Repeater/Logger/Proxy raw viewers read these)
  let msgFont = "mono";             // mono | system
  let msgTabSize = 4;
  let msgLineWrap = true;
  let _mqlDark = null;              // MediaQueryList for system theme tracking

  // ── Updates ───────────────────────────────────────────────────────────────
  let autoCheckUpdates = false;
  let updateChannel = "stable";     // stable | beta
  let updateStatus = "";

  // ── Misc ──────────────────────────────────────────────────────────────────
  let perfFeedback = false;

  // ── Logger options ────────────────────────────────────────────────────────
  let loggerMaxRows = 1000;
  let loggerAutoScroll = true;
  let loggerCaptureProxy = true;
  let loggerCaptureTools = true;

  const categories = [
    { id: "proxy",    label: "Proxy" },
    { id: "network",  label: "Network" },
    { id: "scanner",  label: "Scanner" },
    { id: "repeater", label: "Repeater" },
    { id: "logger",   label: "Logger" },
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
      // Prefer the raw choice sidecar ("system"/"dark"/"light"); fall back to
      // the resolved value stored under "lancer.theme".
      theme = localStorage.getItem("lancer.theme.mode") || localStorage.getItem("lancer.theme") || "light";
      fontSize = localStorage.getItem("lancer.fontSize") || "13px";
      fontFamily = localStorage.getItem("lancer.fontFamily") || "system";
      density = localStorage.getItem("lancer.density") || "comfortable";
      msgFont = localStorage.getItem("lancer.msg.font") || "mono";
      const mts = parseInt(localStorage.getItem("lancer.msg.tabSize") || "4", 10);
      if (!isNaN(mts)) msgTabSize = mts;
      const mlw = localStorage.getItem("lancer.msg.lineWrap");
      if (mlw !== null) msgLineWrap = mlw === "true";
    } catch {}

    // Logger options
    try {
      const lmr = parseInt(localStorage.getItem("lancer.logger.maxRows") || "1000", 10);
      if (!isNaN(lmr)) loggerMaxRows = lmr;
      const las = localStorage.getItem("lancer.logger.autoScroll");
      if (las !== null) loggerAutoScroll = las === "true";
      const lcp = localStorage.getItem("lancer.logger.captureProxy");
      if (lcp !== null) loggerCaptureProxy = lcp === "true";
      const lct = localStorage.getItem("lancer.logger.captureTools");
      if (lct !== null) loggerCaptureTools = lct === "true";
    } catch {}

    // Updates
    try {
      autoCheckUpdates = localStorage.getItem("lancer.autoCheckUpdates") === "true";
      updateChannel = localStorage.getItem("lancer.updateChannel") || "stable";
    } catch {}

    // Misc
    try {
      perfFeedback = localStorage.getItem("lancer.perfFeedback") === "true";
    } catch {}

    // Apply persisted display preferences so they take visual effect.
    applyFontFamily();
    applyDensity();
    applyMsgDisplay();
    // Re-attach the system-theme listener if "system" is the saved theme.
    if (theme === "system") applyTheme();

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
      upstreamRules = Array.isArray(proxyCfg.upstream_rules)
        ? proxyCfg.upstream_rules.map(u => ({
            host_pattern: u?.host_pattern || "",
            kind: u?.upstream?.kind || u?.kind || "Http",
            host: u?.upstream?.host || u?.host || "",
            port: typeof (u?.upstream?.port ?? u?.port) === "number" ? (u?.upstream?.port ?? u?.port) : 8080,
            username: u?.upstream?.username || u?.username || "",
            password: u?.upstream?.password || u?.password || "",
          }))
        : [];
      clientTls = Array.isArray(proxyCfg.client_tls)
        ? proxyCfg.client_tls.map(c => ({
            host_pattern: c?.host_pattern || "",
            cert_pem_path: c?.cert_pem_path || "",
            key_pem_path: c?.key_pem_path || "",
          }))
        : [];
      connectTimeoutMs = typeof proxyCfg.connect_timeout_ms === "number" ? proxyCfg.connect_timeout_ms : 30000;
      readTimeoutMs = typeof proxyCfg.read_timeout_ms === "number" ? proxyCfg.read_timeout_ms : 30000;
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
  function addUpstreamRule() {
    upstreamRules = [...upstreamRules, { host_pattern: "", kind: "Http", host: "", port: 8080, username: "", password: "" }];
  }
  function removeUpstreamRule(i) { upstreamRules = upstreamRules.filter((_, idx) => idx !== i); }
  function addClientTls() {
    clientTls = [...clientTls, { host_pattern: "", cert_pem_path: "", key_pem_path: "" }];
  }
  function removeClientTls(i) { clientTls = clientTls.filter((_, idx) => idx !== i); }

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
    // Per-host upstream rules: preserve any original fields, overwrite known ones.
    const origRules = Array.isArray(proxyCfg?.upstream_rules) ? proxyCfg.upstream_rules : [];
    out.upstream_rules = upstreamRules
      .filter(u => u.host_pattern.trim())
      .map((u, i) => {
        const base = origRules[i] && typeof origRules[i] === "object" ? { ...origRules[i] } : {};
        const inner = {
          kind: u.kind,
          host: u.host.trim(),
          port: Number(u.port) || 0,
          username: u.username ? u.username : null,
          password: u.password ? u.password : null,
        };
        base.host_pattern = u.host_pattern.trim();
        // Match whichever shape the backend uses (nested `upstream` vs flat).
        if (origRules[i] && origRules[i].upstream !== undefined) {
          base.upstream = inner;
        } else if (origRules[i] && origRules[i].host !== undefined) {
          Object.assign(base, inner);
        } else {
          base.upstream = inner;
        }
        return base;
      });
    out.client_tls = clientTls
      .filter(c => c.host_pattern.trim() && c.cert_pem_path.trim())
      .map(c => ({
        host_pattern: c.host_pattern.trim(),
        cert_pem_path: c.cert_pem_path.trim(),
        key_pem_path: c.key_pem_path.trim(),
      }));
    out.connect_timeout_ms = Number(connectTimeoutMs) || 0;
    out.read_timeout_ms = Number(readTimeoutMs) || 0;
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

  function resolveTheme(t) {
    if (t === "system") {
      try {
        return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
      } catch { return "light"; }
    }
    return t;
  }

  function applyTheme() {
    try {
      document.body.setAttribute("data-theme", resolveTheme(theme));
      // App.svelte's initial-load only understands "dark"/"light" (it forces
      // light for anything else), so persist the RESOLVED value under the key
      // it reads to avoid a forced-light flash on full reload. The raw choice
      // (which may be "system") is kept in a sidecar key so this view can
      // restore the picker and re-attach the follow-OS listener on remount.
      localStorage.setItem("lancer.theme", resolveTheme(theme));
      localStorage.setItem("lancer.theme.mode", theme);
      // Track OS changes while in "system" mode.
      if (_mqlDark) {
        try { _mqlDark.removeEventListener("change", onSystemThemeChange); } catch {}
        _mqlDark = null;
      }
      if (theme === "system") {
        _mqlDark = window.matchMedia("(prefers-color-scheme: dark)");
        try { _mqlDark.addEventListener("change", onSystemThemeChange); } catch {}
      }
    } catch {}
  }

  function onSystemThemeChange() {
    if (theme === "system") {
      try { document.body.setAttribute("data-theme", resolveTheme("system")); } catch {}
    }
  }

  function applyFontSize() {
    try {
      document.documentElement.style.fontSize = fontSize;
      localStorage.setItem("lancer.fontSize", fontSize);
    } catch {}
  }

  const FONT_STACKS = {
    system: '"Segoe UI", -apple-system, BlinkMacSystemFont, "Helvetica Neue", Arial, sans-serif',
    mono: '"Cascadia Code", "JetBrains Mono", "SF Mono", Consolas, "Liberation Mono", Menlo, monospace',
    serif: 'Georgia, "Times New Roman", Times, serif',
  };

  function applyFontFamily() {
    try {
      const stack = FONT_STACKS[fontFamily] || FONT_STACKS.system;
      document.documentElement.style.setProperty("--ui-font", stack);
      document.body.style.fontFamily = stack;
      localStorage.setItem("lancer.fontFamily", fontFamily);
    } catch {}
  }

  function applyDensity() {
    try {
      document.body.setAttribute("data-density", density);
      localStorage.setItem("lancer.density", density);
    } catch {}
  }

  const MSG_FONT_STACKS = {
    mono: '"Cascadia Code", "JetBrains Mono", "SF Mono", Consolas, "Liberation Mono", Menlo, monospace',
    system: '"Segoe UI", -apple-system, BlinkMacSystemFont, "Helvetica Neue", Arial, sans-serif',
  };

  function applyMsgDisplay() {
    try {
      const root = document.documentElement.style;
      root.setProperty("--msg-font", MSG_FONT_STACKS[msgFont] || MSG_FONT_STACKS.mono);
      root.setProperty("--msg-tab-size", String(Number(msgTabSize) || 4));
      root.setProperty("--msg-wrap", msgLineWrap ? "pre-wrap" : "pre");
      localStorage.setItem("lancer.msg.font", msgFont);
      localStorage.setItem("lancer.msg.tabSize", String(Number(msgTabSize) || 4));
      localStorage.setItem("lancer.msg.lineWrap", String(!!msgLineWrap));
    } catch {}
  }

  function saveLogger() {
    try {
      localStorage.setItem("lancer.logger.maxRows", String(Number(loggerMaxRows) || 1000));
      localStorage.setItem("lancer.logger.autoScroll", String(!!loggerAutoScroll));
      localStorage.setItem("lancer.logger.captureProxy", String(!!loggerCaptureProxy));
      localStorage.setItem("lancer.logger.captureTools", String(!!loggerCaptureTools));
    } catch {}
  }

  function savePerfFeedback() {
    try { localStorage.setItem("lancer.perfFeedback", String(!!perfFeedback)); } catch {}
  }

  function saveUpdateChannel() {
    try { localStorage.setItem("lancer.updateChannel", updateChannel); } catch {}
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
    if (category === "display") { applyTheme(); applyFontSize(); applyFontFamily(); applyDensity(); applyMsgDisplay(); flashSaved(); return; }
    if (category === "logger")  { saveLogger(); flashSaved(); return; }
    if (category === "updates") { saveAutoCheck(); saveUpdateChannel(); flashSaved(); return; }
    if (category === "misc")    { savePerfFeedback(); flashSaved(); return; }
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

        <div class="settings-card">
          <div class="card-title">Per-host upstream rules</div>
          {#each upstreamRules as u, i}
            <div class="setting-row">
              <span class="setting-label">{i === 0 ? "Rules" : ""}</span>
              <div class="setting-controls">
                <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap;">
                  <input bind:value={u.host_pattern} style="width:160px" placeholder="host or *.example.com" />
                  <select bind:value={u.kind} style="width:100px">
                    <option value="Http">HTTP</option>
                    <option value="Socks5">SOCKS5</option>
                  </select>
                  <input bind:value={u.host} style="width:160px" placeholder="proxy.example.com" />
                  <input type="number" bind:value={u.port} style="width:80px" min="1" max="65535" placeholder="8080" />
                  <input bind:value={u.username} style="width:110px" placeholder="user (opt)" autocomplete="off" />
                  <input type="password" bind:value={u.password} style="width:110px" placeholder="pass (opt)" autocomplete="off" />
                  <button class="btn-row-remove" type="button" on:click={() => removeUpstreamRule(i)}>Remove</button>
                </div>
              </div>
            </div>
          {/each}
          {#if upstreamRules.length === 0}
            <div class="dim" style="font-size:12px;margin-bottom:10px;">No per-host upstream rules — the default upstream proxy above applies to all traffic.</div>
          {/if}
          <button class="btn-secondary" type="button" on:click={addUpstreamRule}>+ Add rule</button>
          <span class="setting-hint" style="display:block;margin-top:6px;">First matching rule wins; falls back to the default upstream proxy.</span>
        </div>

        <div class="settings-card">
          <div class="card-title">Connection details</div>
          <div class="setting-row">
            <label class="setting-label" for="net-connect-to">Connect timeout (ms)</label>
            <div class="setting-controls">
              <input id="net-connect-to" type="number" bind:value={connectTimeoutMs} style="width:120px" min="0" max="600000" />
              <span class="setting-hint">Time to establish a TCP/TLS connection before giving up</span>
            </div>
          </div>
          <div class="setting-row">
            <label class="setting-label" for="net-read-to">Response timeout (ms)</label>
            <div class="setting-controls">
              <input id="net-read-to" type="number" bind:value={readTimeoutMs} style="width:120px" min="0" max="600000" />
              <span class="setting-hint">Time to wait for the upstream response</span>
            </div>
          </div>
        </div>

        <div class="settings-card">
          <div class="card-title">Client TLS certificates (per-host)</div>
          {#each clientTls as c, i}
            <div class="setting-row">
              <span class="setting-label">{i === 0 ? "Certificates" : ""}</span>
              <div class="setting-controls">
                <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap;">
                  <input bind:value={c.host_pattern} style="width:160px" placeholder="host or *.example.com" />
                  <input bind:value={c.cert_pem_path} style="width:220px" placeholder="/path/to/client-cert.pem" />
                  <input bind:value={c.key_pem_path} style="width:220px" placeholder="/path/to/client-key.pem" />
                  <button class="btn-row-remove" type="button" on:click={() => removeClientTls(i)}>Remove</button>
                </div>
              </div>
            </div>
          {/each}
          {#if clientTls.length === 0}
            <div class="dim" style="font-size:12px;margin-bottom:10px;">No client certificates configured.</div>
          {/if}
          <button class="btn-secondary" type="button" on:click={addClientTls}>+ Add certificate</button>
          <span class="setting-hint" style="display:block;margin-top:6px;">Presented for outbound mutual-TLS when the host matches.</span>
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

      {:else if category === "logger"}
        <div class="settings-card">
          <div class="card-title">Logger options</div>
          <div class="setting-row">
            <span class="setting-label">Capture from</span>
            <div class="setting-controls">
              <label class="check-label">
                <input type="checkbox" bind:checked={loggerCaptureProxy} />
                Proxy traffic
              </label>
              <label class="check-label">
                <input type="checkbox" bind:checked={loggerCaptureTools} />
                Tool traffic (Repeater / Intruder / Scanner)
              </label>
            </div>
          </div>
          <div class="setting-row">
            <label class="setting-label" for="log-max-rows">Max rows</label>
            <div class="setting-controls">
              <input id="log-max-rows" type="number" bind:value={loggerMaxRows} style="width:100px" min="50" max="100000" />
              <span class="setting-hint">Older entries are dropped once this limit is reached</span>
            </div>
          </div>
          <div class="setting-row">
            <span class="setting-label">Behaviour</span>
            <div class="setting-controls">
              <label class="check-label">
                <input type="checkbox" bind:checked={loggerAutoScroll} />
                Auto-scroll to newest entry
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
                <option value="system">System</option>
              </select>
              <span class="setting-hint">Applies immediately{theme === "system" ? " — follows your OS preference" : ""}</span>
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
          <div class="setting-row">
            <label class="setting-label" for="font-family-sel">Font family</label>
            <div class="setting-controls">
              <select id="font-family-sel" bind:value={fontFamily} on:change={applyFontFamily} style="width:140px">
                <option value="system">System UI</option>
                <option value="mono">Monospace</option>
                <option value="serif">Serif</option>
              </select>
            </div>
          </div>
          <div class="setting-row">
            <label class="setting-label" for="density-sel">Look and feel</label>
            <div class="setting-controls">
              <select id="density-sel" bind:value={density} on:change={applyDensity} style="width:140px">
                <option value="compact">Compact</option>
                <option value="comfortable">Comfortable</option>
                <option value="spacious">Spacious</option>
              </select>
              <span class="setting-hint">Adjusts row spacing and density</span>
            </div>
          </div>
        </div>

        <div class="settings-card">
          <div class="card-title">HTTP message display</div>
          <div class="setting-row">
            <label class="setting-label" for="msg-font-sel">Message font</label>
            <div class="setting-controls">
              <select id="msg-font-sel" bind:value={msgFont} on:change={applyMsgDisplay} style="width:140px">
                <option value="mono">Monospace</option>
                <option value="system">System UI</option>
              </select>
              <span class="setting-hint">Font for raw request / response viewers</span>
            </div>
          </div>
          <div class="setting-row">
            <label class="setting-label" for="msg-tab-size">Tab size</label>
            <div class="setting-controls">
              <input id="msg-tab-size" type="number" bind:value={msgTabSize} on:change={applyMsgDisplay} style="width:80px" min="1" max="16" />
              <span class="setting-hint">Number of spaces a tab renders as</span>
            </div>
          </div>
          <div class="setting-row">
            <span class="setting-label">Line wrap</span>
            <div class="setting-controls">
              <label class="check-label">
                <input type="checkbox" bind:checked={msgLineWrap} on:change={applyMsgDisplay} />
                Wrap long lines in message viewers
              </label>
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
          <div class="setting-row">
            <label class="setting-label" for="update-channel">Channel</label>
            <div class="setting-controls">
              <select id="update-channel" bind:value={updateChannel} on:change={saveUpdateChannel} style="width:140px">
                <option value="stable">Stable</option>
                <option value="beta">Beta</option>
              </select>
              <span class="setting-hint">Beta receives pre-release builds earlier</span>
            </div>
          </div>
        </div>

      {:else if category === "misc"}
        <div class="settings-card">
          <div class="card-title">About Lancer</div>
          <div class="about-row">
            <svg width="40" height="40" viewBox="0 0 40 40" fill="none">
              <polygon points="20,4 8,22 17,22 17,36 32,18 22,18" fill="#e5481d"/>
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

        <div class="settings-card">
          <div class="card-title">Privacy</div>
          <div class="setting-row">
            <span class="setting-label">Performance feedback</span>
            <div class="setting-controls">
              <label class="check-label">
                <input type="checkbox" bind:checked={perfFeedback} on:change={savePerfFeedback} />
                Submit anonymous performance feedback
              </label>
              <span class="setting-hint">Stored locally only — no telemetry is transmitted</span>
            </div>
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
    background: var(--surface-2);
    border-right: 1px solid var(--border);
    display: flex; flex-direction: column;
    overflow-y: auto;
  }
  .settings-left-title {
    font-size: 11px; font-weight: 700;
    text-transform: uppercase; letter-spacing: 0.07em;
    color: var(--text-muted);
    padding: 12px 14px 8px;
    border-bottom: 1px solid var(--border);
  }
  .cat-item {
    padding: 9px 14px;
    background: transparent;
    border: none; border-radius: 0;
    border-bottom: 1px solid var(--border);
    color: var(--text-2); font-size: 13px;
    text-align: left; cursor: pointer;
    transition: background 0.1s, color 0.1s;
  }
  .cat-item:hover { background: var(--border); }
  .cat-active {
    background: #ffffff !important;
    color: var(--accent) !important;
    font-weight: 600;
    border-left: 3px solid var(--accent);
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
    background: var(--surface-2);
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }
  .settings-page-title {
    font-size: 14px; font-weight: 600; color: var(--text);
  }
  .btn-save {
    background: var(--accent); color: #fff;
    border: none; border-radius: 3px;
    padding: 5px 14px; font-size: 13px; cursor: pointer;
  }
  .btn-save:hover { background: var(--accent-hover); }

  .settings-body {
    flex: 1; overflow-y: auto;
    padding: 16px 18px;
  }

  .settings-card {
    background: var(--surface-1);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 16px 18px;
    margin-bottom: 14px;
  }
  .card-title {
    font-size: 11px; font-weight: 700;
    text-transform: uppercase; letter-spacing: 0.06em;
    color: var(--text-muted); margin-bottom: 14px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
  }
  .setting-row {
    display: flex; align-items: flex-start; gap: 16px;
    margin-bottom: 12px; flex-wrap: wrap;
  }
  .setting-row:last-child { margin-bottom: 0; }
  .setting-label {
    font-size: 13px; color: var(--text-2);
    min-width: 120px; padding-top: 5px; flex-shrink: 0;
    font-weight: 500;
  }
  .setting-controls {
    display: flex; flex-direction: column; gap: 6px;
  }
  .setting-hint { font-size: 11px; color: var(--text-muted); }
  .check-label {
    display: flex; align-items: center; gap: 7px;
    font-size: 13px; color: var(--text-2); cursor: pointer;
  }
  .check-label input { cursor: pointer; accent-color: var(--accent); }

  /* About */
  .about-row {
    display: flex; gap: 16px; align-items: flex-start; margin-bottom: 14px;
  }
  .about-name { font-size: 18px; font-weight: 700; color: var(--text); margin-bottom: 2px; }
  .about-version { font-size: 12px; margin-bottom: 6px; }
  .about-desc { font-size: 13px; line-height: 1.5; max-width: 420px; }
  .about-info { display: flex; flex-direction: column; }
  .about-actions { display: flex; gap: 8px; }
  .btn-secondary {
    background: var(--surface-2); color: var(--text);
    border: 1px solid var(--border-strong); border-radius: 3px;
    padding: 5px 12px; font-size: 13px; cursor: pointer;
  }
  .btn-secondary:hover { background: var(--surface-3); }

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
    background: var(--surface-2); color: #c0392b;
    border: 1px solid #d8c0c0; border-radius: 3px;
    padding: 4px 9px; font-size: 12px; cursor: pointer;
  }
  .btn-row-remove:hover { background: #f7e0e0; }

  .settings-card textarea,
  .settings-card select {
    font: inherit; font-size: 13px;
    border: 1px solid var(--border-strong); border-radius: 3px;
    padding: 4px 6px; color: var(--text); background: #fff;
  }
  .settings-card textarea { resize: vertical; }

  /* Look and feel (density) — scales spacing across the settings surface and
     exposes --density-pad / --density-gap for other views to opt into. */
  :global([data-density="compact"])    { --density-pad: 4px;  --density-gap: 5px; }
  :global([data-density="comfortable"]){ --density-pad: 8px;  --density-gap: 8px; }
  :global([data-density="spacious"])   { --density-pad: 14px; --density-gap: 13px; }
  :global([data-density="compact"]) .settings-card   { padding: 10px 12px; margin-bottom: 9px; }
  :global([data-density="compact"]) .setting-row     { margin-bottom: 7px; }
  :global([data-density="spacious"]) .settings-card  { padding: 22px 24px; margin-bottom: 20px; }
  :global([data-density="spacious"]) .setting-row    { margin-bottom: 18px; }
</style>
