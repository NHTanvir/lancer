<script>
  import { onMount } from "svelte";

  // ── Tab state ────────────────────────────────────────────────────────────────
  let tabs = [{ id: 1, label: "1" }];
  let activeTab = 1;
  let nextId = 2;

  let tabStates = {
    1: {
      request: `GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Lancer/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n`,
      response: "",
      rawResponse: "",
      scheme: "https",
      host: "example.com",
      port: "443",
      history: [],
      histIdx: -1,
      reqSubtab: "raw",
      respSubtab: "pretty",
      layout: "side-by-side",   // side-by-side | stacked | inspector-only
    },
  };

  // ── Send state ────────────────────────────────────────────────────────────────
  let sending = false;
  let cancelled = false;
  let controller = null;

  // ── Inspector ─────────────────────────────────────────────────────────────────
  let inspectorOpen = true;

  // Inspector sections: collapsed state
  let sectionsCollapsed = {
    reqAttributes: false,
    reqHeaders: false,
    reqBody: false,
    respHeaders: false,
  };

  // Context menu
  let ctxMenu = null;

  // Burp AI tooltip
  let showAiTooltip = false;

  // ── Derived ───────────────────────────────────────────────────────────────────
  $: state = tabStates[activeTab] || tabStates[Object.keys(tabStates)[0]];
  $: inspectorData = parseInspector(state?.request || "");
  $: respInspectorData = parseResponseHeaders(state?.response || "");
  $: targetUrl = state ? `${state.scheme}://${state.host}${state.port && state.port !== defaultPort(state.scheme) ? ":" + state.port : ""}` : "";

  function defaultPort(scheme) {
    return scheme === "https" ? "443" : scheme === "http" ? "80" : "";
  }

  // ── Parsers ───────────────────────────────────────────────────────────────────
  function parseInspector(raw) {
    const lines = raw.split(/\r?\n/);
    const firstLine = lines[0] || "";
    const parts = firstLine.split(" ");
    const method = parts[0] || "";
    const fullPath = parts[1] || "/";
    const version = parts[2] || "HTTP/1.1";

    const headers = [];
    const cookies = [];
    const queryParams = [];
    let host = "";

    if (fullPath.includes("?")) {
      const qs = fullPath.split("?")[1] || "";
      for (const pair of qs.split("&")) {
        const [k, v] = pair.split("=");
        if (k) queryParams.push({ name: decodeURIComponent(k || ""), value: decodeURIComponent(v || "") });
      }
    }

    let i = 1;
    for (; i < lines.length; i++) {
      const line = lines[i];
      if (!line.trim()) break;
      const colonIdx = line.indexOf(":");
      if (colonIdx > 0) {
        const name = line.slice(0, colonIdx).trim();
        const value = line.slice(colonIdx + 1).trim();
        headers.push({ name, value });
        if (name.toLowerCase() === "host") host = value;
        if (name.toLowerCase() === "cookie") {
          for (const c of value.split(";")) {
            const [cn, cv] = c.trim().split("=");
            if (cn) cookies.push({ name: cn.trim(), value: (cv || "").trim() });
          }
        }
      }
    }

    const bodyLines = lines.slice(i + 1);
    const body = bodyLines.join("\n").trim();
    const bodyParams = [];
    if (body && headers.some(h => h.name.toLowerCase() === "content-type" && h.value.includes("urlencoded"))) {
      for (const pair of body.split("&")) {
        const [k, v] = pair.split("=");
        if (k) bodyParams.push({ name: decodeURIComponent(k || ""), value: decodeURIComponent(v || "") });
      }
    }

    return { method, fullPath, version, host, headers, cookies, queryParams, bodyParams, body };
  }

  function parseResponseHeaders(raw) {
    if (!raw) return { statusLine: "", headers: [] };
    const lines = raw.split(/\r?\n/);
    const statusLine = lines[0] || "";
    const headers = [];
    for (let i = 1; i < lines.length; i++) {
      const line = lines[i];
      if (!line.trim()) break;
      const colonIdx = line.indexOf(":");
      if (colonIdx > 0) {
        headers.push({
          name: line.slice(0, colonIdx).trim(),
          value: line.slice(colonIdx + 1).trim(),
        });
      }
    }
    return { statusLine, headers };
  }

  // ── Syntax highlight the request for display ──────────────────────────────────
  function highlightRequest(raw) {
    if (!raw) return "";
    const lines = raw.split(/\r?\n/);
    return lines.map((line, idx) => {
      if (idx === 0) {
        // Request line: METHOD PATH VERSION
        const m = line.match(/^([A-Z]+)(\s+)(.+?)(\s+)(HTTP\/\S+)$/);
        if (m) {
          return `<span class="hl-method">${esc(m[1])}</span>${esc(m[2])}<span class="hl-path">${esc(m[3])}</span>${esc(m[4])}<span class="hl-version">${esc(m[5])}</span>`;
        }
        return `<span class="hl-method">${esc(line)}</span>`;
      }
      if (!line.trim()) return "";
      const colon = line.indexOf(":");
      if (colon > 0) {
        const name = line.slice(0, colon);
        const val = line.slice(colon + 1);
        return `<span class="hl-hname">${esc(name)}</span><span class="hl-colon">:</span><span class="hl-hval">${esc(val)}</span>`;
      }
      return `<span class="hl-body">${esc(line)}</span>`;
    }).join("\n");
  }

  function highlightResponse(raw) {
    if (!raw) return "";
    const lines = raw.split(/\r?\n/);
    let inHeaders = true;
    return lines.map((line, idx) => {
      if (idx === 0) {
        return `<span class="hl-version">${esc(line)}</span>`;
      }
      if (inHeaders) {
        if (!line.trim()) { inHeaders = false; return ""; }
        const colon = line.indexOf(":");
        if (colon > 0) {
          const name = line.slice(0, colon);
          const val = line.slice(colon + 1);
          return `<span class="hl-hname">${esc(name)}</span><span class="hl-colon">:</span><span class="hl-hval">${esc(val)}</span>`;
        }
      }
      return `<span class="hl-body">${esc(line)}</span>`;
    }).join("\n");
  }

  function esc(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  // Build line-numbered HTML for the code view
  function buildLineNumbers(raw) {
    const lines = (raw || "").split(/\r?\n/);
    return lines.map((_, i) => `<div class="ln">${i + 1}</div>`).join("");
  }

  // ── Tab management ─────────────────────────────────────────────────────────────
  function addTab() {
    const id = nextId++;
    const label = String(tabs.length + 1);
    tabs = [...tabs, { id, label }];
    tabStates[id] = {
      request: `GET / HTTP/1.1\r\nHost: \r\nUser-Agent: Lancer/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n`,
      response: "", rawResponse: "",
      scheme: "https", host: "", port: "443",
      history: [], histIdx: -1,
      reqSubtab: "raw", respSubtab: "pretty",
      layout: "side-by-side",
    };
    activeTab = id;
  }

  function closeTab(id) {
    if (tabs.length === 1) return;
    const idx = tabs.findIndex(t => t.id === id);
    tabs = tabs.filter(t => t.id !== id);
    delete tabStates[id];
    if (activeTab === id) {
      activeTab = tabs[Math.max(0, idx - 1)].id;
    }
  }

  // ── State setters ──────────────────────────────────────────────────────────────
  function setScheme(v) {
    tabStates[activeTab].scheme = v;
    if (v === "https" && tabStates[activeTab].port === "80") tabStates[activeTab].port = "443";
    if (v === "http" && tabStates[activeTab].port === "443") tabStates[activeTab].port = "80";
    tabStates = tabStates;
  }
  function setHost(v) { tabStates[activeTab].host = v; tabStates = tabStates; }
  function setPort(v) { tabStates[activeTab].port = v; tabStates = tabStates; }
  function setRequest(v) { tabStates[activeTab].request = v; tabStates = tabStates; }
  function setLayout(v) { tabStates[activeTab].layout = v; tabStates = tabStates; }

  // ── History navigation ─────────────────────────────────────────────────────────
  function histBack() {
    const s = tabStates[activeTab];
    if (s.histIdx < s.history.length - 1) {
      s.histIdx++;
      s.request = s.history[s.histIdx].request;
      s.response = s.history[s.histIdx].response;
      tabStates = tabStates;
    }
  }

  function histForward() {
    const s = tabStates[activeTab];
    if (s.histIdx > 0) {
      s.histIdx--;
      s.request = s.history[s.histIdx].request;
      s.response = s.history[s.histIdx].response;
      tabStates = tabStates;
    }
  }

  // ── Send / Cancel ──────────────────────────────────────────────────────────────
  async function send() {
    if (sending) return;
    const s = tabStates[activeTab];
    sending = true;
    cancelled = false;
    s.response = "";
    s.rawResponse = "";
    tabStates = tabStates;
    controller = new AbortController();
    try {
      const r = await fetch("/api/v1/repeater", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          request: s.request,
          scheme: s.scheme,
          host: s.host,
          port: parseInt(s.port, 10) || 443,
        }),
        signal: controller.signal,
      });
      const data = await r.json();
      const rawResp = data.raw || (
        `HTTP/1.1 ${data.status}\n` +
        (data.headers || []).map(h => `${h.name}: ${h.value}`).join("\n") +
        "\n\n" + (data.body || "")
      );
      s.rawResponse = rawResp;
      s.response = rawResp;
      s.history = [{ request: s.request, response: s.response }, ...s.history].slice(0, 50);
      s.histIdx = -1;
      // Update tab label with host
      const t = tabs.find(x => x.id === activeTab);
      if (t && s.host) t.label = s.host.length > 18 ? s.host.slice(0, 18) + "…" : s.host;
      tabs = tabs;
      tabStates = tabStates;
    } catch (e) {
      tabStates[activeTab].response = cancelled ? "(request cancelled)" : `Error: ${e.message || e}`;
      tabStates = tabStates;
    } finally {
      sending = false;
      controller = null;
    }
  }

  function cancel() {
    if (controller) { cancelled = true; controller.abort(); }
  }

  // ── Pretty format ──────────────────────────────────────────────────────────────
  function prettyResponse(raw) {
    if (!raw) return "";
    const parts = raw.split(/\r?\n\r?\n/);
    if (parts.length >= 2) {
      const body = parts.slice(1).join("\n\n");
      try {
        const parsed = JSON.parse(body);
        return parts[0] + "\n\n" + JSON.stringify(parsed, null, 2);
      } catch {}
    }
    return raw;
  }

  function extractResponseBody(raw) {
    if (!raw) return "";
    const idx = raw.indexOf("\r\n\r\n");
    const nlIdx = idx >= 0 ? idx + 4 : raw.indexOf("\n\n") >= 0 ? raw.indexOf("\n\n") + 2 : -1;
    return nlIdx >= 0 ? raw.slice(nlIdx) : "";
  }

  // ── Context menu ───────────────────────────────────────────────────────────────
  function onContextMenu(e) {
    e.preventDefault();
    ctxMenu = { x: e.clientX, y: e.clientY };
  }

  function closeCtx() { ctxMenu = null; }

  function ctxCopyUrl() {
    const s = tabStates[activeTab];
    const url = `${s.scheme}://${s.host}:${s.port}${inspectorData.fullPath}`;
    navigator.clipboard.writeText(url).catch(() => {});
    closeCtx();
  }

  function ctxCopyCurl() {
    const s = tabStates[activeTab];
    const url = `${s.scheme}://${s.host}:${s.port}${inspectorData.fullPath}`;
    const hdrs = inspectorData.headers.map(h => `-H '${h.name}: ${h.value}'`).join(" ");
    const mth = inspectorData.method !== "GET" ? `-X ${inspectorData.method}` : "";
    const bdy = inspectorData.body ? `--data '${inspectorData.body.replace(/'/g, "\\'")}'` : "";
    const curl = `curl ${mth} ${hdrs} ${bdy} '${url}'`.replace(/  +/g, " ").trim();
    navigator.clipboard.writeText(curl).catch(() => {});
    closeCtx();
  }

  function ctxSendToIntruder() {
    const s = tabStates[activeTab];
    localStorage.setItem("intruder_prefill", JSON.stringify({
      request: s.request, scheme: s.scheme, host: s.host, port: s.port
    }));
    window.dispatchEvent(new CustomEvent("lancer:navigate", { detail: "intruder" }));
    closeCtx();
  }

  function ctxChangeMethod() {
    const methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
    const s = tabStates[activeTab];
    const next = methods[(methods.indexOf(inspectorData.method) + 1) % methods.length];
    s.request = s.request.replace(/^[A-Z]+/, next);
    tabStates = tabStates;
    closeCtx();
  }

  function ctxAddToSiteMap() {
    const s = tabStates[activeTab];
    window.dispatchEvent(new CustomEvent("lancer:siteMapAdd", {
      detail: { url: `${s.scheme}://${s.host}${inspectorData.fullPath}`, method: inspectorData.method }
    }));
    closeCtx();
  }

  function ctxPasteHostAsRequest() {
    navigator.clipboard.readText().then(text => {
      const m = text.trim().match(/^(https?):\/\/([^/:]+)(?::(\d+))?(\/.*)?$/);
      if (m) {
        const [, scheme, host, port, path] = m;
        const p = port || (scheme === "https" ? "443" : "80");
        tabStates[activeTab].scheme = scheme;
        tabStates[activeTab].host = host;
        tabStates[activeTab].port = p;
        tabStates[activeTab].request = `GET ${path || "/"} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: Lancer/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n`;
        tabStates = tabStates;
      }
    }).catch(() => {});
    closeCtx();
  }

  // ── onMount ────────────────────────────────────────────────────────────────────
  onMount(() => {
    const prefill = localStorage.getItem("repeater_prefill");
    if (prefill) {
      try {
        const data = JSON.parse(prefill);
        if (data.request) {
          tabStates[activeTab].request = data.request;
          if (data.scheme) tabStates[activeTab].scheme = data.scheme;
          if (data.host)   tabStates[activeTab].host   = data.host;
          if (data.port)   tabStates[activeTab].port   = String(data.port);
          tabStates = tabStates;
        }
        localStorage.removeItem("repeater_prefill");
      } catch {}
    }
    document.addEventListener("click", closeCtx);
    return () => document.removeEventListener("click", closeCtx);
  });
</script>

<!-- ═══════════════════════════ MARKUP ═══════════════════════════ -->
<div class="view">

  <!-- 1. Session tab bar -->
  <div class="rep-tabbar">
    {#each tabs as t (t.id)}
      <button
        class="rep-tab"
        class:rep-tab-active={activeTab === t.id}
        on:click={() => (activeTab = t.id)}
      >
        <span class="tab-label">{t.label}</span>
        <!-- svelte-ignore a11y-click-events-have-key-events -->
        <span
          class="tab-close"
          title="Close tab"
          on:click|stopPropagation={() => closeTab(t.id)}
        >×</span>
      </button>
    {/each}
    <button class="rep-tab-add" on:click={addTab} title="Open new tab">+</button>
  </div>

  {#if tabStates[activeTab]}
    <!-- 2. Button / toolbar row -->
    <div class="toolbar-row">
      <!-- Send -->
      <button class="btn-send" on:click={send} disabled={sending}>
        {#if sending}
          <svg class="spin" width="11" height="11" viewBox="0 0 12 12" fill="none">
            <circle cx="6" cy="6" r="4.5" stroke="#fff" stroke-width="1.5" stroke-dasharray="14 8"/>
          </svg>
          Sending
        {:else}
          Send
        {/if}
      </button>

      <!-- Gear -->
      <button class="toolbar-btn icon-btn" title="Repeater settings">
        <svg width="14" height="14" viewBox="0 0 16 16" fill="none">
          <circle cx="8" cy="8" r="2.8" stroke="currentColor" stroke-width="1.4"/>
          <path d="M8 1.5v2M8 12.5v2M1.5 8h2M12.5 8h2M3.4 3.4l1.42 1.42M11.18 11.18l1.42 1.42M3.4 12.6l1.42-1.42M11.18 4.82l1.42-1.42"
            stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/>
        </svg>
      </button>

      <!-- Cancel -->
      <button class="toolbar-btn btn-cancel" on:click={cancel} disabled={!sending}>Cancel</button>

      <div class="toolbar-sep"></div>

      <!-- History back -->
      <button
        class="toolbar-btn nav-btn"
        title="Previous request"
        on:click={histBack}
        disabled={tabStates[activeTab].histIdx >= tabStates[activeTab].history.length - 1}
      >
        <svg width="9" height="9" viewBox="0 0 10 10"><path d="M7 2L3 5l4 3" stroke="currentColor" stroke-width="1.4" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>
        <svg width="7" height="7" viewBox="0 0 8 8"><path d="M1 3l3 3 3-3" stroke="currentColor" stroke-width="1.3" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>
      </button>

      <!-- History forward -->
      <button
        class="toolbar-btn nav-btn"
        title="Next request"
        on:click={histForward}
        disabled={tabStates[activeTab].histIdx <= 0}
      >
        <svg width="9" height="9" viewBox="0 0 10 10"><path d="M3 2l4 3-4 3" stroke="currentColor" stroke-width="1.4" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>
        <svg width="7" height="7" viewBox="0 0 8 8"><path d="M1 3l3 3 3-3" stroke="currentColor" stroke-width="1.3" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>
      </button>

      <div style="flex:1"></div>

      <!-- Burp AI (stub) -->
      <div class="burp-ai-wrap">
        <button
          class="toolbar-btn btn-ai"
          on:mouseenter={() => (showAiTooltip = true)}
          on:mouseleave={() => (showAiTooltip = false)}
        >
          <svg width="12" height="12" viewBox="0 0 14 14" fill="none">
            <path d="M7 1l1.2 3.8H12L9 7.3l1.2 3.7L7 9.1 3.8 11l1.2-3.7L2 4.8h3.8z"
              fill="currentColor" opacity="0.9"/>
          </svg>
          Burp AI
        </button>
        {#if showAiTooltip}
          <div class="ai-tooltip">Coming soon</div>
        {/if}
      </div>
    </div>

    <!-- 3. Target / URL bar (inside request pane area, full width) -->
    <div class="target-bar">
      <!-- Lock icon -->
      {#if tabStates[activeTab].scheme === "https"}
        <svg class="lock-icon" width="13" height="13" viewBox="0 0 14 14" fill="none" title="HTTPS">
          <rect x="2.5" y="6.5" width="9" height="6" rx="1.2" stroke="#27a745" stroke-width="1.3"/>
          <path d="M4.5 6.5V4.5a2.5 2.5 0 0 1 5 0v2" stroke="#27a745" stroke-width="1.3" fill="none"/>
        </svg>
      {:else}
        <svg class="lock-icon" width="13" height="13" viewBox="0 0 14 14" fill="none" title="HTTP (insecure)">
          <rect x="2.5" y="6.5" width="9" height="6" rx="1.2" stroke="#e87700" stroke-width="1.3"/>
          <path d="M4.5 6.5V4.5a2.5 2.5 0 0 1 4.3-1.7" stroke="#e87700" stroke-width="1.3" fill="none" stroke-linecap="round"/>
        </svg>
      {/if}

      <!-- Scheme selector -->
      <select class="scheme-sel" value={tabStates[activeTab].scheme} on:change={e => setScheme(e.target.value)}>
        <option value="https">https</option>
        <option value="http">http</option>
        <option value="ws">ws</option>
        <option value="wss">wss</option>
      </select>
      <span class="url-sep">://</span>
      <input
        class="host-input"
        value={tabStates[activeTab].host}
        on:input={e => setHost(e.target.value)}
        placeholder="target.example.com"
        spellcheck="false"
      />
      <span class="url-sep port-sep">:</span>
      <input
        class="port-input"
        value={tabStates[activeTab].port}
        on:input={e => setPort(e.target.value)}
        placeholder="443"
        spellcheck="false"
      />
    </div>

    <!-- 4. Main three-pane body -->
    {@const layout = tabStates[activeTab].layout}
    <div class="body-root"
      class:layout-side={layout === "side-by-side"}
      class:layout-stacked={layout === "stacked"}
      class:layout-inspector={layout === "inspector-only"}
    >
      <!-- Request + Response column -->
      <div class="req-resp-col"
        class:col-stacked={layout === "stacked"}
        style={layout === "inspector-only" ? "display:none" : ""}
      >
        <!-- ── Request pane ── -->
        <div class="pane req-pane"
          class:pane-stacked-half={layout === "stacked"}
        >
          <div class="pane-header">
            <span class="pane-title">Request</span>
            <div class="subtab-row">
              <button class="stab" class:stab-active={tabStates[activeTab].reqSubtab==="pretty"}
                on:click={() => { tabStates[activeTab].reqSubtab="pretty"; tabStates=tabStates; }}>Pretty</button>
              <button class="stab" class:stab-active={tabStates[activeTab].reqSubtab==="raw"}
                on:click={() => { tabStates[activeTab].reqSubtab="raw"; tabStates=tabStates; }}>Raw</button>
              <button class="stab" class:stab-active={tabStates[activeTab].reqSubtab==="hex"}
                on:click={() => { tabStates[activeTab].reqSubtab="hex"; tabStates=tabStates; }}>Hex</button>
            </div>
            <div class="pane-icon-btns">
              <!-- Eye / search -->
              <button class="pane-icon-btn" title="Search">
                <svg width="12" height="12" viewBox="0 0 14 14" fill="none">
                  <circle cx="5.5" cy="5.5" r="3.5" stroke="currentColor" stroke-width="1.3"/>
                  <path d="M8.5 8.5l3 3" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/>
                </svg>
              </button>
              <!-- List (toggle line wrap) -->
              <button class="pane-icon-btn" title="Toggle word wrap">
                <svg width="12" height="12" viewBox="0 0 14 14" fill="none">
                  <path d="M2 3h10M2 7h7M2 11h5" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/>
                  <path d="M11 9.5v-2c0-.8-.7-1.5-1.5-1.5H8" stroke="currentColor" stroke-width="1.1" fill="none"/>
                  <path d="M9.5 8.5l1.5 1-1.5 1" stroke="currentColor" stroke-width="1.1" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
              </button>
            </div>
          </div>

          <!-- Code area with line numbers -->
          <div class="code-wrap" on:contextmenu={onContextMenu}>
            <div class="line-nums" aria-hidden="true">
              {#each (tabStates[activeTab].request || "").split(/\r?\n/) as _line, i}
                <div class="ln">{i + 1}</div>
              {/each}
            </div>
            <textarea
              class="code-area req-editable"
              value={tabStates[activeTab].request}
              on:input={e => setRequest(e.target.value)}
              spellcheck="false"
              autocorrect="off"
              autocomplete="off"
            ></textarea>
          </div>
        </div>

        <!-- ── Response pane ── -->
        <div class="pane resp-pane"
          class:pane-stacked-half={layout === "stacked"}
        >
          <div class="pane-header">
            <span class="pane-title">
              Response
              {#if state.response}
                <span class="resp-status">{state.response.split("\n")[0]}</span>
              {/if}
            </span>
            <div class="subtab-row">
              <button class="stab" class:stab-active={tabStates[activeTab].respSubtab==="pretty"}
                on:click={() => { tabStates[activeTab].respSubtab="pretty"; tabStates=tabStates; }}>Pretty</button>
              <button class="stab" class:stab-active={tabStates[activeTab].respSubtab==="raw"}
                on:click={() => { tabStates[activeTab].respSubtab="raw"; tabStates=tabStates; }}>Raw</button>
              <button class="stab" class:stab-active={tabStates[activeTab].respSubtab==="hex"}
                on:click={() => { tabStates[activeTab].respSubtab="hex"; tabStates=tabStates; }}>Hex</button>
              <button class="stab" class:stab-active={tabStates[activeTab].respSubtab==="render"}
                on:click={() => { tabStates[activeTab].respSubtab="render"; tabStates=tabStates; }}>Render</button>
            </div>
            <!-- Layout toggle icons (top-right of response pane) -->
            <div class="layout-btns">
              <button
                class="layout-btn" title="Side by side"
                class:layout-btn-active={layout === "side-by-side"}
                on:click={() => setLayout("side-by-side")}
              >
                <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
                  <rect x="1" y="2" width="5" height="10" rx="1" stroke="currentColor" stroke-width="1.2"/>
                  <rect x="8" y="2" width="5" height="10" rx="1" stroke="currentColor" stroke-width="1.2"/>
                </svg>
              </button>
              <button
                class="layout-btn" title="Stacked"
                class:layout-btn-active={layout === "stacked"}
                on:click={() => setLayout("stacked")}
              >
                <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
                  <rect x="1" y="1.5" width="12" height="4.5" rx="1" stroke="currentColor" stroke-width="1.2"/>
                  <rect x="1" y="8" width="12" height="4.5" rx="1" stroke="currentColor" stroke-width="1.2"/>
                </svg>
              </button>
              <button
                class="layout-btn" title="Inspector only"
                class:layout-btn-active={layout === "inspector-only"}
                on:click={() => setLayout("inspector-only")}
              >
                <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
                  <rect x="1" y="2" width="9" height="10" rx="1" stroke="currentColor" stroke-width="1.2"/>
                  <rect x="11.5" y="2" width="1.5" height="10" rx="0.5" fill="currentColor" opacity="0.5"/>
                </svg>
              </button>
            </div>
          </div>

          {#if tabStates[activeTab].respSubtab === "render"}
            {@const html = extractResponseBody(tabStates[activeTab].response)}
            {#if html}
              <iframe
                class="resp-frame"
                title="Rendered response"
                sandbox=""
                srcdoc={html}
              ></iframe>
            {:else}
              <div class="resp-empty">No response body to render.</div>
            {/if}
          {:else}
            <div class="code-wrap">
              {#if tabStates[activeTab].response}
                <div class="line-nums" aria-hidden="true">
                  {#each (tabStates[activeTab].respSubtab === "pretty"
                    ? prettyResponse(tabStates[activeTab].response)
                    : tabStates[activeTab].response).split(/\r?\n/) as _l, i}
                    <div class="ln">{i + 1}</div>
                  {/each}
                </div>
              {/if}
              <textarea
                class="code-area"
                readonly
                value={
                  tabStates[activeTab].respSubtab === "pretty"
                    ? prettyResponse(tabStates[activeTab].response)
                    : (tabStates[activeTab].response || "")
                }
                placeholder={sending ? "Waiting for response…" : "Send a request to see the response"}
                spellcheck="false"
              ></textarea>
            </div>
          {/if}
        </div>
      </div>

      <!-- ── Inspector panel ── -->
      <div class="inspector-panel" class:inspector-collapsed={!inspectorOpen}>
        <!-- Inspector header -->
        <div class="inspector-hdr">
          <span class="inspector-title">Inspector</span>
          <button
            class="inspector-toggle"
            title={inspectorOpen ? "Collapse Inspector" : "Expand Inspector"}
            on:click={() => (inspectorOpen = !inspectorOpen)}
          >
            <svg width="10" height="10" viewBox="0 0 10 10" fill="none"
              style="transform: rotate({inspectorOpen ? 0 : 180}deg); transition: transform 0.15s">
              <path d="M2 4l3 3 3-3" stroke="currentColor" stroke-width="1.4"
                fill="none" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
          </button>
        </div>

        {#if inspectorOpen}
          <div class="inspector-body">

            <!-- Request attributes -->
            <div class="isec">
              <!-- svelte-ignore a11y-click-events-have-key-events -->
              <div class="isec-hdr" on:click={() => (sectionsCollapsed.reqAttributes = !sectionsCollapsed.reqAttributes)}>
                <svg class="isec-arrow" width="8" height="8" viewBox="0 0 8 8" fill="none"
                  style="transform: rotate({sectionsCollapsed.reqAttributes ? -90 : 0}deg)">
                  <path d="M1 3l3 3 3-3" stroke="currentColor" stroke-width="1.4" fill="none" stroke-linecap="round"/>
                </svg>
                <span>Request attributes</span>
                <span class="isec-badge">3</span>
              </div>
              {#if !sectionsCollapsed.reqAttributes}
                <div class="isec-rows">
                  <div class="irow">
                    <span class="ikey">Method</span>
                    <span class="ival method-badge method-{inspectorData.method}">{inspectorData.method || "—"}</span>
                  </div>
                  <div class="irow">
                    <span class="ikey">Path</span>
                    <span class="ival mono" title={inspectorData.fullPath}>{inspectorData.fullPath || "/"}</span>
                  </div>
                  <div class="irow">
                    <span class="ikey">Version</span>
                    <span class="ival mono dim">{inspectorData.version || "HTTP/1.1"}</span>
                  </div>
                </div>
              {/if}
            </div>

            <!-- Request headers -->
            <div class="isec">
              <!-- svelte-ignore a11y-click-events-have-key-events -->
              <div class="isec-hdr" on:click={() => (sectionsCollapsed.reqHeaders = !sectionsCollapsed.reqHeaders)}>
                <svg class="isec-arrow" width="8" height="8" viewBox="0 0 8 8" fill="none"
                  style="transform: rotate({sectionsCollapsed.reqHeaders ? -90 : 0}deg)">
                  <path d="M1 3l3 3 3-3" stroke="currentColor" stroke-width="1.4" fill="none" stroke-linecap="round"/>
                </svg>
                <span>Request headers</span>
                <span class="isec-badge">{inspectorData.headers.length}</span>
              </div>
              {#if !sectionsCollapsed.reqHeaders && inspectorData.headers.length > 0}
                <div class="isec-rows">
                  {#each inspectorData.headers as h}
                    <div class="irow">
                      <span class="ikey mono orange" title={h.name}>{h.name}</span>
                      <span class="ival mono" title={h.value}>{h.value}</span>
                    </div>
                  {/each}
                </div>
              {:else if !sectionsCollapsed.reqHeaders}
                <div class="isec-empty">No headers</div>
              {/if}
            </div>

            <!-- Request body -->
            <div class="isec">
              <!-- svelte-ignore a11y-click-events-have-key-events -->
              <div class="isec-hdr" on:click={() => (sectionsCollapsed.reqBody = !sectionsCollapsed.reqBody)}>
                <svg class="isec-arrow" width="8" height="8" viewBox="0 0 8 8" fill="none"
                  style="transform: rotate({sectionsCollapsed.reqBody ? -90 : 0}deg)">
                  <path d="M1 3l3 3 3-3" stroke="currentColor" stroke-width="1.4" fill="none" stroke-linecap="round"/>
                </svg>
                <span>Request body</span>
                <span class="isec-badge">{inspectorData.body ? 1 : 0}</span>
              </div>
              {#if !sectionsCollapsed.reqBody}
                {#if inspectorData.bodyParams.length > 0}
                  <div class="isec-rows">
                    {#each inspectorData.bodyParams as p}
                      <div class="irow">
                        <span class="ikey mono orange" title={p.name}>{p.name}</span>
                        <span class="ival mono" title={p.value}>{p.value}</span>
                      </div>
                    {/each}
                  </div>
                {:else if inspectorData.body}
                  <div class="isec-body-preview">{inspectorData.body.slice(0, 200)}{inspectorData.body.length > 200 ? "…" : ""}</div>
                {:else}
                  <div class="isec-empty">No body</div>
                {/if}
              {/if}
            </div>

            <!-- Response headers (when response exists) -->
            {#if state.response}
              <div class="isec isec-resp">
                <!-- svelte-ignore a11y-click-events-have-key-events -->
                <div class="isec-hdr" on:click={() => (sectionsCollapsed.respHeaders = !sectionsCollapsed.respHeaders)}>
                  <svg class="isec-arrow" width="8" height="8" viewBox="0 0 8 8" fill="none"
                    style="transform: rotate({sectionsCollapsed.respHeaders ? -90 : 0}deg)">
                    <path d="M1 3l3 3 3-3" stroke="currentColor" stroke-width="1.4" fill="none" stroke-linecap="round"/>
                  </svg>
                  <span>Response headers</span>
                  <span class="isec-badge">{respInspectorData.headers.length}</span>
                </div>
                {#if !sectionsCollapsed.respHeaders && respInspectorData.headers.length > 0}
                  <div class="isec-rows">
                    {#each respInspectorData.headers as h}
                      <div class="irow">
                        <span class="ikey mono orange" title={h.name}>{h.name}</span>
                        <span class="ival mono" title={h.value}>{h.value}</span>
                      </div>
                    {/each}
                  </div>
                {:else if !sectionsCollapsed.respHeaders}
                  <div class="isec-empty">No headers</div>
                {/if}
              </div>
            {/if}

          </div>
        {/if}
      </div>
    </div>
  {/if}
</div>

<!-- ── Right-click context menu ── -->
{#if ctxMenu}
  <!-- svelte-ignore a11y-no-static-element-interactions -->
  <!-- svelte-ignore a11y-click-events-have-key-events -->
  <div class="ctx-overlay" on:click={closeCtx}></div>
  <div class="ctx-menu" style="left:{ctxMenu.x}px;top:{ctxMenu.y}px">
    <div class="ctx-item ctx-disabled">Scan</div>
    <div class="ctx-sep"></div>
    <div class="ctx-item" on:click={ctxSendToIntruder}>Send to Intruder <span class="ctx-shortcut">Ctrl+I</span></div>
    <div class="ctx-item ctx-disabled">Send to Sequencer</div>
    <div class="ctx-item ctx-disabled">Send to Comparer</div>
    <div class="ctx-item ctx-disabled">Send to Decoder</div>
    <div class="ctx-sep"></div>
    <div class="ctx-item" on:click={ctxChangeMethod}>Change request method</div>
    <div class="ctx-sep"></div>
    <div class="ctx-item" on:click={() => { navigator.clipboard.writeText(state.request || ""); closeCtx(); }}>Copy <span class="ctx-shortcut">Ctrl+C</span></div>
    <div class="ctx-item" on:click={ctxCopyUrl}>Copy URL</div>
    <div class="ctx-item" on:click={ctxCopyCurl}>Copy as curl command (bash)</div>
    <div class="ctx-sep"></div>
    <div class="ctx-item" on:click={ctxPasteHostAsRequest}>Paste host / URL as request</div>
    <div class="ctx-item" on:click={ctxAddToSiteMap}>Add to site map</div>
    <div class="ctx-sep"></div>
    <!-- svelte-ignore a11y-click-events-have-key-events -->
    <div class="ctx-item" on:click={() => { document.execCommand("cut"); closeCtx(); }}>Cut <span class="ctx-shortcut">Ctrl+X</span></div>
    <!-- svelte-ignore a11y-click-events-have-key-events -->
    <div class="ctx-item" on:click={() => { navigator.clipboard.readText().then(t => { tabStates[activeTab].request = t; tabStates = tabStates; }); closeCtx(); }}>Paste <span class="ctx-shortcut">Ctrl+V</span></div>
  </div>
{/if}

<style>
  /* ── Reset / base ── */
  * { box-sizing: border-box; }

  .view {
    display: flex;
    flex-direction: column;
    height: 100%;
    overflow: hidden;
    background: #f5f5f5;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    font-size: 13px;
    color: #212121;
  }

  /* ════════════════════════════════════
     1. Session tab bar
  ════════════════════════════════════ */
  .rep-tabbar {
    display: flex;
    align-items: stretch;
    background: #f0f0f0;
    border-bottom: 1px solid #dedede;
    flex-shrink: 0;
    height: 34px;
    overflow-x: auto;
    overflow-y: hidden;
  }
  .rep-tabbar::-webkit-scrollbar { height: 3px; }
  .rep-tabbar::-webkit-scrollbar-thumb { background: #c8c8c8; }

  .rep-tab {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 0 14px 0 14px;
    background: transparent;
    border: none;
    border-bottom: 2px solid transparent;
    border-right: 1px solid #dedede;
    border-radius: 0;
    color: #555;
    font-size: 12px;
    cursor: pointer;
    white-space: nowrap;
    height: 100%;
    min-width: 52px;
    transition: background 0.1s;
  }
  .rep-tab:hover { background: #e6e6e6; }
  .rep-tab-active {
    color: #e03a00;
    border-bottom-color: #e03a00;
    font-weight: 600;
    background: #ffffff;
  }
  .tab-label { pointer-events: none; }
  .tab-close {
    font-size: 14px;
    line-height: 1;
    color: #909090;
    cursor: pointer;
    padding: 0 1px;
    border-radius: 3px;
  }
  .tab-close:hover { color: #d42c2c; background: #f0d0d0; }

  .rep-tab-add {
    padding: 0 14px;
    background: transparent;
    border: none;
    color: #767676;
    font-size: 20px;
    line-height: 1;
    cursor: pointer;
    display: flex;
    align-items: center;
  }
  .rep-tab-add:hover { color: #e03a00; }

  /* ════════════════════════════════════
     2. Toolbar row
  ════════════════════════════════════ */
  .toolbar-row {
    display: flex;
    align-items: center;
    gap: 5px;
    padding: 5px 10px;
    background: #f5f5f5;
    border-bottom: 1px solid #dedede;
    flex-shrink: 0;
  }

  .btn-send {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    background: #e03a00;
    color: #ffffff;
    border: none;
    border-radius: 3px;
    padding: 5px 18px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    letter-spacing: 0.01em;
  }
  .btn-send:hover:not(:disabled) { background: #c83400; }
  .btn-send:disabled { opacity: 0.55; cursor: not-allowed; }

  .toolbar-btn {
    display: inline-flex;
    align-items: center;
    gap: 3px;
    padding: 4px 10px;
    font-size: 12px;
    background: #ececec;
    color: #333;
    border: 1px solid #c8c8c8;
    border-radius: 3px;
    cursor: pointer;
    white-space: nowrap;
    height: 26px;
  }
  .toolbar-btn:hover:not(:disabled) { background: #e0e0e0; }
  .toolbar-btn:disabled { opacity: 0.38; cursor: not-allowed; }

  .icon-btn { padding: 4px 7px; }
  .nav-btn { gap: 1px; padding: 4px 8px; }

  .btn-cancel { color: #444; }

  .toolbar-sep {
    width: 1px;
    height: 18px;
    background: #d0d0d0;
    margin: 0 3px;
    flex-shrink: 0;
  }

  /* Burp AI button */
  .burp-ai-wrap { position: relative; }
  .btn-ai {
    color: #555;
    gap: 4px;
  }
  .btn-ai svg { opacity: 0.85; }
  .ai-tooltip {
    position: absolute;
    right: 0;
    top: calc(100% + 6px);
    background: #333;
    color: #fff;
    font-size: 11px;
    padding: 4px 10px;
    border-radius: 4px;
    white-space: nowrap;
    z-index: 500;
    pointer-events: none;
  }
  .ai-tooltip::before {
    content: "";
    position: absolute;
    top: -5px;
    right: 12px;
    border: 5px solid transparent;
    border-bottom-color: #333;
    border-top: none;
  }

  /* Spin animation */
  .spin {
    animation: spin 0.8s linear infinite;
  }
  @keyframes spin {
    to { transform: rotate(360deg); }
  }

  /* ════════════════════════════════════
     3. Target / URL bar
  ════════════════════════════════════ */
  .target-bar {
    display: flex;
    align-items: center;
    padding: 4px 8px;
    background: #ffffff;
    border-bottom: 1px solid #dedede;
    flex-shrink: 0;
    font-family: ui-monospace, "Cascadia Code", Consolas, monospace;
    font-size: 12px;
    gap: 0;
  }

  .lock-icon {
    flex-shrink: 0;
    margin-right: 5px;
  }

  .scheme-sel {
    font-size: 12px;
    background: #f5f5f5;
    border: 1px solid #c8c8c8;
    border-radius: 3px 0 0 3px;
    color: #e03a00;
    font-weight: 600;
    padding: 3px 6px;
    min-width: 66px;
    font-family: ui-monospace, "Cascadia Code", Consolas, monospace;
    cursor: pointer;
    outline: none;
    height: 26px;
  }
  .url-sep {
    color: #888;
    padding: 0;
    flex-shrink: 0;
    align-self: center;
  }
  .port-sep { padding: 0 1px; }
  .host-input {
    flex: 1;
    border: 1px solid #c8c8c8;
    border-left: none;
    border-right: none;
    border-radius: 0;
    font-size: 12px;
    padding: 3px 8px;
    font-family: ui-monospace, "Cascadia Code", Consolas, monospace;
    background: #ffffff;
    color: #212121;
    outline: none;
    height: 26px;
  }
  .host-input:focus { background: #fff9f7; border-color: #e03a00; z-index: 1; position: relative; }
  .port-input {
    width: 58px;
    border: 1px solid #c8c8c8;
    border-radius: 0 3px 3px 0;
    font-size: 12px;
    padding: 3px 6px;
    font-family: ui-monospace, "Cascadia Code", Consolas, monospace;
    background: #ffffff;
    color: #212121;
    outline: none;
    height: 26px;
  }
  .port-input:focus { background: #fff9f7; border-color: #e03a00; }

  /* ════════════════════════════════════
     4. Main body (three panes)
  ════════════════════════════════════ */
  .body-root {
    flex: 1;
    display: flex;
    overflow: hidden;
    min-height: 0;
  }

  /* Side-by-side: req | resp side by side, inspector on right */
  .layout-side .req-resp-col {
    display: flex;
    flex-direction: row;
    flex: 1;
    min-width: 0;
    overflow: hidden;
  }
  .layout-side .req-pane,
  .layout-side .resp-pane {
    flex: 1;
    min-width: 0;
  }

  /* Stacked: req on top of resp */
  .layout-stacked .req-resp-col {
    display: flex;
    flex-direction: column;
    flex: 1;
    min-width: 0;
    overflow: hidden;
  }
  .layout-stacked .pane-stacked-half {
    flex: 1;
    min-height: 0;
  }

  /* Inspector-only hides req/resp */
  .layout-inspector .req-resp-col {
    display: none;
  }
  .layout-inspector .inspector-panel {
    flex: 1;
    width: auto !important;
    max-width: none !important;
  }

  .req-resp-col {
    flex: 1;
    overflow: hidden;
    min-width: 0;
  }

  /* ── Pane ── */
  .pane {
    display: flex;
    flex-direction: column;
    overflow: hidden;
    border-right: 1px solid #dedede;
    min-width: 0;
    background: #ffffff;
  }
  .pane:last-child { border-right: none; }

  .pane-header {
    display: flex;
    align-items: center;
    padding: 5px 10px;
    background: #f5f5f5;
    border-bottom: 1px solid #dedede;
    flex-shrink: 0;
    gap: 6px;
    min-height: 32px;
  }

  .pane-title {
    font-size: 12px;
    font-weight: 700;
    color: #333;
    flex-shrink: 0;
    letter-spacing: 0.01em;
  }

  .resp-status {
    font-size: 11px;
    font-weight: 400;
    color: #767676;
    margin-left: 6px;
    font-family: ui-monospace, Consolas, monospace;
  }

  /* Sub-tabs (Pretty / Raw / Hex / Render) */
  .subtab-row {
    display: flex;
    gap: 1px;
    margin-left: 4px;
  }
  .stab {
    padding: 2px 9px;
    font-size: 11px;
    background: transparent;
    border: 1px solid transparent;
    border-radius: 3px;
    color: #767676;
    cursor: pointer;
    line-height: 1.5;
  }
  .stab:hover { background: #e8e8e8; color: #333; }
  .stab-active {
    color: #e03a00 !important;
    border-color: #e03a00 !important;
    background: transparent !important;
  }

  /* Pane icon buttons (search, wrap, etc.) */
  .pane-icon-btns {
    display: flex;
    gap: 2px;
    margin-left: auto;
  }
  .pane-icon-btn {
    background: transparent;
    border: none;
    cursor: pointer;
    color: #888;
    padding: 3px 4px;
    border-radius: 3px;
    display: flex;
    align-items: center;
  }
  .pane-icon-btn:hover { color: #333; background: #e8e8e8; }

  /* Layout toggle buttons (response pane top-right) */
  .layout-btns {
    display: flex;
    gap: 2px;
    margin-left: auto;
  }
  .layout-btn {
    background: transparent;
    border: 1px solid transparent;
    cursor: pointer;
    color: #888;
    padding: 3px 4px;
    border-radius: 3px;
    display: flex;
    align-items: center;
  }
  .layout-btn:hover { color: #333; background: #e8e8e8; }
  .layout-btn-active {
    color: #e03a00 !important;
    border-color: #e03a00 !important;
  }

  /* ── Code area with line numbers ── */
  .code-wrap {
    display: flex;
    flex: 1;
    overflow: hidden;
    min-height: 0;
    background: #ffffff;
  }

  .line-nums {
    flex-shrink: 0;
    width: 38px;
    background: #f8f8f8;
    border-right: 1px solid #ebebeb;
    overflow: hidden;
    padding: 10px 0;
    text-align: right;
    user-select: none;
  }
  .line-nums .ln {
    font-size: 11px;
    font-family: ui-monospace, "Cascadia Code", Consolas, monospace;
    color: #aaaaaa;
    line-height: 1.55;
    padding-right: 8px;
    height: 1.55em;
  }

  .code-area {
    flex: 1;
    resize: none;
    border: none;
    border-radius: 0;
    background: #ffffff;
    color: #212121;
    padding: 10px 12px;
    min-height: 0;
    font-size: 12px;
    font-family: ui-monospace, "Cascadia Code", Consolas, monospace;
    outline: none;
    line-height: 1.55;
    tab-size: 2;
    overflow: auto;
  }
  .code-area::placeholder { color: #b0b0b0; font-style: italic; }
  .req-editable:focus { background: #fffdf9; }

  /* Render iframe */
  .resp-frame {
    flex: 1;
    border: none;
    background: #fff;
    width: 100%;
    height: 100%;
  }
  .resp-empty {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #888;
    font-size: 13px;
    font-style: italic;
  }

  /* ════════════════════════════════════
     Inspector panel
  ════════════════════════════════════ */
  .inspector-panel {
    width: 230px;
    min-width: 230px;
    flex-shrink: 0;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    border-left: 1px solid #dedede;
    background: #fafafa;
    transition: width 0.15s, min-width 0.15s;
  }
  .inspector-collapsed {
    width: 30px !important;
    min-width: 30px !important;
  }
  .inspector-collapsed .inspector-body { display: none; }

  .inspector-hdr {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 5px 10px;
    background: #f0f0f0;
    border-bottom: 1px solid #dedede;
    flex-shrink: 0;
    min-height: 32px;
  }
  .inspector-title {
    font-size: 12px;
    font-weight: 700;
    color: #333;
    white-space: nowrap;
    overflow: hidden;
    letter-spacing: 0.01em;
  }
  .inspector-collapsed .inspector-title { display: none; }

  .inspector-toggle {
    background: transparent;
    border: none;
    cursor: pointer;
    color: #555;
    padding: 2px;
    display: flex;
    align-items: center;
    border-radius: 3px;
    flex-shrink: 0;
  }
  .inspector-toggle:hover { background: #e0e0e0; }

  .inspector-body {
    flex: 1;
    overflow-y: auto;
    overflow-x: hidden;
  }
  .inspector-body::-webkit-scrollbar { width: 5px; }
  .inspector-body::-webkit-scrollbar-thumb { background: #c8c8c8; border-radius: 3px; }

  /* Inspector sections */
  .isec {
    border-bottom: 1px solid #e4e4e4;
  }
  .isec-resp .isec-hdr { background: #f5f0ff; }

  .isec-hdr {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 7px 10px 7px 8px;
    cursor: pointer;
    font-size: 12px;
    font-weight: 600;
    color: #3a3a3a;
    background: #f2f2f2;
    user-select: none;
    min-height: 32px;
  }
  .isec-hdr:hover { background: #eaeaea; }

  .isec-arrow {
    flex-shrink: 0;
    color: #777;
    transition: transform 0.12s;
  }

  .isec-badge {
    margin-left: auto;
    font-size: 10px;
    font-weight: 500;
    background: #e0e0e0;
    color: #555;
    padding: 1px 6px;
    border-radius: 8px;
    flex-shrink: 0;
  }

  .isec-rows { padding: 2px 0 4px; }

  .irow {
    display: flex;
    gap: 6px;
    padding: 3px 10px 3px 8px;
    font-size: 11px;
    border-bottom: 1px solid #f0f0f0;
    min-width: 0;
    overflow: hidden;
  }
  .irow:last-child { border-bottom: none; }

  .ikey {
    color: #777;
    flex-shrink: 0;
    min-width: 70px;
    max-width: 90px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .ival {
    color: #212121;
    flex: 1;
    min-width: 0;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .orange { color: #c0392b !important; }
  .mono { font-family: ui-monospace, "Cascadia Code", Consolas, monospace; }
  .dim { color: #888 !important; }

  /* Method badge */
  .method-badge {
    display: inline-block;
    font-size: 10px;
    font-weight: 700;
    padding: 1px 5px;
    border-radius: 3px;
    background: #e8f5e9;
    color: #2e7d32;
    font-family: ui-monospace, Consolas, monospace;
    letter-spacing: 0.03em;
  }
  .method-GET    { background: #e8f5e9; color: #2e7d32; }
  .method-POST   { background: #fff3e0; color: #e65100; }
  .method-PUT    { background: #e3f2fd; color: #1565c0; }
  .method-PATCH  { background: #fce4ec; color: #880e4f; }
  .method-DELETE { background: #ffebee; color: #b71c1c; }
  .method-HEAD   { background: #f3e5f5; color: #4a148c; }
  .method-OPTIONS { background: #e0f2f1; color: #004d40; }

  .isec-empty {
    padding: 6px 10px;
    font-size: 11px;
    color: #aaa;
    font-style: italic;
  }
  .isec-body-preview {
    padding: 6px 10px;
    font-size: 11px;
    font-family: ui-monospace, Consolas, monospace;
    color: #555;
    word-break: break-all;
    white-space: pre-wrap;
    max-height: 120px;
    overflow: hidden;
  }

  /* ════════════════════════════════════
     Context menu
  ════════════════════════════════════ */
  .ctx-overlay {
    position: fixed;
    inset: 0;
    z-index: 9998;
  }
  .ctx-menu {
    position: fixed;
    z-index: 9999;
    background: #ffffff;
    border: 1px solid #c0c0c0;
    border-radius: 4px;
    padding: 4px 0;
    box-shadow: 0 4px 18px rgba(0, 0, 0, 0.16);
    min-width: 250px;
    font-size: 13px;
  }
  .ctx-item {
    padding: 5px 16px;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: space-between;
    white-space: nowrap;
    color: #212121;
  }
  .ctx-item:hover { background: #f0f4ff; }
  .ctx-disabled { color: #b0b0b0 !important; cursor: not-allowed; }
  .ctx-disabled:hover { background: transparent !important; }
  .ctx-sep { height: 1px; background: #e8e8e8; margin: 3px 0; }
  .ctx-shortcut { font-size: 11px; color: #999; margin-left: 16px; }
</style>
