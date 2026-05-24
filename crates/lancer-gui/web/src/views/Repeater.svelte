<script>
  import { onMount } from "svelte";

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
    }
  };

  let sending = false;
  let cancelled = false;
  let controller = null;

  // Inspector panel
  let inspectorOpen = true;
  let inspectorSection = "attributes"; // attributes | query | body | cookies | headers

  // Context menu
  let ctxMenu = null;

  $: state = tabStates[activeTab] || tabStates[1];

  // Parse inspector data from request text
  $: inspectorData = parseInspector(state?.request || "");

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

    // Parse query params from path
    if (fullPath.includes("?")) {
      const qs = fullPath.split("?")[1] || "";
      for (const pair of qs.split("&")) {
        const [k, v] = pair.split("=");
        if (k) queryParams.push({ name: decodeURIComponent(k || ""), value: decodeURIComponent(v || "") });
      }
    }

    // Parse headers
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

    // Body
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

  function addTab() {
    const id = nextId++;
    tabs = [...tabs, { id, label: String(id) }];
    tabStates[id] = {
      request: `GET / HTTP/1.1\r\nHost: \r\nUser-Agent: Lancer/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n`,
      response: "", rawResponse: "",
      scheme: "https", host: "", port: "443",
      history: [], histIdx: -1,
      reqSubtab: "raw", respSubtab: "pretty",
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

  function setScheme(v) {
    tabStates[activeTab].scheme = v;
    if (v === "https" && tabStates[activeTab].port === "80") tabStates[activeTab].port = "443";
    if (v === "http"  && tabStates[activeTab].port === "443") tabStates[activeTab].port = "80";
    tabStates = tabStates;
  }
  function setHost(v)    { tabStates[activeTab].host = v; tabStates = tabStates; }
  function setPort(v)    { tabStates[activeTab].port = v; tabStates = tabStates; }
  function setRequest(v) { tabStates[activeTab].request = v; tabStates = tabStates; }

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

  async function send() {
    if (sending) return;
    const s = tabStates[activeTab];
    sending = true; cancelled = false;
    s.response = ""; s.rawResponse = "";
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
      tabStates = tabStates;
    } catch (e) {
      tabStates[activeTab].response = cancelled ? "(request cancelled)" : `Error: ${e.message || e}`;
      tabStates = tabStates;
    } finally {
      sending = false; controller = null;
    }
  }

  function cancel() {
    if (controller) { cancelled = true; controller.abort(); }
  }

  // Context menu
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
    const headers = inspectorData.headers.map(h => `-H '${h.name}: ${h.value}'`).join(" ");
    const method = inspectorData.method !== "GET" ? `-X ${inspectorData.method}` : "";
    const body = inspectorData.body ? `--data '${inspectorData.body.replace(/'/g, "\\'")}'` : "";
    const curl = `curl ${method} ${headers} ${body} '${url}'`.replace(/  +/g, " ").trim();
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
    const curMethod = inspectorData.method;
    const next = methods[(methods.indexOf(curMethod) + 1) % methods.length];
    s.request = s.request.replace(/^[A-Z]+/, next);
    tabStates = tabStates;
    closeCtx();
  }

  function ctxAddToSiteMap() {
    const s = tabStates[activeTab];
    // Dispatch as a site-map add request (Target tab handles this)
    window.dispatchEvent(new CustomEvent("lancer:siteMapAdd", {
      detail: { url: `${s.scheme}://${s.host}${inspectorData.fullPath}`, method: inspectorData.method }
    }));
    closeCtx();
  }

  function ctxPasteHostAsRequest() {
    try {
      navigator.clipboard.readText().then(text => {
        const url = text.trim();
        // Parse scheme://host:port/path
        const m = url.match(/^(https?):\/\/([^/:]+)(?::(\d+))?(\/.*)?$/);
        if (m) {
          const [, scheme, host, port, path] = m;
          const p = port || (scheme === "https" ? "443" : "80");
          tabStates[activeTab].scheme = scheme;
          tabStates[activeTab].host = host;
          tabStates[activeTab].port = p;
          tabStates[activeTab].request = `GET ${path || "/"} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: Lancer/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n`;
          tabStates = tabStates;
        }
      });
    } catch {}
    closeCtx();
  }

  // Pretty-format response for display
  function prettyResponse(raw) {
    if (!raw) return "";
    // Try to pretty-print JSON body
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

  onMount(() => {
    // Read "Send to Repeater" prefill from localStorage (set by Target tab)
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

    // Click outside to close context menu
    document.addEventListener("click", closeCtx);
    return () => document.removeEventListener("click", closeCtx);
  });
</script>

<div class="view">
  <!-- Session tab strip -->
  <div class="rep-tabbar">
    {#each tabs as t}
      <button
        class="rep-tab"
        class:rep-tab-active={activeTab === t.id}
        on:click={() => activeTab = t.id}
      >
        {t.label}
        <span class="tab-close dim" on:click|stopPropagation={() => closeTab(t.id)}>×</span>
      </button>
    {/each}
    <button class="rep-tab-add" on:click={addTab} title="New tab">+</button>
  </div>

  {#if tabStates[activeTab]}
    <!-- Action toolbar -->
    <div class="action-toolbar">
      <button class="btn-send" on:click={send} disabled={sending}>
        {sending ? "Sending..." : "Send"}
      </button>
      <button class="toolbar-btn icon-btn" title="Settings">
        <svg width="13" height="13" viewBox="0 0 14 14" fill="none">
          <circle cx="7" cy="7" r="2.5" stroke="currentColor" stroke-width="1.3"/>
          <path d="M7 1v2M7 11v2M1 7h2M11 7h2M2.9 2.9l1.4 1.4M9.7 9.7l1.4 1.4M2.9 11.1l1.4-1.4M9.7 4.3l1.4-1.4" stroke="currentColor" stroke-width="1.1" stroke-linecap="round"/>
        </svg>
      </button>
      <button class="toolbar-btn" on:click={cancel} disabled={!sending}>Cancel</button>
      <div class="toolbar-sep"></div>
      <button class="toolbar-btn nav-btn" on:click={histBack}
        disabled={tabStates[activeTab].histIdx >= tabStates[activeTab].history.length - 1}>
        ← <span class="dd-arrow">▼</span>
      </button>
      <button class="toolbar-btn nav-btn" on:click={histForward}
        disabled={tabStates[activeTab].histIdx <= 0}>
        → <span class="dd-arrow">▼</span>
      </button>
      <div style="flex:1"></div>
      <span class="target-label dim">Target: <code>{tabStates[activeTab].scheme}://{tabStates[activeTab].host}</code></span>
      <button
        class="toolbar-btn icon-btn"
        title="Toggle Inspector"
        on:click={() => inspectorOpen = !inspectorOpen}
        style="color:{inspectorOpen ? '#e03a00' : '#767676'}"
      >
        <svg width="13" height="13" viewBox="0 0 14 14" fill="none">
          <rect x="1" y="1" width="12" height="12" rx="2" stroke="currentColor" stroke-width="1.3"/>
          <path d="M9 1v12" stroke="currentColor" stroke-width="1.1"/>
        </svg>
      </button>
    </div>

    <!-- URL bar -->
    <div class="url-bar">
      <select class="scheme-sel" value={tabStates[activeTab].scheme} on:change={e => setScheme(e.target.value)}>
        <option value="https">https</option>
        <option value="http">http</option>
        <option value="ws">ws</option>
      </select>
      <span class="url-sep">://</span>
      <input class="host-input" value={tabStates[activeTab].host} on:input={e => setHost(e.target.value)} placeholder="target.example.com" />
      <span class="url-sep">:</span>
      <input class="port-input" value={tabStates[activeTab].port} on:input={e => setPort(e.target.value)} placeholder="443" />
    </div>

    <!-- Three-pane body: request | response | inspector -->
    <div class="body-panes" style="flex:1;overflow:hidden;display:flex;">
      <!-- Request pane -->
      <div class="pane" style="flex:1;min-width:0">
        <div class="pane-header">
          <span class="pane-title">Request</span>
          <div class="inline-tabs">
            <button class="itab" class:itab-active={tabStates[activeTab].reqSubtab==="pretty"} on:click={() => { tabStates[activeTab].reqSubtab="pretty"; tabStates=tabStates; }}>Pretty</button>
            <button class="itab" class:itab-active={tabStates[activeTab].reqSubtab==="raw"}    on:click={() => { tabStates[activeTab].reqSubtab="raw";    tabStates=tabStates; }}>Raw</button>
            <button class="itab" class:itab-active={tabStates[activeTab].reqSubtab==="hex"}    on:click={() => { tabStates[activeTab].reqSubtab="hex";    tabStates=tabStates; }}>Hex</button>
          </div>
        </div>
        <!-- svelte-ignore a11y-no-static-element-interactions -->
        <textarea
          class="req-area"
          value={tabStates[activeTab].request}
          on:input={e => setRequest(e.target.value)}
          on:contextmenu={onContextMenu}
          spellcheck="false"
        ></textarea>
      </div>

      <!-- Response pane -->
      <div class="pane" style="flex:1;min-width:0">
        <div class="pane-header">
          <span class="pane-title">
            Response
            {#if tabStates[activeTab].response}
              <span class="resp-first-line dim">{tabStates[activeTab].response.split("\n")[0]}</span>
            {/if}
          </span>
          <div class="inline-tabs">
            <button class="itab" class:itab-active={tabStates[activeTab].respSubtab==="pretty"} on:click={() => { tabStates[activeTab].respSubtab="pretty"; tabStates=tabStates; }}>Pretty</button>
            <button class="itab" class:itab-active={tabStates[activeTab].respSubtab==="raw"}    on:click={() => { tabStates[activeTab].respSubtab="raw";    tabStates=tabStates; }}>Raw</button>
            <button class="itab" class:itab-active={tabStates[activeTab].respSubtab==="hex"}    on:click={() => { tabStates[activeTab].respSubtab="hex";    tabStates=tabStates; }}>Hex</button>
          </div>
        </div>
        <textarea
          class="resp-area"
          readonly
          value={tabStates[activeTab].respSubtab === "pretty"
            ? prettyResponse(tabStates[activeTab].response)
            : (tabStates[activeTab].response || "(send a request to see the response)")}
          spellcheck="false"
        ></textarea>
      </div>

      <!-- Inspector pane (toggleable) -->
      {#if inspectorOpen}
        <div class="inspector-pane">
          <div class="inspector-header">
            <span class="pane-title">Inspector</span>
            <div class="inspector-view-btns">
              <button class="itab" class:itab-active={inspectorSection==="attributes"} on:click={() => inspectorSection="attributes"}>Attribs</button>
            </div>
          </div>
          <div class="inspector-body">
            <!-- Request attributes -->
            <div class="inspect-section">
              <div class="inspect-section-hdr" on:click={() => {}} role="button" tabindex="0">
                Request attributes
                <span class="inspect-count">{2}</span>
              </div>
              <div class="inspect-rows">
                <div class="inspect-row"><span class="inspect-key">Method</span><span class="inspect-val method-{inspectorData.method}">{inspectorData.method}</span></div>
                <div class="inspect-row"><span class="inspect-key">Path</span><span class="inspect-val mono">{inspectorData.fullPath}</span></div>
                <div class="inspect-row"><span class="inspect-key">Version</span><span class="inspect-val dim">{inspectorData.version}</span></div>
              </div>
            </div>

            <!-- Query parameters -->
            <div class="inspect-section">
              <div class="inspect-section-hdr">
                Request query parameters
                <span class="inspect-count">{inspectorData.queryParams.length}</span>
              </div>
              {#if inspectorData.queryParams.length > 0}
                <div class="inspect-rows">
                  {#each inspectorData.queryParams as p}
                    <div class="inspect-row"><span class="inspect-key mono">{p.name}</span><span class="inspect-val mono">{p.value}</span></div>
                  {/each}
                </div>
              {/if}
            </div>

            <!-- Body parameters -->
            <div class="inspect-section">
              <div class="inspect-section-hdr">
                Request body parameters
                <span class="inspect-count">{inspectorData.bodyParams.length}</span>
              </div>
              {#if inspectorData.bodyParams.length > 0}
                <div class="inspect-rows">
                  {#each inspectorData.bodyParams as p}
                    <div class="inspect-row"><span class="inspect-key mono">{p.name}</span><span class="inspect-val mono">{p.value}</span></div>
                  {/each}
                </div>
              {/if}
            </div>

            <!-- Cookies -->
            <div class="inspect-section">
              <div class="inspect-section-hdr">
                Request cookies
                <span class="inspect-count">{inspectorData.cookies.length}</span>
              </div>
              {#if inspectorData.cookies.length > 0}
                <div class="inspect-rows">
                  {#each inspectorData.cookies as c}
                    <div class="inspect-row"><span class="inspect-key mono">{c.name}</span><span class="inspect-val mono">{c.value}</span></div>
                  {/each}
                </div>
              {/if}
            </div>

            <!-- Headers -->
            <div class="inspect-section">
              <div class="inspect-section-hdr">
                Request headers
                <span class="inspect-count">{inspectorData.headers.length}</span>
              </div>
              {#if inspectorData.headers.length > 0}
                <div class="inspect-rows">
                  {#each inspectorData.headers as h}
                    <div class="inspect-row"><span class="inspect-key mono">{h.name}</span><span class="inspect-val mono">{h.value}</span></div>
                  {/each}
                </div>
              {/if}
            </div>
          </div>
        </div>
      {/if}
    </div>
  {/if}
</div>

<!-- Right-click context menu -->
{#if ctxMenu}
  <!-- svelte-ignore a11y-no-static-element-interactions -->
  <div class="ctx-overlay" on:click={closeCtx} on:keydown={e => e.key==="Escape" && closeCtx()}></div>
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
    <div class="ctx-item" on:click={() => { document.execCommand("cut"); closeCtx(); }}>Cut <span class="ctx-shortcut">Ctrl+X</span></div>
    <div class="ctx-item" on:click={() => { navigator.clipboard.writeText(state.request || ""); closeCtx(); }}>Copy <span class="ctx-shortcut">Ctrl+C</span></div>
    <div class="ctx-item" on:click={() => { navigator.clipboard.readText().then(t => { tabStates[activeTab].request = t; tabStates = tabStates; }); closeCtx(); }}>Paste <span class="ctx-shortcut">Ctrl+V</span></div>
  </div>
{/if}

<style>
  /* Session tab strip */
  .rep-tabbar {
    display: flex; align-items: stretch;
    background: #f5f5f5; border-bottom: 1px solid #dedede;
    flex-shrink: 0; overflow-x: auto; height: 32px;
  }
  .rep-tab {
    display: flex; align-items: center; gap: 5px;
    padding: 0 14px;
    background: transparent; border: none;
    border-bottom: 2px solid transparent;
    border-right: 1px solid #dedede; border-radius: 0;
    color: #444; font-size: 13px; cursor: pointer;
    white-space: nowrap; height: 100%;
  }
  .rep-tab:hover { background: #ebebeb; }
  .rep-tab-active { color: #e03a00; border-bottom-color: #e03a00; font-weight: 600; background: #ffffff; }
  .tab-close { font-size: 14px; line-height: 1; color: #767676; cursor: pointer; }
  .tab-close:hover { color: #d42c2c; }
  .rep-tab-add {
    padding: 0 12px; background: transparent; border: none; border-radius: 0;
    color: #767676; font-size: 18px; line-height: 1; cursor: pointer; align-self: center;
  }
  .rep-tab-add:hover { color: #e03a00; }

  /* Action toolbar */
  .action-toolbar {
    display: flex; align-items: center; gap: 4px;
    padding: 5px 10px; background: #f5f5f5;
    border-bottom: 1px solid #dedede; flex-shrink: 0;
  }
  .btn-send {
    background: #e03a00; color: #ffffff; border: none; border-radius: 3px;
    padding: 4px 16px; font-size: 13px; font-weight: 500; cursor: pointer;
  }
  .btn-send:hover:not(:disabled) { background: #c73400; }
  .btn-send:disabled { opacity: 0.5; cursor: not-allowed; }
  .toolbar-btn {
    padding: 4px 10px; font-size: 13px;
    background: #f0f0f0; color: #333;
    border: 1px solid #c8c8c8; border-radius: 3px; cursor: pointer;
  }
  .toolbar-btn:hover:not(:disabled) { background: #e4e4e4; }
  .toolbar-btn:disabled { opacity: 0.4; cursor: not-allowed; }
  .icon-btn { padding: 4px 8px; }
  .nav-btn { display: flex; align-items: center; gap: 3px; }
  .dd-arrow { font-size: 10px; }
  .toolbar-sep { width: 1px; height: 20px; background: #dedede; margin: 0 4px; }
  .target-label { font-size: 11px; white-space: nowrap; }
  .target-label code { font-size: 11px; background: transparent; padding: 0; }

  /* URL bar */
  .url-bar {
    display: flex; align-items: center;
    padding: 4px 8px; background: #ffffff;
    border-bottom: 1px solid #dedede; flex-shrink: 0;
    font-family: ui-monospace, Consolas, monospace;
  }
  .scheme-sel {
    font-size: 12px; background: #f0f0f0;
    border: 1px solid #c8c8c8; border-radius: 3px 0 0 3px;
    color: #e03a00; font-weight: 600; padding: 3px 6px;
    min-width: 68px; font-family: inherit;
  }
  .url-sep { color: #767676; font-size: 12px; padding: 0 2px; flex-shrink: 0; }
  .host-input {
    flex: 1; border-radius: 0; border: 1px solid #c8c8c8;
    border-left: none; border-right: none;
    font-size: 12px; padding: 3px 8px;
    font-family: ui-monospace, Consolas, monospace;
    background: #ffffff; color: #212121; outline: none;
  }
  .port-input {
    width: 56px; border-radius: 0 3px 3px 0;
    border: 1px solid #c8c8c8; font-size: 12px; padding: 3px 6px;
    font-family: ui-monospace, Consolas, monospace;
    background: #ffffff; color: #212121; outline: none;
  }

  /* Body panes */
  .body-panes { display: flex; flex: 1; overflow: hidden; }
  .pane {
    display: flex; flex-direction: column; overflow: hidden;
    border-right: 1px solid #dedede;
  }
  .pane:last-child { border-right: none; }
  .pane-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 5px 10px; background: #f5f5f5;
    border-bottom: 1px solid #dedede; flex-shrink: 0;
  }
  .pane-title { font-size: 12px; font-weight: 600; color: #444; }
  .resp-first-line { font-size: 11px; font-weight: 400; margin-left: 8px; color: #767676; }
  .inline-tabs { display: flex; gap: 2px; }
  .itab {
    padding: 2px 8px; font-size: 11px;
    background: transparent; border: 1px solid transparent; border-radius: 3px;
    color: #767676; cursor: pointer;
  }
  .itab:hover { color: #212121; background: #ebebeb; }
  .itab-active { color: #e03a00 !important; border-color: #e03a00 !important; background: transparent !important; }
  .req-area, .resp-area {
    flex: 1; resize: none; border: none; border-radius: 0;
    background: #ffffff; color: #212121;
    padding: 10px 12px; min-height: 0; font-size: 12px;
    font-family: ui-monospace, "Cascadia Code", Consolas, monospace;
    outline: none; height: 100%;
  }
  .resp-area { color: #444; }

  /* Inspector */
  .inspector-pane {
    width: 260px; flex-shrink: 0;
    display: flex; flex-direction: column; overflow: hidden;
    border-left: 1px solid #dedede;
  }
  .inspector-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 5px 10px; background: #f5f5f5;
    border-bottom: 1px solid #dedede; flex-shrink: 0;
  }
  .inspector-view-btns { display: flex; gap: 2px; }
  .inspector-body { flex: 1; overflow-y: auto; }

  .inspect-section { border-bottom: 1px solid #e8e8e8; }
  .inspect-section-hdr {
    display: flex; align-items: center; justify-content: space-between;
    padding: 7px 12px; cursor: pointer;
    font-size: 12px; font-weight: 600; color: #444;
    background: #fafafa;
    user-select: none;
  }
  .inspect-section-hdr:hover { background: #f0f0f0; }
  .inspect-count {
    font-size: 11px; font-weight: 400;
    background: #e8e8e8; color: #555;
    padding: 1px 6px; border-radius: 8px;
  }
  .inspect-rows { padding: 4px 0; }
  .inspect-row {
    display: flex; gap: 8px; padding: 3px 12px;
    font-size: 11px; border-bottom: 1px solid #f0f0f0;
    min-width: 0; overflow: hidden;
  }
  .inspect-key {
    color: #767676; flex-shrink: 0; min-width: 80px;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  }
  .inspect-val {
    color: #212121; flex: 1; min-width: 0;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  }
  .mono { font-family: ui-monospace, Consolas, monospace; }

  /* Context menu */
  .ctx-overlay {
    position: fixed; inset: 0; z-index: 9998;
  }
  .ctx-menu {
    position: fixed; z-index: 9999;
    background: #ffffff; border: 1px solid #c8c8c8;
    border-radius: 4px; padding: 4px 0;
    box-shadow: 0 4px 16px rgba(0,0,0,0.15);
    min-width: 240px; font-size: 13px;
  }
  .ctx-item {
    padding: 5px 16px; cursor: pointer;
    display: flex; align-items: center; justify-content: space-between;
    white-space: nowrap;
  }
  .ctx-item:hover { background: #f0f7ff; }
  .ctx-disabled { color: #aaaaaa; cursor: not-allowed; }
  .ctx-disabled:hover { background: transparent; }
  .ctx-sep { height: 1px; background: #e8e8e8; margin: 3px 0; }
  .ctx-shortcut { font-size: 11px; color: #767676; }
</style>
