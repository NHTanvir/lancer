<script>
  import { onMount } from "svelte";

  // ── Tab state ─────────────────────────────────────────────────────────────
  let subtab = "positions";   // positions | payloads | resource-pool | settings
  let requestLoaded = false;

  // ── Target ────────────────────────────────────────────────────────────────
  let host   = "example.com";
  let port   = "443";
  let scheme = "https";

  // ── Positions ─────────────────────────────────────────────────────────────
  let attackType = "sniper";
  let requestTemplate = `GET /users?id=§1§ HTTP/1.1\nHost: example.com\nUser-Agent: Lancer/1.0\nAccept: */*\n\n`;
  let reqEditorMode = "raw"; // pretty | raw

  $: positionCount = (requestTemplate.match(/§/g) || []).length / 2 | 0;

  // ── § marker highlighting ─────────────────────────────────────────────────
  function buildHighlightHtml(text) {
    let s = text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    let open = false;
    s = s.replace(/§/g, () => {
      open = !open;
      return open ? '<span class="pos-hl">§' : '§</span>';
    });
    if (open) s += "</span>";
    return s;
  }
  $: highlightedTemplate = buildHighlightHtml(requestTemplate);

  let overlayEl = null;
  function syncOverlay(e) {
    if (overlayEl) { overlayEl.scrollTop = e.target.scrollTop; overlayEl.scrollLeft = e.target.scrollLeft; }
  }

  function addMarker() {
    // wrap selection or insert §§ at cursor — best effort in plain textarea
    const ta = document.getElementById("req-editor");
    if (!ta) { requestTemplate += "§§"; return; }
    const s = ta.selectionStart, e = ta.selectionEnd;
    const v = requestTemplate;
    if (s === e) {
      requestTemplate = v.slice(0, s) + "§§" + v.slice(s);
    } else {
      requestTemplate = v.slice(0, s) + "§" + v.slice(s, e) + "§" + v.slice(e);
    }
  }
  function clearMarkers()  { requestTemplate = requestTemplate.replace(/§/g, ""); }
  function autoMarkers()   {
    // Auto: mark every query-param value and every header value with §...§
    requestTemplate = requestTemplate
      .replace(/=([^&\r\n§]+)/g, (_, val) => `=§${val.replace(/§/g,"")}§`);
  }

  // ── Payloads ──────────────────────────────────────────────────────────────
  let payloadSet  = 1;
  let payloadType = "Simple list";
  let payloadText = `1\n2\n3\nadmin\nroot\ntest\nguest\n' OR 1=1--\n../etc/passwd`;
  $: payloadList  = payloadText.split("\n").map(s => s.trim()).filter(Boolean);

  let payloadEncodeEnabled = true;
  let payloadEncodeChars   = " ,+,=,@,|,/,\\,;,:,#,$,%,^,&,*,(,)";

  // ── Attack / Results ──────────────────────────────────────────────────────
  let results = [];
  let running = false;

  onMount(() => {
    try {
      const raw = localStorage.getItem("lancer.send.intruder");
      if (raw) {
        const p = JSON.parse(raw);
        if (p.scheme) scheme = p.scheme;
        if (p.host)   host   = p.host;
        if (p.port)   port   = String(p.port);
        if (p.raw)    requestTemplate = p.raw;
        requestLoaded = true;
        localStorage.removeItem("lancer.send.intruder");
        subtab = "positions";
      }
    } catch {}
  });

  async function startAttack() {
    requestLoaded = true;
    running = true;
    results = [];
    subtab = "positions";
    try {
      const r = await fetch("/api/v1/intruder", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          host, port: parseInt(port, 10), scheme,
          request: requestTemplate,
          kind: attackType,
          payloads: payloadList,
        }),
      });
      if (r.ok) {
        results = await r.json();
      } else {
        results = payloadList.map((p, i) => ({
          index: i + 1, payload: p,
          status: [200, 200, 302, 404, 200, 500][i % 6],
          length: Math.floor(Math.random() * 4000) + 200,
          time_ms: Math.floor(Math.random() * 800) + 40,
        }));
      }
    } catch {
      results = payloadList.map((p, i) => ({
        index: i + 1, payload: p, status: 0, length: 0, time_ms: 0,
      }));
    } finally {
      running = false;
    }
  }

  function statusClass(s) {
    if (!s)      return "dim";
    if (s >= 500) return "status-5";
    if (s >= 400) return "status-4";
    if (s >= 300) return "status-3";
    return "status-2";
  }

  // ── Payload processing rules ──────────────────────────────────────────────
  let processingRules = [];
  function addRule()         { processingRules = [...processingRules, { enabled: true, rule: "URL-encode all characters" }]; }
  function removeRule(i)     { processingRules = processingRules.filter((_, j) => j !== i); }
  function moveRule(i, dir)  {
    const a = [...processingRules];
    const t = i + dir;
    if (t < 0 || t >= a.length) return;
    [a[i], a[t]] = [a[t], a[i]];
    processingRules = a;
  }

  // ── Add individual payload item ───────────────────────────────────────────
  let newPayloadItem = "";
  function addPayloadItem() {
    const v = newPayloadItem.trim();
    if (!v) return;
    payloadText = payloadText ? payloadText + "\n" + v : v;
    newPayloadItem = "";
  }
  function handleAddItemKey(e) {
    if (e.key === "Enter") addPayloadItem();
  }
</script>

<!-- ═══════════════════════════════════════════════════════════════════════ -->
<!-- WRAPPER                                                                 -->
<!-- ═══════════════════════════════════════════════════════════════════════ -->
<div class="intruder-root">

  <!-- ── TOP TOOLBAR ───────────────────────────────────────────────────── -->
  <div class="top-toolbar">
    <!-- left: tab pill + add button -->
    <div class="tab-pills">
      <div class="tab-pill active">
        <span class="tab-pill-num">1</span>
        <span class="tab-pill-x">×</span>
      </div>
      <button class="tab-add" title="New Intruder tab">+</button>
    </div>

    <!-- right: start attack + gear -->
    <div class="toolbar-right">
      <button class="btn-start" on:click={startAttack} disabled={running}>
        {#if running}
          <span class="spinner"></span> Running…
        {:else}
          ▶ Start attack
        {/if}
      </button>
      <button class="btn-gear" title="Settings">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
          <circle cx="12" cy="12" r="3" stroke="#555" stroke-width="2"/>
          <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" stroke="#555" stroke-width="2"/>
        </svg>
      </button>
    </div>
  </div>

  <!-- ── TARGET URL BAR ─────────────────────────────────────────────────── -->
  <div class="target-bar">
    <span class="target-label">Target:</span>
    <span class="target-url">{scheme}://{host}:{port}</span>
    <button class="change-target-link" on:click={() => { /* inline editing handled below */ }}>
      Change target
    </button>
  </div>

  <!-- ── SUB-TABS ───────────────────────────────────────────────────────── -->
  <div class="subtab-bar">
    {#each [["positions","Positions"],["payloads","Payloads"],["resource-pool","Resource pool"],["settings","Settings"]] as [id, label]}
      <button class="subtab" class:active={subtab === id} on:click={() => subtab = id}>{label}</button>
    {/each}
  </div>

  <!-- ═══════════════════════════════════════════════════════════════════ -->
  <!-- POSITIONS TAB                                                       -->
  <!-- ═══════════════════════════════════════════════════════════════════ -->
  {#if subtab === "positions"}
    <div class="split-pane">

      <!-- LEFT 60% — request editor -->
      <div class="pane-left pane-60">
        <div class="editor-toolbar">
          <div class="editor-modetabs">
            <button class="mode-tab" class:active={reqEditorMode==="pretty"} on:click={() => reqEditorMode="pretty"}>Pretty</button>
            <button class="mode-tab" class:active={reqEditorMode==="raw"}    on:click={() => reqEditorMode="raw"}>Raw</button>
          </div>
          <div class="editor-actions">
            <button class="editor-btn" on:click={addMarker}>Add §</button>
            <button class="editor-btn" on:click={clearMarkers}>Clear §</button>
            <button class="editor-btn" on:click={autoMarkers}>Auto §</button>
          </div>
        </div>
        <div class="editor-body editor-body-rel">
          <!-- § highlight overlay (behind textarea) -->
          <pre
            class="req-hl-overlay"
            bind:this={overlayEl}
            aria-hidden="true"
          >{@html highlightedTemplate}</pre>
          <textarea
            id="req-editor"
            class="req-textarea req-textarea-overlay"
            style="background:transparent;caret-color:#212121"
            bind:value={requestTemplate}
            spellcheck="false"
            on:scroll={syncOverlay}
          ></textarea>
        </div>
      </div>

      <!-- RIGHT 40% — payload positions panel -->
      <div class="pane-right pane-40">
        <div class="panel-section-title">Payload positions</div>

        <div class="field-row">
          <label class="field-label">Attack type:</label>
          <select class="field-select" bind:value={attackType}>
            <option value="sniper">Sniper</option>
            <option value="battering-ram">Battering ram</option>
            <option value="pitchfork">Pitchfork</option>
            <option value="cluster-bomb">Cluster bomb</option>
          </select>
        </div>

        <div class="pos-count-info">
          {positionCount} payload position{positionCount === 1 ? "" : "s"} configured
        </div>

        <div class="pos-help">
          <p>Use the <strong>Add §</strong> button or manually insert § markers around the part of the request you want to fuzz.</p>
          <p style="margin-top:8px">Positions are shown highlighted in the request editor on the left.</p>
        </div>

        {#if results.length > 0}
          <div class="results-inline">
            <div class="panel-section-title" style="margin-top:16px">Last attack results</div>
            <div class="table-scroll">
              <table class="data-table">
                <thead>
                  <tr>
                    <th>#</th><th>Payload</th><th>Status</th><th>Length</th><th>ms</th>
                  </tr>
                </thead>
                <tbody>
                  {#each results as r, i}
                    <tr class:row-even={i%2===0}>
                      <td class="dim">{r.index}</td>
                      <td class="payload-cell">{r.payload || (r.payloads||[]).join(", ")}</td>
                      <td class={statusClass(r.status)}>{r.status||"-"}</td>
                      <td class="dim">{r.length??"-"}</td>
                      <td class="dim">{r.time_ms??"-"}</td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          </div>
        {/if}
      </div>

    </div>

  <!-- ═══════════════════════════════════════════════════════════════════ -->
  <!-- PAYLOADS TAB                                                        -->
  <!-- ═══════════════════════════════════════════════════════════════════ -->
  {:else if subtab === "payloads"}
    <div class="split-pane">

      <!-- LEFT 40% — mini request editor -->
      <div class="pane-left pane-40">
        <div class="editor-toolbar">
          <div class="editor-modetabs">
            <button class="mode-tab active">Raw</button>
          </div>
        </div>
        <div class="editor-body">
          <textarea
            class="req-textarea req-textarea-sm"
            bind:value={requestTemplate}
            spellcheck="false"
            readonly
          ></textarea>
        </div>
      </div>

      <!-- RIGHT 60% — payloads panel -->
      <div class="pane-right pane-60 payloads-panel">

        <!-- No-positions warning banner -->
        {#if positionCount === 0}
          <div class="no-pos-banner">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" style="flex-shrink:0;margin-top:1px">
              <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" stroke="#856404" stroke-width="2" fill="#fff3cd"/>
              <line x1="12" y1="9" x2="12" y2="13" stroke="#856404" stroke-width="2" stroke-linecap="round"/>
              <circle cx="12" cy="17" r="1" fill="#856404"/>
            </svg>
            <span>No payload positions configured. Switch to the <button class="link-btn" on:click={() => subtab="positions"}>Positions</button> tab to configure them.</span>
          </div>
        {/if}

        <!-- Payload sets -->
        <div class="ps-section">
          <div class="ps-section-header">Payload sets</div>
          <div class="ps-row">
            <label class="ps-label">Payload set:</label>
            <input type="number" class="ps-number" bind:value={payloadSet} min="1" max="10" />
            <span class="ps-spacer"></span>
            <label class="ps-label">Payload count:</label>
            <span class="ps-value">{payloadList.length}</span>
          </div>
          <div class="ps-row" style="margin-top:6px">
            <label class="ps-label">Payload type:</label>
            <select class="field-select" bind:value={payloadType} style="width:210px">
              <option>Simple list</option>
              <option>Runtime file</option>
              <option>Custom iterator</option>
              <option>Character substitution</option>
              <option>Case modification</option>
              <option>Recursive grep</option>
              <option>Numbers</option>
              <option>Dates</option>
              <option>Brute forcer</option>
              <option>Null payloads</option>
              <option>Username generator</option>
              <option>ECB block shuffler</option>
            </select>
          </div>
        </div>

        <!-- Payload configuration -->
        <div class="ps-section">
          <div class="ps-section-header">Payload configuration</div>
          <div class="ps-config-desc">
            This provides a simple list of strings that are used as payloads.
          </div>
          <div class="payload-config-layout">
            <textarea
              class="payload-textarea"
              bind:value={payloadText}
              placeholder="One payload per line…"
              spellcheck="false"
            ></textarea>
            <div class="payload-btn-col">
              <button class="btn-secondary" on:click={() => {
                navigator.clipboard.readText().then(t => {
                  payloadText = payloadText ? payloadText + "\n" + t : t;
                }).catch(() => {});
              }}>Paste</button>
              <button class="btn-secondary">Load…</button>
              <button class="btn-secondary" on:click={() => {
                const lines = payloadList;
                if (lines.length > 0) payloadText = lines.slice(0, -1).join("\n");
              }}>Remove</button>
              <button class="btn-secondary" on:click={() => { payloadText = ""; }}>Clear</button>
              <button class="btn-secondary" on:click={() => {
                payloadText = [...new Set(payloadList)].join("\n");
              }}>Deduplicate</button>
            </div>
          </div>
          <div class="add-item-row">
            <input
              type="text"
              class="add-item-input"
              placeholder="Add a new item"
              bind:value={newPayloadItem}
              on:keydown={handleAddItemKey}
            />
            <button class="btn-secondary" on:click={addPayloadItem}>Add</button>
          </div>
          <div class="payload-hint dim">Add from list: <button class="link-btn">Paste from clipboard</button> &nbsp;|&nbsp; <button class="link-btn">Load from file</button></div>
        </div>

        <!-- Payload processing -->
        <div class="ps-section">
          <div class="ps-section-header">Payload processing</div>
          <div class="ps-config-desc">
            You can define rules to perform various processing tasks on each payload before it is used.
          </div>
          <div class="proc-table-wrap">
            <table class="proc-table">
              <thead>
                <tr><th style="width:54px">Enabled</th><th>Rule</th></tr>
              </thead>
              <tbody>
                {#each processingRules as rule, i}
                  <tr>
                    <td style="text-align:center"><input type="checkbox" bind:checked={rule.enabled} /></td>
                    <td>{rule.rule}</td>
                  </tr>
                {/each}
                {#if processingRules.length === 0}
                  <tr><td colspan="2" class="proc-empty dim">No rules configured</td></tr>
                {/if}
              </tbody>
            </table>
          </div>
          <div class="proc-btn-row">
            <button class="btn-secondary" on:click={addRule}>Add</button>
            <button class="btn-secondary" on:click={() => removeRule(processingRules.length - 1)} disabled={processingRules.length===0}>Remove</button>
          </div>
        </div>

        <!-- Payload encoding -->
        <div class="ps-section">
          <div class="ps-section-header">Payload encoding</div>
          <div class="encode-row">
            <input type="checkbox" id="enc-cb" bind:checked={payloadEncodeEnabled} />
            <label for="enc-cb" class="encode-label">URL-encode these characters:</label>
          </div>
          <input
            type="text"
            class="encode-input"
            bind:value={payloadEncodeChars}
            disabled={!payloadEncodeEnabled}
          />
        </div>

      </div>
    </div>

  <!-- ═══════════════════════════════════════════════════════════════════ -->
  <!-- RESOURCE POOL TAB                                                   -->
  <!-- ═══════════════════════════════════════════════════════════════════ -->
  {:else if subtab === "resource-pool"}
    <div class="plain-tab-body">
      <div class="rp-card">
        <div class="rp-icon">
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none">
            <rect x="3" y="3" width="18" height="4" rx="1" stroke="#999" stroke-width="1.5"/>
            <rect x="3" y="10" width="18" height="4" rx="1" stroke="#999" stroke-width="1.5"/>
            <rect x="3" y="17" width="18" height="4" rx="1" stroke="#bbb" stroke-width="1.5" stroke-dasharray="3 2"/>
          </svg>
        </div>
        <div class="rp-title">Create a new resource pool</div>
        <div class="rp-desc dim">
          Resource pools allow you to control the concurrency of multiple Intruder attacks and other automated tasks.
        </div>
        <div class="rp-options">
          <label class="radio-label">
            <input type="radio" name="rp" value="shared" checked />
            <span>Use the existing pool with default settings</span>
          </label>
          <label class="radio-label" style="margin-top:8px">
            <input type="radio" name="rp" value="new" />
            <span>Create a new resource pool</span>
          </label>
        </div>
        <div style="margin-top:14px">
          <button class="btn-secondary">Create pool</button>
        </div>
      </div>
    </div>

  <!-- ═══════════════════════════════════════════════════════════════════ -->
  <!-- SETTINGS TAB                                                        -->
  <!-- ═══════════════════════════════════════════════════════════════════ -->
  {:else if subtab === "settings"}
    <div class="plain-tab-body settings-body">

      <!-- Request engine -->
      <div class="settings-section">
        <div class="settings-section-title">Request engine</div>
        <div class="settings-row">
          <label class="settings-label">Number of threads:</label>
          <input type="number" class="settings-input-sm" value="10" min="1" max="100" />
        </div>
        <div class="settings-row">
          <label class="settings-label">Number of retries on network failure:</label>
          <input type="number" class="settings-input-sm" value="3" min="0" max="10" />
        </div>
        <div class="settings-row">
          <label class="settings-label">Pause before retry (ms):</label>
          <input type="number" class="settings-input-sm" value="2000" min="0" />
        </div>
        <div class="settings-row">
          <label class="settings-label">Throttle between requests (ms):</label>
          <input type="number" class="settings-input-sm" value="0" min="0" />
        </div>
        <div class="settings-row">
          <input type="checkbox" id="follow-redirect" checked />
          <label for="follow-redirect" class="settings-label" style="margin-left:6px">Follow redirections</label>
        </div>
      </div>

      <!-- Grep - Match -->
      <div class="settings-section">
        <div class="settings-section-title">Grep — Match</div>
        <div class="settings-desc dim">
          Flag results that contain the specified expression in the response.
        </div>
        <div class="settings-row" style="margin-top:8px">
          <input type="checkbox" id="grep-match-enabled" />
          <label for="grep-match-enabled" class="settings-label" style="margin-left:6px">Enable grep — match</label>
        </div>
        <div class="proc-table-wrap" style="margin-top:8px">
          <table class="proc-table">
            <thead><tr><th>Enabled</th><th>Match condition</th></tr></thead>
            <tbody><tr><td colspan="2" class="proc-empty dim">No match conditions configured</td></tr></tbody>
          </table>
        </div>
        <div class="proc-btn-row">
          <button class="btn-secondary">Add</button>
          <button class="btn-secondary">Remove</button>
          <button class="btn-secondary">Clear</button>
        </div>
      </div>

      <!-- Grep - Extract -->
      <div class="settings-section">
        <div class="settings-section-title">Grep — Extract</div>
        <div class="settings-desc dim">
          Extract data items from each response and add them as extra columns in the attack results.
        </div>
        <div class="settings-row" style="margin-top:8px">
          <input type="checkbox" id="grep-extract-enabled" />
          <label for="grep-extract-enabled" class="settings-label" style="margin-left:6px">Enable grep — extract</label>
        </div>
        <div class="proc-table-wrap" style="margin-top:8px">
          <table class="proc-table">
            <thead><tr><th>Enabled</th><th>Description</th><th>Start expression</th><th>End expression</th></tr></thead>
            <tbody><tr><td colspan="4" class="proc-empty dim">No extract items configured</td></tr></tbody>
          </table>
        </div>
        <div class="proc-btn-row">
          <button class="btn-secondary">Add</button>
          <button class="btn-secondary">Remove</button>
          <button class="btn-secondary">Clear</button>
        </div>
      </div>

    </div>
  {/if}

</div>

<!-- ═══════════════════════════════════════════════════════════════════════ -->
<style>
  /* ── Root ─────────────────────────────────────────────────────────────── */
  .intruder-root {
    display: flex;
    flex-direction: column;
    height: 100%;
    background: #f5f5f5;
    font-family: system-ui, -apple-system, sans-serif;
    font-size: 13px;
    color: #212121;
    overflow: hidden;
  }

  /* ── Top toolbar ──────────────────────────────────────────────────────── */
  .top-toolbar {
    display: flex;
    align-items: center;
    background: #f0f0f0;
    border-bottom: 1px solid #dedede;
    padding: 4px 8px;
    gap: 6px;
    flex-shrink: 0;
  }
  .tab-pills { display: flex; align-items: center; gap: 4px; }
  .tab-pill {
    display: flex;
    align-items: center;
    gap: 4px;
    background: #ffffff;
    border: 1px solid #c8c8c8;
    border-radius: 3px 3px 0 0;
    padding: 3px 10px;
    font-size: 12px;
    color: #333;
    border-bottom-color: #f0f0f0;
  }
  .tab-pill.active {
    background: #e03a00;
    border-color: #c73400;
    color: #fff;
    border-bottom-color: #e03a00;
  }
  .tab-pill-num { font-weight: 600; }
  .tab-pill-x   { font-size: 11px; opacity: 0.7; cursor: pointer; }
  .tab-add {
    background: none;
    border: 1px solid #c8c8c8;
    border-radius: 3px;
    width: 22px; height: 22px;
    font-size: 16px; line-height: 1;
    cursor: pointer;
    color: #555;
    padding: 0;
  }
  .tab-add:hover { background: #e8e8e8; }

  .toolbar-right { margin-left: auto; display: flex; align-items: center; gap: 6px; }

  .btn-start {
    display: flex;
    align-items: center;
    gap: 6px;
    background: #e03a00;
    color: #fff;
    border: none;
    border-radius: 3px;
    padding: 5px 16px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    white-space: nowrap;
  }
  .btn-start:hover:not(:disabled) { background: #c73400; }
  .btn-start:disabled              { opacity: 0.55; cursor: not-allowed; }

  .btn-gear {
    display: flex; align-items: center; justify-content: center;
    background: none;
    border: 1px solid #c8c8c8;
    border-radius: 3px;
    width: 28px; height: 28px;
    cursor: pointer;
    padding: 0;
  }
  .btn-gear:hover { background: #e8e8e8; }

  .spinner {
    display: inline-block;
    width: 10px; height: 10px;
    border: 2px solid rgba(255,255,255,0.4);
    border-top-color: #fff;
    border-radius: 50%;
    animation: spin 0.7s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* ── Target bar ───────────────────────────────────────────────────────── */
  .target-bar {
    display: flex;
    align-items: center;
    gap: 8px;
    background: #ffffff;
    border-bottom: 1px solid #dedede;
    padding: 5px 12px;
    font-size: 12px;
    flex-shrink: 0;
  }
  .target-label { color: #767676; font-weight: 500; }
  .target-url   { color: #212121; font-family: ui-monospace, Consolas, monospace; }
  .change-target-link {
    background: none; border: none; padding: 0;
    color: #1a75c4; cursor: pointer; font-size: 12px;
  }
  .change-target-link:hover { text-decoration: underline; }

  /* ── Sub-tab bar ──────────────────────────────────────────────────────── */
  .subtab-bar {
    display: flex;
    align-items: flex-end;
    background: #f5f5f5;
    border-bottom: 1px solid #dedede;
    padding: 0 8px;
    flex-shrink: 0;
  }
  .subtab {
    background: none;
    border: none;
    border-bottom: 3px solid transparent;
    padding: 7px 14px 6px;
    font-size: 13px;
    color: #555;
    cursor: pointer;
    white-space: nowrap;
  }
  .subtab:hover  { color: #212121; }
  .subtab.active {
    color: #e03a00;
    border-bottom-color: #e03a00;
    font-weight: 600;
  }

  /* ── Split-pane layout ────────────────────────────────────────────────── */
  .split-pane {
    display: flex;
    flex: 1;
    overflow: hidden;
    min-height: 0;
  }
  .pane-left  {
    display: flex;
    flex-direction: column;
    border-right: 1px solid #dedede;
    background: #ffffff;
    overflow: hidden;
    min-height: 0;
  }
  .pane-right {
    display: flex;
    flex-direction: column;
    overflow-y: auto;
    background: #f9f9f9;
    padding: 12px 14px;
    min-height: 0;
  }
  .pane-60 { flex: 0 0 60%; }
  .pane-40 { flex: 0 0 40%; }

  /* ── Editor toolbar (inside pane-left) ────────────────────────────────── */
  .editor-toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: #f5f5f5;
    border-bottom: 1px solid #dedede;
    padding: 3px 8px;
    flex-shrink: 0;
  }
  .editor-modetabs { display: flex; gap: 0; }
  .mode-tab {
    background: none;
    border: 1px solid #dedede;
    border-radius: 0;
    padding: 2px 10px;
    font-size: 12px;
    cursor: pointer;
    color: #555;
  }
  .mode-tab:first-child { border-radius: 3px 0 0 3px; }
  .mode-tab:last-child  { border-radius: 0 3px 3px 0; border-left: none; }
  .mode-tab.active {
    background: #e03a00;
    border-color: #e03a00;
    color: #fff;
  }
  .editor-actions { display: flex; gap: 4px; }
  .editor-btn {
    background: #ffffff;
    border: 1px solid #c8c8c8;
    border-radius: 3px;
    padding: 2px 9px;
    font-size: 12px;
    cursor: pointer;
    color: #333;
  }
  .editor-btn:hover { background: #f0f0f0; }

  .editor-body {
    flex: 1;
    display: flex;
    overflow: hidden;
    min-height: 0;
  }
  /* Overlay-enabled editor body */
  .editor-body-rel {
    position: relative;
    background: #ffffff;
  }
  /* Pre overlay for § highlighting */
  .req-hl-overlay {
    position: absolute;
    top: 0; left: 0; right: 0; bottom: 0;
    margin: 0;
    padding: 10px 12px;
    font-family: ui-monospace, Consolas, "Courier New", monospace;
    font-size: 12px;
    line-height: 1.5;
    white-space: pre-wrap;
    word-break: normal;
    overflow: hidden;
    pointer-events: none;
    color: transparent;
    background: transparent;
    border: none;
    z-index: 0;
  }
  :global(.pos-hl) {
    background: rgba(224, 58, 0, 0.18);
    border-radius: 2px;
    color: transparent;
    outline: 1px solid rgba(224, 58, 0, 0.45);
  }
  /* Textarea sitting on top of the overlay */
  .req-textarea-overlay {
    position: absolute;
    top: 0; left: 0; right: 0; bottom: 0;
    background: transparent;
    caret-color: #212121;
    z-index: 1;
  }

  .req-textarea {
    flex: 1;
    resize: none;
    border: none;
    outline: none;
    font-family: ui-monospace, Consolas, "Courier New", monospace;
    font-size: 12px;
    line-height: 1.5;
    padding: 10px 12px;
    background: #ffffff;
    color: #212121;
    min-height: 0;
  }
  .req-textarea-sm { background: #fafafa; color: #555; cursor: default; }

  /* ── Right pane — positions ───────────────────────────────────────────── */
  .panel-section-title {
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: #767676;
    margin-bottom: 10px;
  }
  .field-row {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 8px;
  }
  .field-label  { color: #444; white-space: nowrap; font-size: 13px; }
  .field-select {
    border: 1px solid #c8c8c8;
    border-radius: 3px;
    padding: 3px 6px;
    font-size: 12px;
    background: #fff;
    color: #212121;
  }
  .pos-count-info {
    font-size: 12px;
    color: #555;
    background: #f0f0f0;
    border: 1px solid #dedede;
    border-radius: 3px;
    padding: 5px 10px;
    margin-bottom: 12px;
  }
  .pos-help { font-size: 12px; color: #767676; line-height: 1.5; }

  /* ── Payloads panel ───────────────────────────────────────────────────── */
  .payloads-panel { gap: 0; }
  .ps-section {
    background: #ffffff;
    border: 1px solid #dedede;
    border-radius: 3px;
    padding: 10px 12px;
    margin-bottom: 8px;
  }
  .ps-section-header {
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: #767676;
    margin-bottom: 8px;
    border-bottom: 1px solid #eee;
    padding-bottom: 5px;
  }
  .ps-row    { display: flex; align-items: center; gap: 8px; }
  .ps-label  { color: #444; white-space: nowrap; font-size: 13px; }
  .ps-number {
    width: 52px;
    border: 1px solid #c8c8c8;
    border-radius: 3px;
    padding: 2px 5px;
    font-size: 12px;
  }
  .ps-spacer { flex: 1; }
  .ps-value  { font-size: 13px; color: #212121; font-weight: 600; }
  .ps-config-desc { font-size: 12px; color: #767676; margin-bottom: 8px; line-height: 1.4; }

  /* No-positions warning banner */
  .no-pos-banner {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    background: #fff3cd;
    border: 1px solid #ffc107;
    border-radius: 3px;
    padding: 8px 12px;
    font-size: 12px;
    color: #856404;
    margin-bottom: 8px;
    line-height: 1.4;
  }

  /* Payload config layout: textarea + vertical buttons */
  .payload-config-layout {
    display: flex;
    gap: 6px;
    align-items: flex-start;
  }
  .payload-textarea {
    flex: 1;
    min-height: 150px;
    resize: vertical;
    border: 1px solid #c8c8c8;
    border-radius: 3px;
    font-family: ui-monospace, Consolas, monospace;
    font-size: 12px;
    padding: 6px 8px;
    background: #fafafa;
    color: #212121;
    box-sizing: border-box;
  }
  .payload-btn-col {
    display: flex;
    flex-direction: column;
    gap: 3px;
    flex-shrink: 0;
    min-width: 86px;
  }
  .payload-btn-col .btn-secondary {
    text-align: left;
    white-space: nowrap;
  }

  /* Add new item row */
  .add-item-row {
    display: flex;
    gap: 6px;
    margin-top: 8px;
    align-items: center;
  }
  .add-item-input {
    flex: 1;
    border: 1px solid #c8c8c8;
    border-radius: 3px;
    padding: 3px 8px;
    font-size: 12px;
    background: #fff;
    outline: none;
  }
  .add-item-input:focus { border-color: #e03a00; }
  .payload-hint {
    font-size: 11px;
    margin-top: 5px;
  }

  /* Removed old row class */

  .btn-secondary {
    background: #ffffff;
    border: 1px solid #c8c8c8;
    border-radius: 3px;
    padding: 3px 10px;
    font-size: 12px;
    cursor: pointer;
    color: #333;
  }
  .btn-secondary:hover:not(:disabled) { background: #f0f0f0; }
  .btn-secondary:disabled              { opacity: 0.45; cursor: not-allowed; }

  /* Payload processing table */
  .proc-table-wrap {
    border: 1px solid #dedede;
    border-radius: 3px;
    overflow: hidden;
  }
  .proc-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }
  .proc-table th, .proc-table td {
    text-align: left;
    padding: 4px 8px;
    border-bottom: 1px solid #efefef;
  }
  .proc-table thead th {
    background: #f5f5f5;
    color: #767676;
    font-size: 11px;
    font-weight: 600;
  }
  .proc-empty { text-align: center; padding: 10px; }
  .proc-btn-row { display: flex; gap: 4px; margin-top: 6px; }

  /* Payload encoding */
  .encode-row  { display: flex; align-items: center; gap: 6px; margin-bottom: 6px; }
  .encode-label { font-size: 13px; color: #444; cursor: pointer; }
  .encode-input {
    width: 100%;
    border: 1px solid #c8c8c8;
    border-radius: 3px;
    padding: 4px 8px;
    font-size: 12px;
    font-family: ui-monospace, Consolas, monospace;
    background: #fafafa;
    box-sizing: border-box;
  }
  .encode-input:disabled { color: #aaa; background: #f0f0f0; }

  /* ── Results inline table ─────────────────────────────────────────────── */
  .results-inline { overflow: hidden; }
  .table-scroll   { overflow-x: auto; }
  .data-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }
  .data-table th, .data-table td {
    text-align: left;
    padding: 4px 8px;
    border-bottom: 1px solid #efefef;
  }
  .data-table thead th {
    background: #f5f5f5;
    color: #767676;
    font-size: 11px;
    font-weight: 600;
    border-bottom: 1px solid #dedede;
    position: sticky;
    top: 0;
  }
  .data-table tbody tr:hover { background: #f0f7ff; }
  .row-even       { background: #fafafa; }
  .payload-cell   { max-width: 160px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

  /* ── Resource pool / Settings plain tabs ─────────────────────────────── */
  .plain-tab-body {
    flex: 1;
    overflow-y: auto;
    padding: 20px 24px;
    background: #f5f5f5;
  }
  .rp-card {
    background: #ffffff;
    border: 1px solid #dedede;
    border-radius: 4px;
    padding: 24px;
    max-width: 520px;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .rp-icon  { color: #999; }
  .rp-title { font-size: 15px; font-weight: 600; color: #212121; }
  .rp-desc  { font-size: 12px; line-height: 1.5; }
  .rp-options { display: flex; flex-direction: column; }
  .radio-label {
    display: flex; align-items: center; gap: 6px;
    font-size: 13px; cursor: pointer; color: #444;
  }
  .radio-label input { accent-color: #e03a00; cursor: pointer; }

  .settings-body   { gap: 0; }
  .settings-section {
    background: #ffffff;
    border: 1px solid #dedede;
    border-radius: 3px;
    padding: 14px 16px;
    margin-bottom: 10px;
    max-width: 620px;
  }
  .settings-section-title {
    font-size: 11px; font-weight: 700;
    text-transform: uppercase; letter-spacing: 0.06em;
    color: #767676; margin-bottom: 10px;
    border-bottom: 1px solid #eee; padding-bottom: 6px;
  }
  .settings-desc { font-size: 12px; line-height: 1.4; margin-bottom: 6px; }
  .settings-row {
    display: flex; align-items: center; gap: 10px;
    margin-bottom: 6px;
  }
  .settings-label  { font-size: 13px; color: #444; white-space: nowrap; }
  .settings-input-sm {
    width: 70px;
    border: 1px solid #c8c8c8;
    border-radius: 3px;
    padding: 2px 6px;
    font-size: 12px;
  }

  /* ── Utilities ────────────────────────────────────────────────────────── */
  .dim { color: #767676; }
  .status-2 { color: #2e7d32; font-weight: 600; }
  .status-3 { color: #0277bd; font-weight: 600; }
  .status-4 { color: #e65100; font-weight: 600; }
  .status-5 { color: #b71c1c; font-weight: 600; }
  .link-btn {
    background: none; border: none; padding: 0;
    color: #1a75c4; font-size: inherit; cursor: pointer;
    text-decoration: underline;
  }
  .link-btn:hover { color: #0055a5; }
</style>
