<script>
  import { onMount } from "svelte";

  let subtab = "live";
  let tokenLocation = "cookie";
  let tokenParam = "";
  let capturing = false;
  let tokenCount = 0;
  let charEntropy = 0;
  let bitEntropy = 0;
  let effectiveKeyspace = 0;
  let tokens = [];
  let manualTokens = "";
  let captureInterval = null;
  // Real FIPS stats returned by the backend.
  let fips = null; // { monobit_p_value, poker_p_value, runs_p_value, fips_pass }
  let busy = false;

  async function analyseTokens(tokenArr) {
    if (!tokenArr.length) return;
    busy = true;
    try {
      const r = await fetch("/api/v1/sequencer/analyse", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ tokens: tokenArr }),
      });
      if (r.ok) applyStats(await r.json());
    } catch {} finally { busy = false; }
  }

  function applyStats(d) {
    tokenCount = d.tokens || 0;
    bitEntropy = d.bit_entropy ?? d.effective_entropy_bits ?? 0;
    charEntropy = tokenCount ? +(bitEntropy / Math.max(1, (tokens[0] || "x").length)).toFixed(2) : 0;
    effectiveKeyspace = Math.round(Math.pow(2, Math.min(bitEntropy, 53)));
    fips = {
      monobit: d.monobit_p_value, poker: d.poker_p_value, runs: d.runs_p_value,
      pass: d.fips_pass, charPos: d.char_position_entropy,
    };
  }

  // ── Live capture request selection ────────────────────────────────────────
  let captureRequest = null;   // selected proxy history row
  let showRequestPicker = false;
  let historyRows = [];
  let analysisLevel = "normal";

  async function loadHistory() {
    try {
      const r = await fetch("/api/v1/history?limit=100");
      if (r.ok) historyRows = await r.json();
    } catch {}
  }

  function selectRequest(row) {
    captureRequest = row;
    showRequestPicker = false;
  }

  let captureCount = 100;
  async function startCapture() {
    if (!captureRequest || !tokenParam) return;
    capturing = true; busy = true; tokenCount = 0;
    // Real capture: backend re-issues the request N times and extracts the token.
    const row = captureRequest;
    const raw = row.raw_request || `${row.method || "GET"} ${row.path || "/"} HTTP/1.1\r\nHost: ${row.host || ""}\r\n\r\n`;
    try {
      const r = await fetch("/api/v1/sequencer/capture", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({
          request: raw, scheme: row.scheme || (row.port === 80 ? "http" : "https"),
          host: row.host, port: row.port || (row.scheme === "http" ? 80 : 443),
          location: tokenLocation, param: tokenParam, count: +captureCount,
        }),
      });
      if (r.ok) {
        const d = await r.json();
        tokens = d.samples || [];
        applyStats(d);
      }
    } catch {} finally { capturing = false; busy = false; }
  }

  function stopCapture() {
    capturing = false;
    if (captureInterval) clearInterval(captureInterval);
  }

  function clearAll() {
    tokens = []; tokenCount = 0;
    charEntropy = 0; bitEntropy = 0; effectiveKeyspace = 0;
    manualTokens = ""; fips = null;
    capturing = false;
    if (captureInterval) clearInterval(captureInterval);
  }

  function analyseManual() {
    tokens = manualTokens.split("\n").map(t => t.trim()).filter(Boolean);
    analyseTokens(tokens);
  }

  function methodClass(m) {
    if (!m) return "";
    m = m.toUpperCase();
    if (m === "GET") return "m-get";
    if (m === "POST") return "m-post";
    return "m-other";
  }

  onMount(() => {
    loadHistory();
    // Check if something was sent here via context menu
    try {
      const raw = localStorage.getItem("lancer.send.sequencer");
      if (raw) {
        captureRequest = JSON.parse(raw);
        localStorage.removeItem("lancer.send.sequencer");
      }
    } catch {}
  });
</script>

<div class="view seq-root">
  <div class="subtabs">
    <button class="subtab" class:active={subtab==="live"}    on:click={() => subtab="live"}>Live capture</button>
    <button class="subtab" class:active={subtab==="manual"}  on:click={() => subtab="manual"}>Manual load</button>
    <button class="subtab" class:active={subtab==="options"} on:click={() => subtab="options"}>Analysis options</button>
  </div>

  <!-- ── LIVE CAPTURE ──────────────────────────────────────────────────────── -->
  {#if subtab === "live"}
    <div class="panel">

      <!-- Request selector card -->
      <div class="card">
        <div class="card-title">Live capture request</div>
        {#if captureRequest}
          <div class="req-display">
            <span class="req-method {methodClass(captureRequest.method)}">{captureRequest.method || "GET"}</span>
            <span class="req-host">{captureRequest.host || ""}</span>
            <span class="req-path">{captureRequest.path || "/"}</span>
            <button class="btn-secondary btn-sm" on:click={() => { captureRequest = null; }}>Clear</button>
          </div>
        {:else}
          <div class="req-empty dim">No request selected. Choose one to automatically capture tokens from live traffic.</div>
        {/if}
        <div style="margin-top:10px;display:flex;gap:8px">
          <button class="btn-secondary" on:click={() => { loadHistory(); showRequestPicker = !showRequestPicker; }}>
            {showRequestPicker ? "▲ Hide requests" : "▼ Select request"}
          </button>
        </div>

        {#if showRequestPicker}
          <div class="picker-table-wrap">
            {#if historyRows.length === 0}
              <div class="dim" style="padding:12px;font-size:12px">No proxy history yet. Browse through the proxy first.</div>
            {:else}
              <table class="pick-table">
                <thead>
                  <tr><th>#</th><th>Host</th><th>Method</th><th>URL</th><th>Status</th></tr>
                </thead>
                <tbody>
                  {#each historyRows as row, i}
                    <tr
                      class:row-sel={captureRequest === row}
                      on:click={() => selectRequest(row)}
                    >
                      <td class="dim">{i+1}</td>
                      <td>{row.host||"-"}</td>
                      <td class={methodClass(row.method)}>{row.method||"-"}</td>
                      <td class="url-cell">{(row.path||"/").length>60?(row.path||"/").slice(0,60)+"…":(row.path||"/")}</td>
                      <td>{row.status||"-"}</td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            {/if}
          </div>
        {/if}
      </div>

      <!-- Token location card -->
      <div class="card" style="margin-top:10px">
        <div class="card-title">Token location</div>
        <div class="location-row">
          <label class="radio-label">
            <input type="radio" bind:group={tokenLocation} value="header" />
            <span>Response header</span>
          </label>
          <label class="radio-label">
            <input type="radio" bind:group={tokenLocation} value="cookie" />
            <span>Cookie</span>
          </label>
          <label class="radio-label">
            <input type="radio" bind:group={tokenLocation} value="body" />
            <span>Body parameter</span>
          </label>
        </div>
        <div class="field-row" style="margin-top:12px">
          <label class="field-label" for="token-param">
            {tokenLocation === "cookie" ? "Cookie name" : tokenLocation === "header" ? "Header name" : "Parameter name"}
          </label>
          <input id="token-param" bind:value={tokenParam}
            placeholder={tokenLocation === "cookie" ? "e.g. session" : tokenLocation === "header" ? "e.g. Set-Cookie" : "e.g. token"}
            style="width:220px" />
        </div>
        <div class="field-row" style="margin-top:12px">
          <label class="field-label" for="cap-count">Samples to capture</label>
          <input id="cap-count" type="number" min="16" max="300" bind:value={captureCount} style="width:90px" />
        </div>
        <div style="display:flex;gap:8px;margin-top:14px;align-items:center">
          {#if !capturing}
            <button class="btn-orange" on:click={startCapture} disabled={!captureRequest || !tokenParam}>Start live capture</button>
            {#if !captureRequest}
              <span class="dim" style="font-size:12px">Select a request first</span>
            {:else if !tokenParam}
              <span class="dim" style="font-size:12px">Enter the token's {tokenLocation} name</span>
            {/if}
          {:else}
            <div class="capture-progress">
              <span class="capturing-pulse">● Re-issuing request &amp; collecting tokens…</span>
            </div>
          {/if}
        </div>
      </div>

      <!-- Results card -->
      <div class="card" style="margin-top:10px">
        <div class="card-title">Results</div>
        {#if tokenCount === 0}
          <div class="empty-hint">
            <svg width="32" height="32" viewBox="0 0 32 32" fill="none">
              <rect x="4" y="12" width="24" height="14" rx="2" stroke="#c8c8c8" stroke-width="1.2" fill="#f5f5f5"/>
              <rect x="8" y="8" width="16" height="6" rx="2" stroke="#c8c8c8" stroke-width="1.2" fill="#f5f5f5"/>
            </svg>
            <span class="dim">No tokens captured yet</span>
            <span class="dim" style="font-size:12px">Start capture or paste tokens to see entropy statistics</span>
          </div>
        {:else}
          <table class="data-table">
            <thead>
              <tr><th>Metric</th><th>Value</th><th>Rating</th></tr>
            </thead>
            <tbody>
              <tr>
                <td>Token count</td>
                <td class="mono">{tokenCount}</td>
                <td class="dim">{tokenCount < 100 ? "Need more samples" : "Sufficient"}</td>
              </tr>
              <tr class="row-even">
                <td>Character entropy</td>
                <td class="mono">{charEntropy} bits/char</td>
                <td class={charEntropy >= 4 ? "status-2" : charEntropy >= 3 ? "status-4" : "status-5"}>
                  {charEntropy >= 4 ? "Good" : charEntropy >= 3 ? "Medium" : "Low"}
                </td>
              </tr>
              <tr>
                <td>Bit entropy</td>
                <td class="mono">{bitEntropy} bits</td>
                <td class={bitEntropy >= 64 ? "status-2" : bitEntropy >= 32 ? "status-4" : "status-5"}>
                  {bitEntropy >= 64 ? "Strong" : bitEntropy >= 32 ? "Moderate" : "Weak"}
                </td>
              </tr>
              <tr class="row-even">
                <td>Effective key space</td>
                <td class="mono">2<sup>{bitEntropy}</sup></td>
                <td class="dim">—</td>
              </tr>
              {#if fips}
                <tr><td>FIPS 140-2 Monobit</td><td class="mono">p = {(fips.monobit ?? 0).toFixed(4)}</td><td class={fips.monobit >= 0.01 ? "status-2" : "status-5"}>{fips.monobit >= 0.01 ? "Pass" : "Fail"}</td></tr>
                <tr class="row-even"><td>FIPS Poker</td><td class="mono">p = {(fips.poker ?? 0).toFixed(4)}</td><td class={fips.poker >= 0.01 ? "status-2" : "status-5"}>{fips.poker >= 0.01 ? "Pass" : "Fail"}</td></tr>
                <tr><td>FIPS Runs</td><td class="mono">p = {(fips.runs ?? 0).toFixed(4)}</td><td class={fips.runs >= 0.01 ? "status-2" : "status-5"}>{fips.runs >= 0.01 ? "Pass" : "Fail"}</td></tr>
                <tr class="row-even"><td>Overall FIPS battery</td><td class="mono">{fips.pass ? "PASS" : "FAIL"}</td><td class={fips.pass ? "status-2" : "status-5"}>{fips.pass ? "Random" : "Predictable"}</td></tr>
              {/if}
            </tbody>
          </table>
          <div style="margin-top:10px">
            <button on:click={clearAll} class="btn-secondary">Clear results</button>
          </div>
        {/if}
      </div>
    </div>
  {/if}

  <!-- ── MANUAL LOAD ─────────────────────────────────────────────────────── -->
  {#if subtab === "manual"}
    <div class="panel">
      <div class="card">
        <div class="card-title">Paste tokens</div>
        <div class="dim" style="font-size:12px;margin-bottom:8px;line-height:1.5">
          Paste one token per line. Lancer will analyse the randomness quality of the token set.
        </div>
        <textarea
          class="token-textarea"
          placeholder="abc123&#10;xyz789&#10;tok_abc456&#10;..."
          bind:value={manualTokens}
        ></textarea>
        <div style="margin-top:10px;display:flex;gap:8px;align-items:center">
          <button class="btn-orange" on:click={analyseManual} disabled={!manualTokens.trim()}>Analyse now</button>
          <span class="dim" style="font-size:12px">
            {manualTokens.split("\n").filter(l=>l.trim()).length} tokens
          </span>
        </div>
        {#if tokenCount > 0}
          <table class="data-table" style="margin-top:14px">
            <thead>
              <tr><th>Metric</th><th>Value</th><th>Rating</th></tr>
            </thead>
            <tbody>
              <tr>
                <td>Tokens</td>
                <td class="mono">{tokenCount}</td>
                <td class="dim">{tokenCount < 100 ? "Need more" : "Sufficient"}</td>
              </tr>
              <tr class="row-even">
                <td>Character entropy</td>
                <td class="mono">{charEntropy} bits/char</td>
                <td class={charEntropy >= 4 ? "status-2" : "status-4"}>{charEntropy >= 4 ? "Good" : "Medium"}</td>
              </tr>
              <tr>
                <td>Bit entropy</td>
                <td class="mono">{bitEntropy} bits</td>
                <td class={bitEntropy >= 64 ? "status-2" : bitEntropy >= 32 ? "status-4" : "status-5"}>
                  {bitEntropy >= 64 ? "Strong" : "Moderate"}
                </td>
              </tr>
            </tbody>
          </table>
        {/if}
      </div>
    </div>
  {/if}

  <!-- ── ANALYSIS OPTIONS ───────────────────────────────────────────────── -->
  {#if subtab === "options"}
    <div class="panel">
      <div class="card">
        <div class="card-title">Analysis level</div>
        <div class="dim" style="font-size:12px;margin-bottom:12px;line-height:1.5">
          The analysis level controls the depth of statistical testing. Higher levels take longer but produce more reliable results.
        </div>
        <div style="display:flex;flex-direction:column;gap:8px">
          {#each [["fastest","Fastest — basic entropy only"],["normal","Normal — recommended"],["comprehensive","Comprehensive — full statistical suite"]] as [val, label]}
            <label class="radio-label">
              <input type="radio" bind:group={analysisLevel} value={val} />
              <span>{label}</span>
            </label>
          {/each}
        </div>
      </div>

      <div class="card" style="margin-top:10px">
        <div class="card-title">Token handling</div>
        <div class="settings-row">
          <input type="checkbox" id="trim-whitespace" checked />
          <label for="trim-whitespace" class="field-label" style="margin-left:6px">Trim whitespace from tokens</label>
        </div>
        <div class="settings-row" style="margin-top:6px">
          <input type="checkbox" id="ignore-dups" />
          <label for="ignore-dups" class="field-label" style="margin-left:6px">Ignore duplicate tokens</label>
        </div>
        <div class="settings-row" style="margin-top:6px">
          <input type="checkbox" id="base64-decode" />
          <label for="base64-decode" class="field-label" style="margin-left:6px">Base64-decode tokens before analysis</label>
        </div>
      </div>
    </div>
  {/if}
</div>

<style>
  .seq-root { font-size: 13px; }
  .panel {
    flex: 1; overflow-y: auto;
    padding: 14px 16px;
    background: #f5f5f5;
  }
  .card {
    background: #ffffff;
    border: 1px solid #dedede;
    border-radius: 4px;
    padding: 14px 16px;
  }
  .card-title {
    font-size: 11px; font-weight: 700;
    text-transform: uppercase; letter-spacing: 0.06em;
    color: #767676; margin-bottom: 12px;
    padding-bottom: 8px; border-bottom: 1px solid #eee;
  }

  /* Request display */
  .req-display {
    display: flex; align-items: center; gap: 8px;
    background: #f5f5f5; border: 1px solid #dedede;
    border-radius: 3px; padding: 6px 10px;
    font-size: 12px; font-family: ui-monospace, Consolas, monospace;
  }
  .req-method { font-weight: 700; }
  .req-host   { color: #444; }
  .req-path   { color: #767676; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .req-empty  { font-size: 12px; padding: 8px 0; }
  .m-get   { color: #2e7d32; }
  .m-post  { color: #e65100; }
  .m-other { color: #555; }

  /* Request picker table */
  .picker-table-wrap {
    margin-top: 8px;
    border: 1px solid #dedede; border-radius: 3px;
    overflow: hidden; max-height: 180px; overflow-y: auto;
  }
  .pick-table { width: 100%; border-collapse: collapse; font-size: 11px; }
  .pick-table th {
    background: #f0f0f0; padding: 3px 6px;
    text-align: left; color: #767676; font-weight: 600;
    border-bottom: 1px solid #dedede;
    position: sticky; top: 0;
  }
  .pick-table td { padding: 3px 6px; border-bottom: 1px solid #f0f0f0; }
  .pick-table tr { cursor: pointer; }
  .pick-table tr:hover { background: #f0f7ff; }
  .row-sel { background: #fce8e2 !important; }
  .url-cell { max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

  /* Token location */
  .location-row { display: flex; gap: 20px; flex-wrap: wrap; }
  .radio-label {
    display: flex; align-items: center; gap: 6px;
    font-size: 13px; cursor: pointer; color: #444;
  }
  .radio-label input { cursor: pointer; accent-color: #e03a00; }
  .field-row { display: flex; align-items: center; gap: 10px; }
  .field-label { font-size: 13px; color: #444; flex-shrink: 0; }

  /* Capture progress */
  .capture-progress {
    display: flex; align-items: center; gap: 8px; flex: 1;
  }
  .progress-bar-wrap {
    flex: 1; max-width: 160px; height: 6px;
    background: #e8e8e8; border-radius: 3px; overflow: hidden;
  }
  .progress-bar-fill {
    height: 100%; background: #e03a00;
    border-radius: 3px;
    transition: width 0.4s ease;
  }

  /* Buttons */
  .btn-orange {
    background: #e03a00; color: #fff;
    border: none; border-radius: 3px;
    padding: 5px 14px; font-size: 13px; cursor: pointer;
  }
  .btn-orange:hover:not(:disabled) { background: #c73400; }
  .btn-orange:disabled { opacity: 0.5; cursor: not-allowed; }
  .btn-stop {
    background: #d42c2c; color: #fff;
    border: none; border-radius: 3px;
    padding: 5px 14px; font-size: 13px; cursor: pointer;
  }
  .btn-stop:hover { background: #b82020; }
  .btn-secondary {
    background: #f0f0f0; color: #333;
    border: 1px solid #c8c8c8; border-radius: 3px;
    padding: 4px 10px; font-size: 12px; cursor: pointer;
  }
  .btn-secondary:hover { background: #e4e4e4; }
  .btn-sm { padding: 2px 8px; font-size: 11px; margin-left: auto; }

  .capturing-pulse {
    font-size: 13px; color: #1a75c4;
    animation: pulse 1.2s ease-in-out infinite;
  }
  @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.35; } }

  .empty-hint {
    display: flex; flex-direction: column;
    align-items: center; gap: 8px;
    padding: 20px 0; text-align: center;
  }

  /* Token textarea */
  .token-textarea {
    width: 100%; min-height: 140px; resize: vertical;
    border: 1px solid #c8c8c8; border-radius: 3px;
    font-family: ui-monospace, Consolas, monospace;
    font-size: 12px; padding: 6px 8px;
    background: #fafafa; color: #212121;
    box-sizing: border-box; outline: none;
  }
  .token-textarea:focus { border-color: #e03a00; }

  /* Data table */
  .data-table { width: 100%; border-collapse: collapse; font-size: 13px; }
  .data-table th, .data-table td {
    padding: 6px 10px; border-bottom: 1px solid #e8e8e8; text-align: left;
  }
  .data-table thead th {
    background: #f5f5f5; color: #767676;
    font-size: 11px; font-weight: 600;
    border-bottom: 1px solid #dedede;
  }
  .data-table tbody tr:hover { background: #f0f7ff; }
  .row-even { background: #fafafa; }
  .mono { font-family: ui-monospace, Consolas, monospace; font-size: 12px; font-weight: 600; color: #212121; }
  .settings-row { display: flex; align-items: center; }

  /* Status colors */
  .status-2 { color: #2e7d32; font-weight: 600; }
  .status-4 { color: #e65100; font-weight: 600; }
  .status-5 { color: #b71c1c; font-weight: 600; }
  .dim { color: #767676; }
</style>
