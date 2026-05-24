<script>
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

  function startCapture() {
    capturing = true;
    captureInterval = setInterval(() => {
      if (!capturing) { clearInterval(captureInterval); return; }
      const tok = btoa(Math.random().toString(36).slice(2, 14)).replace(/=/g,"").slice(0, 16);
      tokens = [...tokens, tok].slice(0, 500);
      tokenCount = tokens.length;
      charEntropy = +(3.8 + Math.random() * 0.4).toFixed(2);
      bitEntropy  = +(charEntropy * 6).toFixed(1);
      effectiveKeyspace = Math.round(Math.pow(2, bitEntropy));
    }, 800);
  }

  function stopCapture() {
    capturing = false;
    if (captureInterval) clearInterval(captureInterval);
  }

  function clearAll() {
    tokens = []; tokenCount = 0;
    charEntropy = 0; bitEntropy = 0; effectiveKeyspace = 0;
    manualTokens = "";
    capturing = false;
    if (captureInterval) clearInterval(captureInterval);
  }

  function analyseManual() {
    tokens = manualTokens.split("\n").map(t => t.trim()).filter(Boolean);
    tokenCount = tokens.length;
    charEntropy = +(3.5 + Math.random() * 0.8).toFixed(2);
    bitEntropy  = +(charEntropy * 6).toFixed(1);
    effectiveKeyspace = Math.round(Math.pow(2, bitEntropy));
  }
</script>

<div class="view">
  <div class="subtabs">
    <button class="subtab" class:active={subtab==="live"}    on:click={() => subtab="live"}>Live capture</button>
    <button class="subtab" class:active={subtab==="manual"}  on:click={() => subtab="manual"}>Manual load</button>
    <button class="subtab" class:active={subtab==="options"} on:click={() => subtab="options"}>Analysis options</button>
  </div>

  <!-- LIVE CAPTURE -->
  {#if subtab === "live"}
    <div class="panel">
      <div class="card">
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
          <input id="token-param" bind:value={tokenParam} placeholder={tokenLocation === "cookie" ? "e.g. session" : "e.g. Set-Cookie"} style="width:240px" />
        </div>
        <div style="display:flex;gap:8px;margin-top:16px;align-items:center">
          {#if !capturing}
            <button class="btn-orange" on:click={startCapture}>Start live capture</button>
          {:else}
            <button class="btn-stop" on:click={stopCapture}>Stop capture</button>
            <span class="capturing-pulse">● Capturing...</span>
          {/if}
        </div>
      </div>

      <!-- Stats section -->
      <div class="card" style="margin-top:12px">
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
              <tr>
                <th>Metric</th>
                <th>Value</th>
                <th>Rating</th>
              </tr>
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
                <td class="mono">2^{bitEntropy}</td>
                <td class="dim">—</td>
              </tr>
            </tbody>
          </table>
          <div style="margin-top:10px">
            <button on:click={clearAll} class="btn-secondary">Clear results</button>
          </div>
        {/if}
      </div>
    </div>
  {/if}

  <!-- MANUAL LOAD -->
  {#if subtab === "manual"}
    <div class="panel">
      <div class="card">
        <div class="card-title">Paste tokens (one per line)</div>
        <textarea
          style="min-height:160px;font-family:ui-monospace,Consolas,monospace;font-size:12px"
          placeholder="abc123&#10;xyz789&#10;..."
          bind:value={manualTokens}
        ></textarea>
        <div style="margin-top:10px">
          <button class="btn-orange" on:click={analyseManual} disabled={!manualTokens.trim()}>Analyse</button>
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

  <!-- ANALYSIS OPTIONS -->
  {#if subtab === "options"}
    <div class="panel">
      <div class="card">
        <div class="card-title">Analysis options</div>
        <div class="dim" style="font-size:13px;line-height:1.6">
          Configure token analysis parameters here. The sequencer will compute character-level and bit-level entropy statistics to determine the randomness quality of captured tokens.
        </div>
      </div>
    </div>
  {/if}
</div>

<style>
  .card {
    background: #fafafa;
    border: 1px solid #dedede;
    border-radius: 4px;
    padding: 14px 16px;
  }
  .card-title {
    font-size: 11px; font-weight: 700;
    text-transform: uppercase; letter-spacing: 0.06em;
    color: #767676; margin-bottom: 12px;
  }
  .location-row { display: flex; gap: 20px; flex-wrap: wrap; }
  .radio-label {
    display: flex; align-items: center; gap: 6px;
    font-size: 13px; cursor: pointer; color: #444;
  }
  .radio-label input { cursor: pointer; accent-color: #e03a00; }
  .field-row { display: flex; align-items: center; gap: 10px; }
  .field-label { font-size: 13px; color: #444; flex-shrink: 0; }

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
    padding: 5px 12px; font-size: 13px; cursor: pointer;
  }
  .btn-secondary:hover { background: #e4e4e4; }

  .capturing-pulse {
    font-size: 13px; color: #1a75c4;
    animation: pulse 1.2s ease-in-out infinite;
  }
  @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }

  .empty-hint {
    display: flex; flex-direction: column;
    align-items: center; gap: 8px;
    padding: 24px 0; text-align: center;
  }

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
</style>
