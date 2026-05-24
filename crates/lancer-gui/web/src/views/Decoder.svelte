<script>
  // Each row: { input, output, encodeOp, decodeOp }
  let rows = [
    { input: "", output: "", encodeOp: "", decodeOp: "", mode: "decode" }
  ];

  function b64decode(s) {
    try { return atob(s); } catch { return "(invalid Base64)"; }
  }
  function b64encode(s) {
    try { return btoa(unescape(encodeURIComponent(s))); } catch { return "(encoding error)"; }
  }
  function urlDecode(s) {
    try { return decodeURIComponent(s.replace(/\+/g, " ")); } catch { return "(invalid URL encoding)"; }
  }
  function urlEncode(s) { return encodeURIComponent(s); }
  function htmlDecode(s) {
    try { const d = new DOMParser().parseFromString(s, "text/html"); return d.body.textContent || ""; } catch { return s; }
  }
  function htmlEncode(s) {
    const el = document.createElement("div");
    el.appendChild(document.createTextNode(s));
    return el.innerHTML;
  }

  const encodeOps = [
    { label: "Base64",    fn: b64encode },
    { label: "URL",       fn: urlEncode  },
    { label: "HTML",      fn: htmlEncode },
  ];
  const decodeOps = [
    { label: "Base64",    fn: b64decode },
    { label: "URL",       fn: urlDecode  },
    { label: "HTML",      fn: htmlDecode },
  ];

  function applyEncode(i, op) {
    rows[i].encodeOp = op.label;
    rows[i].mode = "encode";
    rows[i].output = op.fn(rows[i].input);
    rows = rows;
  }

  function applyDecode(i, op) {
    rows[i].decodeOp = op.label;
    rows[i].mode = "decode";
    rows[i].output = op.fn(rows[i].input);
    rows = rows;
  }

  function smartDecode(i) {
    const s = rows[i].input;
    // try base64 first, then url
    try {
      const r = atob(s);
      rows[i].output = r;
      rows[i].decodeOp = "Base64 (smart)";
    } catch {
      try {
        rows[i].output = decodeURIComponent(s.replace(/\+/g," "));
        rows[i].decodeOp = "URL (smart)";
      } catch {
        rows[i].output = s;
        rows[i].decodeOp = "none";
      }
    }
    rows[i].mode = "smart";
    rows = rows;
  }

  function addRow(i) {
    const next = { input: rows[i].output, output: "", encodeOp: "", decodeOp: "", mode: "decode" };
    rows = [...rows.slice(0, i + 1), next, ...rows.slice(i + 1)];
  }

  function clearRow(i) {
    rows[i] = { input: "", output: "", encodeOp: "", decodeOp: "", mode: "decode" };
    rows = rows;
  }
</script>

<div class="view">
  <div class="panel">
    {#each rows as row, i}
      <div class="decoder-row">
        <!-- Input area -->
        <div class="io-block">
          <div class="io-header">
            <span class="io-label">Input</span>
            <div class="io-actions">
              <button class="sm-btn" on:click={() => clearRow(i)}>Clear</button>
            </div>
          </div>
          <textarea
            class="io-area"
            bind:value={row.input}
            placeholder="Paste text to encode or decode..."
            spellcheck="false"
          ></textarea>
        </div>

        <!-- Operations toolbar -->
        <div class="ops-bar">
          <div class="ops-group">
            <span class="ops-label">Decode as</span>
            {#each decodeOps as op}
              <button
                class="op-btn"
                class:op-active={row.mode === "decode" && row.decodeOp === op.label}
                on:click={() => applyDecode(i, op)}
                disabled={!row.input}
              >{op.label}</button>
            {/each}
          </div>
          <div class="ops-sep"></div>
          <div class="ops-group">
            <span class="ops-label">Encode as</span>
            {#each encodeOps as op}
              <button
                class="op-btn"
                class:op-active={row.mode === "encode" && row.encodeOp === op.label}
                on:click={() => applyEncode(i, op)}
                disabled={!row.input}
              >{op.label}</button>
            {/each}
          </div>
          <div class="ops-sep"></div>
          <button
            class="op-btn op-smart"
            on:click={() => smartDecode(i)}
            disabled={!row.input}
          >Smart decode</button>
        </div>

        <!-- Output area -->
        <div class="io-block">
          <div class="io-header">
            <span class="io-label">
              Output
              {#if row.decodeOp || row.encodeOp}
                <span class="op-tag">
                  {row.mode === "encode" ? "Encoded: " + row.encodeOp : row.mode === "smart" ? "Smart: " + row.decodeOp : "Decoded: " + row.decodeOp}
                </span>
              {/if}
            </span>
            <div class="io-actions">
              <button class="sm-btn" on:click={() => { if (row.output) navigator.clipboard.writeText(row.output); }} disabled={!row.output}>
                Copy
              </button>
              <button class="sm-btn" on:click={() => addRow(i)} disabled={!row.output} title="Use output as next input">
                + Chain
              </button>
            </div>
          </div>
          <textarea
            class="io-area io-output"
            readonly
            value={row.output || "(output will appear here)"}
          ></textarea>
        </div>

        {#if i < rows.length - 1}
          <div class="chain-arrow">
            <svg width="16" height="20" viewBox="0 0 16 20" fill="none">
              <path d="M8 2 L8 14 M4 10 L8 14 L12 10" stroke="#767676" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
          </div>
        {/if}
      </div>
    {/each}

    <!-- Info footer -->
    {#if rows[0].input}
      <div class="info-footer dim" style="font-size:12px;margin-top:6px">
        Input: {rows[0].input.length} chars
        {#if rows[0].output && (rows[0].decodeOp || rows[0].encodeOp)} · Output: {rows[0].output.length} chars{/if}
      </div>
    {/if}
  </div>
</div>

<style>
  .decoder-row { margin-bottom: 4px; }
  .io-block {
    border: 1px solid #dedede;
    border-radius: 3px;
    overflow: hidden;
    background: #ffffff;
  }
  .io-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 5px 10px;
    background: #f5f5f5;
    border-bottom: 1px solid #dedede;
  }
  .io-label { font-size: 12px; font-weight: 600; color: #444; }
  .io-actions { display: flex; gap: 5px; }
  .sm-btn {
    font-size: 11px; padding: 2px 8px;
    background: #f0f0f0; color: #333;
    border: 1px solid #c8c8c8; border-radius: 3px; cursor: pointer;
  }
  .sm-btn:hover:not(:disabled) { background: #e4e4e4; }
  .sm-btn:disabled { opacity: 0.4; cursor: not-allowed; }
  .io-area {
    min-height: 90px; resize: vertical;
    border: none; border-radius: 0;
    background: #ffffff; color: #212121;
    padding: 8px 10px;
    font-size: 12px;
    font-family: ui-monospace, "Cascadia Code", Consolas, monospace;
    width: 100%; outline: none;
  }
  .io-area:focus { outline: none; }
  .io-output { color: #444; background: #fafafa; }
  .op-tag { font-size: 11px; color: #e03a00; font-weight: 500; margin-left: 8px; }

  .ops-bar {
    display: flex; align-items: center; gap: 6px; flex-wrap: wrap;
    padding: 6px 10px;
    background: #f5f5f5;
    border-left: 1px solid #dedede;
    border-right: 1px solid #dedede;
  }
  .ops-group { display: flex; align-items: center; gap: 4px; }
  .ops-label { font-size: 11px; color: #767676; margin-right: 2px; white-space: nowrap; }
  .op-btn {
    font-size: 12px; padding: 3px 10px;
    background: #f0f0f0; color: #333;
    border: 1px solid #c8c8c8; border-radius: 3px; cursor: pointer;
  }
  .op-btn:hover:not(:disabled) { background: #e4e4e4; border-color: #aaa; }
  .op-btn:disabled { opacity: 0.4; cursor: not-allowed; }
  .op-active {
    background: #fce8e2 !important;
    border-color: #e03a00 !important;
    color: #e03a00 !important;
  }
  .op-smart {
    background: #e6f0fb; color: #1a75c4;
    border-color: #9dc3e8;
  }
  .op-smart:hover:not(:disabled) { background: #cde1f5; }
  .ops-sep { width: 1px; height: 18px; background: #dedede; margin: 0 2px; }

  .chain-arrow {
    display: flex; justify-content: center;
    padding: 2px 0;
  }

  .info-footer { padding: 4px 0; }
</style>
