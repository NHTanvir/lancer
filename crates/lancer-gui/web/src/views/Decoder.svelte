<script>
  import { onMount } from "svelte";

  // Each row: { input, output, opLabel, mode }
  let rows = [
    { input: "", output: "", opLabel: "", mode: "decode" }
  ];

  onMount(() => {
    try {
      const raw = localStorage.getItem("lancer.send.decoder");
      if (raw) {
        const v = JSON.parse(raw);
        if (v.input) rows[0].input = v.input;
        localStorage.removeItem("lancer.send.decoder");
      }
    } catch {}
  });

  const enc = new TextEncoder();
  const dec = new TextDecoder("utf-8", { fatal: false });

  function strToBytes(s) { return enc.encode(s); }
  function bytesToStr(b) { return dec.decode(b); }

  // ── Base64 ─────────────────────────────────────────────
  function b64decode(s) {
    try {
      const bin = atob(s.replace(/\s+/g,""));
      const buf = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
      return bytesToStr(buf);
    } catch { return "(invalid Base64)"; }
  }
  function b64encode(s) {
    try {
      const buf = strToBytes(s);
      let bin = "";
      for (let i = 0; i < buf.length; i++) bin += String.fromCharCode(buf[i]);
      return btoa(bin);
    } catch { return "(encoding error)"; }
  }
  // ── URL ────────────────────────────────────────────────
  function urlDecode(s) {
    try { return decodeURIComponent(s.replace(/\+/g, " ")); } catch { return "(invalid URL encoding)"; }
  }
  function urlEncode(s) { return encodeURIComponent(s); }
  // ── HTML ───────────────────────────────────────────────
  function htmlDecode(s) {
    try { const d = new DOMParser().parseFromString(s, "text/html"); return d.body.textContent || ""; } catch { return s; }
  }
  function htmlEncode(s) {
    const el = document.createElement("div");
    el.appendChild(document.createTextNode(s));
    return el.innerHTML;
  }
  // ── Hex (lowercase, no separator) ──────────────────────
  function hexEncode(s) {
    return Array.from(strToBytes(s)).map(b => b.toString(16).padStart(2,"0")).join("");
  }
  function hexDecode(s) {
    const t = s.replace(/[\s:,-]/g, "");
    if (!/^[0-9a-fA-F]*$/.test(t) || t.length % 2 !== 0) return "(invalid hex)";
    const buf = new Uint8Array(t.length / 2);
    for (let i = 0; i < buf.length; i++) buf[i] = parseInt(t.substr(i*2, 2), 16);
    return bytesToStr(buf);
  }
  // ── ASCII-hex (space separated) ────────────────────────
  function asciiHexEncode(s) {
    return Array.from(strToBytes(s)).map(b => b.toString(16).padStart(2,"0")).join(" ");
  }
  function asciiHexDecode(s) { return hexDecode(s); }
  // ── Octal (per-byte, space separated) ──────────────────
  function octalEncode(s) {
    return Array.from(strToBytes(s)).map(b => b.toString(8).padStart(3,"0")).join(" ");
  }
  function octalDecode(s) {
    const parts = s.trim().split(/\s+/);
    try {
      const buf = new Uint8Array(parts.map(p => {
        const n = parseInt(p, 8);
        if (Number.isNaN(n) || n < 0 || n > 255) throw new Error("bad");
        return n;
      }));
      return bytesToStr(buf);
    } catch { return "(invalid octal)"; }
  }
  // ── Binary (per-byte, space separated) ─────────────────
  function binaryEncode(s) {
    return Array.from(strToBytes(s)).map(b => b.toString(2).padStart(8,"0")).join(" ");
  }
  function binaryDecode(s) {
    const parts = s.replace(/\s+/g," ").trim().split(" ");
    try {
      const buf = new Uint8Array(parts.map(p => {
        if (!/^[01]+$/.test(p)) throw new Error("bad");
        const n = parseInt(p, 2);
        if (n > 255) throw new Error("bad");
        return n;
      }));
      return bytesToStr(buf);
    } catch { return "(invalid binary)"; }
  }
  // ── GZIP via DecompressionStream / CompressionStream ───
  async function gzipEncode(s) {
    if (typeof CompressionStream === "undefined") return "(CompressionStream not supported)";
    const stream = new Blob([strToBytes(s)]).stream().pipeThrough(new CompressionStream("gzip"));
    const buf = new Uint8Array(await new Response(stream).arrayBuffer());
    // Show as base64 — GZIP output is binary
    let bin = "";
    for (let i = 0; i < buf.length; i++) bin += String.fromCharCode(buf[i]);
    return "(base64) " + btoa(bin);
  }
  async function gzipDecode(s) {
    if (typeof DecompressionStream === "undefined") return "(DecompressionStream not supported)";
    let bytes;
    const t = s.startsWith("(base64) ") ? s.slice(9) : s;
    try {
      const bin = atob(t.replace(/\s+/g,""));
      bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    } catch { return "(input must be base64-encoded gzip)"; }
    try {
      const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip"));
      const buf = new Uint8Array(await new Response(stream).arrayBuffer());
      return bytesToStr(buf);
    } catch (e) { return "(gzip decode failed: " + e.message + ")"; }
  }
  // ── Hash via Web Crypto API ────────────────────────────
  async function hashHex(name, s) {
    if (!crypto || !crypto.subtle) return "(SubtleCrypto unavailable)";
    try {
      const buf = await crypto.subtle.digest(name, strToBytes(s));
      return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,"0")).join("");
    } catch (e) { return "(hash failed: " + e.message + ")"; }
  }
  // MD5 is not in SubtleCrypto — pure-JS fallback (RFC 1321)
  function md5(s) {
    const bytes = strToBytes(s);
    const r = [7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21];
    const k = new Uint32Array(64);
    for (let i = 0; i < 64; i++) k[i] = Math.floor(Math.abs(Math.sin(i+1)) * 0x100000000) >>> 0;
    const ml = bytes.length;
    const bits = ml * 8;
    const padded = new Uint8Array(((ml + 9 + 63) >>> 6) << 6);
    padded.set(bytes);
    padded[ml] = 0x80;
    const dv = new DataView(padded.buffer);
    dv.setUint32(padded.length - 8, bits >>> 0, true);
    dv.setUint32(padded.length - 4, Math.floor(bits / 0x100000000) >>> 0, true);
    let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    for (let off = 0; off < padded.length; off += 64) {
      const m = new Uint32Array(16);
      for (let j = 0; j < 16; j++) m[j] = dv.getUint32(off + j*4, true);
      let a = a0, b = b0, c = c0, d = d0;
      for (let i = 0; i < 64; i++) {
        let f, g;
        if (i < 16) { f = (b & c) | (~b & d); g = i; }
        else if (i < 32) { f = (d & b) | (~d & c); g = (5*i + 1) % 16; }
        else if (i < 48) { f = b ^ c ^ d; g = (3*i + 5) % 16; }
        else { f = c ^ (b | ~d); g = (7*i) % 16; }
        f = (f + a + k[i] + m[g]) >>> 0;
        a = d; d = c; c = b;
        b = (b + ((f << r[i]) | (f >>> (32 - r[i])))) >>> 0;
      }
      a0 = (a0 + a) >>> 0; b0 = (b0 + b) >>> 0; c0 = (c0 + c) >>> 0; d0 = (d0 + d) >>> 0;
    }
    function hex32(n) {
      return ((n & 0xff).toString(16).padStart(2,"0")) +
             (((n >>> 8) & 0xff).toString(16).padStart(2,"0")) +
             (((n >>> 16) & 0xff).toString(16).padStart(2,"0")) +
             (((n >>> 24) & 0xff).toString(16).padStart(2,"0"));
    }
    return hex32(a0) + hex32(b0) + hex32(c0) + hex32(d0);
  }

  // ── Backend transform (MD2 / SHA-3 — Web Crypto can't do these) ────────
  // POST /api/v1/transform {op, input} -> { ok, text, hex, base64 }
  async function backendTransform(op, s) {
    try {
      const r = await fetch("/api/v1/transform", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ op, input: s }),
      });
      const data = await r.json().catch(() => null);
      if (!r.ok || !data || data.ok === false) {
        const msg = (data && data.error) || ("HTTP " + r.status);
        return "(backend error: " + msg + ")";
      }
      return data;
    } catch (e) {
      return "(backend unreachable: " + e.message + ")";
    }
  }
  // For hashes, surface the hex digest from the backend response.
  async function backendHash(op, s) {
    const data = await backendTransform(op, s);
    return typeof data === "string" ? data : data.hex;
  }

  // ── Pretty-print JSON (client-side) ────────────────────────────────────
  function prettyJson(s) {
    try {
      return JSON.stringify(JSON.parse(s), null, 2);
    } catch (e) {
      return "(invalid JSON: " + e.message + ")";
    }
  }

  const encodeOps = [
    { label: "Base64", fn: b64encode },
    { label: "URL",    fn: urlEncode },
    { label: "HTML",   fn: htmlEncode },
    { label: "Hex",    fn: hexEncode },
    { label: "ASCII hex", fn: asciiHexEncode },
    { label: "Octal",  fn: octalEncode },
    { label: "Binary", fn: binaryEncode },
    { label: "GZIP",   fn: gzipEncode, async: true },
  ];
  const decodeOps = [
    { label: "Base64", fn: b64decode },
    { label: "URL",    fn: urlDecode },
    { label: "HTML",   fn: htmlDecode },
    { label: "Hex",    fn: hexDecode },
    { label: "ASCII hex", fn: asciiHexDecode },
    { label: "Octal",  fn: octalDecode },
    { label: "Binary", fn: binaryDecode },
    { label: "GZIP",   fn: gzipDecode, async: true },
  ];
  const hashOps = [
    { label: "MD2",        fn: (s) => backendHash("md2", s) },
    { label: "MD5",        fn: (s) => Promise.resolve(md5(s)) },
    { label: "SHA-1",      fn: (s) => hashHex("SHA-1", s) },
    { label: "SHA-256",    fn: (s) => hashHex("SHA-256", s) },
    { label: "SHA-384",    fn: (s) => hashHex("SHA-384", s) },
    { label: "SHA-512",    fn: (s) => hashHex("SHA-512", s) },
    { label: "SHA-3-256",  fn: (s) => backendHash("sha3-256", s) },
    { label: "SHA-3-512",  fn: (s) => backendHash("sha3-512", s) },
  ];
  const formatOps = [
    { label: "Pretty-print JSON", fn: prettyJson },
  ];

  async function apply(i, op, mode) {
    const r = rows[i];
    try {
      const out = op.async || op.fn.constructor.name === "AsyncFunction"
        ? await op.fn(r.input)
        : op.fn(r.input);
      r.output = out;
    } catch (e) {
      r.output = "(error: " + e.message + ")";
    }
    r.opLabel = op.label;
    r.mode = mode;
    rows = rows;
  }

  function applyEncode(i, op) { return apply(i, op, "encode"); }
  function applyDecode(i, op) { return apply(i, op, "decode"); }
  function applyFormat(i, op) { return apply(i, op, "format"); }
  function applyHash(i, op)   { return apply(i, op, "hash"); }

  function smartDecode(i) {
    const s = rows[i].input;
    try {
      const r = atob(s.replace(/\s+/g,""));
      rows[i].output = r;
      rows[i].opLabel = "Base64";
    } catch {
      try {
        rows[i].output = decodeURIComponent(s.replace(/\+/g," "));
        rows[i].opLabel = "URL";
      } catch {
        const t = s.replace(/\s+/g,"");
        if (/^[0-9a-fA-F]+$/.test(t) && t.length % 2 === 0) {
          rows[i].output = hexDecode(t);
          rows[i].opLabel = "Hex";
        } else {
          rows[i].output = s;
          rows[i].opLabel = "none";
        }
      }
    }
    rows[i].mode = "smart";
    rows = rows;
  }

  function addRow(i) {
    const next = { input: rows[i].output, output: "", opLabel: "", mode: "decode" };
    rows = [...rows.slice(0, i + 1), next, ...rows.slice(i + 1)];
  }

  function clearRow(i) {
    rows[i] = { input: "", output: "", opLabel: "", mode: "decode" };
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
                class:op-active={row.mode === "decode" && row.opLabel === op.label}
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
                class:op-active={row.mode === "encode" && row.opLabel === op.label}
                on:click={() => applyEncode(i, op)}
                disabled={!row.input}
              >{op.label}</button>
            {/each}
          </div>
          <div class="ops-sep"></div>
          <div class="ops-group">
            <span class="ops-label">Hash</span>
            {#each hashOps as op}
              <button
                class="op-btn"
                class:op-active={row.mode === "hash" && row.opLabel === op.label}
                on:click={() => applyHash(i, op)}
                disabled={!row.input}
              >{op.label}</button>
            {/each}
          </div>
          <div class="ops-sep"></div>
          <div class="ops-group">
            <span class="ops-label">Format</span>
            {#each formatOps as op}
              <button
                class="op-btn"
                class:op-active={row.mode === "format" && row.opLabel === op.label}
                on:click={() => applyFormat(i, op)}
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
              {#if row.opLabel}
                <span class="op-tag">
                  {row.mode === "encode" ? "Encoded: " + row.opLabel : row.mode === "smart" ? "Smart: " + row.opLabel : row.mode === "hash" ? "Hash: " + row.opLabel : row.mode === "format" ? "Formatted: " + row.opLabel : "Decoded: " + row.opLabel}
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
