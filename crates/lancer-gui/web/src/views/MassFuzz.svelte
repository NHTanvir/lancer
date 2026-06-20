<script>
  import { onMount } from "svelte";

  let url = "https://example.com/FUZZ";
  let method = "GET";
  let wordsText = "";
  let extensions = "";
  let concurrency = 40;
  let recursionDepth = 0;
  let matchStatus = "200,204,301,302,307,401,403";
  let filterStatus = "404";
  let filterSize = "";
  let running = false;
  let results = [];
  let error = "";
  let viewFilter = "";

  function parseNums(s) { return s.split(/[,\s]+/).map(x => parseInt(x.trim(), 10)).filter(n => !isNaN(n)); }
  function parseList(s) { return s.split(/[\n,]+/).map(x => x.trim()).filter(Boolean); }

  $: filteredResults = results.filter(r =>
    !viewFilter ||
    r.word.toLowerCase().includes(viewFilter.toLowerCase()) ||
    String(r.status).includes(viewFilter) ||
    String(r.length).includes(viewFilter)
  );

  async function loadCommon() {
    try {
      const r = await fetch("/api/v1/massfuzz/wordlist");
      if (r.ok) { const w = await r.json(); wordsText = w.join("\n"); }
    } catch {}
  }

  async function run() {
    error = ""; results = [];
    const words = parseList(wordsText);
    if (!url.includes("FUZZ")) { error = "URL must contain the FUZZ marker."; return; }
    if (!words.length) { error = "Provide a wordlist (or click Load common)."; return; }
    running = true;
    try {
      const r = await fetch("/api/v1/massfuzz", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({
          url, method, words,
          extensions: parseList(extensions).map(e => e.startsWith(".") || e === "" ? e : "." + e),
          concurrency: +concurrency,
          recursion_depth: +recursionDepth,
          match_status: parseNums(matchStatus),
          filter_status: parseNums(filterStatus),
          filter_size: parseNums(filterSize),
        }),
      });
      if (r.ok) results = await r.json();
      else error = `Fuzz failed (${r.status}): ${await r.text()}`;
    } catch (e) { error = `Could not reach Lancer API (${e})`; }
    finally { running = false; }
  }

  function statusClass(s) { if (s >= 500) return "s5"; if (s >= 400) return "s4"; if (s >= 300) return "s3"; return "s2"; }
  function copyUrl(r) { navigator.clipboard.writeText(r.url).catch(() => {}); }

  onMount(() => {});
</script>

<div class="view">
  <div class="config">
    <div class="row">
      <select bind:value={method} class="method">
        {#each ["GET", "POST", "PUT", "HEAD", "OPTIONS"] as m}<option>{m}</option>{/each}
      </select>
      <input class="url" bind:value={url} placeholder="https://target/FUZZ  (FUZZ marks the fuzz position)" />
      <button class="btn-primary" on:click={run} disabled={running}>{running ? "Fuzzing…" : "Start fuzz"}</button>
    </div>
    <div class="row wrap">
      <label class="fld grow">Wordlist
        <textarea bind:value={wordsText} rows="3" placeholder="one entry per line"></textarea>
      </label>
      <div class="col">
        <button class="btn-sec" on:click={loadCommon}>Load common</button>
        <label class="fld">Extensions<input bind:value={extensions} placeholder=".php,.bak,~" /></label>
        <label class="fld">Concurrency<input type="number" bind:value={concurrency} min="1" max="256" /></label>
        <label class="fld">Recursion depth<input type="number" bind:value={recursionDepth} min="0" max="3" /></label>
      </div>
      <div class="col">
        <label class="fld">Match status (mc)<input bind:value={matchStatus} placeholder="200,301" /></label>
        <label class="fld">Filter status (fc)<input bind:value={filterStatus} placeholder="404" /></label>
        <label class="fld">Filter size (fs)<input bind:value={filterSize} placeholder="1234,0" /></label>
      </div>
    </div>
    {#if error}<div class="err">{error}</div>{/if}
  </div>

  <div class="results-bar">
    <input class="vf" bind:value={viewFilter} placeholder="Filter results…" />
    <span class="dim">{filteredResults.length} / {results.length} results</span>
  </div>

  <div class="table-wrap">
    <table class="data-table">
      <thead><tr><th>Word</th><th>Status</th><th>Length</th><th>Words</th><th>Lines</th><th>Time</th><th>URL</th></tr></thead>
      <tbody>
        {#each filteredResults as r, i}
          <tr class:row-even={i % 2 === 0}>
            <td><strong>{r.word}</strong></td>
            <td><span class="badge {statusClass(r.status)}">{r.status}</span></td>
            <td class="num">{r.length}</td>
            <td class="num dim">{r.words}</td>
            <td class="num dim">{r.lines}</td>
            <td class="num dim">{r.time_ms}ms</td>
            <td class="url-cell" title={r.url} on:click={() => copyUrl(r)}>{r.url}</td>
          </tr>
        {/each}
        {#if results.length === 0}
          <tr><td colspan="7" class="empty">
            {running ? "Fuzzing…" : "Set a URL with the FUZZ marker, load or paste a wordlist, then Start fuzz. High-speed async — calibrate noise away with filter-status / filter-size."}
          </td></tr>
        {/if}
      </tbody>
    </table>
  </div>
</div>

<style>
  .view { display: flex; flex-direction: column; height: 100%; overflow: hidden; }
  .config { padding: 10px 12px; background: var(--surface-1); border-bottom: 1px solid var(--border); }
  .row { display: flex; gap: 8px; align-items: center; margin-bottom: 8px; }
  .row.wrap { align-items: flex-start; }
  .method { padding: 6px 8px; border: 1px solid var(--border-strong); border-radius: 3px; }
  .url { flex: 1; padding: 6px 9px; border: 1px solid var(--border-strong); border-radius: 3px; font-family: ui-monospace, Consolas, monospace; font-size: 13px; }
  .fld { display: flex; flex-direction: column; gap: 4px; font-size: 11px; color: var(--text-muted); }
  .fld.grow { flex: 1; }
  .fld input, .fld textarea { padding: 5px 8px; border: 1px solid var(--border-strong); border-radius: 3px; font-size: 12px; font-family: ui-monospace, Consolas, monospace; }
  .fld input { width: 150px; }
  .col { display: flex; flex-direction: column; gap: 6px; }
  .btn-primary { background: var(--accent); color: #fff; border: none; border-radius: 3px; padding: 6px 16px; font-size: 13px; cursor: pointer; white-space: nowrap; }
  .btn-primary:hover { background: var(--accent-hover); }
  .btn-primary:disabled { opacity: 0.5; }
  .btn-sec { background: var(--surface-2); color: var(--text); border: 1px solid var(--border-strong); border-radius: 3px; padding: 5px 12px; font-size: 12px; cursor: pointer; }
  .err { color: #d42c2c; font-size: 12px; margin-top: 4px; }
  .results-bar { display: flex; align-items: center; gap: 10px; padding: 6px 12px; background: var(--surface-2); border-bottom: 1px solid #ededed; }
  .vf { flex: 0 0 320px; padding: 4px 8px; border: 1px solid var(--border-strong); border-radius: 3px; font-size: 12px; }
  .table-wrap { flex: 1; overflow: auto; min-height: 0; }
  .data-table { width: 100%; border-collapse: collapse; font-size: 12px; }
  .data-table th, .data-table td { text-align: left; padding: 4px 10px; border-bottom: 1px solid var(--border); white-space: nowrap; }
  .data-table thead th { background: var(--surface-2); color: var(--text-muted); font-size: 11px; font-weight: 600; position: sticky; top: 0; }
  .row-even { background: var(--surface-1); }
  .num { text-align: right; font-variant-numeric: tabular-nums; }
  .url-cell { max-width: 400px; overflow: hidden; text-overflow: ellipsis; font-family: ui-monospace, Consolas, monospace; color: #2e6fae; cursor: pointer; }
  .badge { font-size: 10px; font-weight: 700; padding: 1px 7px; border-radius: 3px; }
  .badge.s2 { background: #e9f7ec; color: #2e7d3a; }
  .badge.s3 { background: #fff6e0; color: #a06800; }
  .badge.s4 { background: #fdeaea; color: #c0392b; }
  .badge.s5 { background: #f3e6f7; color: #8e44ad; }
  .empty { text-align: center; padding: 30px; color: var(--text-muted); }
  .dim { color: var(--text-muted); }
</style>
