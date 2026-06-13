<script>
  let a = `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"id":1,"role":"admin"}`;
  let b = `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"id":2,"role":"user"}`;
  let diff = null, error = "";

  async function run() {
    error = ""; diff = null;
    try {
      const r = await fetch("/api/v1/replay/respdiff", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ a, b }),
      });
      if (r.ok) diff = await r.json();
      else error = `Diff failed (${r.status}): ${await r.text()}`;
    } catch (e) { error = `Could not reach API (${e})`; }
  }
</script>

<div class="view">
  <div class="hdr">
    <strong>Response Differ</strong>
    <span class="dim">Structured, response-aware comparison: status, headers, and body similarity side-by-side.</span>
    <button class="btn-primary" on:click={run} style="margin-left:auto">Compare</button>
  </div>

  <div class="cols">
    <div class="col"><div class="lbl">Response A</div><textarea bind:value={a} spellcheck="false"></textarea></div>
    <div class="col"><div class="lbl">Response B</div><textarea bind:value={b} spellcheck="false"></textarea></div>
  </div>

  {#if error}<div class="err">{error}</div>{/if}

  {#if diff}
    <div class="result">
      <div class="metrics">
        <div class="metric"><span class="mk">Status</span><span class="mv">{diff.status_a} {diff.same_status ? "=" : "≠"} {diff.status_b}</span></div>
        <div class="metric"><span class="mk">Body length</span><span class="mv">{diff.len_a} vs {diff.len_b}</span></div>
        <div class="metric"><span class="mk">Similarity</span><span class="mv" class:hi={diff.similarity >= 0.9}>{Math.round(diff.similarity * 100)}%</span></div>
        <div class="metric"><span class="mk">Lines +/−</span><span class="mv"><span class="add">+{diff.added_lines}</span> <span class="del">−{diff.removed_lines}</span></span></div>
      </div>

      {#if diff.headers_only_a.length || diff.headers_only_b.length || diff.headers_changed.length}
        <div class="hdiff">
          <div class="hcol"><div class="lbl">Only in A</div>{#each diff.headers_only_a as [k, v]}<div class="hline del">{k}: {v}</div>{/each}{#if !diff.headers_only_a.length}<div class="dim">—</div>{/if}</div>
          <div class="hcol"><div class="lbl">Only in B</div>{#each diff.headers_only_b as [k, v]}<div class="hline add">{k}: {v}</div>{/each}{#if !diff.headers_only_b.length}<div class="dim">—</div>{/if}</div>
          <div class="hcol"><div class="lbl">Changed</div>{#each diff.headers_changed as [k, va, vb]}<div class="hline chg">{k}: <span class="del">{va}</span> → <span class="add">{vb}</span></div>{/each}{#if !diff.headers_changed.length}<div class="dim">—</div>{/if}</div>
        </div>
      {/if}
    </div>
  {/if}
</div>

<style>
  .view { display: flex; flex-direction: column; height: 100%; overflow: auto; padding: 12px; gap: 12px; box-sizing: border-box; }
  .hdr { display: flex; align-items: center; gap: 10px; } .hdr .dim { font-size: 12px; }
  .cols { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .lbl { font-size: 11px; font-weight: 700; text-transform: uppercase; color: #767676; margin-bottom: 5px; }
  textarea { width: 100%; box-sizing: border-box; min-height: 200px; font-family: ui-monospace, Consolas, monospace; font-size: 12px; padding: 8px; border: 1px solid #c8c8c8; border-radius: 4px; resize: vertical; }
  .btn-primary { background: #e03a00; color: #fff; border: none; border-radius: 3px; padding: 6px 16px; font-size: 13px; cursor: pointer; }
  .btn-primary:hover { background: #c73400; }
  .err { color: #d42c2c; font-size: 12px; }
  .metrics { display: flex; gap: 24px; flex-wrap: wrap; }
  .metric { display: flex; flex-direction: column; gap: 3px; }
  .mk { font-size: 10px; text-transform: uppercase; color: #999; }
  .mv { font-size: 15px; font-weight: 600; } .mv.hi { color: #c0392b; }
  .add { color: #1b8c1b; } .del { color: #d42c2c; }
  .hdiff { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 14px; margin-top: 14px; }
  .hline { font-family: ui-monospace, Consolas, monospace; font-size: 11px; padding: 1px 0; word-break: break-all; }
  .dim { color: #999; font-size: 12px; }
</style>
