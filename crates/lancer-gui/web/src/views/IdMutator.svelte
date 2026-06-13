<script>
  import { onMount } from "svelte";

  let request = `GET /api/account/1024 HTTP/1.1\r\nHost: target.example\r\nAccept: application/json\r\n\r\n`;
  let scheme = "https", host = "target.example", port = 443;
  let report = null, running = false, error = "";
  let onlyInteresting = false;

  $: hits = report ? report.hits.filter(h => !onlyInteresting || h.interesting) : [];

  async function run() {
    error = ""; report = null; running = true;
    try {
      const r = await fetch("/api/v1/replay/idfuzz", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ request, scheme, host, port: +port }),
      });
      if (r.ok) report = await r.json();
      else error = `Fuzz failed (${r.status}): ${await r.text()}`;
    } catch (e) { error = `Could not reach API (${e})`; }
    finally { running = false; }
  }

  function statusClass(s) { if (!s) return "dim"; if (s >= 500) return "s5"; if (s >= 400) return "s4"; if (s >= 300) return "s3"; return "s2"; }
  function send(h) {
    // Send the mutated request to Repeater for manual confirmation.
    const mutated = request.replace(h.original, h.mutated);
    try { localStorage.setItem("lancer.send.repeater", JSON.stringify({ raw: mutated, host })); window.dispatchEvent(new CustomEvent("lancer:navigate", { detail: "repeater" })); } catch {}
  }

  onMount(() => {
    try { const raw = localStorage.getItem("lancer.send.idmutator"); if (raw) { const v = JSON.parse(raw); if (v.raw) request = v.raw; if (v.host) host = v.host; localStorage.removeItem("lancer.send.idmutator"); } } catch {}
  });
</script>

<div class="view">
  <div class="hdr">
    <strong>ID Mutation Fuzzer</strong>
    <span class="dim">Detect ID-like values, mutate them, replay, and flag mutations that reach another object (IDOR).</span>
  </div>
  <div class="req-row">
    <textarea class="req" bind:value={request} spellcheck="false"></textarea>
    <div class="side">
      <select bind:value={scheme}><option>https</option><option>http</option></select>
      <input bind:value={host} placeholder="host" />
      <input type="number" bind:value={port} placeholder="port" />
      <button class="btn-primary" on:click={run} disabled={running}>{running ? "Fuzzing…" : "Detect & fuzz IDs"}</button>
    </div>
  </div>

  {#if error}<div class="err">{error}</div>{/if}

  {#if report}
    <div class="summary">
      Baseline: <span class="badge {statusClass(report.baseline_status)}">{report.baseline_status}</span> {report.baseline_length} bytes ·
      <strong>{report.candidates.length}</strong> ID candidate(s):
      {#each report.candidates as c}<span class="cand">{c.value} <em>{c.kind}/{c.location}</em></span>{/each}
      <label class="oi"><input type="checkbox" bind:checked={onlyInteresting} /> Only interesting</label>
    </div>
    <div class="table-wrap">
      <table class="data-table">
        <thead><tr><th>Loc</th><th>Original</th><th>Mutated</th><th>Status</th><th>Length</th><th>Sim→baseline</th><th>IDOR?</th><th></th></tr></thead>
        <tbody>
          {#each hits as h, i}
            <tr class:row-even={i % 2 === 0} class:interesting={h.interesting}>
              <td class="dim">{h.location}</td>
              <td><code>{h.original}</code></td>
              <td><code class="mut">{h.mutated}</code></td>
              <td><span class="badge {statusClass(h.status)}">{h.status || "ERR"}</span></td>
              <td class="num">{h.length}</td>
              <td class="num">{Math.round(h.similarity_to_baseline * 100)}%</td>
              <td>{h.interesting ? "⚠ likely" : ""}</td>
              <td><button class="sm" on:click={() => send(h)}>→ Repeater</button></td>
            </tr>
          {/each}
          {#if hits.length === 0}<tr><td colspan="8" class="empty">No mutations{onlyInteresting ? " flagged interesting" : ""}.</td></tr>{/if}
        </tbody>
      </table>
    </div>
  {/if}
</div>

<style>
  .view { display: flex; flex-direction: column; height: 100%; overflow: hidden; padding: 12px; gap: 10px; box-sizing: border-box; }
  .hdr { display: flex; gap: 10px; align-items: baseline; }
  .hdr .dim { font-size: 12px; }
  .req-row { display: flex; gap: 10px; }
  .req { flex: 1; min-height: 120px; font-family: ui-monospace, Consolas, monospace; font-size: 12px; padding: 8px; border: 1px solid #c8c8c8; border-radius: 4px; resize: vertical; }
  .side { display: flex; flex-direction: column; gap: 6px; width: 160px; }
  .side select, .side input { padding: 5px 7px; border: 1px solid #c8c8c8; border-radius: 3px; font-size: 12px; }
  .btn-primary { background: #e03a00; color: #fff; border: none; border-radius: 3px; padding: 7px 12px; font-size: 13px; cursor: pointer; }
  .btn-primary:hover { background: #c73400; } .btn-primary:disabled { opacity: 0.5; }
  .err { color: #d42c2c; font-size: 12px; }
  .summary { font-size: 12px; display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
  .cand { background: #eef2f7; border-radius: 3px; padding: 1px 7px; font-family: ui-monospace, Consolas, monospace; }
  .cand em { color: #888; font-style: normal; font-size: 10px; }
  .oi { margin-left: auto; display: flex; align-items: center; gap: 4px; color: #555; }
  .table-wrap { flex: 1; overflow: auto; min-height: 0; border: 1px solid #eee; border-radius: 4px; }
  .data-table { width: 100%; border-collapse: collapse; font-size: 12px; }
  .data-table th, .data-table td { text-align: left; padding: 4px 10px; border-bottom: 1px solid #f0f0f0; white-space: nowrap; }
  .data-table thead th { background: #f5f5f5; color: #767676; font-size: 11px; position: sticky; top: 0; }
  .row-even { background: #fafafa; }
  .interesting { background: #fff6ec !important; }
  .num { text-align: right; font-variant-numeric: tabular-nums; }
  code { font-family: ui-monospace, Consolas, monospace; } .mut { color: #c73400; }
  .badge { font-size: 10px; font-weight: 700; padding: 1px 6px; border-radius: 3px; }
  .s2 { background: #e9f7ec; color: #2e7d3a; } .s3 { background: #fff6e0; color: #a06800; }
  .s4 { background: #fdeaea; color: #c0392b; } .s5 { background: #f3e6f7; color: #8e44ad; }
  .sm { font-size: 11px; padding: 2px 7px; background: #f0f0f0; border: 1px solid #c8c8c8; border-radius: 3px; cursor: pointer; }
  .empty { text-align: center; padding: 24px; color: #888; }
  .dim { color: #888; }
</style>
