<script>
  import { onMount } from "svelte";

  let all = [];
  let search = "";
  let category = "all";

  $: categories = ["all", ...Array.from(new Set(all.map(p => p.category)))];
  $: filtered = all.filter(p =>
    (category === "all" || p.category === category) &&
    (!search ||
      p.label.toLowerCase().includes(search.toLowerCase()) ||
      p.payload.toLowerCase().includes(search.toLowerCase()) ||
      (p.tags || []).some(t => t.toLowerCase().includes(search.toLowerCase())))
  );

  async function load() {
    try { const r = await fetch("/api/v1/payloads"); if (r.ok) all = await r.json(); } catch {}
  }
  function copy(p) { navigator.clipboard.writeText(p.payload).catch(() => {}); }
  function sendToRepeater(p) {
    try {
      const request = `GET /?q=${encodeURIComponent(p.payload)} HTTP/1.1\r\nHost: target.com\r\n\r\n`;
      const payload = { request, raw: request, scheme: "http", host: "target.com", port: 80 };
      localStorage.setItem("lancer.send.repeater", JSON.stringify(payload));
      localStorage.setItem("repeater_prefill", JSON.stringify(payload));
      window.dispatchEvent(new CustomEvent("lancer:navigate", { detail: "repeater" }));
    } catch {}
  }
  function sendToIntruder(p) {
    try {
      localStorage.setItem("lancer.send.intruder", JSON.stringify({
        raw: `GET /?q=§${p.payload}§ HTTP/1.1\r\nHost: target.com\r\n\r\n`,
        payloadText: p.payload,
      }));
      window.dispatchEvent(new CustomEvent("lancer:navigate", { detail: "intruder" }));
    } catch {}
  }

  onMount(load);
</script>

<div class="view">
  <div class="toolbar">
    <input class="search" placeholder="Search payloads, labels, tags…" bind:value={search} />
    <div class="chips">
      {#each categories as c}
        <button class="chip" class:active={category === c} on:click={() => (category = c)}>{c.toUpperCase()}</button>
      {/each}
    </div>
    <span class="dim" style="margin-left:auto;font-size:12px">{filtered.length} / {all.length}</span>
  </div>

  <div class="table-wrap">
    <table class="data-table">
      <thead><tr><th>Category</th><th>Label</th><th>Payload</th><th>Tags</th><th></th></tr></thead>
      <tbody>
        {#each filtered as p, i}
          <tr class:row-even={i % 2 === 0}>
            <td><span class="cat">{p.category}</span></td>
            <td>{p.label}</td>
            <td><code class="pl">{p.payload}</code></td>
            <td class="dim">{(p.tags || []).join(", ")}</td>
            <td style="white-space:nowrap">
              <button class="sm-btn" on:click={() => copy(p)} title="Copy">⎘</button>
              <button class="sm-btn" on:click={() => sendToRepeater(p)} title="Send to Repeater">→ R</button>
              <button class="sm-btn" on:click={() => sendToIntruder(p)} title="Use in Intruder">→ I</button>
            </td>
          </tr>
        {/each}
        {#if filtered.length === 0}
          <tr><td colspan="5" class="empty">{all.length === 0 ? "Loading payload encyclopedia…" : "No payloads match."}</td></tr>
        {/if}
      </tbody>
    </table>
  </div>
</div>

<style>
  .view { display: flex; flex-direction: column; height: 100%; overflow: hidden; }
  .toolbar { display: flex; align-items: center; gap: 10px; padding: 8px 12px; background: var(--surface-2); border-bottom: 1px solid var(--border); flex-wrap: wrap; }
  .search { flex: 0 0 280px; padding: 5px 9px; border: 1px solid var(--border-strong); border-radius: 3px; font-size: 13px; }
  .chips { display: flex; flex-wrap: wrap; gap: 4px; }
  .chip { font-size: 10px; padding: 3px 9px; border: 1px solid #d0d0d0; border-radius: 12px; background: #fff; color: var(--text-2); cursor: pointer; }
  .chip.active { background: var(--accent); color: #fff; border-color: var(--accent); }
  .table-wrap { flex: 1; overflow: auto; min-height: 0; }
  .data-table { width: 100%; border-collapse: collapse; font-size: 12px; }
  .data-table th, .data-table td { text-align: left; padding: 5px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
  .data-table thead th { background: var(--surface-2); color: var(--text-muted); font-size: 11px; font-weight: 600; position: sticky; top: 0; }
  .row-even { background: var(--surface-1); }
  .cat { font-size: 10px; font-weight: 700; text-transform: uppercase; color: #2e6fae; }
  .pl { font-family: ui-monospace, Consolas, monospace; color: var(--accent-hover); word-break: break-all; }
  .sm-btn { font-size: 11px; padding: 2px 7px; background: var(--surface-2); color: var(--text); border: 1px solid var(--border-strong); border-radius: 3px; cursor: pointer; margin-left: 2px; }
  .sm-btn:hover { background: var(--surface-3); }
  .empty { text-align: center; padding: 30px; color: var(--text-muted); }
  .dim { color: var(--text-muted); }
</style>
