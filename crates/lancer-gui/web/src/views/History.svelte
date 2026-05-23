<script>
  import { onMount } from "svelte";
  let rows = [];
  let filter = "";

  async function refresh() {
    try {
      const r = await fetch("/api/v1/history?limit=200");
      rows = await r.json();
    } catch {
      rows = [];
    }
  }

  onMount(refresh);

  $: filtered = rows.filter(
    (r) =>
      !filter ||
      r.host.includes(filter) ||
      r.path.includes(filter) ||
      String(r.status).includes(filter),
  );
</script>

<div class="bar">
  <input placeholder="filter host / path / status" bind:value={filter} />
  <button on:click={refresh}>Reload</button>
</div>

<table>
  <thead>
    <tr>
      <th>#</th>
      <th>Method</th>
      <th>Host</th>
      <th>Path</th>
      <th>Status</th>
      <th>Length</th>
      <th>Time</th>
    </tr>
  </thead>
  <tbody>
    {#each filtered as r, i}
      <tr>
        <td>{i + 1}</td>
        <td>{r.method}</td>
        <td>{r.host}</td>
        <td title={r.path}>{r.path.length > 80 ? r.path.slice(0, 80) + "…" : r.path}</td>
        <td class="sev-{r.status >= 500 ? 'high' : r.status >= 400 ? 'med' : 'ok'}">{r.status || "-"}</td>
        <td>{r.response_length ?? "-"}</td>
        <td>{r.elapsed_ms ?? "-"}</td>
      </tr>
    {/each}
  </tbody>
</table>

<style>
  .bar {
    display: flex;
    gap: 8px;
    margin-bottom: 12px;
  }
  .bar input {
    flex: 1;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }
  th, td {
    text-align: left;
    padding: 6px 8px;
    border-bottom: 1px solid #292d40;
  }
  thead {
    color: #9aa0bd;
    text-transform: uppercase;
    font-size: 11px;
    letter-spacing: 0.04em;
  }
  .sev-ok { color: #8acf8a; }
  .sev-med { color: #e0b35a; }
  .sev-high { color: #e36b6b; }
</style>
