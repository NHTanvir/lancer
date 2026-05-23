<script>
  import { onMount } from "svelte";
  let q = "";
  let commands = [];
  async function search() {
    try {
      const r = await fetch(`/api/palette?q=${encodeURIComponent(q)}`);
      commands = await r.json();
    } catch {
      commands = [];
    }
  }
  onMount(search);
  $: (q || q === "") && search();
</script>

<input class="search" bind:value={q} placeholder="Type a command — try 'scan', 'repeater', 'theme'…" autofocus />
<ul>
  {#each commands as c}
    <li>
      <span>{c.label}</span>
      {#if c.hotkey}<span class="hot">{c.hotkey}</span>{/if}
    </li>
  {/each}
</ul>

<style>
  .search {
    width: 100%;
    padding: 10px 14px;
    font-size: 15px;
    margin-bottom: 12px;
  }
  ul {
    list-style: none;
    padding: 0;
    margin: 0;
    display: flex;
    flex-direction: column;
  }
  li {
    background: #1a1d2b;
    border: 1px solid #292d40;
    padding: 8px 12px;
    border-radius: 4px;
    margin-bottom: 4px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .hot {
    color: #6a7090;
    font-size: 11px;
  }
</style>
