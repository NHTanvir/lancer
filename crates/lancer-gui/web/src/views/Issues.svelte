<script>
  import { onMount } from "svelte";
  let issues = [];
  let filter = "all";
  onMount(async () => {
    try {
      const r = await fetch("/api/v1/issues");
      issues = await r.json();
    } catch {
      issues = [];
    }
  });
  $: filtered = filter === "all" ? issues : issues.filter((i) => i.severity === filter);
</script>

<div class="bar">
  {#each ["all", "critical", "high", "medium", "low", "info"] as f}
    <button class:active={filter === f} on:click={() => (filter = f)}>{f}</button>
  {/each}
</div>

<ul>
  {#each filtered as i}
    <li class="sev-{i.severity}">
      <strong>{i.name}</strong>
      <span class="meta">{i.host} · {i.confidence}</span>
      <p>{i.description}</p>
      {#if i.remediation}<p class="rem"><em>Fix:</em> {i.remediation}</p>{/if}
    </li>
  {/each}
</ul>

<style>
  .bar {
    display: flex;
    gap: 6px;
    margin-bottom: 14px;
  }
  .bar button {
    text-transform: capitalize;
  }
  .bar .active {
    background: #2a2e44;
    border-color: #4a86ff;
  }
  ul {
    list-style: none;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  li {
    background: #1a1d2b;
    border: 1px solid #292d40;
    border-left-width: 4px;
    border-radius: 6px;
    padding: 10px 14px;
  }
  li.sev-critical { border-left-color: #ff4d4d; }
  li.sev-high { border-left-color: #e36b6b; }
  li.sev-medium { border-left-color: #d97000; }
  li.sev-low { border-left-color: #a37a00; }
  li.sev-info { border-left-color: #4a86ff; }
  .meta {
    color: #6a7090;
    font-size: 12px;
    margin-left: 8px;
  }
  .rem {
    color: #9aa0bd;
    font-size: 12px;
  }
</style>
