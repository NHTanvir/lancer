<script>
  let url = "https://example.com/";
  let issues = [];
  let running = false;
  async function fullScan() {
    running = true;
    try {
      const r = await fetch("/api/v1/scan/full", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ url }),
      });
      issues = await r.json();
    } catch (e) {
      issues = [];
    } finally {
      running = false;
    }
  }
</script>

<div class="bar">
  <input bind:value={url} placeholder="https://target.example/" />
  <button on:click={fullScan} disabled={running}>{running ? "Scanning…" : "Full scan"}</button>
</div>

{#if !issues.length}
  <p class="dim">No issues yet. Hit "Full scan" to start passive + active checks.</p>
{:else}
  <ul class="issues">
    {#each issues as i}
      <li class="sev-{i.severity}">
        <span class="badge">{i.severity}</span>
        <strong>{i.name}</strong>
        <span class="dim">— {i.host}</span>
        <div class="desc">{i.description}</div>
      </li>
    {/each}
  </ul>
{/if}

<style>
  .bar {
    display: flex;
    gap: 8px;
    margin-bottom: 12px;
  }
  .bar input {
    flex: 1;
  }
  .dim {
    color: #6a7090;
  }
  .issues {
    list-style: none;
    padding: 0;
    margin: 0;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .issues li {
    background: #1a1d2b;
    border: 1px solid #292d40;
    border-left-width: 4px;
    border-radius: 6px;
    padding: 10px 14px;
  }
  .issues li.sev-critical { border-left-color: #ff4d4d; }
  .issues li.sev-high { border-left-color: #e36b6b; }
  .issues li.sev-medium { border-left-color: #d97000; }
  .issues li.sev-low { border-left-color: #a37a00; }
  .issues li.sev-info { border-left-color: #4a86ff; }
  .badge {
    text-transform: uppercase;
    font-size: 10px;
    background: #2a2e44;
    border-radius: 3px;
    padding: 2px 6px;
    margin-right: 8px;
  }
  .desc {
    margin-top: 6px;
    color: #9aa0bd;
    font-size: 12px;
  }
</style>
