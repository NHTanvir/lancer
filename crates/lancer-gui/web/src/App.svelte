<script>
  import { onMount } from "svelte";
  import Sidebar from "./lib/Sidebar.svelte";
  import History from "./views/History.svelte";
  import Repeater from "./views/Repeater.svelte";
  import Intruder from "./views/Intruder.svelte";
  import Scanner from "./views/Scanner.svelte";
  import Issues from "./views/Issues.svelte";
  import Reports from "./views/Reports.svelte";
  import Settings from "./views/Settings.svelte";
  import Palette from "./views/Palette.svelte";
  import Proxy from "./views/Proxy.svelte";

  let active = "proxy";
  let status = "connecting…";

  onMount(async () => {
    try {
      const r = await fetch("/api/status");
      const data = await r.json();
      status = `Lancer ${data.version} · project ${data.project_open ? "open" : "memory-only"}`;
    } catch (e) {
      status = "offline (start `lancer-api` to connect)";
    }
  });

  function pick(view) {
    active = view;
  }
</script>

<div class="app">
  <Sidebar {active} on:pick={(e) => pick(e.detail)} />
  <main>
    <header>
      <h1>{active}</h1>
      <span class="status">{status}</span>
    </header>
    <section>
      {#if active === "proxy"}<Proxy />{/if}
      {#if active === "history"}<History />{/if}
      {#if active === "repeater"}<Repeater />{/if}
      {#if active === "intruder"}<Intruder />{/if}
      {#if active === "scanner"}<Scanner />{/if}
      {#if active === "issues"}<Issues />{/if}
      {#if active === "reports"}<Reports />{/if}
      {#if active === "palette"}<Palette />{/if}
      {#if active === "settings"}<Settings />{/if}
    </section>
  </main>
</div>

<style>
  :global(body, html) {
    margin: 0;
    padding: 0;
    height: 100vh;
    overflow: hidden;
    background: #0f111a;
    color: #d3d6e0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    font-size: 14px;
  }
  :global(button) {
    background: #1f2233;
    color: inherit;
    border: 1px solid #292d40;
    border-radius: 4px;
    padding: 6px 12px;
    cursor: pointer;
  }
  :global(button:hover) {
    background: #2a2e44;
  }
  :global(input, textarea, select) {
    background: #1a1d2b;
    color: inherit;
    border: 1px solid #292d40;
    border-radius: 4px;
    padding: 6px 10px;
  }
  :global(textarea) {
    width: 100%;
    min-height: 120px;
    font-family: ui-monospace, "JetBrains Mono", Menlo, Consolas, monospace;
  }
  .app {
    display: grid;
    grid-template-columns: 220px 1fr;
    height: 100vh;
  }
  main {
    overflow: hidden;
    display: flex;
    flex-direction: column;
  }
  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 12px 18px;
    background: #1a1d2b;
    border-bottom: 1px solid #292d40;
  }
  header h1 {
    margin: 0;
    font-size: 15px;
    text-transform: capitalize;
  }
  .status {
    color: #6a7090;
    font-size: 12px;
  }
  section {
    flex: 1;
    overflow: auto;
    padding: 18px;
  }
</style>
