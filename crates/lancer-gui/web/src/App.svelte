<script>
  import { onMount } from "svelte";
  import Dashboard from "./views/Dashboard.svelte";
  import Target from "./views/Target.svelte";
  import Proxy from "./views/Proxy.svelte";
  import Intruder from "./views/Intruder.svelte";
  import Repeater from "./views/Repeater.svelte";
  import Sequencer from "./views/Sequencer.svelte";
  import Decoder from "./views/Decoder.svelte";
  import Comparer from "./views/Comparer.svelte";
  import Logger from "./views/Logger.svelte";
  import Scanner from "./views/Scanner.svelte";
  import Reports from "./views/Reports.svelte";
  import Settings from "./views/Settings.svelte";
  import PaletteModal from "./lib/PaletteModal.svelte";

  let active = "dashboard";
  let status = "connecting...";
  let paletteOpen = false;

  async function openBrowser() {
    try {
      const r = await fetch("/api/browser/open", { method: "POST" });
      const d = await r.json();
      if (!d.ok) status = "Could not launch browser — install Chrome or Edge";
    } catch {
      status = "Browser launch failed";
    }
  }

  const tabs = [
    { id: "dashboard", label: "Dashboard" },
    { id: "target",    label: "Target" },
    { id: "proxy",     label: "Proxy" },
    { id: "intruder",  label: "Intruder" },
    { id: "repeater",  label: "Repeater" },
    { id: "sequencer", label: "Sequencer" },
    { id: "decoder",   label: "Decoder" },
    { id: "comparer",  label: "Comparer" },
    { id: "logger",    label: "Logger" },
    { id: "reports",   label: "Reports" },
    { id: "settings",  label: "Settings" },
  ];

  onMount(async () => {
    try {
      const r = await fetch("/api/status");
      const data = await r.json();
      status = `Lancer ${data.version} · ${data.project_open ? "project open" : "memory-only"}`;
    } catch {
      status = "offline — start lancer-api";
    }

    function onKey(e) {
      if ((e.ctrlKey || e.metaKey) && e.key === "k") {
        e.preventDefault();
        paletteOpen = true;
      }
      if (e.key === "Escape") paletteOpen = false;
    }
    window.addEventListener("keydown", onKey);

    // Cross-tab navigation (e.g. "Send to Repeater" from Target)
    function onLancerNavigate(e) {
      const tab = tabs.find(t => t.id === e.detail);
      if (tab) active = tab.id;
    }
    window.addEventListener("lancer:navigate", onLancerNavigate);

    return () => {
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("lancer:navigate", onLancerNavigate);
    };
  });

  function onPaletteNavigate(e) {
    const tab = tabs.find(t => t.id === e.detail);
    if (tab) active = tab.id;
    paletteOpen = false;
  }
</script>

<div class="app">
  <!-- Top header bar -->
  <header class="topbar">
    <div class="brand">
      <!-- Orange lightning bolt SVG logo -->
      <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
        <polygon points="11,2 4,11 9,11 9,18 16,9 11,9" fill="#e03a00"/>
      </svg>
      <span class="brand-name">Lancer</span>
    </div>

    <nav class="tabs">
      {#each tabs as tab}
        <button
          class="tab"
          class:active={active === tab.id}
          on:click={() => active = tab.id}
        >{tab.label}</button>
      {/each}
    </nav>

    <div class="topbar-right">
      <span class="status-text">{status}</span>
      <button class="open-browser-btn" on:click={openBrowser} title="Open browser pre-configured to use Lancer as proxy">
        <svg width="13" height="13" viewBox="0 0 14 14" fill="none">
          <circle cx="7" cy="7" r="5.5" stroke="currentColor" stroke-width="1.4"/>
          <ellipse cx="7" cy="7" rx="2.2" ry="5.5" stroke="currentColor" stroke-width="1.1"/>
          <path d="M1.5 7 H12.5" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>
        </svg>
        Open Browser
      </button>
      <button class="palette-btn" on:click={() => paletteOpen = true} title="Command Palette (Ctrl+K)">
        <svg width="13" height="13" viewBox="0 0 14 14" fill="none">
          <circle cx="6" cy="6" r="4.5" stroke="currentColor" stroke-width="1.5"/>
          <path d="M9.5 9.5 L13 13" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
        </svg>
      </button>
    </div>
  </header>

  <!-- Main content -->
  <main class="content">
    {#if active === "dashboard"}<Dashboard />{/if}
    {#if active === "target"}<Target />{/if}
    {#if active === "proxy"}<Proxy />{/if}
    {#if active === "intruder"}<Intruder />{/if}
    {#if active === "repeater"}<Repeater />{/if}
    {#if active === "sequencer"}<Sequencer />{/if}
    {#if active === "decoder"}<Decoder />{/if}
    {#if active === "comparer"}<Comparer />{/if}
    {#if active === "logger"}<Logger />{/if}
    {#if active === "scanner"}<Scanner />{/if}
    {#if active === "reports"}<Reports />{/if}
    {#if active === "settings"}<Settings />{/if}
  </main>
</div>

{#if paletteOpen}
  <PaletteModal
    on:close={() => paletteOpen = false}
    on:navigate={onPaletteNavigate}
  />
{/if}

<style>
  /* ── Reset & base ── */
  :global(*, *::before, *::after) { box-sizing: border-box; }
  :global(body, html) {
    margin: 0; padding: 0;
    height: 100vh; overflow: hidden;
    background: #ffffff;
    color: #212121;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
    font-size: 13px;
    line-height: 1.5;
  }
  :global(button) {
    background: #f0f0f0;
    color: #333333;
    border: 1px solid #c8c8c8;
    border-radius: 3px;
    padding: 5px 11px;
    cursor: pointer;
    font-size: 13px;
    font-family: inherit;
    transition: background 0.1s;
  }
  :global(button:hover) { background: #e4e4e4; }
  :global(button:disabled) { opacity: 0.45; cursor: not-allowed; }
  :global(input, select) {
    background: #ffffff;
    color: #212121;
    border: 1px solid #c8c8c8;
    border-radius: 3px;
    padding: 4px 8px;
    font-size: 13px;
    font-family: inherit;
    outline: none;
  }
  :global(input:focus, select:focus) { border-color: #e03a00; outline: none; }
  :global(textarea) {
    background: #ffffff;
    color: #212121;
    border: 1px solid #c8c8c8;
    border-radius: 3px;
    padding: 8px 10px;
    font-size: 12px;
    font-family: ui-monospace, "Cascadia Code", Consolas, monospace;
    resize: vertical;
    width: 100%;
    outline: none;
    font-family: inherit;
  }
  :global(textarea:focus) { border-color: #e03a00; }

  /* ── Global utility classes ── */
  :global(.view) {
    display: flex; flex-direction: column;
    height: 100%; overflow: hidden;
    background: #ffffff;
  }
  :global(.panel) {
    flex: 1; overflow-y: auto;
    padding: 14px 16px;
    background: #ffffff;
  }
  :global(.toolbar) {
    display: flex; align-items: center; gap: 8px;
    padding: 6px 12px;
    background: #f5f5f5;
    border-bottom: 1px solid #dedede;
    flex-shrink: 0;
  }
  :global(.split-h) {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0;
    flex: 1;
    overflow: hidden;
  }
  :global(.pane) {
    display: flex; flex-direction: column;
    overflow: hidden;
    border-right: 1px solid #dedede;
  }
  :global(.pane:last-child) { border-right: none; }
  :global(.pane-header) {
    padding: 5px 10px;
    background: #f5f5f5;
    border-bottom: 1px solid #dedede;
    font-size: 12px;
    font-weight: 600;
    color: #444444;
    flex-shrink: 0;
  }

  /* ── Sub-tabs ── */
  :global(.subtabs) {
    display: flex; align-items: stretch;
    background: #f5f5f5;
    border-bottom: 1px solid #dedede;
    flex-shrink: 0;
    height: 36px;
  }
  :global(.subtab) {
    padding: 0 16px;
    cursor: pointer;
    border: none;
    border-bottom: 2px solid transparent;
    background: transparent;
    color: #444444;
    font-size: 13px;
    border-radius: 0;
    transition: color 0.1s, border-color 0.1s;
    white-space: nowrap;
    height: 100%;
  }
  :global(.subtab:hover) { color: #212121; background: rgba(0,0,0,0.04); }
  :global(.subtab.active) {
    color: #e03a00;
    border-bottom-color: #e03a00;
    font-weight: 600;
    background: transparent;
  }

  /* ── Primary (orange) button ── */
  :global(.btn-primary) {
    background: #e03a00;
    color: #ffffff;
    border: none;
    border-radius: 3px;
    padding: 5px 14px;
    font-size: 13px;
    font-weight: 500;
    cursor: pointer;
  }
  :global(.btn-primary:hover) { background: #c73400; }
  :global(.btn-primary:disabled) { opacity: 0.5; cursor: not-allowed; }

  /* ── Badges ── */
  :global(.badge) {
    display: inline-block;
    font-size: 11px; font-weight: 600;
    text-transform: uppercase;
    padding: 1px 6px;
    border-radius: 2px;
    letter-spacing: 0.03em;
  }
  :global(.badge-Critical) { background: #fde8e8; color: #d42c2c; border: 1px solid #f5b8b8; }
  :global(.badge-High)     { background: #fef0e6; color: #e86c00; border: 1px solid #f8c89a; }
  :global(.badge-Medium)   { background: #fef8e6; color: #c98a00; border: 1px solid #f5dfa0; }
  :global(.badge-Low)      { background: #eaf5ea; color: #1b8c1b; border: 1px solid #a8d8a8; }
  :global(.badge-Info)     { background: #e6f0fb; color: #1a75c4; border: 1px solid #9dc3e8; }

  /* ── Status / method colors ── */
  :global(.status-2) { color: #1b8c1b; }
  :global(.status-3) { color: #1a75c4; }
  :global(.status-4) { color: #c98a00; }
  :global(.status-5) { color: #d42c2c; }
  :global(.method-GET)    { color: #1b8c1b; font-weight: 600; }
  :global(.method-POST)   { color: #e86c00; font-weight: 600; }
  :global(.method-PUT)    { color: #1a75c4; font-weight: 600; }
  :global(.method-PATCH)  { color: #7b5ea7; font-weight: 600; }
  :global(.method-DELETE) { color: #d42c2c; font-weight: 600; }
  :global(.method-HEAD)   { color: #767676; font-weight: 600; }
  :global(.method-OPTIONS){ color: #767676; font-weight: 600; }

  /* ── Misc ── */
  :global(.dim) { color: #767676; }
  :global(.empty-state) {
    flex: 1; display: flex;
    flex-direction: column;
    align-items: center; justify-content: center;
    gap: 10px; color: #767676;
    font-size: 13px;
    text-align: center;
    padding: 40px;
  }

  /* ── Layout ── */
  .app {
    display: flex; flex-direction: column;
    height: 100vh; overflow: hidden;
  }

  .topbar {
    display: flex; align-items: stretch;
    height: 36px;
    background: #ffffff;
    border-bottom: 1px solid #dedede;
    flex-shrink: 0;
  }

  .brand {
    display: flex; align-items: center; gap: 6px;
    padding: 0 14px;
    border-right: 1px solid #dedede;
    flex-shrink: 0;
  }
  .brand-name {
    font-weight: 700; font-size: 14px;
    color: #212121;
    letter-spacing: 0.01em;
  }

  .tabs {
    display: flex; align-items: stretch;
    flex: 1;
    overflow-x: auto;
  }
  .tab {
    padding: 0 16px;
    background: transparent;
    border: none;
    border-bottom: 2px solid transparent;
    border-radius: 0;
    color: #444444;
    font-size: 13px;
    cursor: pointer;
    transition: color 0.1s, border-color 0.1s;
    white-space: nowrap;
    height: 100%;
    flex-shrink: 0;
    font-family: inherit;
  }
  .tab:hover { color: #212121; background: rgba(0,0,0,0.03); }
  .tab.active {
    color: #e03a00;
    border-bottom-color: #e03a00;
    font-weight: 600;
    background: transparent;
  }

  .topbar-right {
    display: flex; align-items: center; gap: 8px;
    padding: 0 10px;
    border-left: 1px solid #dedede;
    flex-shrink: 0;
  }
  .status-text {
    font-size: 11px; color: #767676;
    white-space: nowrap;
    max-width: 220px;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .open-browser-btn {
    display: flex; align-items: center; gap: 5px;
    padding: 4px 12px;
    background: #e03a00;
    color: #ffffff;
    border: none;
    border-radius: 3px;
    font-size: 12px;
    font-weight: 500;
    flex-shrink: 0;
    cursor: pointer;
  }
  .open-browser-btn:hover { background: #c73400; }

  .palette-btn {
    display: flex; align-items: center; justify-content: center;
    padding: 4px 8px;
    background: #f0f0f0;
    border: 1px solid #c8c8c8;
    border-radius: 3px;
    color: #767676;
    flex-shrink: 0;
    cursor: pointer;
  }
  .palette-btn:hover { background: #e4e4e4; color: #333; }

  .content {
    flex: 1; overflow: hidden;
    display: flex; flex-direction: column;
  }
</style>
