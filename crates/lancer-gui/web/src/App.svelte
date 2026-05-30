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
  import Cookies from "./views/Cookies.svelte";
  import Organizer from "./views/Organizer.svelte";
  import Plugins from "./views/Plugins.svelte";
  import Findings from "./views/Findings.svelte";
  import JsMining from "./views/JsMining.svelte";
  import SecretScanner from "./views/SecretScanner.svelte";
  import AuthBypass from "./views/AuthBypass.svelte";
  import BulkProbe from "./views/BulkProbe.svelte";
  import ApiRoutes from "./views/ApiRoutes.svelte";
  import DeserPayload from "./views/DeserPayload.svelte";
  import LlmScan from "./views/LlmScan.svelte";
  import LlmRedTeam from "./views/LlmRedTeam.svelte";
  import McpScan from "./views/McpScan.svelte";
  import Shodan from "./views/Shodan.svelte";
  import StatefulFuzz from "./views/StatefulFuzz.svelte";
  import CmsScan from "./views/CmsScan.svelte";
  import Exploits from "./views/Exploits.svelte";
  import Modules from "./views/Modules.svelte";
  import PaletteModal from "./lib/PaletteModal.svelte";

  let active = "dashboard";
  let status = "connecting...";
  let paletteOpen = false;
  let theme = "light";
  let proxyAddr = "";
  let pluginCount = 0;
  let projectName = "memory-only";

  function applyTheme(t) {
    theme = t;
    document.body.setAttribute("data-theme", t);
    try { localStorage.setItem("lancer.theme", t); } catch {}
  }
  function toggleTheme() {
    applyTheme(theme === "dark" ? "light" : "dark");
  }

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
    { id: "organizer", label: "Organizer" },
    { id: "findings",  label: "Findings" },
    { id: "jsmining",   label: "JS Miner" },
    { id: "secrets",    label: "Secrets" },
    { id: "authbypass", label: "Auth Bypass" },
    { id: "bulkprobe",  label: "Bulk Probe" },
    { id: "apiroutes",  label: "API Routes" },
    { id: "deser",      label: "Deser Payloads" },
    { id: "llmscan",    label: "LLM Scan" },
    { id: "redteam",    label: "LLM Red-Team" },
    { id: "mcp",        label: "MCP Scan" },
    { id: "shodan",     label: "Shodan" },
    { id: "fuzz",       label: "Stateful Fuzz" },
    { id: "cms",        label: "CMS Scan" },
    { id: "exploits",   label: "Exploit DB" },
    { id: "modules",    label: "Modules" },
    { id: "cookies",   label: "Cookies" },
    { id: "plugins",   label: "Plugins" },
    { id: "reports",   label: "Reports" },
    { id: "settings",  label: "Settings" },
  ];

  async function refreshStatus() {
    try {
      const r = await fetch("/api/v1/status");
      const data = await r.json();
      status = `Lancer ${data.version} · ${data.project_open ? "project open" : "memory-only"}`;
      projectName = data.project_open ? "project open" : "memory-only";
      proxyAddr = data.proxy_addr || "";
    } catch {
      status = "offline — start lancer-api";
    }
    try {
      const r = await fetch("/api/v1/plugins");
      if (r.ok) {
        const d = await r.json();
        pluginCount = Array.isArray(d) ? d.length : (d.plugins || []).length;
      }
    } catch {}
  }

  onMount(async () => {
    try {
      const saved = localStorage.getItem("lancer.theme");
      if (saved === "dark" || saved === "light") applyTheme(saved);
      else applyTheme("light");
    } catch {}

    await refreshStatus();
    const statusTimer = setInterval(refreshStatus, 10000);

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
      clearInterval(statusTimer);
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
      <button class="palette-btn" on:click={toggleTheme} title={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}>
        {#if theme === "dark"}
          <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
            <circle cx="7" cy="7" r="3" fill="currentColor"/>
            <g stroke="currentColor" stroke-width="1.2" stroke-linecap="round">
              <path d="M7 1 V2.5"/><path d="M7 11.5 V13"/>
              <path d="M1 7 H2.5"/><path d="M11.5 7 H13"/>
              <path d="M2.6 2.6 L3.7 3.7"/><path d="M10.3 10.3 L11.4 11.4"/>
              <path d="M11.4 2.6 L10.3 3.7"/><path d="M3.7 10.3 L2.6 11.4"/>
            </g>
          </svg>
        {:else}
          <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
            <path d="M11 8.5 A4.5 4.5 0 1 1 5.5 3 A3.5 3.5 0 0 0 11 8.5 Z" fill="currentColor"/>
          </svg>
        {/if}
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
    {#if active === "organizer"}<Organizer />{/if}
    {#if active === "findings"}<Findings />{/if}
    {#if active === "jsmining"}<JsMining />{/if}
    {#if active === "secrets"}<SecretScanner />{/if}
    {#if active === "authbypass"}<AuthBypass />{/if}
    {#if active === "bulkprobe"}<BulkProbe />{/if}
    {#if active === "apiroutes"}<ApiRoutes />{/if}
    {#if active === "deser"}<DeserPayload />{/if}
    {#if active === "llmscan"}<LlmScan />{/if}
    {#if active === "redteam"}<LlmRedTeam />{/if}
    {#if active === "mcp"}<McpScan />{/if}
    {#if active === "shodan"}<Shodan />{/if}
    {#if active === "fuzz"}<StatefulFuzz />{/if}
    {#if active === "cms"}<CmsScan />{/if}
    {#if active === "exploits"}<Exploits />{/if}
    {#if active === "modules"}<Modules />{/if}
    {#if active === "cookies"}<Cookies />{/if}
    {#if active === "plugins"}<Plugins />{/if}
    {#if active === "reports"}<Reports />{/if}
    {#if active === "settings"}<Settings />{/if}
  </main>

  <!-- Status bar -->
  <footer class="statusbar">
    <span class="sb-cell">Project: <strong>{projectName}</strong></span>
    <span class="sb-sep">·</span>
    <span class="sb-cell">Proxy: <code>{proxyAddr || "—"}</code></span>
    <span class="sb-sep">·</span>
    <span class="sb-cell">Plugins: <strong>{pluginCount}</strong></span>
    <span class="sb-sep">·</span>
    <span class="sb-cell">Theme: <strong>{theme}</strong></span>
    <span class="sb-spacer"></span>
    <span class="sb-cell dim">Ctrl+K — command palette</span>
  </footer>
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
    font-size: 12px;
    line-height: 1.45;
  }
  /* Slim, unobtrusive scrollbars (or hidden entirely when not needed) */
  :global(::-webkit-scrollbar) { width: 8px; height: 8px; }
  :global(::-webkit-scrollbar-thumb) { background: #c8c8c8; border-radius: 4px; }
  :global(::-webkit-scrollbar-thumb:hover) { background: #a8a8a8; }
  :global(::-webkit-scrollbar-track) { background: transparent; }
  :global([data-theme="dark"] ::-webkit-scrollbar-thumb) { background: #555; }
  :global([data-theme="dark"] ::-webkit-scrollbar-thumb:hover) { background: #777; }
  :global(.tabs::-webkit-scrollbar) { display: none; }
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
    overflow-x: hidden;
    min-width: 0;
  }
  .tab {
    padding: 0 10px;
    background: transparent;
    border: none;
    border-bottom: 2px solid transparent;
    border-radius: 0;
    color: #444444;
    font-size: 12px;
    cursor: pointer;
    transition: color 0.1s, border-color 0.1s;
    white-space: nowrap;
    height: 100%;
    flex-shrink: 1;
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

  /* ── Status bar (footer) ── */
  .statusbar {
    display: flex; align-items: center; gap: 6px;
    height: 22px;
    padding: 0 12px;
    background: #f5f5f5;
    border-top: 1px solid #dedede;
    font-size: 11px;
    color: #444;
    flex-shrink: 0;
    white-space: nowrap;
    overflow: hidden;
  }
  .sb-cell { display: inline-flex; align-items: center; gap: 4px; }
  .sb-cell code { font-family: ui-monospace, Consolas, monospace; background: #ffffff; padding: 0 5px; border: 1px solid #dedede; border-radius: 2px; }
  .sb-cell strong { color: #212121; }
  .sb-sep { color: #c8c8c8; }
  .sb-spacer { flex: 1; }

  /* ── Dark theme ── */
  :global([data-theme="dark"]) {
    background: #1e1f22 !important;
    color: #d6d6d6 !important;
  }
  :global([data-theme="dark"] body) { background: #1e1f22; color: #d6d6d6; }
  :global([data-theme="dark"] .app) { background: #1e1f22; }
  :global([data-theme="dark"] .topbar) { background: #25262a; border-bottom-color: #3a3b3f; }
  :global([data-theme="dark"] .brand) { border-right-color: #3a3b3f; }
  :global([data-theme="dark"] .brand-name) { color: #f0f0f0; }
  :global([data-theme="dark"] .tab) { color: #b8b8b8; }
  :global([data-theme="dark"] .tab:hover) { color: #f0f0f0; background: rgba(255,255,255,0.04); }
  :global([data-theme="dark"] .tab.active) { color: #ff5722; border-bottom-color: #ff5722; }
  :global([data-theme="dark"] .topbar-right) { border-left-color: #3a3b3f; }
  :global([data-theme="dark"] .status-text) { color: #999; }
  :global([data-theme="dark"] .palette-btn) { background: #2d2e32; border-color: #4a4b50; color: #b8b8b8; }
  :global([data-theme="dark"] .palette-btn:hover) { background: #38393d; color: #f0f0f0; }
  :global([data-theme="dark"] button) { background: #2d2e32; color: #d6d6d6; border-color: #4a4b50; }
  :global([data-theme="dark"] button:hover) { background: #38393d; }
  :global([data-theme="dark"] input, [data-theme="dark"] select) { background: #1e1f22; color: #d6d6d6; border-color: #4a4b50; }
  :global([data-theme="dark"] textarea) { background: #1e1f22; color: #d6d6d6; border-color: #4a4b50; }
  :global([data-theme="dark"] .view) { background: #1e1f22; }
  :global([data-theme="dark"] .panel) { background: #1e1f22; }
  :global([data-theme="dark"] .toolbar) { background: #25262a; border-bottom-color: #3a3b3f; }
  :global([data-theme="dark"] .pane) { border-right-color: #3a3b3f; }
  :global([data-theme="dark"] .pane-header) { background: #25262a; color: #d6d6d6; border-bottom-color: #3a3b3f; }
  :global([data-theme="dark"] .subtabs) { background: #25262a; border-bottom-color: #3a3b3f; }
  :global([data-theme="dark"] .subtab) { color: #b8b8b8; }
  :global([data-theme="dark"] .subtab:hover) { color: #f0f0f0; }
  :global([data-theme="dark"] .subtab.active) { color: #ff5722; border-bottom-color: #ff5722; }
  :global([data-theme="dark"] .dim) { color: #888; }
  :global([data-theme="dark"] .statusbar) { background: #25262a; color: #b8b8b8; border-top-color: #3a3b3f; }
  :global([data-theme="dark"] .sb-cell strong) { color: #f0f0f0; }
  :global([data-theme="dark"] .sb-cell code) { background: #1e1f22; border-color: #4a4b50; color: #d6d6d6; }
</style>
