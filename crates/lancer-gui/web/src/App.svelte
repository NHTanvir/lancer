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
  import Mobile from "./views/Mobile.svelte";
  import Iac from "./views/Iac.svelte";
  import Collaborator from "./views/Collaborator.svelte";
  import SessionHandling from "./views/SessionHandling.svelte";
  import MassFuzz from "./views/MassFuzz.svelte";
  import Payloads from "./views/Payloads.svelte";
  import DualSession from "./views/DualSession.svelte";
  import IdMutator from "./views/IdMutator.svelte";
  import ResponseDiffer from "./views/ResponseDiffer.svelte";
  import FlowGrapher from "./views/FlowGrapher.svelte";
  import Scripts from "./views/Scripts.svelte";
  import Collab from "./views/Collab.svelte";
  import PaletteModal from "./lib/PaletteModal.svelte";

  let active = "dashboard";
  let status = "connecting...";
  let paletteOpen = false;
  let theme = "light";
  let proxyAddr = "";
  let pluginCount = 0;
  let projectName = "memory-only";
  let runningScans = 0;
  let memMb = 0;
  let appVersion = "";
  let helpMenuOpen = false;
  let aboutOpen = false;

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
    { id: "massfuzz",  label: "Mass Fuzz" },
    { id: "repeater",  label: "Repeater" },
    { id: "sequencer", label: "Sequencer" },
    { id: "decoder",   label: "Decoder" },
    { id: "comparer",  label: "Comparer" },
    { id: "payloads",  label: "Payloads" },
    { id: "scanner",   label: "Scanner" },
    { id: "collaborator", label: "Collaborator" },
    { id: "dualsession", label: "Dual-Session" },
    { id: "idmutator",   label: "ID Fuzzer" },
    { id: "respdiff",    label: "Resp Differ" },
    { id: "flowgraph",   label: "Flow Graph" },
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
    { id: "mobile",     label: "Mobile" },
    { id: "iac",        label: "IaC" },
    { id: "modules",    label: "Modules" },
    { id: "cookies",   label: "Cookies" },
    { id: "sessions",  label: "Sessions" },
    { id: "scripts",   label: "Scripts" },
    { id: "collab",    label: "Collab" },
    { id: "plugins",   label: "Plugins" },
    { id: "reports",   label: "Reports" },
    { id: "settings",  label: "Settings" },
  ];

  // ── §24 Hotkey customizer + §33 workspace presets ──────────────────────────
  const DEFAULT_HOTKEYS = {
    "ctrl+k": "palette", "ctrl+e": "repeater", "ctrl+i": "intruder",
    "ctrl+shift+p": "proxy", "ctrl+shift+s": "scanner", "ctrl+shift+t": "target",
    "ctrl+shift+l": "logger", "ctrl+shift+d": "decoder", "ctrl+shift+m": "theme",
  };
  let hotkeys = { ...DEFAULT_HOTKEYS };
  try { const s = localStorage.getItem("lancer.hotkeys"); if (s) hotkeys = JSON.parse(s); } catch {}
  let showHotkeys = false;
  let workspaces = [];
  try { workspaces = JSON.parse(localStorage.getItem("lancer.workspaces") || "[]"); } catch {}

  function comboFromEvent(e) {
    const parts = [];
    if (e.ctrlKey || e.metaKey) parts.push("ctrl");
    if (e.shiftKey) parts.push("shift");
    if (e.altKey) parts.push("alt");
    const k = (e.key || "").toLowerCase();
    if (!["control", "shift", "alt", "meta"].includes(k)) parts.push(k);
    return parts.join("+");
  }
  function runAction(action) {
    if (action === "palette") { paletteOpen = true; return; }
    if (action === "theme") { toggleTheme(); return; }
    const tab = tabs.find(t => t.id === action);
    if (tab) active = tab.id;
  }
  let capturingFor = null; // hotkey being rebound
  function startCapture(action) { capturingFor = action; }
  function onHotkeyCapture(e) {
    if (!capturingFor) return;
    e.preventDefault();
    const combo = comboFromEvent(e);
    if (["", "escape"].includes(combo)) { capturingFor = null; return; }
    // remove combo from any other action, assign to this one
    for (const c of Object.keys(hotkeys)) if (hotkeys[c] === capturingFor) delete hotkeys[c];
    hotkeys[combo] = capturingFor;
    hotkeys = hotkeys;
    capturingFor = null;
    try { localStorage.setItem("lancer.hotkeys", JSON.stringify(hotkeys)); } catch {}
  }
  function resetHotkeys() { hotkeys = { ...DEFAULT_HOTKEYS }; try { localStorage.setItem("lancer.hotkeys", JSON.stringify(hotkeys)); } catch {} }

  function saveWorkspace() {
    const name = prompt("Workspace preset name:");
    if (!name) return;
    const ws = { name, theme, active, hotkeys };
    workspaces = [...workspaces.filter(w => w.name !== name), ws];
    try { localStorage.setItem("lancer.workspaces", JSON.stringify(workspaces)); } catch {}
  }
  function loadWorkspace(ws) {
    if (ws.theme) applyTheme(ws.theme);
    if (ws.active) active = ws.active;
    if (ws.hotkeys) { hotkeys = ws.hotkeys; try { localStorage.setItem("lancer.hotkeys", JSON.stringify(hotkeys)); } catch {} }
  }
  function deleteWorkspace(ws) {
    workspaces = workspaces.filter(w => w.name !== ws.name);
    try { localStorage.setItem("lancer.workspaces", JSON.stringify(workspaces)); } catch {}
  }

  // ── §33 Crash recovery — periodic snapshot of the active view ──────────────
  function snapshotState() {
    try { localStorage.setItem("lancer.recovery", JSON.stringify({ active, ts: Date.now() })); } catch {}
  }

  // ── §18 File menu ──────────────────────────────────────────────────────────
  let fileMenuOpen = false;
  let projectInfo = { open: false, kind: "temporary", path: null };
  let recentProjects = [];

  async function loadProjectInfo() {
    try { const r = await fetch("/api/v1/project"); if (r.ok) projectInfo = await r.json(); } catch {}
    try { recentProjects = JSON.parse(localStorage.getItem("lancer.recentProjects") || "[]"); } catch { recentProjects = []; }
  }
  function pushRecent(path) {
    if (!path) return;
    recentProjects = [path, ...recentProjects.filter(p => p !== path)].slice(0, 10);
    try { localStorage.setItem("lancer.recentProjects", JSON.stringify(recentProjects)); } catch {}
  }
  async function newProject() {
    fileMenuOpen = false;
    try { await fetch("/api/v1/project/new-temporary", { method: "POST" }); await loadProjectInfo(); await refreshStatus(); } catch {}
  }
  async function openProject(path) {
    fileMenuOpen = false;
    const p = path || prompt("Open project — path to .lancer file on the server:");
    if (!p) return;
    try {
      const r = await fetch("/api/v1/project/open", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ path: p }) });
      if (r.ok) { pushRecent(p); await loadProjectInfo(); await refreshStatus(); }
      else alert("Open failed: " + (await r.text()));
    } catch {}
  }

  async function refreshStatus() {
    try {
      const r = await fetch("/api/v1/status");
      const data = await r.json();
      status = `Lancer ${data.version} · ${data.project_open ? "project open" : "memory-only"}`;
      projectName = data.project_open ? "project open" : "memory-only";
      proxyAddr = data.proxy_addr || "";
      appVersion = data.version || appVersion;
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
    // §24 status bar: live running-scan count + JS heap usage
    try {
      const r = await fetch("/api/v1/scan/queue");
      if (r.ok) {
        const d = await r.json();
        const q = Array.isArray(d) ? d : (d.queue || []);
        runningScans = q.length;
      }
    } catch {}
    try {
      if (typeof performance !== "undefined" && performance.memory) {
        memMb = Math.round(performance.memory.usedJSHeapSize / 1048576);
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
      if (capturingFor) { onHotkeyCapture(e); return; }
      if (e.key === "Escape") { paletteOpen = false; showHotkeys = false; return; }
      // Don't hijack typing in inputs/textareas (except the palette combo).
      const combo = comboFromEvent(e);
      const action = hotkeys[combo];
      if (action) {
        const tag = (e.target && e.target.tagName) || "";
        if (["INPUT", "TEXTAREA", "SELECT"].includes(tag) && action !== "palette") return;
        e.preventDefault();
        runAction(action);
      }
    }
    window.addEventListener("keydown", onKey);

    // §33 crash recovery: restore last active view, then snapshot periodically.
    try {
      const rec = JSON.parse(localStorage.getItem("lancer.recovery") || "null");
      if (rec && rec.active && tabs.find(t => t.id === rec.active)) active = rec.active;
    } catch {}
    const recoveryTimer = setInterval(snapshotState, 20000);

    function onWinClick() { fileMenuOpen = false; helpMenuOpen = false; }
    window.addEventListener("click", onWinClick);

    // Cross-tab navigation (e.g. "Send to Repeater" from Target)
    function onLancerNavigate(e) {
      const tab = tabs.find(t => t.id === e.detail);
      if (tab) active = tab.id;
    }
    window.addEventListener("lancer:navigate", onLancerNavigate);

    return () => {
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("click", onWinClick);
      window.removeEventListener("lancer:navigate", onLancerNavigate);
      clearInterval(statusTimer);
      clearInterval(recoveryTimer);
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
        <polygon points="11,2 4,11 9,11 9,18 16,9 11,9" fill="#e5481d"/>
      </svg>
      <span class="brand-name">Lancer</span>
      <div class="file-menu-wrap">
        <button class="file-menu-btn" on:click|stopPropagation={() => { fileMenuOpen = !fileMenuOpen; if (fileMenuOpen) loadProjectInfo(); }}>File ▾</button>
        {#if fileMenuOpen}
          <div class="file-menu" on:click|stopPropagation>
            <div class="fm-item" on:click={newProject}>New project (temporary)</div>
            <div class="fm-item" on:click={() => openProject()}>Open project…</div>
            <div class="fm-sep"></div>
            <div class="fm-label">Current: {projectInfo.path || projectInfo.kind}</div>
            {#if recentProjects.length}
              <div class="fm-sep"></div>
              <div class="fm-label">Recent</div>
              {#each recentProjects as p}
                <div class="fm-item fm-recent" on:click={() => openProject(p)} title={p}>{p.split(/[\\/]/).pop()}</div>
              {/each}
            {/if}
          </div>
        {/if}
      </div>
      <div class="file-menu-wrap">
        <button class="file-menu-btn" on:click|stopPropagation={() => { helpMenuOpen = !helpMenuOpen; }}>Help ▾</button>
        {#if helpMenuOpen}
          <div class="file-menu" on:click|stopPropagation>
            <div class="fm-item" on:click={() => { helpMenuOpen = false; window.open('https://github.com/NHTanvir/lancer', '_blank'); }}>Documentation</div>
            <div class="fm-item" on:click={() => { helpMenuOpen = false; window.open('https://github.com/NHTanvir/lancer/issues', '_blank'); }}>Report issue…</div>
            <div class="fm-sep"></div>
            <div class="fm-item" on:click={() => { helpMenuOpen = false; aboutOpen = true; }}>About Lancer</div>
          </div>
        {/if}
      </div>
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
      <button class="palette-btn" on:click={() => showHotkeys = true} title="Keyboard shortcuts & workspaces">
        <svg width="14" height="14" viewBox="0 0 16 16" fill="none">
          <rect x="1" y="4" width="14" height="8" rx="1.5" stroke="currentColor" stroke-width="1.2"/>
          <path d="M4 7h0M7 7h0M10 7h0M5 9.5h6" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/>
        </svg>
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
    {#if active === "massfuzz"}<MassFuzz />{/if}
    {#if active === "repeater"}<Repeater />{/if}
    {#if active === "sequencer"}<Sequencer />{/if}
    {#if active === "decoder"}<Decoder />{/if}
    {#if active === "comparer"}<Comparer />{/if}
    {#if active === "payloads"}<Payloads />{/if}
    {#if active === "logger"}<Logger />{/if}
    {#if active === "scanner"}<Scanner />{/if}
    {#if active === "collaborator"}<Collaborator />{/if}
    {#if active === "dualsession"}<DualSession />{/if}
    {#if active === "idmutator"}<IdMutator />{/if}
    {#if active === "respdiff"}<ResponseDiffer />{/if}
    {#if active === "flowgraph"}<FlowGrapher />{/if}
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
    {#if active === "mobile"}<Mobile />{/if}
    {#if active === "iac"}<Iac />{/if}
    {#if active === "modules"}<Modules />{/if}
    {#if active === "cookies"}<Cookies />{/if}
    {#if active === "sessions"}<SessionHandling />{/if}
    {#if active === "scripts"}<Scripts />{/if}
    {#if active === "collab"}<Collab />{/if}
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
    <span class="sb-cell">Scans: <strong>{runningScans}</strong></span>
    <span class="sb-sep">·</span>
    <span class="sb-cell">Theme: <strong>{theme}</strong></span>
    <span class="sb-spacer"></span>
    {#if memMb > 0}<span class="sb-cell">Mem: <strong>{memMb}</strong> MB</span><span class="sb-sep">·</span>{/if}
    <span class="sb-cell dim">Ctrl+K — command palette</span>
  </footer>
</div>

{#if paletteOpen}
  <PaletteModal
    on:close={() => paletteOpen = false}
    on:navigate={onPaletteNavigate}
  />
{/if}

{#if showHotkeys}
  <div class="hk-overlay" on:click={() => { showHotkeys = false; capturingFor = null; }}>
    <div class="hk-modal" on:click|stopPropagation>
      <div class="hk-head">
        <strong>Keyboard shortcuts & workspaces</strong>
        <button class="palette-btn" on:click={() => { showHotkeys = false; capturingFor = null; }}>×</button>
      </div>
      <div class="hk-body">
        <div class="hk-section">Hotkeys <button class="hk-mini" on:click={resetHotkeys}>Reset defaults</button></div>
        <table class="hk-table">
          <tbody>
            {#each Object.entries(hotkeys) as [combo, action]}
              <tr>
                <td class="hk-action">{action}</td>
                <td><button class="hk-combo" class:capturing={capturingFor === action} on:click={() => startCapture(action)}>{capturingFor === action ? "press keys…" : combo}</button></td>
              </tr>
            {/each}
          </tbody>
        </table>
        <div class="hk-section">Workspace presets <button class="hk-mini" on:click={saveWorkspace}>Save current</button></div>
        {#if workspaces.length === 0}
          <div class="dim" style="font-size:12px">No saved workspaces. "Save current" stores the active view, theme, and hotkeys.</div>
        {:else}
          {#each workspaces as ws}
            <div class="hk-ws"><span>{ws.name}</span><span class="dim">{ws.active} · {ws.theme}</span><button class="hk-mini" on:click={() => loadWorkspace(ws)}>Load</button><button class="hk-mini danger" on:click={() => deleteWorkspace(ws)}>×</button></div>
          {/each}
        {/if}
      </div>
    </div>
  </div>
{/if}

{#if aboutOpen}
  <div class="hk-overlay" on:click={() => aboutOpen = false}>
    <div class="about-modal" on:click|stopPropagation>
      <svg width="44" height="44" viewBox="0 0 20 20" fill="none"><polygon points="11,2 4,11 9,11 9,18 16,9 11,9" fill="#e5481d"/></svg>
      <div class="about-name">Lancer</div>
      <div class="about-ver">Version {appVersion || "0.1.0"}</div>
      <div class="about-desc">A Rust-native web-security testing workbench — intercepting proxy, scanner, intruder, repeater and 40+ integrated tools.</div>
      <button class="btn-primary" on:click={() => aboutOpen = false}>Close</button>
    </div>
  </div>
{/if}

<style>
  /* ════════════════════════════════════════════════════════════════════
     Lancer design tokens — refined, light, modern workbench.
     Light is the default (:root); dark redefines the SAME tokens, so every
     view that uses var(--…) re-themes automatically.
     ════════════════════════════════════════════════════════════════════ */
  :global(:root) {
    /* Brand accent — refined ember */
    --accent:        #e5481d;
    --accent-hover:  #c93d15;
    --accent-active: #b3350f;
    --accent-soft:   #fdede7;
    --accent-ring:   rgba(229, 72, 29, 0.26);
    --on-accent:     #ffffff;

    /* Canvas + layered surfaces */
    --bg:        #f4f6f8;
    --surface:   #ffffff;
    --surface-1: #fafbfc;
    --surface-2: #f1f3f6;
    --surface-3: #e8ebef;

    /* Hairline borders */
    --border:        #e6e9ee;
    --border-strong: #d5dae1;

    /* Text scale */
    --text:       #1b2026;
    --text-2:     #434a54;
    --text-muted: #69707b;
    --text-dim:   #98a0ab;

    /* Row hover / selection */
    --row-hover:  #eef4fd;
    --row-active: #dde9fb;

    /* Semantic */
    --danger: #d83b3b;

    /* Elevation */
    --shadow-sm: 0 1px 2px rgba(20, 28, 40, 0.06);
    --shadow-md: 0 4px 14px rgba(20, 28, 40, 0.10), 0 1px 3px rgba(20, 28, 40, 0.06);
    --shadow-lg: 0 16px 44px rgba(20, 28, 40, 0.18), 0 3px 10px rgba(20, 28, 40, 0.10);

    /* Radii */
    --radius-sm: 4px;
    --radius:    7px;
    --radius-lg: 11px;
  }
  :global([data-theme="dark"]) {
    --accent:        #ff6a47;
    --accent-hover:  #ff8062;
    --accent-active: #ff5230;
    --accent-soft:   rgba(255, 106, 71, 0.16);
    --accent-ring:   rgba(255, 106, 71, 0.40);
    --on-accent:     #ffffff;

    --bg:        #161719;
    --surface:   #1f2125;
    --surface-1: #24262b;
    --surface-2: #24262b;
    --surface-3: #2d3036;

    --border:        #32353c;
    --border-strong: #41454f;

    --text:       #e5e7eb;
    --text-2:     #b7bcc5;
    --text-muted: #8a909b;
    --text-dim:   #686e79;

    --row-hover:  rgba(255, 255, 255, 0.045);
    --row-active: rgba(120, 160, 255, 0.18);

    --danger: #ff5d5d;

    --shadow-sm: 0 1px 2px rgba(0, 0, 0, 0.35);
    --shadow-md: 0 4px 14px rgba(0, 0, 0, 0.45), 0 1px 3px rgba(0, 0, 0, 0.30);
    --shadow-lg: 0 16px 44px rgba(0, 0, 0, 0.60), 0 3px 10px rgba(0, 0, 0, 0.40);
  }

  /* ── Reset & base ── */
  :global(*, *::before, *::after) { box-sizing: border-box; }
  :global(html, body) {
    margin: 0; padding: 0;
    height: 100vh; overflow: hidden;
    background: var(--bg);
    color: var(--text);
    font-family: "Segoe UI", -apple-system, BlinkMacSystemFont, "Helvetica Neue", Arial, sans-serif;
    font-size: 13px;
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
    text-rendering: optimizeLegibility;
  }
  :global(::selection) { background: var(--accent-soft); }
  :global([data-theme="dark"] ::selection) { background: rgba(255, 106, 71, 0.30); }

  /* Slim, padded scrollbars */
  :global(::-webkit-scrollbar) { width: 11px; height: 11px; }
  :global(::-webkit-scrollbar-thumb) {
    background: var(--border-strong);
    border-radius: 7px;
    border: 3px solid transparent;
    background-clip: padding-box;
  }
  :global(::-webkit-scrollbar-thumb:hover) {
    background: var(--text-dim);
    border: 3px solid transparent;
    background-clip: padding-box;
  }
  :global(::-webkit-scrollbar-track) { background: transparent; }
  :global(.tabs::-webkit-scrollbar) { display: none; }

  /* ── Form controls ── */
  :global(button) {
    background: var(--surface);
    color: var(--text-2);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius);
    padding: 5px 12px;
    cursor: pointer;
    font-size: 13px;
    font-family: inherit;
    font-weight: 500;
    transition: background 0.12s ease, border-color 0.12s ease, color 0.12s ease, box-shadow 0.12s ease, transform 0.05s ease;
  }
  :global(button:hover) { background: var(--surface-2); color: var(--text); }
  :global(button:active) { transform: translateY(0.5px); }
  :global(button:disabled) { opacity: 0.5; cursor: not-allowed; }
  :global(button:focus-visible) { outline: none; box-shadow: 0 0 0 3px var(--accent-ring); }

  :global(input, select) {
    background: var(--surface);
    color: var(--text);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius);
    padding: 5px 9px;
    font-size: 13px;
    font-family: inherit;
    outline: none;
    transition: border-color 0.12s ease, box-shadow 0.12s ease;
  }
  :global(input::placeholder, textarea::placeholder) { color: var(--text-dim); }
  :global(input:focus, select:focus) { border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-ring); }
  :global(input[type="checkbox"], input[type="radio"]) { accent-color: var(--accent); cursor: pointer; }
  :global(input[type="range"]) { accent-color: var(--accent); }
  :global(textarea) {
    background: var(--surface);
    color: var(--text);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius);
    padding: 9px 11px;
    font-size: 12.5px;
    font-family: ui-monospace, "Cascadia Code", "JetBrains Mono", Consolas, monospace;
    resize: vertical;
    width: 100%;
    outline: none;
    line-height: 1.55;
    transition: border-color 0.12s ease, box-shadow 0.12s ease;
  }
  :global(textarea:focus) { border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-ring); }

  /* ── Global utility classes ── */
  :global(.view) {
    display: flex; flex-direction: column;
    height: 100%; overflow: hidden;
    background: var(--surface);
  }
  :global(.panel) {
    flex: 1; overflow-y: auto;
    padding: 14px 16px;
    background: var(--surface);
  }
  :global(.toolbar) {
    display: flex; align-items: center; gap: 8px;
    padding: 7px 12px;
    background: var(--surface-2);
    border-bottom: 1px solid var(--border);
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
    border-right: 1px solid var(--border);
  }
  :global(.pane:last-child) { border-right: none; }
  :global(.pane-header) {
    padding: 6px 11px;
    background: var(--surface-2);
    border-bottom: 1px solid var(--border);
    font-size: 11.5px;
    font-weight: 600;
    color: var(--text-2);
    letter-spacing: 0.02em;
    flex-shrink: 0;
  }

  /* ── Sub-tabs ── */
  :global(.subtabs) {
    display: flex; align-items: stretch;
    background: var(--surface-2);
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
    height: 36px;
    padding: 0 4px;
    gap: 2px;
  }
  :global(.subtab) {
    padding: 0 14px;
    cursor: pointer;
    border: none;
    border-bottom: 2px solid transparent;
    background: transparent;
    color: var(--text-muted);
    font-size: 13px;
    border-radius: 0;
    transition: color 0.12s, border-color 0.12s, background 0.12s;
    white-space: nowrap;
    height: 100%;
    font-weight: 500;
  }
  :global(.subtab:hover) { color: var(--text); background: var(--row-hover); }
  :global(.subtab.active) {
    color: var(--accent);
    border-bottom-color: var(--accent);
    font-weight: 600;
    background: transparent;
  }

  /* ── Primary (accent) button ── */
  :global(.btn-primary) {
    background: var(--accent);
    color: var(--on-accent);
    border: 1px solid transparent;
    border-radius: var(--radius);
    padding: 5px 14px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    box-shadow: var(--shadow-sm);
    transition: background 0.12s, box-shadow 0.12s, transform 0.05s;
  }
  :global(.btn-primary:hover) { background: var(--accent-hover); box-shadow: var(--shadow-md); }
  :global(.btn-primary:active) { background: var(--accent-active); transform: translateY(0.5px); }
  :global(.btn-primary:disabled) { opacity: 0.5; cursor: not-allowed; box-shadow: none; }
  :global(.btn-primary:focus-visible) { outline: none; box-shadow: 0 0 0 3px var(--accent-ring); }

  /* ── Badges (pill, semantic) ── */
  :global(.badge) {
    display: inline-block;
    font-size: 10.5px; font-weight: 700;
    text-transform: uppercase;
    padding: 2px 8px;
    border-radius: 999px;
    letter-spacing: 0.04em;
    line-height: 1.5;
  }
  :global(.badge-Critical) { background: #fdeaea; color: #c92a2a; border: 1px solid #f4c2c2; }
  :global(.badge-High)     { background: #fef0e6; color: #d9670a; border: 1px solid #f6cfa6; }
  :global(.badge-Medium)   { background: #fef8e6; color: #b07d0a; border: 1px solid #f0dca0; }
  :global(.badge-Low)      { background: #e9f7ec; color: #1f8a3b; border: 1px solid #b6e0bf; }
  :global(.badge-Info)     { background: #e9f1fd; color: #1f6fd6; border: 1px solid #b9d3f3; }

  /* ── Status / method colors ── */
  :global(.status-2) { color: #1f9d3f; }
  :global(.status-3) { color: #1f6fd6; }
  :global(.status-4) { color: #b07d0a; }
  :global(.status-5) { color: #d83b3b; }
  :global(.method-GET)    { color: #1f9d3f; font-weight: 600; }
  :global(.method-POST)   { color: #d9670a; font-weight: 600; }
  :global(.method-PUT)    { color: #1f6fd6; font-weight: 600; }
  :global(.method-PATCH)  { color: #7b5ea7; font-weight: 600; }
  :global(.method-DELETE) { color: #d83b3b; font-weight: 600; }
  :global(.method-HEAD)   { color: var(--text-muted); font-weight: 600; }
  :global(.method-OPTIONS){ color: var(--text-muted); font-weight: 600; }

  /* ── Misc ── */
  :global(.dim) { color: var(--text-muted); }
  :global(.empty-state) {
    flex: 1; display: flex;
    flex-direction: column;
    align-items: center; justify-content: center;
    gap: 10px; color: var(--text-muted);
    font-size: 13px;
    text-align: center;
    padding: 40px;
  }

  /* ── Layout shell ── */
  .app {
    display: flex; flex-direction: column;
    height: 100vh; overflow: hidden;
    background: var(--bg);
  }

  .topbar {
    display: flex; align-items: stretch;
    height: 38px;
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    box-shadow: var(--shadow-sm);
    flex-shrink: 0;
    z-index: 5;
  }

  .brand {
    display: flex; align-items: center; gap: 7px;
    padding: 0 14px;
    border-right: 1px solid var(--border);
    flex-shrink: 0;
  }
  .brand-name {
    font-weight: 700; font-size: 14.5px;
    color: var(--text);
    letter-spacing: -0.01em;
  }
  .file-menu-wrap { position: relative; }
  .file-menu-btn { background: transparent; border: 1px solid transparent; padding: 3px 9px; font-size: 12px; cursor: pointer; color: var(--text-muted); border-radius: var(--radius-sm); font-weight: 500; }
  .file-menu-btn:hover { background: var(--surface-2); color: var(--text); }
  .file-menu { position: absolute; top: 100%; left: 0; margin-top: 4px; background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); box-shadow: var(--shadow-lg); z-index: 300; min-width: 230px; padding: 5px; }
  .fm-item { padding: 7px 12px; font-size: 12.5px; cursor: pointer; color: var(--text-2); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; border-radius: var(--radius-sm); }
  .fm-item:hover { background: var(--row-hover); color: var(--text); }
  .fm-recent { font-family: ui-monospace, Consolas, monospace; font-size: 11px; color: var(--accent); }
  .fm-sep { height: 1px; background: var(--border); margin: 5px 4px; }
  .fm-label { padding: 4px 12px; font-size: 10px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-dim); }

  .hk-overlay { position: fixed; inset: 0; background: rgba(15, 20, 28, 0.45); backdrop-filter: blur(2px); z-index: 400; display: flex; align-items: center; justify-content: center; }
  .hk-modal { width: 470px; max-width: 92vw; max-height: 80vh; background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-lg); box-shadow: var(--shadow-lg); display: flex; flex-direction: column; overflow: hidden; color: var(--text); }
  .hk-head { display: flex; justify-content: space-between; align-items: center; padding: 14px 18px; border-bottom: 1px solid var(--border); }
  .hk-body { padding: 14px 18px; overflow: auto; }
  .hk-section { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin: 14px 0 7px; display: flex; justify-content: space-between; align-items: center; }
  .hk-table { width: 100%; }
  .hk-action { font-size: 13px; color: var(--text-2); padding: 3px 0; }
  .hk-combo { font-family: ui-monospace, Consolas, monospace; font-size: 12px; padding: 3px 10px; border: 1px solid var(--border-strong); border-radius: var(--radius-sm); background: var(--surface-2); cursor: pointer; color: var(--text); }
  .hk-combo.capturing { border-color: var(--accent); color: var(--accent); }
  .hk-mini { font-size: 11px; padding: 3px 9px; border: 1px solid var(--border-strong); border-radius: var(--radius-sm); background: var(--surface); cursor: pointer; }
  .hk-mini.danger { color: var(--danger); }
  .hk-ws { display: flex; align-items: center; gap: 8px; padding: 5px 0; font-size: 12px; }
  .hk-ws span:first-child { font-weight: 600; flex: 1; }

  .about-modal {
    width: 360px; max-width: 90vw;
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius-lg); box-shadow: var(--shadow-lg);
    padding: 30px 28px;
    display: flex; flex-direction: column; align-items: center; text-align: center; gap: 7px;
  }
  .about-name { font-size: 23px; font-weight: 700; letter-spacing: -0.02em; color: var(--text); margin-top: 4px; }
  .about-ver { font-size: 12px; color: var(--text-muted); }
  .about-desc { font-size: 12.5px; color: var(--text-2); line-height: 1.55; margin: 8px 0 14px; }

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
    color: var(--text-muted);
    font-size: 12.5px;
    cursor: pointer;
    transition: color 0.12s, border-color 0.12s, background 0.12s;
    white-space: nowrap;
    height: 100%;
    flex-shrink: 1;
    font-family: inherit;
    font-weight: 500;
  }
  .tab:hover { color: var(--text); background: var(--surface-2); }
  .tab.active {
    color: var(--accent);
    border-bottom-color: var(--accent);
    font-weight: 600;
    background: var(--accent-soft);
  }

  .topbar-right {
    display: flex; align-items: center; gap: 8px;
    padding: 0 12px;
    border-left: 1px solid var(--border);
    flex-shrink: 0;
  }
  .status-text {
    font-size: 11px; color: var(--text-muted);
    white-space: nowrap;
    max-width: 220px;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .open-browser-btn {
    display: flex; align-items: center; gap: 6px;
    padding: 5px 12px;
    background: var(--accent);
    color: var(--on-accent);
    border: 1px solid transparent;
    border-radius: var(--radius);
    font-size: 12px;
    font-weight: 600;
    flex-shrink: 0;
    cursor: pointer;
    box-shadow: var(--shadow-sm);
    transition: background 0.12s, box-shadow 0.12s;
  }
  .open-browser-btn:hover { background: var(--accent-hover); box-shadow: var(--shadow-md); }

  .palette-btn {
    display: flex; align-items: center; justify-content: center;
    padding: 5px 8px;
    background: var(--surface);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius);
    color: var(--text-muted);
    flex-shrink: 0;
    cursor: pointer;
    transition: background 0.12s, color 0.12s, border-color 0.12s;
  }
  .palette-btn:hover { background: var(--surface-2); color: var(--text); }

  .content {
    flex: 1; overflow: hidden;
    display: flex; flex-direction: column;
    background: var(--bg);
  }

  /* ── Status bar (footer) ── */
  .statusbar {
    display: flex; align-items: center; gap: 7px;
    height: 24px;
    padding: 0 14px;
    background: var(--surface);
    border-top: 1px solid var(--border);
    font-size: 11px;
    color: var(--text-muted);
    flex-shrink: 0;
    white-space: nowrap;
    overflow: hidden;
  }
  .sb-cell { display: inline-flex; align-items: center; gap: 4px; }
  .sb-cell code { font-family: ui-monospace, Consolas, monospace; background: var(--surface-2); padding: 1px 6px; border: 1px solid var(--border); border-radius: var(--radius-sm); color: var(--text-2); }
  .sb-cell strong { color: var(--text); font-weight: 600; }
  .sb-sep { color: var(--border-strong); }
  .sb-spacer { flex: 1; }
</style>
