<script>
  import { onMount, createEventDispatcher } from "svelte";
  const dispatch = createEventDispatcher();

  let q = "";
  let commands = [];
  let filtered = [];
  let selected = 0;

  // Every nav target, so Ctrl+K can jump to any tab. IDs must match App.svelte's
  // `tabs[].id`. The optional `/api/palette` endpoint (plugin-registered commands)
  // is merged on top when present; until then this list is the source of truth —
  // previously the palette listed only 11 of the 42 tabs and 404'd the rest.
  const NAV = [
    ["dashboard","Dashboard"],["target","Target"],["proxy","Proxy"],["intruder","Intruder"],
    ["massfuzz","Mass Fuzz"],["repeater","Repeater"],["sequencer","Sequencer"],["decoder","Decoder"],
    ["comparer","Comparer"],["payloads","Payloads"],["scanner","Scanner"],["collaborator","Collaborator"],
    ["dualsession","Dual-Session"],["idmutator","ID Fuzzer"],["respdiff","Resp Differ"],["flowgraph","Flow Graph"],
    ["logger","Logger"],["organizer","Organizer"],["findings","Findings"],["jsmining","JS Miner"],
    ["secrets","Secrets"],["authbypass","Auth Bypass"],["bulkprobe","Bulk Probe"],["apiroutes","API Routes"],
    ["deser","Deser Payloads"],["llmscan","LLM Scan"],["redteam","LLM Red-Team"],["mcp","MCP Scan"],
    ["shodan","Shodan"],["fuzz","Stateful Fuzz"],["cms","CMS Scan"],["exploits","Exploit DB"],
    ["mobile","Mobile"],["iac","IaC"],["modules","Modules"],["cookies","Cookies"],
    ["sessions","Sessions"],["scripts","Scripts"],["collab","Collab"],["plugins","Plugins"],
    ["reports","Reports"],["settings","Settings"],
  ].map(([id, label]) => ({ id, label: "Go to " + label, hotkey: null, kind: "nav" }));

  async function load() {
    commands = NAV; // always have the full nav set, even if the endpoint is absent
    try {
      const r = await fetch("/api/palette");
      if (r.ok) {
        const data = await r.json();
        if (Array.isArray(data) && data.length) {
          commands = [...NAV, ...data.filter((c) => c && c.kind !== "nav")];
        }
      }
    } catch {}
  }

  $: {
    const lq = q.toLowerCase();
    filtered = lq ? commands.filter(c => c.label.toLowerCase().includes(lq)) : commands;
    selected = 0;
  }

  function onKey(e) {
    if (e.key === "Escape") { dispatch("close"); return; }
    if (e.key === "ArrowDown") { e.preventDefault(); selected = Math.min(selected + 1, filtered.length - 1); return; }
    if (e.key === "ArrowUp")   { e.preventDefault(); selected = Math.max(selected - 1, 0); return; }
    if (e.key === "Enter" && filtered[selected]) { activate(filtered[selected]); }
  }

  function activate(cmd) {
    if (cmd.kind === "nav") dispatch("navigate", cmd.id);
    dispatch("close");
  }

  onMount(() => { load(); });
</script>

<!-- svelte-ignore a11y-click-events-have-key-events -->
<!-- svelte-ignore a11y-no-static-element-interactions -->
<div class="backdrop" on:click={() => dispatch("close")}>
  <!-- svelte-ignore a11y-click-events-have-key-events -->
  <!-- svelte-ignore a11y-no-static-element-interactions -->
  <div class="palette-panel" on:click|stopPropagation>
    <div class="search-wrap">
      <svg class="search-icon" width="14" height="14" viewBox="0 0 14 14" fill="none">
        <circle cx="6" cy="6" r="4.5" stroke="#69707b" stroke-width="1.5"/>
        <path d="M9.5 9.5 L13 13" stroke="#69707b" stroke-width="1.5" stroke-linecap="round"/>
      </svg>
      <!-- svelte-ignore a11y-autofocus -->
      <input
        class="search-input"
        bind:value={q}
        placeholder="Search commands..."
        autofocus
        on:keydown={onKey}
      />
      <kbd class="esc-key">Esc</kbd>
    </div>

    <ul class="cmd-list" role="listbox">
      {#each filtered as cmd, i}
        <!-- svelte-ignore a11y-click-events-have-key-events -->
        <li
          class="cmd-item"
          class:cmd-active={i === selected}
          role="option"
          aria-selected={i === selected}
          on:click={() => activate(cmd)}
          on:mouseenter={() => selected = i}
        >
          <span class="cmd-label">{cmd.label}</span>
          {#if cmd.hotkey}
            <kbd class="cmd-hotkey">{cmd.hotkey}</kbd>
          {/if}
        </li>
      {/each}
      {#if filtered.length === 0}
        <li class="cmd-empty">No commands match "{q}"</li>
      {/if}
    </ul>
  </div>
</div>

<style>
  .backdrop {
    position: fixed; inset: 0;
    background: rgba(0,0,0,0.25);
    backdrop-filter: blur(2px);
    display: flex; align-items: flex-start; justify-content: center;
    padding-top: 80px;
    z-index: 1000;
  }
  .palette-panel {
    background: #ffffff;
    border: 1px solid var(--border-strong);
    border-radius: 6px;
    width: 540px;
    max-height: 420px;
    display: flex; flex-direction: column;
    overflow: hidden;
    box-shadow: 0 8px 32px rgba(0,0,0,0.16), 0 2px 8px rgba(0,0,0,0.08);
  }
  .search-wrap {
    display: flex; align-items: center; gap: 10px;
    padding: 10px 14px;
    border-bottom: 1px solid var(--border);
    background: var(--surface-2);
  }
  .search-icon { flex-shrink: 0; }
  .search-input {
    flex: 1; border: none; background: transparent;
    color: var(--text); font-size: 14px; padding: 0;
    font-family: inherit;
    outline: none;
  }
  .esc-key {
    font-size: 10px; color: var(--text-muted);
    background: var(--surface-2);
    border: 1px solid var(--border-strong);
    border-radius: 3px;
    padding: 2px 6px;
    flex-shrink: 0;
    font-family: inherit;
  }
  .cmd-list {
    list-style: none; margin: 0; padding: 4px;
    overflow-y: auto; flex: 1;
  }
  .cmd-item {
    display: flex; align-items: center; justify-content: space-between;
    padding: 8px 12px;
    border-radius: 4px;
    cursor: pointer;
    color: var(--text-2);
    transition: background 0.06s, color 0.06s;
    font-size: 13px;
  }
  .cmd-item:hover, .cmd-active {
    background: var(--row-hover);
    color: var(--text);
  }
  .cmd-active { background: var(--row-active) !important; }
  .cmd-label { font-size: 13px; }
  .cmd-hotkey {
    font-size: 11px; color: var(--text-muted);
    background: var(--surface-2);
    border: 1px solid var(--border-strong);
    border-radius: 3px;
    padding: 1px 6px;
    font-family: inherit;
  }
  .cmd-empty {
    padding: 20px; text-align: center;
    color: var(--text-muted); font-size: 13px;
  }
</style>
