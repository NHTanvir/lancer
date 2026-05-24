<script>
  import { onMount, createEventDispatcher } from "svelte";
  const dispatch = createEventDispatcher();

  let q = "";
  let commands = [];
  let filtered = [];
  let selected = 0;

  async function load() {
    try {
      const r = await fetch("/api/palette");
      commands = await r.json();
    } catch {
      commands = [
        { id: "dashboard", label: "Go to Dashboard",  hotkey: null, kind: "nav" },
        { id: "proxy",     label: "Go to Proxy",      hotkey: null, kind: "nav" },
        { id: "target",    label: "Go to Target",     hotkey: null, kind: "nav" },
        { id: "repeater",  label: "Go to Repeater",   hotkey: null, kind: "nav" },
        { id: "intruder",  label: "Go to Intruder",   hotkey: null, kind: "nav" },
        { id: "sequencer", label: "Go to Sequencer",  hotkey: null, kind: "nav" },
        { id: "decoder",   label: "Go to Decoder",    hotkey: null, kind: "nav" },
        { id: "comparer",  label: "Go to Comparer",   hotkey: null, kind: "nav" },
        { id: "logger",    label: "Go to Logger",     hotkey: null, kind: "nav" },
        { id: "reports",   label: "Go to Reports",    hotkey: null, kind: "nav" },
        { id: "settings",  label: "Go to Settings",   hotkey: null, kind: "nav" },
      ];
    }
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
        <circle cx="6" cy="6" r="4.5" stroke="#767676" stroke-width="1.5"/>
        <path d="M9.5 9.5 L13 13" stroke="#767676" stroke-width="1.5" stroke-linecap="round"/>
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
    border: 1px solid #c8c8c8;
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
    border-bottom: 1px solid #dedede;
    background: #f5f5f5;
  }
  .search-icon { flex-shrink: 0; }
  .search-input {
    flex: 1; border: none; background: transparent;
    color: #212121; font-size: 14px; padding: 0;
    font-family: inherit;
    outline: none;
  }
  .esc-key {
    font-size: 10px; color: #767676;
    background: #f0f0f0;
    border: 1px solid #c8c8c8;
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
    color: #444;
    transition: background 0.06s, color 0.06s;
    font-size: 13px;
  }
  .cmd-item:hover, .cmd-active {
    background: #f0f7ff;
    color: #212121;
  }
  .cmd-active { background: #daeeff !important; }
  .cmd-label { font-size: 13px; }
  .cmd-hotkey {
    font-size: 11px; color: #767676;
    background: #f0f0f0;
    border: 1px solid #c8c8c8;
    border-radius: 3px;
    padding: 1px 6px;
    font-family: inherit;
  }
  .cmd-empty {
    padding: 20px; text-align: center;
    color: #767676; font-size: 13px;
  }
</style>
