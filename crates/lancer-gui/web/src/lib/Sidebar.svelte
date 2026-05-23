<script>
  import { createEventDispatcher } from "svelte";
  export let active = "proxy";
  const dispatch = createEventDispatcher();
  const items = [
    { id: "proxy", label: "Proxy", hotkey: "1" },
    { id: "history", label: "History", hotkey: "2" },
    { id: "repeater", label: "Repeater", hotkey: "3" },
    { id: "intruder", label: "Intruder", hotkey: "4" },
    { id: "scanner", label: "Scanner", hotkey: "5" },
    { id: "issues", label: "Issues", hotkey: "6" },
    { id: "reports", label: "Reports", hotkey: "7" },
    { id: "palette", label: "Palette", hotkey: "Ctrl+K" },
    { id: "settings", label: "Settings", hotkey: "," },
  ];
</script>

<aside>
  <div class="brand">Lancer</div>
  <ul>
    {#each items as item}
      <li class:active={item.id === active}>
        <button on:click={() => dispatch("pick", item.id)}>
          <span>{item.label}</span>
          <span class="hot">{item.hotkey}</span>
        </button>
      </li>
    {/each}
  </ul>
</aside>

<style>
  aside {
    background: #161823;
    border-right: 1px solid #292d40;
    padding: 14px 12px;
    overflow-y: auto;
  }
  .brand {
    font-weight: 600;
    font-size: 18px;
    margin: 4px 6px 18px;
  }
  ul {
    list-style: none;
    padding: 0;
    margin: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  li.active button {
    background: #2a2e44;
  }
  button {
    width: 100%;
    text-align: left;
    border: none;
    background: transparent;
    padding: 8px 12px;
    border-radius: 4px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .hot {
    color: #6a7090;
    font-size: 11px;
  }
</style>
