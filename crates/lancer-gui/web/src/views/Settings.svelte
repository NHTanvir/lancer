<script>
  let theme = "dark";
  let keybindings = "default";
  let preset = "pentest";
  let snapshotMin = 10;
</script>

<div class="grid">
  <div class="card">
    <h3>Appearance</h3>
    <label>Theme <select bind:value={theme}>
      <option>dark</option>
      <option>light</option>
    </select></label>
  </div>
  <div class="card">
    <h3>Keybindings</h3>
    <select bind:value={keybindings}>
      <option>default</option>
      <option>vim</option>
      <option>emacs</option>
      <option>vscode</option>
    </select>
  </div>
  <div class="card">
    <h3>Workspace preset</h3>
    <select bind:value={preset}>
      <option>bug-bounty</option>
      <option>pentest</option>
      <option>red-team</option>
      <option>api-audit</option>
      <option>mobile-audit</option>
    </select>
  </div>
  <div class="card">
    <h3>Auto-snapshot</h3>
    <label>Every <input type="number" bind:value={snapshotMin} /> minutes</label>
  </div>
</div>

<style>
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: 12px;
  }
  .card {
    background: #1a1d2b;
    border: 1px solid #292d40;
    border-radius: 8px;
    padding: 12px 14px;
  }
  h3 {
    margin: 0 0 8px;
    font-size: 12px;
    text-transform: uppercase;
    color: #9aa0bd;
  }
  label {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 13px;
  }
</style>
