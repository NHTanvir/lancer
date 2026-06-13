<script>
  import { onMount } from "svelte";

  let subtab = "rules"; // rules | macros
  const TOOLS = ["Proxy", "Repeater", "Intruder", "Scanner", "Sequencer", "Extension"];
  const ACTION_TYPES = ["SetHeader", "SetCookie", "UseCookieJar", "RunMacro", "PromptUser"];

  let rules = [];
  let macros = [];
  let editing = null; // the rule object being edited (null = none)
  let macroResult = null;

  // ── Rules ──────────────────────────────────────────────────────────────
  async function loadRules() {
    try { const r = await fetch("/api/v1/sessions/rules"); if (r.ok) rules = await r.json(); } catch {}
  }
  function newRule() {
    editing = { id: "00000000-0000-0000-0000-000000000000", name: "New rule", enabled: true, tools: ["Proxy"], url_pattern: "", actions: [] };
  }
  function editRule(r) { editing = JSON.parse(JSON.stringify(r)); }
  function toggleTool(t) {
    if (!editing) return;
    editing.tools = editing.tools.includes(t) ? editing.tools.filter(x => x !== t) : [...editing.tools, t];
  }
  function addAction(type) {
    if (!editing) return;
    let a;
    if (type === "SetHeader") a = { SetHeader: { name: "", value: "" } };
    else if (type === "SetCookie") a = { SetCookie: { name: "", value: "", domain: "", path: "/" } };
    else if (type === "UseCookieJar") a = "UseCookieJar";
    else if (type === "RunMacro") a = { RunMacro: { macro_id: macros[0]?.id || "00000000-0000-0000-0000-000000000000" } };
    else a = { PromptUser: { message: "Confirm session" } };
    editing.actions = [...editing.actions, a];
  }
  function removeAction(i) { editing.actions = editing.actions.filter((_, j) => j !== i); }
  function actionType(a) { return typeof a === "string" ? a : Object.keys(a)[0]; }

  async function saveRule() {
    if (!editing) return;
    const isNew = editing.id === "00000000-0000-0000-0000-000000000000";
    const payload = { ...editing, url_pattern: editing.url_pattern || null };
    try {
      if (isNew) await fetch("/api/v1/sessions/rules", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
      else await fetch(`/api/v1/sessions/rules/${editing.id}`, { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
      editing = null;
      await loadRules();
    } catch {}
  }
  async function deleteRule(r) {
    if (!confirm(`Delete rule "${r.name}"?`)) return;
    try { await fetch(`/api/v1/sessions/rules/${r.id}`, { method: "DELETE" }); await loadRules(); } catch {}
  }

  // ── Macros ─────────────────────────────────────────────────────────────
  async function loadMacros() {
    try { const r = await fetch("/api/v1/macros"); if (r.ok) macros = await r.json(); } catch {}
  }
  async function newMacro() {
    const name = prompt("Macro name:");
    if (!name) return;
    try {
      await fetch("/api/v1/macros", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ id: "00000000-0000-0000-0000-000000000000", name, steps: [] }) });
      await loadMacros();
    } catch {}
  }
  async function runMacro(m) {
    macroResult = null;
    try {
      const r = await fetch(`/api/v1/macros/${m.id}/run`, { method: "POST" });
      macroResult = { name: m.name, ...(await r.json()) };
    } catch (e) { macroResult = { name: m.name, ok: false, error: String(e) }; }
  }
  async function deleteMacro(m) {
    if (!confirm(`Delete macro "${m.name}"?`)) return;
    try { await fetch(`/api/v1/macros/${m.id}`, { method: "DELETE" }); await loadMacros(); } catch {}
  }

  onMount(() => { loadRules(); loadMacros(); });
</script>

<div class="view">
  <div class="subtabs">
    <button class="subtab" class:active={subtab === "rules"} on:click={() => (subtab = "rules")}>Session Handling Rules</button>
    <button class="subtab" class:active={subtab === "macros"} on:click={() => (subtab = "macros")}>Macros</button>
    <span class="dim note">Rules apply ordered actions (set header/cookie, use jar, run macro) to in-scope tool traffic.</span>
  </div>

  {#if subtab === "rules"}
    <div class="split">
      <div class="list-pane">
        <div class="pane-head">
          <span>Rules ({rules.length})</span>
          <button class="btn-primary sm" on:click={newRule}>+ New rule</button>
        </div>
        <table class="data-table">
          <thead><tr><th>Name</th><th>On</th><th>Tools</th><th>URL</th><th>Actions</th><th></th></tr></thead>
          <tbody>
            {#each rules as r}
              <tr class:sel={editing && editing.id === r.id} on:click={() => editRule(r)}>
                <td><strong>{r.name}</strong></td>
                <td>{r.enabled ? "✓" : ""}</td>
                <td class="dim">{(r.tools || []).join(", ")}</td>
                <td class="dim">{r.url_pattern || "(any)"}</td>
                <td class="dim">{(r.actions || []).length}</td>
                <td><button class="sm-btn danger" on:click|stopPropagation={() => deleteRule(r)}>✕</button></td>
              </tr>
            {/each}
            {#if rules.length === 0}<tr><td colspan="6" class="empty">No session-handling rules. Create one to set auth headers/cookies or run a login macro before requests.</td></tr>{/if}
          </tbody>
        </table>
      </div>

      {#if editing}
        <div class="edit-pane">
          <div class="pane-title">Edit rule</div>
          <label class="fld">Name<input bind:value={editing.name} /></label>
          <label class="check"><input type="checkbox" bind:checked={editing.enabled} /> Enabled</label>
          <div class="fld">
            <span class="lbl">Apply to tools</span>
            <div class="tool-chips">
              {#each TOOLS as t}
                <button class="chip" class:on={editing.tools.includes(t)} on:click={() => toggleTool(t)}>{t}</button>
              {/each}
            </div>
          </div>
          <label class="fld">URL pattern (regex, blank = any)<input bind:value={editing.url_pattern} placeholder="^https://api\.example\.com/" /></label>

          <div class="fld">
            <span class="lbl">Actions (ordered)</span>
            {#each editing.actions as a, i}
              <div class="action-row">
                <span class="action-type">{actionType(a)}</span>
                {#if a.SetHeader}
                  <input placeholder="Header name" bind:value={a.SetHeader.name} />
                  <input placeholder="Value" bind:value={a.SetHeader.value} />
                {:else if a.SetCookie}
                  <input placeholder="Name" bind:value={a.SetCookie.name} />
                  <input placeholder="Value" bind:value={a.SetCookie.value} />
                  <input placeholder="Domain" bind:value={a.SetCookie.domain} />
                {:else if a.RunMacro}
                  <select bind:value={a.RunMacro.macro_id}>
                    {#each macros as m}<option value={m.id}>{m.name}</option>{/each}
                  </select>
                {:else if a.PromptUser}
                  <input placeholder="Message" bind:value={a.PromptUser.message} />
                {:else}
                  <span class="dim">Inject shared cookie jar</span>
                {/if}
                <button class="sm-btn danger" on:click={() => removeAction(i)}>✕</button>
              </div>
            {/each}
            {#if editing.actions.length === 0}<div class="dim empty-actions">No actions yet.</div>{/if}
            <div class="add-actions">
              {#each ACTION_TYPES as t}<button class="sm-btn" on:click={() => addAction(t)}>+ {t}</button>{/each}
            </div>
          </div>

          <div class="edit-actions">
            <button class="btn-primary" on:click={saveRule}>Save rule</button>
            <button class="btn-sec" on:click={() => (editing = null)}>Cancel</button>
          </div>
        </div>
      {:else}
        <div class="edit-pane empty-pane dim">Select a rule to edit, or create a new one.</div>
      {/if}
    </div>
  {:else}
    <div class="macros-pane">
      <div class="pane-head">
        <span>Macros ({macros.length})</span>
        <button class="btn-primary sm" on:click={newMacro}>+ New macro</button>
      </div>
      <table class="data-table">
        <thead><tr><th>Name</th><th>Steps</th><th></th></tr></thead>
        <tbody>
          {#each macros as m}
            <tr>
              <td><strong>{m.name}</strong></td>
              <td class="dim">{(m.steps || []).length}</td>
              <td style="white-space:nowrap">
                <button class="sm-btn" on:click={() => runMacro(m)} disabled={!(m.steps || []).length} title="Replay macro">▶ Run</button>
                <button class="sm-btn danger" on:click={() => deleteMacro(m)}>✕</button>
              </td>
            </tr>
          {/each}
          {#if macros.length === 0}<tr><td colspan="3" class="empty">No macros. Macros replay a recorded login/token-refresh sequence and feed extracted values into later requests. Record steps from Repeater (coming) or build via the API.</td></tr>{/if}
        </tbody>
      </table>
      {#if macroResult}
        <div class="macro-result">
          <strong>Run "{macroResult.name}":</strong>
          {#if macroResult.ok}
            <span class="dim">{(macroResult.steps || []).length} steps —</span>
            {#each macroResult.steps || [] as s, i}<span class="step-chip">#{i + 1}: {s.status} ({s.length}b)</span>{/each}
          {:else}
            <span class="err">{macroResult.error || "failed"}</span>
          {/if}
        </div>
      {/if}
    </div>
  {/if}
</div>

<style>
  .view { display: flex; flex-direction: column; height: 100%; overflow: hidden; }
  .subtabs { display: flex; align-items: center; gap: 4px; padding: 6px 12px; background: #f5f5f5; border-bottom: 1px solid #dedede; }
  .subtab { padding: 4px 12px; font-size: 13px; background: transparent; border: none; border-bottom: 2px solid transparent; cursor: pointer; color: #555; }
  .subtab.active { color: #e03a00; border-bottom-color: #e03a00; font-weight: 600; }
  .note { margin-left: auto; font-size: 11px; }
  .split { flex: 1; display: flex; overflow: hidden; min-height: 0; }
  .list-pane { width: 50%; border-right: 1px solid #dedede; display: flex; flex-direction: column; overflow: auto; }
  .edit-pane { flex: 1; padding: 14px 16px; overflow: auto; }
  .empty-pane { display: flex; align-items: center; justify-content: center; }
  .macros-pane { flex: 1; display: flex; flex-direction: column; overflow: auto; }
  .pane-head { display: flex; align-items: center; justify-content: space-between; padding: 8px 12px; background: #fafafa; border-bottom: 1px solid #ededed; font-size: 12px; font-weight: 600; color: #555; }
  .pane-title { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; color: #767676; margin-bottom: 12px; }
  .data-table { width: 100%; border-collapse: collapse; font-size: 12px; }
  .data-table th, .data-table td { text-align: left; padding: 5px 10px; border-bottom: 1px solid #eee; }
  .data-table thead th { background: #f5f5f5; color: #767676; font-size: 11px; font-weight: 600; }
  .data-table tbody tr { cursor: pointer; }
  .data-table tbody tr:hover { background: #f0f7ff; }
  .data-table tbody tr.sel { background: #daeeff; }
  .empty { text-align: center; padding: 24px; color: #888; }
  .fld { display: block; margin-bottom: 12px; font-size: 11px; color: #767676; }
  .fld input, .fld select { width: 100%; margin-top: 4px; padding: 5px 8px; border: 1px solid #c8c8c8; border-radius: 3px; font-size: 13px; }
  .lbl { display: block; }
  .check { display: flex; align-items: center; gap: 5px; font-size: 12px; margin-bottom: 12px; }
  .tool-chips, .add-actions { display: flex; flex-wrap: wrap; gap: 5px; margin-top: 5px; }
  .chip { font-size: 11px; padding: 3px 10px; border: 1px solid #d0d0d0; border-radius: 12px; background: #fff; color: #555; cursor: pointer; }
  .chip.on { background: #e03a00; color: #fff; border-color: #e03a00; }
  .action-row { display: flex; align-items: center; gap: 5px; margin-bottom: 5px; }
  .action-row input, .action-row select { flex: 1; padding: 3px 6px; border: 1px solid #c8c8c8; border-radius: 3px; font-size: 12px; }
  .action-type { font-size: 11px; font-weight: 600; color: #2e6fae; min-width: 78px; }
  .empty-actions { padding: 6px 0; }
  .edit-actions { margin-top: 14px; display: flex; gap: 8px; }
  .macro-result { padding: 10px 14px; border-top: 1px solid #ededed; background: #fafafa; font-size: 12px; display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
  .step-chip { font-size: 11px; padding: 1px 7px; background: #e9f7ec; color: #2e7d3a; border-radius: 3px; }
  .err { color: #d42c2c; }
  .btn-primary { background: #e03a00; color: #fff; border: none; border-radius: 3px; padding: 5px 14px; font-size: 13px; cursor: pointer; }
  .btn-primary:hover { background: #c73400; }
  .btn-primary.sm { padding: 3px 10px; font-size: 12px; }
  .btn-sec { background: #f0f0f0; color: #333; border: 1px solid #c8c8c8; border-radius: 3px; padding: 5px 12px; font-size: 13px; cursor: pointer; }
  .sm-btn { font-size: 12px; padding: 2px 8px; background: #f0f0f0; color: #333; border: 1px solid #c8c8c8; border-radius: 3px; cursor: pointer; }
  .sm-btn:hover { background: #e4e4e4; }
  .sm-btn.danger { color: #d42c2c; border-color: #f0c4c4; }
  .sm-btn.danger:hover { background: #fde8e8; }
  .dim { color: #888; }
</style>
