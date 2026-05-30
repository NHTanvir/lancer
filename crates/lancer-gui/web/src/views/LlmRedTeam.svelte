<script>
  import { onMount } from "svelte";

  let targetEndpoint = "";
  let targetKey = "";
  let targetModel = "gpt-4o-mini";
  let attackerEndpoint = "";
  let attackerKey = "";
  let attackerModel = "gpt-4o-mini";
  let strategy = "single_turn";
  let goal = "";
  let maxTurns = 10;
  let threshold = 0.8;
  let sessions = [];
  let selected = null;

  const STRATEGIES = [
    { id: "single_turn", label: "Single turn" },
    { id: "tree_of_attacks", label: "Tree of attacks" },
    { id: "crescendo", label: "Crescendo" },
    { id: "pair", label: "PAIR" },
    { id: "many_shot", label: "Many-shot" },
    { id: "flrt", label: "FLRT" },
    { id: "gcg", label: "GCG (suffix search)" },
  ];

  async function load() {
    try {
      const r = await fetch("/api/v1/llm-redteam/sessions");
      if (r.ok) sessions = await r.json();
    } catch {}
  }

  async function start() {
    if (!targetEndpoint || !goal) return;
    const req = {
      target: { endpoint: targetEndpoint, api_key: targetKey, model: targetModel },
      attacker: { endpoint: attackerEndpoint || targetEndpoint, api_key: attackerKey || targetKey, model: attackerModel },
      strategy, goal,
      max_turns: maxTurns,
      success_threshold: threshold,
    };
    await fetch("/api/v1/llm-redteam/start", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify(req),
    });
    for (let i = 0; i < 60; i++) {
      await new Promise(r => setTimeout(r, 2000));
      await load();
    }
  }

  async function clearAll() {
    await fetch("/api/v1/llm-redteam/sessions", { method: "DELETE" });
    sessions = []; selected = null;
  }

  onMount(load);
</script>

<div class="redteam">
  <div class="rt-config">
    <div class="config-section">
      <h4>Target LLM (system under test)</h4>
      <input type="url" bind:value={targetEndpoint} placeholder="https://api.openai.com/v1/chat/completions" />
      <input type="password" bind:value={targetKey} placeholder="API key" />
      <input bind:value={targetModel} placeholder="model" />
    </div>
    <div class="config-section">
      <h4>Attacker LLM (your model)</h4>
      <input type="url" bind:value={attackerEndpoint} placeholder="optional, defaults to target" />
      <input type="password" bind:value={attackerKey} placeholder="optional" />
      <input bind:value={attackerModel} placeholder="model" />
    </div>
    <div class="config-section">
      <h4>Attack</h4>
      <select bind:value={strategy}>
        {#each STRATEGIES as s}<option value={s.id}>{s.label}</option>{/each}
      </select>
      <textarea bind:value={goal} rows="3" placeholder="Goal (e.g. 'extract system prompt')"></textarea>
      <div class="num-row">
        <label>Max turns <input type="number" bind:value={maxTurns} min="1" max="50" /></label>
        <label>Success threshold <input type="number" bind:value={threshold} min="0" max="1" step="0.05" /></label>
      </div>
      <button on:click={start} disabled={!targetEndpoint || !goal} class="run">Start</button>
      <button on:click={clearAll} class="btn-danger">Clear sessions</button>
    </div>
  </div>

  <div class="rt-results">
    <div class="sessions-list">
      <h4>Sessions ({sessions.length})</h4>
      {#each sessions as s (s.id)}
        <div class="session-row" class:selected={selected?.id === s.id} on:click={() => selected = s}>
          <span class="strat">{s.strategy}</span>
          <span class="score" class:success={s.success}>{(s.best_score * 100).toFixed(0)}%</span>
          <span class="goal">{s.goal.slice(0, 50)}{s.goal.length > 50 ? "…" : ""}</span>
          <span class="dim">{s.turns.length} turns</span>
        </div>
      {/each}
    </div>
    {#if selected}
      <div class="conversation">
        <h4>Conversation</h4>
        {#each selected.turns as t}
          <div class="turn role-{t.role}">
            <span class="role-badge">{t.role}</span>
            {#if t.score !== null}<span class="score-badge">{(t.score * 100).toFixed(0)}%</span>{/if}
            <pre>{t.content}</pre>
          </div>
        {/each}
      </div>
    {/if}
  </div>
</div>

<style>
  .redteam{display:flex;height:100%;font-size:13px}
  .rt-config{width:340px;padding:10px;border-right:1px solid var(--border);overflow-y:auto;display:flex;flex-direction:column;gap:14px;background:var(--bg-hover)}
  .config-section h4{margin:0 0 6px;font-size:12px;color:var(--text-muted)}
  .config-section input,.config-section textarea,.config-section select{width:100%;padding:4px 8px;margin-bottom:5px;box-sizing:border-box}
  .num-row{display:flex;gap:8px}
  .num-row label{flex:1;font-size:11px;display:flex;flex-direction:column;gap:2px}
  .num-row input{width:100%}
  .run{background:#e03a00;color:white;border:none;border-radius:4px;padding:6px 14px;cursor:pointer;font-weight:600;width:100%;margin-bottom:5px}
  .btn-danger{background:#fde8e8;color:#c0392b;border:1px solid #e74c3c;padding:4px 10px;border-radius:4px;cursor:pointer;width:100%}
  .rt-results{flex:1;display:flex;overflow:hidden}
  .sessions-list{width:300px;border-right:1px solid var(--border);padding:8px;overflow-y:auto}
  .sessions-list h4{margin:0 0 6px;font-size:12px;color:var(--text-muted)}
  .session-row{padding:6px;border:1px solid var(--border);border-radius:4px;margin-bottom:4px;cursor:pointer;display:flex;flex-direction:column;gap:2px;font-size:11px}
  .session-row.selected{background:#e8f0fe;border-color:#1976d2}
  .strat{font-weight:600;color:#e03a00}
  .score{font-weight:700;color:#c0392b}
  .score.success{color:#27ae60}
  .dim{color:var(--text-muted);font-size:10px}
  .conversation{flex:1;padding:10px;overflow-y:auto}
  .conversation h4{margin:0 0 8px;font-size:12px;color:var(--text-muted)}
  .turn{margin-bottom:10px;padding:6px;border-radius:4px;border-left:3px solid var(--border)}
  .role-attacker{background:#fff0e6;border-left-color:#e03a00}
  .role-target{background:#e6f4ff;border-left-color:#1976d2}
  .role-badge{display:inline-block;background:rgba(0,0,0,0.05);padding:1px 6px;border-radius:8px;font-size:10px;font-weight:700;margin-right:6px}
  .score-badge{display:inline-block;background:#fff;padding:1px 6px;border-radius:8px;font-size:10px;font-weight:700;color:#c0392b}
  .turn pre{margin:6px 0 0;white-space:pre-wrap;word-break:break-word;font-size:11px;font-family:inherit}
</style>
