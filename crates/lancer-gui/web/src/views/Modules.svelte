<script>
  import { onMount } from "svelte";

  let modules = [];
  let busy = {};

  async function load() {
    try {
      const r = await fetch("/api/v1/modules");
      if (r.ok) modules = await r.json();
    } catch {}
  }

  async function start(id) {
    busy[id] = true; busy = busy;
    await fetch(`/api/v1/modules/${id}/start`, { method: "POST" });
    await load();
    busy[id] = false; busy = busy;
  }
  async function stop(id) {
    busy[id] = true; busy = busy;
    await fetch(`/api/v1/modules/${id}/stop`, { method: "POST" });
    await load();
    busy[id] = false; busy = busy;
  }

  function isRunning(m) { return m.status?.status === "running"; }
  function ramMb(kb) { return Math.round(kb / 1024); }
  function categoryLabel(c) {
    return { "plugin-runtime": "Plugin runtime", "network-service": "Network service",
             background: "Background", platform: "Platform" }[c] || c;
  }

  $: byCategory = (() => {
    const map = {};
    for (const m of modules) {
      const key = m.category;
      map[key] = map[key] || [];
      map[key].push(m);
    }
    return map;
  })();

  $: totalIfAll = modules.reduce((s, m) => s + ramMb(m.estimated_idle_ram_kb), 0);
  $: runningRam = modules.filter(isRunning).reduce((s, m) => s + ramMb(m.estimated_idle_ram_kb), 0);

  onMount(load);
</script>

<div class="modules">
  <div class="header">
    <h2>Settings · Modules</h2>
    <p class="dim">Opt-in modules. Off = zero idle cost. Toggle ON only what you need.</p>
  </div>

  {#each Object.entries(byCategory) as [cat, list]}
    <div class="cat-section">
      <h3>{categoryLabel(cat)}</h3>
      <table>
        <thead><tr><th>Module</th><th>Description</th><th>Est. RAM</th><th>Status</th><th></th></tr></thead>
        <tbody>
          {#each list as m (m.id)}
            <tr class:running={isRunning(m)}>
              <td>
                <strong>{m.name}</strong>
                {#if m.requires_elevation}<span class="badge elev">root</span>{/if}
                {#if !m.platform_supported}<span class="badge nope">unsupported</span>{/if}
              </td>
              <td class="dim">{m.description}</td>
              <td>~{ramMb(m.estimated_idle_ram_kb)} MB</td>
              <td>
                <span class="dot dot-{m.status?.status || 'off'}"></span>
                {m.status?.status || "off"}
              </td>
              <td>
                {#if isRunning(m)}
                  <button on:click={() => stop(m.id)} disabled={busy[m.id]} class="btn-off">Stop</button>
                {:else}
                  <button on:click={() => start(m.id)} disabled={busy[m.id] || !m.platform_supported} class="btn-on">Start</button>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/each}

  <div class="footer">
    <div>Current resident: ~{runningRam} MB · If all on: ~{totalIfAll} MB</div>
  </div>
</div>

<style>
  .modules{padding:18px;overflow-y:auto;height:100%;font-size:13px}
  .header h2{margin:0 0 4px}
  .dim{color:var(--text-muted);font-size:11px}
  .cat-section{margin-top:16px;padding:10px;background:var(--bg-hover);border-radius:6px}
  .cat-section h3{margin:0 0 6px;font-size:12px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px}
  table{width:100%;border-collapse:collapse}
  th{padding:5px;text-align:left;font-size:11px;color:var(--text-muted);border-bottom:1px solid var(--border)}
  td{padding:6px;border-bottom:1px solid var(--border-light, var(--border));vertical-align:middle}
  tr.running td{background:#eafaf1}
  .badge{padding:1px 6px;border-radius:8px;font-size:10px;font-weight:700;margin-left:4px}
  .badge.elev{background:#fde8e8;color:#c0392b}
  .badge.nope{background:var(--border);color:var(--text-muted)}
  .dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;vertical-align:middle}
  .dot-running{background:#27ae60}
  .dot-off{background:#bbb}
  .dot-starting,.dot-stopping{background:#f39c12}
  .dot-failed{background:#c0392b}
  .btn-on{background:var(--accent);color:white;border:none;padding:4px 12px;border-radius:4px;cursor:pointer;font-weight:600}
  .btn-on:disabled{opacity:0.5;cursor:not-allowed}
  .btn-off{background:#fde8e8;color:#c0392b;border:1px solid #e74c3c;padding:4px 12px;border-radius:4px;cursor:pointer;font-weight:600}
  .footer{margin-top:18px;padding:10px;background:var(--bg);border:1px solid var(--border);border-radius:6px;font-size:11px;color:var(--text-muted)}
</style>
