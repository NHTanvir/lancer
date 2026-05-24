<script>
  import { onMount, onDestroy } from "svelte";

  let plugins = [];
  let pollTimer;

  async function load() {
    try {
      const r = await fetch("/api/v1/plugins");
      if (r.ok) plugins = await r.json();
    } catch {}
  }

  onMount(() => {
    load();
    pollTimer = setInterval(load, 8000);
  });
  onDestroy(() => { if (pollTimer) clearInterval(pollTimer); });

  function kindBadge(k) {
    const m = { Rhai: "badge-rhai", Wasm: "badge-wasm", Lua: "badge-lua", Python: "badge-py", Native: "badge-native", Jvm: "badge-jvm" };
    return m[k] || "badge-default";
  }
</script>

<div class="view">
  <div class="toolbar">
    <span style="font-size:13px;color:#444"><strong>Installed plugins</strong> — runtimes: Rhai, WASM, Lua, Python, Native (cdylib), JVM (Burp Montoya)</span>
    <button class="toolbar-btn" on:click={load} style="margin-left:auto">Reload</button>
  </div>

  <div class="panel">
    {#if plugins.length === 0}
      <div class="info-card">
        <div class="info-title">No plugins loaded</div>
        <div class="info-desc">
          Lancer scans <code>%LOCALAPPDATA%\Lancer\plugins\</code> on startup, or the directory set in
          <code>LANCER_PLUGINS_DIR</code>. Each plugin lives in its own folder containing a <code>plugin.toml</code> manifest
          and the runtime files (Rhai script / WASM blob / Lua source / Python module / native .dll / .jar).
        </div>
        <div class="info-desc dim" style="margin-top:8px">
          Backend hosts present: Rhai (built-in), Wasm (wasmtime), Lua (mlua), Python (pyo3), Native (libloading), JVM (jni).
        </div>
      </div>
    {:else}
      <table class="data-table">
        <thead>
          <tr>
            <th>On</th>
            <th>Name</th>
            <th>ID</th>
            <th>Kind</th>
            <th>Version</th>
            <th>Author</th>
            <th>Path</th>
          </tr>
        </thead>
        <tbody>
          {#each plugins as p}
            <tr>
              <td><input type="checkbox" checked={p.enabled} disabled title="Toggle support coming soon" /></td>
              <td><strong>{p.manifest?.name || "?"}</strong></td>
              <td class="dim"><code>{p.manifest?.id || ""}</code></td>
              <td><span class={"badge " + kindBadge(p.manifest?.kind)}>{p.manifest?.kind || "?"}</span></td>
              <td class="dim">{p.manifest?.version || ""}</td>
              <td class="dim">{p.manifest?.author || ""}</td>
              <td class="dim mono small">{p.path}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </div>
</div>

<style>
  .toolbar { display: flex; align-items: center; gap: 6px; padding: 6px 12px; background: #f5f5f5; border-bottom: 1px solid #dedede; flex-shrink: 0; }
  .toolbar-btn { padding: 4px 10px; font-size: 13px; background: #f0f0f0; color: #333; border: 1px solid #c8c8c8; border-radius: 3px; cursor: pointer; }
  .toolbar-btn:hover { background: #e4e4e4; }

  .info-card { background: #f5f5f5; border: 1px solid #dedede; border-radius: 4px; padding: 14px 16px; max-width: 700px; }
  .info-title { font-size: 13px; font-weight: 600; color: #212121; margin-bottom: 6px; }
  .info-desc { font-size: 12px; color: #444; line-height: 1.6; }
  code { font-family: ui-monospace, Consolas, monospace; background: #ffffff; padding: 0 5px; border: 1px solid #dedede; border-radius: 2px; font-size: 11px; }
  .data-table { width: 100%; border-collapse: collapse; font-size: 12px; }
  .data-table th, .data-table td { padding: 6px 12px; border-bottom: 1px solid #e8e8e8; text-align: left; }
  .data-table thead th { background: #f5f5f5; color: #767676; font-size: 11px; font-weight: 600; }
  .mono { font-family: ui-monospace, Consolas, monospace; }
  .small { font-size: 11px; }
  .badge { font-size: 10px; font-weight: 600; text-transform: uppercase; padding: 1px 6px; border-radius: 2px; }
  .badge-rhai   { background: #fce8e2; color: #e03a00; }
  .badge-wasm   { background: #e6f0fb; color: #1a75c4; }
  .badge-lua    { background: #eaf5ea; color: #1b8c1b; }
  .badge-py     { background: #fef0e6; color: #e86c00; }
  .badge-native { background: #fef8e6; color: #c98a00; }
  .badge-jvm    { background: #f3eaf5; color: #7b3fa0; }
  .badge-default{ background: #eee; color: #444; }
</style>
