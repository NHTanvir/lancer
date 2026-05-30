<script>
  import { onMount } from "svelte";

  let chains = [];
  let chain = "CommonsCollections1";
  let cmd = "touch /tmp/lancer";
  let encoding = "base64";
  let payload = null;
  let history = [];

  async function loadChains() {
    try {
      const r = await fetch("/api/v1/deser/chains");
      if (r.ok) chains = await r.json();
    } catch {
      chains = [
        { name: "CommonsCollections1", platform: "java", description: "Apache Commons Collections 3.x", library: "commons-collections:3.1" },
        { name: "Spring1", platform: "java", description: "Spring AOP", library: "spring-core" },
        { name: "TypeConfuseDelegate", platform: "dot_net", description: "BinaryFormatter", library: ".NET" },
      ];
    }
  }

  async function loadHistory() {
    try {
      const r = await fetch("/api/v1/deser");
      if (r.ok) history = await r.json();
    } catch {}
  }

  async function generate() {
    try {
      const r = await fetch("/api/v1/deser/generate", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ chain, cmd, encoding }),
      });
      if (r.ok) {
        payload = await r.json();
        await loadHistory();
      } else {
        payload = { error: await r.text() };
      }
    } catch (e) {
      payload = { error: e.message };
    }
  }

  async function clearAll() {
    await fetch("/api/v1/deser", { method: "DELETE" });
    history = [];
    payload = null;
  }

  function copy() {
    if (payload?.payload) navigator.clipboard?.writeText(payload.payload);
  }

  onMount(async () => { await loadChains(); await loadHistory(); });
</script>

<div class="deser-page">
  <div class="dp-form">
    <h3>Deserialization payload generator <span class="warn">⚠ requires explicit target authorization</span></h3>
    <div class="row">
      <label>Chain</label>
      <select bind:value={chain}>
        {#each chains as c}
          <option value={c.name}>{c.name} — {c.platform} — {c.library}</option>
        {/each}
      </select>
    </div>
    <div class="row">
      <label>Command</label>
      <input bind:value={cmd} placeholder="cmd /c calc.exe" />
    </div>
    <div class="row">
      <label>Encoding</label>
      <select bind:value={encoding}>
        <option value="base64">base64</option>
        <option value="hex">hex</option>
        <option value="url_encoded">url-encoded</option>
        <option value="form_encoded">form-encoded</option>
        <option value="raw">raw</option>
      </select>
    </div>
    <button on:click={generate} class="run">Generate</button>
  </div>

  {#if payload}
    <div class="dp-result">
      {#if payload.error}
        <pre class="err">{payload.error}</pre>
      {:else}
        <div class="info">
          <strong>{payload.chain}</strong>
          <span class="badge">{payload.platform}</span>
          <span class="badge enc">{payload.encoding}</span>
        </div>
        <pre class="payload">{payload.payload}</pre>
        <button on:click={copy}>Copy</button>
      {/if}
    </div>
  {/if}

  <div class="dp-history">
    <div class="history-head">
      <h4>Generated payloads ({history.length})</h4>
      <button on:click={clearAll} class="btn-danger">Clear all</button>
    </div>
    <table>
      <thead><tr><th>Chain</th><th>Platform</th><th>Encoding</th><th>Length</th></tr></thead>
      <tbody>
        {#each history as h}
          <tr><td>{h.chain}</td><td>{h.platform}</td><td>{h.encoding}</td><td>{h.payload.length}</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
</div>

<style>
  .deser-page{display:flex;flex-direction:column;height:100%;padding:12px;gap:14px;overflow:auto;font-size:13px}
  .warn{color:#c0392b;font-size:11px;margin-left:8px;font-weight:normal}
  .dp-form{background:var(--bg-hover);border-radius:6px;padding:10px}
  .row{display:flex;align-items:center;gap:8px;margin-bottom:6px}
  .row label{width:90px;font-size:11px;font-weight:600;color:var(--text-muted)}
  .row input,.row select{flex:1;padding:4px 8px}
  .run{background:#e03a00;color:white;border:none;border-radius:4px;padding:5px 14px;cursor:pointer;font-weight:600}
  .dp-result{padding:10px;border:1px solid var(--border);border-radius:6px}
  .info{margin-bottom:6px;display:flex;gap:8px;align-items:center}
  .badge{padding:1px 6px;border-radius:8px;font-size:10px;font-weight:700;background:#fef0e6;color:#d35400}
  .badge.enc{background:#eaf4fb;color:#2980b9}
  .payload{background:#23272e;color:#dcdcdc;padding:10px;border-radius:4px;overflow:auto;font-family:monospace;font-size:11px;max-height:200px;word-break:break-all;white-space:pre-wrap}
  .err{background:#fde8e8;color:#c0392b;padding:8px;border-radius:4px}
  .dp-history{margin-top:10px}
  .history-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px}
  .btn-danger{background:#fde8e8;color:#c0392b;border:1px solid #e74c3c;padding:3px 10px;border-radius:4px;cursor:pointer}
  table{width:100%;border-collapse:collapse;font-size:12px}
  th{background:var(--bg-hover);padding:5px;border-bottom:1px solid var(--border);text-align:left;font-size:11px}
  td{padding:4px 5px;border-bottom:1px solid var(--border-light, #eee)}
</style>
