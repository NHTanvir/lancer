<script>
  import { onMount, onDestroy } from "svelte";

  let cookies = [];
  let filter = "";
  let pollTimer;
  let newCookie = { domain: "", path: "/", name: "", value: "", secure: false, http_only: false };

  $: filtered = cookies.filter(c =>
    !filter ||
    (c.domain || "").toLowerCase().includes(filter.toLowerCase()) ||
    (c.name || "").toLowerCase().includes(filter.toLowerCase()) ||
    (c.value || "").toLowerCase().includes(filter.toLowerCase())
  );

  async function load() {
    try {
      const r = await fetch("/api/v1/cookies");
      if (r.ok) cookies = await r.json();
    } catch {}
  }

  async function addCookie() {
    if (!newCookie.domain || !newCookie.name) return;
    try {
      await fetch("/api/v1/cookies", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          ...newCookie,
          expires: null,
          same_site: null,
        }),
      });
      newCookie = { domain: "", path: "/", name: "", value: "", secure: false, http_only: false };
      await load();
    } catch {}
  }

  async function clearAll() {
    if (!confirm("Empty the entire cookie jar?")) return;
    try {
      await fetch("/api/v1/cookies", { method: "DELETE" });
      await load();
    } catch {}
  }

  function copyValue(c) {
    navigator.clipboard.writeText(c.value || "").catch(() => {});
  }

  async function delCookie(c) {
    const key = encodeURIComponent(`${c.domain}|${c.path}|${c.name}`);
    try {
      await fetch(`/api/v1/cookies/${key}`, { method: "DELETE" });
      await load();
    } catch {}
  }

  onMount(() => {
    load();
    pollTimer = setInterval(load, 4000);
  });
  onDestroy(() => { if (pollTimer) clearInterval(pollTimer); });
</script>

<div class="view">
  <div class="toolbar">
    <input style="flex:1;max-width:380px" placeholder="Filter domain / name / value..." bind:value={filter} />
    <button class="toolbar-btn" on:click={load}>Reload</button>
    <button class="toolbar-btn danger" on:click={clearAll}>Empty jar</button>
    <span class="dim" style="font-size:12px;margin-left:auto">{filtered.length} / {cookies.length} cookies</span>
  </div>

  <div class="cookie-body">
    <div class="table-wrap">
      <table class="data-table">
        <thead>
          <tr>
            <th>Domain</th>
            <th>Path</th>
            <th>Name</th>
            <th>Value</th>
            <th>Expires</th>
            <th>Secure</th>
            <th>HttpOnly</th>
            <th>SameSite</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each filtered as c, i}
            <tr class:row-even={i % 2 === 0}>
              <td><code>{c.domain}</code></td>
              <td>{c.path}</td>
              <td><strong>{c.name}</strong></td>
              <td class="value-cell" title={c.value}>{(c.value || "").length > 80 ? (c.value || "").slice(0, 80) + "..." : c.value}</td>
              <td class="dim">{c.expires || "session"}</td>
              <td class="dim">{c.secure ? "yes" : ""}</td>
              <td class="dim">{c.http_only ? "yes" : ""}</td>
              <td class="dim">{c.same_site || ""}</td>
              <td style="white-space:nowrap">
                <button class="sm-btn" on:click={() => copyValue(c)} title="Copy value">⎘</button>
                <button class="sm-btn danger" on:click={() => delCookie(c)} title="Delete cookie">✕</button>
              </td>
            </tr>
          {/each}
          {#if filtered.length === 0}
            <tr><td colspan="9" class="empty-cell">
              {cookies.length === 0
                ? "Cookie jar is empty. Cookies set via Set-Cookie on captured responses will populate this jar automatically."
                : "No cookies match the current filter."}
            </td></tr>
          {/if}
        </tbody>
      </table>
    </div>

    <div class="add-pane">
      <div class="pane-title">Add cookie</div>
      <div class="cookie-form">
        <label>Domain
          <input bind:value={newCookie.domain} placeholder="example.com" />
        </label>
        <label>Path
          <input bind:value={newCookie.path} />
        </label>
        <label>Name
          <input bind:value={newCookie.name} placeholder="session" />
        </label>
        <label class="grow">Value
          <input bind:value={newCookie.value} placeholder="abc123" />
        </label>
        <label class="check-inline"><input type="checkbox" bind:checked={newCookie.secure} /> Secure</label>
        <label class="check-inline"><input type="checkbox" bind:checked={newCookie.http_only} /> HttpOnly</label>
        <button class="btn-primary" on:click={addCookie}>Add cookie</button>
      </div>
    </div>
  </div>
</div>

<style>
  .toolbar { display: flex; align-items: center; gap: 6px; padding: 6px 12px; background: var(--surface-2); border-bottom: 1px solid var(--border); flex-shrink: 0; }
  .toolbar-btn { padding: 4px 10px; font-size: 13px; background: var(--surface-2); color: var(--text); border: 1px solid var(--border-strong); border-radius: 3px; cursor: pointer; }
  .toolbar-btn:hover { background: var(--surface-3); }
  .toolbar-btn.danger { color: #d42c2c; border-color: #f5b8b8; }
  .toolbar-btn.danger:hover { background: #fde8e8; }

  .cookie-body { flex: 1; display: flex; flex-direction: column; overflow: hidden; min-height: 0; }
  .table-wrap { flex: 1; overflow-y: auto; min-height: 0; }
  .data-table { width: 100%; border-collapse: collapse; font-size: 12px; }
  .data-table th, .data-table td { text-align: left; padding: 5px 10px; border-bottom: 1px solid var(--border); white-space: nowrap; }
  .data-table thead th { background: var(--surface-2); color: var(--text-muted); font-size: 11px; font-weight: 600; position: sticky; top: 0; z-index: 1; }
  .row-even { background: var(--surface-1); }
  .value-cell { max-width: 360px; overflow: hidden; text-overflow: ellipsis; font-family: ui-monospace, Consolas, monospace; }
  .empty-cell { text-align: center; padding: 30px; color: var(--text-muted); }
  code { font-family: ui-monospace, Consolas, monospace; }
  .sm-btn { font-size: 12px; padding: 2px 8px; background: var(--surface-2); color: var(--text); border: 1px solid var(--border-strong); border-radius: 3px; cursor: pointer; }
  .sm-btn:hover { background: var(--surface-3); }
  .sm-btn.danger { color: #d42c2c; border-color: #f0c4c4; margin-left: 3px; }
  .sm-btn.danger:hover { background: #fde8e8; }

  .add-pane { padding: 12px 14px; background: var(--surface-1); border-top: 2px solid var(--border); flex-shrink: 0; }
  .pane-title { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-muted); margin-bottom: 10px; }
  .cookie-form { display: flex; flex-wrap: wrap; align-items: flex-end; gap: 10px; }
  .cookie-form label { display: flex; flex-direction: column; gap: 4px; font-size: 11px; color: var(--text-muted); font-weight: 500; min-width: 120px; }
  .cookie-form label.grow { flex: 1; min-width: 200px; }
  .cookie-form .check-inline { flex-direction: row; align-items: center; }
  .cookie-form .check-inline input { margin-right: 4px; }
  .btn-primary { background: var(--accent); color: #fff; border: none; border-radius: 3px; padding: 5px 14px; font-size: 13px; font-weight: 500; cursor: pointer; }
  .btn-primary:hover { background: var(--accent-hover); }
</style>
