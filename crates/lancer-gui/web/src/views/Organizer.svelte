<script>
  import { onMount, onDestroy } from "svelte";

  let entries = [];
  let filter = "";
  let selected = null;
  let pollTimer;

  $: filtered = entries.filter(e =>
    !filter ||
    (e.title || "").toLowerCase().includes(filter.toLowerCase()) ||
    (e.tags || []).some(t => t.toLowerCase().includes(filter.toLowerCase())) ||
    (e.notes || "").toLowerCase().includes(filter.toLowerCase())
  );

  async function load() {
    try {
      const r = await fetch("/api/v1/organizer");
      if (r.ok) entries = await r.json();
    } catch {}
  }

  function bytesToText(b) {
    if (b == null) return "";
    if (typeof b === "string") return b;
    if (Array.isArray(b)) {
      try { return new TextDecoder("utf-8", { fatal: false }).decode(new Uint8Array(b)); } catch { return ""; }
    }
    return String(b);
  }

  function formatRequest(req) {
    if (!req) return "";
    const m = req.meta || {};
    const ver = req.version === "Http2" ? "HTTP/2" : "HTTP/1.1";
    const hdrs = (req.headers || []).map(h => `${h.name}: ${h.value}`).join("\n");
    return `${req.method || "GET"} ${req.path || "/"} ${ver}\n${hdrs}\n\n${bytesToText(req.body)}`;
  }
  function formatResponse(resp) {
    if (!resp) return "";
    const ver = resp.version === "Http2" ? "HTTP/2" : "HTTP/1.1";
    const hdrs = (resp.headers || []).map(h => `${h.name}: ${h.value}`).join("\n");
    return `${ver} ${resp.status || ""} ${resp.reason || ""}\n${hdrs}\n\n${bytesToText(resp.body)}`;
  }

  onMount(() => {
    load();
    pollTimer = setInterval(load, 5000);
  });
  onDestroy(() => { if (pollTimer) clearInterval(pollTimer); });
</script>

<div class="view">
  <div class="toolbar">
    <input style="flex:1;max-width:380px" placeholder="Filter title / tag / notes..." bind:value={filter} />
    <button class="toolbar-btn" on:click={load}>Reload</button>
    <span class="dim" style="font-size:12px;margin-left:auto">{filtered.length} / {entries.length} saved items</span>
  </div>

  <div class="organizer-body">
    <div class="list-pane">
      {#if filtered.length === 0}
        <div class="empty-state-sm dim">
          {entries.length === 0
            ? "No saved items. Right-click a request anywhere and choose 'Save to Organizer' to add it here."
            : "No items match the filter."}
        </div>
      {:else}
        <ul class="entry-list">
          {#each filtered as e}
            <li class:active={selected === e} on:click={() => selected = e}>
              <div class="entry-title">{e.title || "(untitled)"}</div>
              <div class="entry-meta">
                <span class="dim mono">{e.added_at || ""}</span>
                {#if e.tags && e.tags.length}
                  <div class="entry-tags">
                    {#each e.tags as t}<span class="tag">{t}</span>{/each}
                  </div>
                {/if}
              </div>
              {#if e.notes}<div class="entry-notes dim">{e.notes.slice(0, 100)}</div>{/if}
            </li>
          {/each}
        </ul>
      {/if}
    </div>

    {#if selected}
      <div class="detail-pane">
        <div class="pane">
          <div class="pane-header">Request</div>
          <textarea class="raw-area" readonly value={formatRequest(selected.request)}></textarea>
        </div>
        <div class="pane">
          <div class="pane-header">Response</div>
          <textarea class="raw-area" readonly value={formatResponse(selected.response)}></textarea>
        </div>
      </div>
    {/if}
  </div>
</div>

<style>
  .toolbar { display: flex; align-items: center; gap: 6px; padding: 6px 12px; background: #f5f5f5; border-bottom: 1px solid #dedede; flex-shrink: 0; }
  .toolbar-btn { padding: 4px 10px; font-size: 13px; background: #f0f0f0; color: #333; border: 1px solid #c8c8c8; border-radius: 3px; cursor: pointer; }
  .toolbar-btn:hover { background: #e4e4e4; }

  .organizer-body { flex: 1; display: flex; overflow: hidden; min-height: 0; }
  .list-pane { width: 360px; flex-shrink: 0; border-right: 1px solid #dedede; overflow-y: auto; background: #fafafa; }
  .empty-state-sm { padding: 30px 16px; text-align: center; font-size: 13px; }
  .entry-list { list-style: none; margin: 0; padding: 0; }
  .entry-list li { padding: 10px 14px; border-bottom: 1px solid #e8e8e8; cursor: pointer; }
  .entry-list li:hover { background: #ffffff; }
  .entry-list li.active { background: #daeeff; }
  .entry-title { font-size: 13px; font-weight: 600; color: #212121; margin-bottom: 4px; }
  .entry-meta { display: flex; gap: 8px; align-items: center; font-size: 11px; }
  .mono { font-family: ui-monospace, Consolas, monospace; }
  .entry-tags { display: flex; gap: 4px; }
  .tag { font-size: 10px; padding: 1px 6px; background: #fce8e2; color: #e03a00; border-radius: 2px; }
  .entry-notes { font-size: 12px; margin-top: 4px; max-height: 30px; overflow: hidden; }

  .detail-pane { flex: 1; display: flex; overflow: hidden; }
  .pane { flex: 1; display: flex; flex-direction: column; border-right: 1px solid #dedede; }
  .pane:last-child { border-right: none; }
  .pane-header { padding: 5px 10px; background: #f5f5f5; border-bottom: 1px solid #dedede; font-size: 12px; font-weight: 600; color: #444; }
  .raw-area { flex: 1; resize: none; border: none; background: #fff; color: #212121; font-size: 11px; padding: 10px; outline: none; font-family: ui-monospace, Consolas, monospace; }
</style>
