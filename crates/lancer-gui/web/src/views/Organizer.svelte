<script>
  import { onMount, onDestroy } from "svelte";

  let entries = [];
  let filter = "";
  let selected = null;
  let pollTimer;

  // ── Edit form state (mirrors the selected entry) ─────────────────────
  let editTitle = "";
  let editTags = "";       // comma-separated text
  let editNotes = "";
  let saving = false;
  let busy = false;        // delete in flight
  let msg = null;          // { kind: "ok"|"err", text }

  $: filtered = entries.filter(e =>
    !filter ||
    (e.title || "").toLowerCase().includes(filter.toLowerCase()) ||
    (e.tags || []).some(t => t.toLowerCase().includes(filter.toLowerCase())) ||
    (e.notes || "").toLowerCase().includes(filter.toLowerCase())
  );

  async function load() {
    try {
      const r = await fetch("/api/v1/organizer");
      if (r.ok) {
        entries = await r.json();
        // Keep selection synced to the refreshed object (match by id).
        if (selected) {
          const id = entryId(selected);
          const match = entries.find(e => entryId(e) === id);
          if (match) selectEntry(match, false);
          else { selected = null; }
        }
      }
    } catch {}
  }

  function entryId(e) {
    // id is a UUID string field; be defensive about shape.
    return e && (e.id != null ? String(e.id) : "");
  }

  function selectEntry(e, fillForm = true) {
    selected = e;
    if (fillForm) {
      editTitle = e.title || "";
      editTags = (e.tags || []).join(", ");
      editNotes = e.notes || "";
      msg = null;
    }
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

  // ── Save (PUT title/tags/notes) ──────────────────────────────────────
  async function save() {
    if (!selected) return;
    const id = entryId(selected);
    if (!id) { msg = { kind: "err", text: "Entry has no id." }; return; }
    saving = true;
    msg = null;
    const tags = editTags.split(",").map(t => t.trim()).filter(Boolean);
    try {
      const r = await fetch(`/api/v1/organizer/${encodeURIComponent(id)}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ title: editTitle, tags, notes: editNotes }),
      });
      if (r.ok) {
        msg = { kind: "ok", text: "Saved." };
        // Reflect locally then refresh from server.
        selected.title = editTitle;
        selected.tags = tags;
        selected.notes = editNotes;
        await load();
      } else {
        msg = { kind: "err", text: `Save failed: ${r.status} ${await r.text()}` };
      }
    } catch (e) {
      msg = { kind: "err", text: `Save failed: ${e.message}` };
    }
    saving = false;
  }

  // ── Delete ───────────────────────────────────────────────────────────
  async function del() {
    if (!selected) return;
    const id = entryId(selected);
    if (!id) { msg = { kind: "err", text: "Entry has no id." }; return; }
    busy = true;
    msg = null;
    try {
      const r = await fetch(`/api/v1/organizer/${encodeURIComponent(id)}`, { method: "DELETE" });
      if (r.ok) {
        selected = null;
        await load();
      } else {
        msg = { kind: "err", text: `Delete failed: ${r.status} ${await r.text()}` };
      }
    } catch (e) {
      msg = { kind: "err", text: `Delete failed: ${e.message}` };
    }
    busy = false;
  }

  // ── Send to Repeater (best-effort raw HTTP build) ────────────────────
  function deriveRaw(req) {
    if (!req) return "";
    // Prefer the canonical formatter; fall back to method/url shape.
    try {
      const raw = formatRequest(req);
      if (raw && raw.trim()) return raw;
    } catch {}
    try {
      const method = req.method || "GET";
      // HttpRequest serde uses `path`; tolerate a `url` field too.
      let target = req.path || req.url || "/";
      let host = "";
      try { host = (req.meta && req.meta.host) || ""; } catch {}
      // If we were given a full URL, split out host + path.
      if (/^https?:\/\//i.test(target)) {
        try {
          const u = new URL(target);
          if (!host) host = u.host;
          target = u.pathname + (u.search || "");
        } catch {}
      }
      const hdrs = (req.headers || []).map(h => `${h.name}: ${h.value}`);
      if (host && !hdrs.some(h => /^host:/i.test(h))) hdrs.unshift(`Host: ${host}`);
      return `${method} ${target} HTTP/1.1\r\n${hdrs.join("\r\n")}\r\n\r\n${bytesToText(req.body)}`;
    } catch {
      return "";
    }
  }

  function sendToRepeater(e) {
    if (!e) return;
    try {
      const req = e.request;
      let scheme = "http", host = "", port = 80;
      try {
        if (req && req.meta) {
          if (req.meta.scheme) scheme = req.meta.scheme;
          if (req.meta.host) host = req.meta.host;
          if (req.meta.port) port = req.meta.port;
        }
      } catch {}
      const raw = deriveRaw(req);
      const payload = { scheme, host, port, raw };
      localStorage.setItem("lancer.send.repeater", JSON.stringify(payload));
      // Repeater's onMount reads `repeater_prefill` (request/scheme/host/port);
      // write it too so the tab is actually prefilled.
      localStorage.setItem("repeater_prefill", JSON.stringify({ request: raw, scheme, host, port }));
      window.dispatchEvent(new CustomEvent("lancer:navigate", { detail: "repeater" }));
    } catch {}
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
            <li class:active={selected && entryId(selected) === entryId(e)} on:click={() => selectEntry(e)}>
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
        <div class="edit-pane">
          <div class="pane-header">Edit entry</div>
          <div class="edit-body">
            <label class="field">
              <span class="field-label">Title</span>
              <input type="text" bind:value={editTitle} placeholder="(untitled)" />
            </label>
            <label class="field">
              <span class="field-label">Tags <span class="dim">(comma-separated)</span></span>
              <input type="text" bind:value={editTags} placeholder="auth, idor, interesting" />
            </label>
            <label class="field">
              <span class="field-label">Notes</span>
              <textarea bind:value={editNotes} rows="5" placeholder="Notes about this request..."></textarea>
            </label>

            <div class="edit-actions">
              <button class="btn-primary" on:click={save} disabled={saving || busy}>
                {saving ? "Saving…" : "Save"}
              </button>
              <button class="toolbar-btn danger" on:click={del} disabled={saving || busy}>
                {busy ? "Deleting…" : "Delete"}
              </button>
              <button class="toolbar-btn" on:click={() => sendToRepeater(selected)} disabled={!selected.request}>
                Send to Repeater
              </button>
            </div>

            {#if msg}
              <div class="inline-msg {msg.kind === 'ok' ? 'ok' : 'err'}">{msg.text}</div>
            {/if}
          </div>
        </div>

        <div class="rr-pane">
          <div class="pane">
            <div class="pane-header">Request</div>
            <textarea class="raw-area" readonly value={formatRequest(selected.request)}></textarea>
          </div>
          <div class="pane">
            <div class="pane-header">Response</div>
            <textarea class="raw-area" readonly value={formatResponse(selected.response)}></textarea>
          </div>
        </div>
      </div>
    {/if}
  </div>
</div>

<style>
  .toolbar { display: flex; align-items: center; gap: 6px; padding: 6px 12px; background: #f5f5f5; border-bottom: 1px solid #dedede; flex-shrink: 0; }
  .toolbar-btn { padding: 4px 10px; font-size: 13px; background: #f0f0f0; color: #333; border: 1px solid #c8c8c8; border-radius: 3px; cursor: pointer; }
  .toolbar-btn:hover { background: #e4e4e4; }
  .toolbar-btn:disabled { opacity: 0.5; cursor: default; }
  .toolbar-btn.danger { color: #c0392b; border-color: #e0b4ac; }
  .toolbar-btn.danger:hover { background: #fde8e8; }

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

  .detail-pane { flex: 1; display: flex; flex-direction: column; overflow: hidden; min-height: 0; }

  .edit-pane { flex-shrink: 0; border-bottom: 1px solid #dedede; display: flex; flex-direction: column; }
  .edit-body { padding: 10px 14px; }
  .field { display: block; margin-bottom: 8px; }
  .field-label { display: block; font-size: 11px; font-weight: 600; color: #555; margin-bottom: 3px; }
  .field input, .field textarea { width: 100%; box-sizing: border-box; padding: 5px 8px; font-size: 13px; border: 1px solid #c8c8c8; border-radius: 3px; background: #fff; color: #212121; }
  .field textarea { resize: vertical; font-family: inherit; }
  .edit-actions { display: flex; gap: 8px; align-items: center; margin-top: 4px; }
  .inline-msg { margin-top: 8px; padding: 5px 8px; border-radius: 3px; font-size: 12px; }
  .inline-msg.ok { background: #e6f4ea; color: #1e7e34; }
  .inline-msg.err { background: #fde8e8; color: #c0392b; }

  .rr-pane { flex: 1; display: flex; overflow: hidden; min-height: 0; }
  .pane { flex: 1; display: flex; flex-direction: column; border-right: 1px solid #dedede; }
  .pane:last-child { border-right: none; }
  .pane-header { padding: 5px 10px; background: #f5f5f5; border-bottom: 1px solid #dedede; font-size: 12px; font-weight: 600; color: #444; }
  .raw-area { flex: 1; resize: none; border: none; background: #fff; color: #212121; font-size: 11px; padding: 10px; outline: none; font-family: ui-monospace, Consolas, monospace; }
</style>
