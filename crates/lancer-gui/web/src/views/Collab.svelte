<script>
  import { onMount, onDestroy } from "svelte";

  let me_ = null;          // our peer {id, display_name, color}
  let name = "";
  let color = "#e03a00";
  let peers = [];
  let events = [];
  let chatMsg = "";
  let timer;
  let surface = "collab";

  async function refresh() {
    try {
      const r = await fetch("/api/v1/collab/state");
      if (r.ok) { const s = await r.json(); peers = s.peers || []; events = s.events || []; }
    } catch {}
  }
  async function join() {
    if (!name.trim()) return;
    try {
      const r = await fetch("/api/v1/collab/join", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ display_name: name, color }) });
      if (r.ok) { me_ = await r.json(); await ping(); await refresh(); }
    } catch {}
  }
  async function leave() {
    if (!me_) return;
    try { await fetch("/api/v1/collab/leave", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ id: me_.id }) }); } catch {}
    me_ = null; await refresh();
  }
  async function ping() {
    if (!me_) return;
    try {
      const active = document.querySelector(".tab.active");
      surface = active ? active.textContent.trim() : "Collab";
      await fetch("/api/v1/collab/cursor", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ author: me_.id, surface, position: {} }) });
    } catch {}
  }
  async function sendChat() {
    if (!me_ || !chatMsg.trim()) return;
    try { await fetch("/api/v1/collab/chat", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ author: me_.id, message: chatMsg }) }); chatMsg = ""; await refresh(); } catch {}
  }

  function peerName(id) { const p = peers.find(x => x.id === id); return p ? p.display_name : id.slice(0, 6); }
  function surfaceOf(id) {
    // latest CursorMoved surface for this peer
    const ev = [...events].reverse().find(e => e.type === "cursor_moved" && e.author === id);
    return ev ? ev.surface : "—";
  }
  $: chats = events.filter(e => e.type === "chat");

  onMount(() => {
    refresh();
    timer = setInterval(() => { refresh(); ping(); }, 3000);
  });
  onDestroy(() => { if (timer) clearInterval(timer); leave(); });
</script>

<div class="view">
  <div class="hdr">
    <strong>Live Collaboration</strong>
    <span class="dim">Multiple testers on the same Lancer API see each other's presence, current view, and chat in real time.</span>
  </div>

  {#if !me_}
    <div class="join">
      <input bind:value={name} placeholder="Your display name" on:keydown={(e) => e.key === "Enter" && join()} />
      <input type="color" bind:value={color} />
      <button class="btn-primary" on:click={join} disabled={!name.trim()}>Join session</button>
    </div>
  {:else}
    <div class="joined">
      <span class="me" style="--c:{me_.color}">● {me_.display_name} (you)</span>
      <button class="btn-sec" on:click={leave}>Leave</button>
    </div>
  {/if}

  <div class="cols">
    <div class="peers">
      <div class="lbl">Peers ({peers.length})</div>
      {#each peers as p}
        <div class="peer"><span class="dot" style="background:{p.color}"></span><strong>{p.display_name}</strong><span class="dim view-tag">{surfaceOf(p.id)}</span></div>
      {/each}
      {#if peers.length === 0}<div class="dim">No one connected. Share this Lancer API URL with a teammate.</div>{/if}
    </div>

    <div class="chat">
      <div class="lbl">Chat</div>
      <div class="chat-log">
        {#each chats as c}
          <div class="msg"><span class="msg-author">{peerName(c.author)}:</span> {c.message}</div>
        {/each}
        {#if chats.length === 0}<div class="dim">No messages yet.</div>{/if}
      </div>
      {#if me_}
        <div class="chat-input">
          <input bind:value={chatMsg} placeholder="Message…" on:keydown={(e) => e.key === "Enter" && sendChat()} />
          <button class="btn-primary" on:click={sendChat}>Send</button>
        </div>
      {/if}
    </div>
  </div>
</div>

<style>
  .view { display: flex; flex-direction: column; height: 100%; overflow: hidden; padding: 14px; gap: 12px; box-sizing: border-box; }
  .hdr { display: flex; gap: 10px; align-items: baseline; } .hdr .dim { font-size: 12px; }
  .join, .joined { display: flex; gap: 8px; align-items: center; }
  .join input[type="text"], .join input:not([type]) { padding: 6px 9px; border: 1px solid #c8c8c8; border-radius: 3px; }
  .me { font-weight: 600; color: var(--c); }
  .cols { flex: 1; display: grid; grid-template-columns: 1fr 1.4fr; gap: 14px; min-height: 0; }
  .peers, .chat { border: 1px solid #e3e3e3; border-radius: 6px; padding: 10px; display: flex; flex-direction: column; overflow: hidden; }
  .lbl { font-size: 11px; font-weight: 700; text-transform: uppercase; color: #888; margin-bottom: 8px; }
  .peer { display: flex; align-items: center; gap: 8px; padding: 4px 0; font-size: 13px; }
  .dot { width: 9px; height: 9px; border-radius: 50%; }
  .view-tag { margin-left: auto; font-size: 11px; background: #eef2f7; padding: 1px 7px; border-radius: 3px; }
  .chat-log { flex: 1; overflow: auto; font-size: 13px; }
  .msg { padding: 2px 0; } .msg-author { font-weight: 600; color: #2e6fae; }
  .chat-input { display: flex; gap: 6px; margin-top: 8px; }
  .chat-input input { flex: 1; padding: 6px 9px; border: 1px solid #c8c8c8; border-radius: 3px; }
  .btn-primary { background: #e03a00; color: #fff; border: none; border-radius: 3px; padding: 6px 14px; font-size: 13px; cursor: pointer; }
  .btn-sec { background: #f0f0f0; border: 1px solid #c8c8c8; border-radius: 3px; padding: 5px 12px; cursor: pointer; }
  .dim { color: #888; font-size: 12px; }
</style>
