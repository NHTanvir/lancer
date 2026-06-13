<script>
  import { onMount, onDestroy } from "svelte";

  let graph = { nodes: [], edges: [] };
  let auto = true, timer, selected = null, truncated = 0;
  const MAX = 60;

  async function load() {
    try {
      const r = await fetch("/api/v1/replay/flowgraph");
      if (r.ok) {
        const g = await r.json();
        truncated = Math.max(0, (g.nodes || []).length - MAX);
        const keep = new Set((g.nodes || []).slice(0, MAX).map(n => n.id));
        graph = { nodes: (g.nodes || []).slice(0, MAX), edges: (g.edges || []).filter(e => keep.has(e.from) && keep.has(e.to)) };
      }
    } catch {}
  }

  // Circular layout positions.
  const W = 900, H = 560, cx = W / 2, cy = H / 2;
  $: R = Math.min(W, H) / 2 - 80;
  $: pos = (() => {
    const m = {};
    const n = graph.nodes.length || 1;
    graph.nodes.forEach((node, i) => {
      const ang = (2 * Math.PI * i) / n - Math.PI / 2;
      m[node.id] = { x: cx + R * Math.cos(ang), y: cy + R * Math.sin(ang) };
    });
    return m;
  })();

  function nodeLabel(n) { const l = n.label || n.path || n.id; return l.length > 22 ? l.slice(0, 22) + "…" : l; }
  function connected(id) {
    if (!selected) return true;
    return id === selected || graph.edges.some(e => (e.from === selected && e.to === id) || (e.to === selected && e.from === id));
  }
  function edgeOn(e) { return !selected || e.from === selected || e.to === selected; }

  onMount(() => { load(); timer = setInterval(() => { if (auto) load(); }, 4000); });
  onDestroy(() => { if (timer) clearInterval(timer); });
</script>

<div class="view">
  <div class="hdr">
    <strong>Flow Grapher</strong>
    <span class="dim">Live navigation graph built from the proxy request log (edges inferred from Referer + sequence).</span>
    <label class="auto"><input type="checkbox" bind:checked={auto} /> Auto-refresh</label>
    <button class="btn" on:click={load}>Refresh</button>
    <span class="dim" style="margin-left:auto">{graph.nodes.length} nodes · {graph.edges.length} edges{truncated ? ` (+${truncated} hidden)` : ""}</span>
  </div>

  <div class="canvas-wrap">
    {#if graph.nodes.length === 0}
      <div class="empty dim">No traffic yet. Browse through the proxy and the application flow will appear here.</div>
    {:else}
      <svg viewBox="0 0 {W} {H}" class="graph">
        <defs>
          <marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
            <path d="M0,0 L7,3 L0,6 Z" fill="#b0b8c4" />
          </marker>
        </defs>
        {#each graph.edges as e}
          {#if pos[e.from] && pos[e.to]}
            <line x1={pos[e.from].x} y1={pos[e.from].y} x2={pos[e.to].x} y2={pos[e.to].y}
              stroke={edgeOn(e) ? "#8aa0bd" : "#e6e6e6"} stroke-width={Math.min(1 + e.count * 0.4, 4)}
              marker-end="url(#arrow)" opacity={edgeOn(e) ? 0.8 : 0.25} />
          {/if}
        {/each}
        {#each graph.nodes as n}
          {#if pos[n.id]}
            <g class="node" class:dim-node={!connected(n.id)} on:click={() => (selected = selected === n.id ? null : n.id)} role="button" tabindex="0">
              <circle cx={pos[n.id].x} cy={pos[n.id].y} r={Math.min(5 + n.count, 16)}
                fill={n.id === selected ? "#e03a00" : "#4a78b5"} stroke="#fff" stroke-width="1.5" />
              <text x={pos[n.id].x} y={pos[n.id].y - Math.min(5 + n.count, 16) - 4} text-anchor="middle" class="nlabel">{nodeLabel(n)}</text>
            </g>
          {/if}
        {/each}
      </svg>
    {/if}
  </div>

  {#if selected}
    {@const node = graph.nodes.find(n => n.id === selected)}
    {#if node}
      <div class="detail">
        <strong>{node.host}{node.path}</strong>
        <span class="dim">· {node.methods.join(", ") || "—"} · {node.count} hits</span>
        <div class="adj">
          <div><span class="lbl">→ outgoing</span>{#each graph.edges.filter(e => e.from === selected) as e}<span class="chip">{graph.nodes.find(n => n.id === e.to)?.path || e.to} ({e.count})</span>{/each}</div>
          <div><span class="lbl">← incoming</span>{#each graph.edges.filter(e => e.to === selected) as e}<span class="chip">{graph.nodes.find(n => n.id === e.from)?.path || e.from} ({e.count})</span>{/each}</div>
        </div>
      </div>
    {/if}
  {/if}
</div>

<style>
  .view { display: flex; flex-direction: column; height: 100%; overflow: hidden; padding: 12px; gap: 10px; box-sizing: border-box; }
  .hdr { display: flex; align-items: center; gap: 12px; } .hdr .dim { font-size: 12px; }
  .auto { display: flex; align-items: center; gap: 4px; font-size: 12px; color: #555; }
  .btn { background: #f0f0f0; border: 1px solid #c8c8c8; border-radius: 3px; padding: 4px 12px; font-size: 12px; cursor: pointer; }
  .canvas-wrap { flex: 1; min-height: 0; border: 1px solid #e3e3e3; border-radius: 6px; overflow: auto; background: #fcfcfd; display: flex; align-items: center; justify-content: center; }
  .graph { width: 100%; height: 100%; }
  .node { cursor: pointer; }
  .node.dim-node { opacity: 0.3; }
  .nlabel { font-size: 9px; fill: #444; font-family: ui-monospace, Consolas, monospace; }
  .empty { padding: 40px; text-align: center; }
  .detail { font-size: 12px; border: 1px solid #e3e3e3; border-radius: 6px; padding: 8px 12px; background: #fafafa; }
  .adj { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 6px; }
  .lbl { font-size: 10px; text-transform: uppercase; color: #999; margin-right: 6px; }
  .chip { display: inline-block; background: #eef2f7; border-radius: 3px; padding: 1px 7px; margin: 2px; font-family: ui-monospace, Consolas, monospace; font-size: 11px; }
  .dim { color: #888; }
</style>
