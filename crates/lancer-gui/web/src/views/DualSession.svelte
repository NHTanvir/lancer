<script>
  import { onMount } from "svelte";

  let request = `GET /api/account/1 HTTP/1.1\r\nHost: target.example\r\nAccept: application/json\r\n\r\n`;
  let scheme = "https", host = "target.example", port = 443;
  let a = { name: "Victim (high-priv)", cookie: "session=AAA", authorization: "", headers: [] };
  let b = { name: "Attacker (low-priv)", cookie: "session=BBB", authorization: "", headers: [] };
  let result = null, running = false, error = "";

  function addHeader(s) { s.headers = [...s.headers, ["", ""]]; a = a; b = b; }
  function rmHeader(s, i) { s.headers = s.headers.filter((_, j) => j !== i); a = a; b = b; }

  function creds(s) {
    return {
      name: s.name,
      cookie: s.cookie || null,
      authorization: s.authorization || null,
      headers: s.headers.filter(([k]) => k),
    };
  }

  async function replay() {
    error = ""; result = null; running = true;
    try {
      const r = await fetch("/api/v1/replay/dual", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ request, scheme, host, port: +port, session_a: creds(a), session_b: creds(b) }),
      });
      if (r.ok) result = await r.json();
      else error = `Replay failed (${r.status}): ${await r.text()}`;
    } catch (e) { error = `Could not reach API (${e})`; }
    finally { running = false; }
  }

  function statusClass(s) { if (!s) return "dim"; if (s >= 500) return "s5"; if (s >= 400) return "s4"; if (s >= 300) return "s3"; return "s2"; }

  onMount(() => {
    try { const raw = localStorage.getItem("lancer.send.dualsession"); if (raw) { const v = JSON.parse(raw); if (v.raw) request = v.raw; if (v.host) host = v.host; localStorage.removeItem("lancer.send.dualsession"); } } catch {}
  });
</script>

<div class="view">
  <div class="hdr">
    <strong>Dual-Session Replay</strong>
    <span class="dim">Replay one request under two identities to detect broken access control / IDOR.</span>
    <button class="btn-primary" on:click={replay} disabled={running} style="margin-left:auto">{running ? "Replaying…" : "Replay in both sessions"}</button>
  </div>

  <div class="cols">
    <div class="req-col">
      <div class="lbl">Request</div>
      <textarea class="req" bind:value={request} spellcheck="false"></textarea>
      <div class="meta">
        <select bind:value={scheme}><option>https</option><option>http</option></select>
        <input bind:value={host} placeholder="host" />
        <input type="number" bind:value={port} style="width:80px" />
      </div>
    </div>

    {#each [a, b] as s, si}
      <div class="sess-col">
        <div class="lbl">{si === 0 ? "Session A" : "Session B"}</div>
        <input class="sess-name" bind:value={s.name} placeholder="Session label" />
        <label class="f">Cookie<input bind:value={s.cookie} placeholder="session=…" /></label>
        <label class="f">Authorization<input bind:value={s.authorization} placeholder="Bearer …" /></label>
        <div class="f">Extra headers
          {#each s.headers as h, i}
            <div class="hrow"><input bind:value={h[0]} placeholder="Name" /><input bind:value={h[1]} placeholder="Value" /><button class="x" on:click={() => rmHeader(s, i)}>×</button></div>
          {/each}
          <button class="add" on:click={() => addHeader(s)}>+ header</button>
        </div>
      </div>
    {/each}
  </div>

  {#if error}<div class="err">{error}</div>{/if}

  {#if result}
    <div class="verdict" class:bad={result.access_control_issue}>
      <strong>{result.access_control_issue ? "⚠ Access control issue" : "Verdict"}:</strong> {result.verdict}
      <span class="sim">body similarity {Math.round(result.similarity * 100)}%</span>
    </div>
    <div class="resp-grid">
      {#each [result.a, result.b] as resp}
        <div class="resp">
          <div class="resp-hd"><strong>{resp.session}</strong><span class="badge {statusClass(resp.status)}">{resp.status || "ERR"}</span><span class="dim">{resp.length} bytes</span></div>
          <pre class="resp-body">{resp.body.slice(0, 4000)}</pre>
        </div>
      {/each}
    </div>
  {/if}
</div>

<style>
  .view { display: flex; flex-direction: column; height: 100%; overflow: auto; padding: 12px; gap: 12px; box-sizing: border-box; }
  .hdr { display: flex; align-items: center; gap: 10px; }
  .hdr .dim { font-size: 12px; }
  .cols { display: grid; grid-template-columns: 1.4fr 1fr 1fr; gap: 12px; }
  .lbl { font-size: 11px; font-weight: 700; text-transform: uppercase; color: #767676; margin-bottom: 5px; }
  .req { width: 100%; box-sizing: border-box; min-height: 150px; font-family: ui-monospace, Consolas, monospace; font-size: 12px; padding: 8px; border: 1px solid #c8c8c8; border-radius: 4px; resize: vertical; }
  .meta { display: flex; gap: 6px; margin-top: 6px; }
  .meta select, .meta input { padding: 4px 6px; border: 1px solid #c8c8c8; border-radius: 3px; font-size: 12px; }
  .meta input:nth-child(2) { flex: 1; }
  .sess-col { background: #fafafa; border: 1px solid #e3e3e3; border-radius: 6px; padding: 10px; }
  .sess-name { width: 100%; box-sizing: border-box; padding: 5px 8px; border: 1px solid #c8c8c8; border-radius: 3px; font-weight: 600; margin-bottom: 8px; }
  .f { display: block; font-size: 11px; color: #767676; margin-bottom: 8px; }
  .f input { width: 100%; box-sizing: border-box; padding: 4px 7px; border: 1px solid #d0d0d0; border-radius: 3px; font-size: 12px; margin-top: 3px; }
  .hrow { display: flex; gap: 4px; margin-top: 4px; }
  .hrow input { flex: 1; }
  .x { background: none; border: none; color: #c44; cursor: pointer; }
  .add { font-size: 11px; margin-top: 5px; padding: 2px 8px; background: #f0f0f0; border: 1px solid #d0d0d0; border-radius: 3px; cursor: pointer; }
  .btn-primary { background: #e03a00; color: #fff; border: none; border-radius: 3px; padding: 6px 16px; font-size: 13px; cursor: pointer; }
  .btn-primary:hover { background: #c73400; }
  .btn-primary:disabled { opacity: 0.5; }
  .err { color: #d42c2c; font-size: 12px; }
  .verdict { padding: 10px 14px; background: #eef6ff; border: 1px solid #cfe2f7; border-radius: 5px; font-size: 13px; }
  .verdict.bad { background: #fdeaea; border-color: #f3c2c2; }
  .verdict .sim { margin-left: 10px; color: #777; font-size: 12px; }
  .resp-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .resp { border: 1px solid #e3e3e3; border-radius: 6px; overflow: hidden; }
  .resp-hd { display: flex; align-items: center; gap: 10px; padding: 6px 10px; background: #f5f5f5; border-bottom: 1px solid #e3e3e3; }
  .resp-body { margin: 0; padding: 10px; font-size: 11px; font-family: ui-monospace, Consolas, monospace; white-space: pre-wrap; word-break: break-all; max-height: 320px; overflow: auto; background: #fff; }
  .badge { font-size: 11px; font-weight: 700; padding: 1px 7px; border-radius: 3px; }
  .s2 { background: #e9f7ec; color: #2e7d3a; } .s3 { background: #fff6e0; color: #a06800; }
  .s4 { background: #fdeaea; color: #c0392b; } .s5 { background: #f3e6f7; color: #8e44ad; }
  .dim { color: #888; font-size: 12px; }
</style>
