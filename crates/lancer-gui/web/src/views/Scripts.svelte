<script>
  let subtab = "bambda";

  // ── Bambda (Rhai) ──
  let kind = "passive_check";
  let script = `// passive_check: return an array of findings.\nlet out = [];\nif resp.body.contains("DEBUG") {\n  out.push(#{ name: "Debug string in response", severity: "Low" });\n}\nout`;
  let sampleReq = `GET /page HTTP/1.1\r\nHost: target.example\r\n\r\n`;
  let sampleResp = `HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>DEBUG mode is on</html>`;
  let bResult = null, bErr = "";

  const EXAMPLES = {
    filter_request: `// filter_request: return true to keep the item.\nreq.method == "POST" && req.path.contains("/api/")`,
    filter_response: `// filter_response: return true to keep the item.\nresp.status >= 500 || resp.body.contains("stack trace")`,
    passive_check: `// passive_check: return an array of findings.\nlet out = [];\nif resp.headers.get("server") != () {\n  out.push(#{ name: "Server header disclosed", severity: "Info" });\n}\nout`,
  };
  function loadExample() { script = EXAMPLES[kind] || script; }

  async function testBambda() {
    bResult = null; bErr = "";
    try {
      const r = await fetch("/api/v1/bambda/test", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ script, kind, request: sampleReq, response: sampleResp }),
      });
      const d = await r.json();
      if (d.ok) bResult = d; else bErr = d.error || "error";
    } catch (e) { bErr = String(e); }
  }

  // ── BCheck ──
  let yaml = `metadata:\n  name: "Example exposure check"\n  description: "Detects an exposed debug endpoint"\n  severity: medium\n  confidence: firm\n\nrun for each:\n  potential_path = "/debug", "/.env"\n\ngiven path then\n  send request:\n    method: GET\n    path: {potential_path}\n  if {response.status_code} is "200" then\n    report issue\n  end if`;
  let cResult = null, cErr = "";
  async function validateBCheck() {
    cResult = null; cErr = "";
    try {
      const r = await fetch("/api/v1/bchecks/validate", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ yaml }),
      });
      const d = await r.json();
      if (d.ok) cResult = d; else cErr = d.error || "parse error";
    } catch (e) { cErr = String(e); }
  }
</script>

<div class="view">
  <div class="subtabs">
    <button class="subtab" class:active={subtab === "bambda"} on:click={() => (subtab = "bambda")}>Bambda (Rhai)</button>
    <button class="subtab" class:active={subtab === "bcheck"} on:click={() => (subtab = "bcheck")}>BCheck (DSL)</button>
    <span class="dim note">In-app scripts: lightweight filters / custom passive checks (Bambda) and scan-check DSL (BCheck).</span>
  </div>

  {#if subtab === "bambda"}
    <div class="pane">
      <div class="row">
        <label>Script kind
          <select bind:value={kind} on:change={loadExample}>
            <option value="filter_request">Filter (request)</option>
            <option value="filter_response">Filter (response)</option>
            <option value="passive_check">Passive check</option>
          </select>
        </label>
        <button class="btn-sec" on:click={loadExample}>Load example</button>
        <button class="btn-primary" on:click={testBambda}>Test script</button>
      </div>
      <label class="lbl">Script</label>
      <textarea class="code tall" bind:value={script} spellcheck="false"></textarea>
      <div class="samples">
        <div><label class="lbl">Sample request</label><textarea class="code" bind:value={sampleReq} spellcheck="false"></textarea></div>
        <div><label class="lbl">Sample response</label><textarea class="code" bind:value={sampleResp} spellcheck="false"></textarea></div>
      </div>
      {#if bErr}<div class="err">⚠ {bErr}</div>{/if}
      {#if bResult}
        <div class="result">
          {#if "matched" in bResult}
            Filter result: <strong class={bResult.matched ? "ok" : "no"}>{bResult.matched ? "MATCHED (kept)" : "not matched (hidden)"}</strong>
          {:else}
            <strong>{(bResult.findings || []).length}</strong> finding(s):
            {#each bResult.findings || [] as f}<div class="finding">{JSON.stringify(f)}</div>{/each}
          {/if}
        </div>
      {/if}
    </div>
  {:else}
    <div class="pane">
      <div class="row">
        <button class="btn-primary" on:click={validateBCheck}>Validate &amp; parse</button>
        <span class="dim">Parses the BCheck DSL with the real `lancer-scanner` runner.</span>
      </div>
      <textarea class="code tall2" bind:value={yaml} spellcheck="false"></textarea>
      {#if cErr}<div class="err">⚠ {cErr}</div>{/if}
      {#if cResult}<div class="result ok">✓ Valid — <strong>{cResult.name}</strong>, {cResult.probes} probe(s)</div>{/if}
    </div>
  {/if}
</div>

<style>
  .view { display: flex; flex-direction: column; height: 100%; overflow: hidden; }
  .subtabs { display: flex; align-items: center; gap: 4px; padding: 6px 12px; background: #f5f5f5; border-bottom: 1px solid #dedede; }
  .subtab { padding: 4px 12px; font-size: 13px; background: transparent; border: none; border-bottom: 2px solid transparent; cursor: pointer; color: #555; }
  .subtab.active { color: #e03a00; border-bottom-color: #e03a00; font-weight: 600; }
  .note { margin-left: auto; font-size: 11px; }
  .pane { flex: 1; overflow: auto; padding: 14px; display: flex; flex-direction: column; gap: 10px; }
  .row { display: flex; align-items: flex-end; gap: 10px; }
  .row label { display: flex; flex-direction: column; gap: 4px; font-size: 11px; color: #767676; }
  .row select { padding: 5px 8px; border: 1px solid #c8c8c8; border-radius: 3px; }
  .lbl { font-size: 11px; font-weight: 600; color: #767676; }
  .code { width: 100%; box-sizing: border-box; font-family: ui-monospace, Consolas, monospace; font-size: 12px; padding: 8px; border: 1px solid #c8c8c8; border-radius: 4px; resize: vertical; min-height: 90px; }
  .tall { min-height: 150px; } .tall2 { min-height: 320px; }
  .samples { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .btn-primary { background: #e03a00; color: #fff; border: none; border-radius: 3px; padding: 6px 14px; font-size: 13px; cursor: pointer; }
  .btn-primary:hover { background: #c73400; }
  .btn-sec { background: #f0f0f0; color: #333; border: 1px solid #c8c8c8; border-radius: 3px; padding: 6px 12px; font-size: 13px; cursor: pointer; }
  .err { color: #d42c2c; font-size: 12px; font-family: ui-monospace, Consolas, monospace; }
  .result { padding: 8px 12px; background: #f5f8fc; border: 1px solid #d8e4f0; border-radius: 4px; font-size: 13px; }
  .result.ok { background: #eef7ee; border-color: #cfe6cf; }
  .ok { color: #1b8c1b; } .no { color: #888; }
  .finding { font-family: ui-monospace, Consolas, monospace; font-size: 11px; margin-top: 3px; color: #444; }
  .dim { color: #888; font-size: 12px; }
</style>
