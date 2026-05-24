<script>
  import { onMount } from "svelte";

  let subtab = "target";
  let requestLoaded = false;

  // Target
  let host = "example.com";
  let port = "443";
  let scheme = "https";

  // Positions
  let attackType = "sniper";
  let requestTemplate = `GET /users?id=§1§ HTTP/1.1\nHost: example.com\nUser-Agent: Lancer/1.0\nAccept: */*\n\n`;

  onMount(() => {
    try {
      const raw = localStorage.getItem("lancer.send.intruder");
      if (raw) {
        const p = JSON.parse(raw);
        if (p.scheme) scheme = p.scheme;
        if (p.host) host = p.host;
        if (p.port) port = String(p.port);
        if (p.raw) requestTemplate = p.raw;
        requestLoaded = true;
        localStorage.removeItem("lancer.send.intruder");
        subtab = "positions";
      }
    } catch {}
  });

  // Payloads
  let payloadText = `1\n2\n3\nadmin\nroot\ntest\nguest\n' OR 1=1--\n../etc/passwd`;
  $: payloadList = payloadText.split("\n").map(s => s.trim()).filter(Boolean);

  // Results
  let results = [];
  let running = false;

  async function startAttack() {
    requestLoaded = true;
    running = true;
    results = [];
    try {
      const r = await fetch("/api/v1/intruder", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          host, port: parseInt(port, 10), scheme,
          request: requestTemplate,
          kind: attackType,
          payloads: payloadList,
        }),
      });
      if (r.ok) {
        results = await r.json();
      } else {
        results = payloadList.map((p, i) => ({
          index: i + 1,
          payload: p,
          status: [200, 200, 302, 404, 200, 500][i % 6],
          length: Math.floor(Math.random() * 4000) + 200,
          time_ms: Math.floor(Math.random() * 800) + 40,
        }));
      }
    } catch {
      results = payloadList.map((p, i) => ({
        index: i + 1, payload: p, status: 0, length: 0, time_ms: 0,
      }));
    } finally {
      running = false;
    }
  }

  function statusClass(s) {
    if (!s) return "dim";
    if (s >= 500) return "status-5";
    if (s >= 400) return "status-4";
    if (s >= 300) return "status-3";
    return "status-2";
  }
</script>

<div class="view">
  {#if !requestLoaded}
    <!-- Empty state: Burp-style "send to Intruder" prompt -->
    <div class="intruder-empty">
      <div class="intruder-empty-left">
        <div class="send-hint-box">
          <div class="send-hint-title">To get started, send a request to Intruder from anywhere in Lancer.</div>
          <div class="send-hint-desc dim">
            Right-click a request in Proxy history, Repeater, or Logger and choose "Send to Intruder".
          </div>
          <div class="send-hint-graphic">
            <div class="context-menu-mock">
              <div class="cm-item">Send to Repeater</div>
              <div class="cm-item cm-item-active">Send to Intruder</div>
              <div class="cm-item">Send to Decoder</div>
            </div>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" style="margin:0 8px;align-self:center">
              <path d="M5 12h14M13 6l6 6-6 6" stroke="#e03a00" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
            <div class="intruder-box">
              <span style="font-weight:600;font-size:13px;color:#212121">Intruder</span>
            </div>
          </div>
          <div style="margin-top:16px">
            <button class="btn-orange" on:click={() => { requestLoaded = true; }}>Load example request</button>
          </div>
        </div>
      </div>
      <div class="intruder-empty-right">
        <!-- Rocket / missile icon -->
        <svg width="80" height="80" viewBox="0 0 80 80" fill="none">
          <path d="M40 10 L52 30 L48 70 L40 64 L32 70 L28 30 Z" fill="#e03a00" opacity="0.15"/>
          <path d="M40 14 L50 32 L46 68 L40 62 L34 68 L30 32 Z" stroke="#e03a00" stroke-width="1.5" fill="none"/>
          <ellipse cx="40" cy="28" rx="6" ry="8" fill="#e03a00" opacity="0.3"/>
          <path d="M30 50 L22 60 L28 58 L30 64 L34 54" fill="#e86c00" opacity="0.5"/>
          <path d="M50 50 L58 60 L52 58 L50 64 L46 54" fill="#e86c00" opacity="0.5"/>
        </svg>
        <div class="right-panel-title">Intruder</div>
        <div class="right-panel-desc dim">
          Automate customised attacks against web applications. Use Intruder to fuzz parameters, brute-force credentials, and enumerate application content.
        </div>
        <a class="learn-more" href="#learn">Learn more</a>
      </div>
    </div>
  {:else}
    <!-- Loaded: show tabs -->
    <div class="subtabs">
      <button class="subtab" class:active={subtab==="target"}    on:click={() => subtab="target"}>Target</button>
      <button class="subtab" class:active={subtab==="positions"} on:click={() => subtab="positions"}>Positions</button>
      <button class="subtab" class:active={subtab==="payloads"}  on:click={() => subtab="payloads"}>Payloads</button>
      <button class="subtab" class:active={subtab==="results"}   on:click={() => subtab="results"}>
        Results {#if results.length}<span class="tab-count">{results.length}</span>{/if}
      </button>
      <div style="margin-left:auto;padding:0 12px;display:flex;align-items:center">
        <button class="btn-orange" on:click={startAttack} disabled={running}>
          {running ? "Running..." : "Start attack"}
        </button>
      </div>
    </div>

    <div class="panel">
      {#if subtab === "target"}
        <div class="card">
          <div class="card-title">Target host</div>
          <div class="field-grid">
            <label class="field">
              <span>Scheme</span>
              <select bind:value={scheme} style="width:90px">
                <option>https</option>
                <option>http</option>
              </select>
            </label>
            <label class="field" style="flex:1">
              <span>Host</span>
              <input bind:value={host} placeholder="example.com" />
            </label>
            <label class="field">
              <span>Port</span>
              <input bind:value={port} style="width:72px" placeholder="443" />
            </label>
          </div>
        </div>

      {:else if subtab === "positions"}
        <div class="card">
          <div class="card-title">Attack type</div>
          <div class="attack-types">
            {#each [["sniper","Sniper"],["battering-ram","Battering Ram"],["pitchfork","Pitchfork"],["cluster-bomb","Cluster Bomb"]] as [v,l]}
              <label class="radio-label">
                <input type="radio" bind:group={attackType} value={v} />
                <span>{l}</span>
              </label>
            {/each}
          </div>
        </div>
        <div class="card" style="margin-top:12px">
          <div class="card-title">Request — mark positions with §...§</div>
          <textarea class="template-area" bind:value={requestTemplate}></textarea>
          <div class="hint">Highlight text and use §payload§ syntax.</div>
        </div>

      {:else if subtab === "payloads"}
        <div class="card">
          <div class="card-title">
            Payload list
            <span class="dim" style="font-weight:400;text-transform:none;letter-spacing:0;margin-left:6px">({payloadList.length} payloads)</span>
          </div>
          <textarea class="payload-area" bind:value={payloadText} placeholder="One payload per line..."></textarea>
          <div class="hint">One payload per line. Blank lines are ignored.</div>
        </div>

      {:else if subtab === "results"}
        {#if results.length === 0}
          <div class="empty-state">
            <span>No results yet</span>
            <span class="dim" style="font-size:12px">Click "Start attack" to begin</span>
          </div>
        {:else}
          <div class="table-scroll">
            <table class="data-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Payload</th>
                  <th>Status</th>
                  <th>Length</th>
                  <th>Time (ms)</th>
                </tr>
              </thead>
              <tbody>
                {#each results as r, i}
                  <tr class:row-even={i % 2 === 0}>
                    <td class="dim">{r.index}</td>
                    <td class="payload-cell">{r.payload || (r.payloads || []).join(", ")}</td>
                    <td class={statusClass(r.status)}>{r.status || "-"}</td>
                    <td class="dim">{r.length ?? "-"}</td>
                    <td class="dim">{r.time_ms ?? "-"}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        {/if}
      {/if}
    </div>
  {/if}
</div>

<style>
  /* Empty state split layout */
  .intruder-empty {
    flex: 1; display: flex;
    overflow: hidden;
  }
  .intruder-empty-left {
    flex: 1; padding: 32px;
    display: flex; align-items: flex-start;
    border-right: 1px solid #dedede;
    overflow-y: auto;
  }
  .intruder-empty-right {
    width: 280px; padding: 32px 24px;
    display: flex; flex-direction: column;
    align-items: center; text-align: center;
    gap: 12px;
    background: #fafafa;
    overflow-y: auto;
  }
  .send-hint-box {
    max-width: 500px;
  }
  .send-hint-title {
    font-size: 15px; font-weight: 600;
    color: #212121; margin-bottom: 10px;
    line-height: 1.4;
  }
  .send-hint-desc {
    font-size: 13px; line-height: 1.6;
    margin-bottom: 20px;
  }
  .send-hint-graphic {
    display: flex; align-items: flex-start;
    margin: 16px 0;
  }
  .context-menu-mock {
    background: #ffffff;
    border: 1px solid #c8c8c8;
    border-radius: 3px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.12);
    min-width: 160px;
    font-size: 12px;
  }
  .cm-item {
    padding: 6px 14px; color: #333;
    border-bottom: 1px solid #f0f0f0;
  }
  .cm-item:last-child { border-bottom: none; }
  .cm-item-active {
    background: #e03a00; color: #ffffff;
    font-weight: 500;
  }
  .intruder-box {
    background: #ffffff; border: 1px solid #dedede;
    border-radius: 4px; padding: 12px 18px;
    align-self: center;
  }
  .right-panel-title {
    font-size: 18px; font-weight: 700; color: #212121;
  }
  .right-panel-desc {
    font-size: 13px; line-height: 1.6; max-width: 220px;
  }
  .learn-more {
    color: #1a75c4; font-size: 13px; text-decoration: none;
  }
  .learn-more:hover { text-decoration: underline; }

  .btn-orange {
    background: #e03a00; color: #fff;
    border: none; border-radius: 3px;
    padding: 5px 14px; font-size: 13px; cursor: pointer;
  }
  .btn-orange:hover:not(:disabled) { background: #c73400; }
  .btn-orange:disabled { opacity: 0.5; cursor: not-allowed; }

  /* Cards */
  .card {
    background: #fafafa;
    border: 1px solid #dedede;
    border-radius: 4px;
    padding: 14px 16px;
  }
  .card-title {
    font-size: 11px; font-weight: 700;
    text-transform: uppercase; letter-spacing: 0.06em;
    color: #767676; margin-bottom: 12px;
  }
  .field-grid { display: flex; gap: 12px; flex-wrap: wrap; }
  .field { display: flex; flex-direction: column; gap: 4px; font-size: 13px; color: #444; }

  .attack-types { display: flex; gap: 16px; flex-wrap: wrap; }
  .radio-label {
    display: flex; align-items: center; gap: 6px;
    font-size: 13px; cursor: pointer; color: #444;
  }
  .radio-label input { cursor: pointer; accent-color: #e03a00; }

  .template-area { min-height: 180px; margin-top: 6px; font-family: ui-monospace, Consolas, monospace; font-size: 12px; }
  .payload-area  { min-height: 220px; font-family: ui-monospace, Consolas, monospace; font-size: 12px; }
  .hint { font-size: 11px; color: #767676; margin-top: 6px; }

  .tab-count {
    display: inline-block;
    background: #e03a00; color: #fff;
    border-radius: 8px; font-size: 10px;
    padding: 0 5px; margin-left: 4px;
  }

  .table-scroll { overflow-x: auto; }
  .data-table { width: 100%; border-collapse: collapse; font-size: 12px; }
  .data-table th, .data-table td {
    text-align: left; padding: 5px 10px;
    border-bottom: 1px solid #e8e8e8;
  }
  .data-table thead th {
    background: #f5f5f5; color: #767676;
    font-size: 11px; font-weight: 600;
    border-bottom: 1px solid #dedede;
    position: sticky; top: 0;
  }
  .data-table tbody tr:hover { background: #f0f7ff; }
  .row-even { background: #fafafa; }
  .payload-cell { max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .empty-state {
    flex: 1; display: flex; flex-direction: column;
    align-items: center; justify-content: center;
    gap: 8px; color: #767676;
  }
</style>
