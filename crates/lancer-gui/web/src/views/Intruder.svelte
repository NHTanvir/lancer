<script>
  let kind = "sniper";
  let request = `GET /users?id=§1§ HTTP/1.1
Host: example.com

`;
  let payloads = "1,2,3,admin,root,test";
  let results = [];
  let running = false;
  async function start() {
    running = true;
    results = [];
    // Stub: POST to a (yet-to-be-wired) /api/v1/intruder endpoint.
    try {
      const r = await fetch("/api/v1/intruder", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          request,
          scheme: "https",
          kind,
          payloads: payloads.split(",").map((s) => s.trim()),
        }),
      });
      results = await r.json();
    } catch (e) {
      results = [{ index: 0, status: 0, error: String(e) }];
    } finally {
      running = false;
    }
  }
</script>

<div class="grid">
  <div class="pane">
    <h3>Attack</h3>
    <label>Type
      <select bind:value={kind}>
        <option value="sniper">Sniper</option>
        <option value="battering-ram">Battering Ram</option>
        <option value="pitchfork">Pitchfork</option>
        <option value="cluster-bomb">Cluster Bomb</option>
      </select>
    </label>
    <label>Request (mark positions with §…§)
      <textarea bind:value={request}></textarea>
    </label>
    <label>Payloads (comma-separated)
      <input bind:value={payloads} />
    </label>
    <button on:click={start} disabled={running}>{running ? "Running…" : "Start"}</button>
  </div>
  <div class="pane">
    <h3>Results</h3>
    <table>
      <thead>
        <tr><th>#</th><th>Payload</th><th>Status</th><th>Length</th><th>Time</th></tr>
      </thead>
      <tbody>
        {#each results as r}
          <tr>
            <td>{r.index}</td>
            <td>{(r.payloads || []).join(",")}</td>
            <td>{r.status}</td>
            <td>{r.length}</td>
            <td>{r.time_ms}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
</div>

<style>
  .grid {
    display: grid;
    grid-template-columns: 380px 1fr;
    gap: 14px;
    height: 100%;
  }
  .pane {
    background: #1a1d2b;
    border: 1px solid #292d40;
    border-radius: 8px;
    padding: 12px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    overflow: hidden;
  }
  .pane textarea {
    min-height: 200px;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }
  th, td {
    border-bottom: 1px solid #292d40;
    padding: 4px 8px;
    text-align: left;
  }
  h3 {
    margin: 0;
    font-size: 12px;
    text-transform: uppercase;
    color: #9aa0bd;
  }
  label {
    display: flex;
    flex-direction: column;
    font-size: 12px;
    gap: 4px;
  }
</style>
