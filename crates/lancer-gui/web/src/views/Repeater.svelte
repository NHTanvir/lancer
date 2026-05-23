<script>
  let request = `GET / HTTP/1.1
Host: example.com
User-Agent: lancer

`;
  let scheme = "https";
  let response = "";
  let sending = false;
  async function send() {
    sending = true;
    try {
      const r = await fetch("/api/v1/repeater", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ request, scheme }),
      });
      const data = await r.json();
      response = `HTTP/1.1 ${data.status}\n` +
        (data.headers || []).map((h) => `${h.name}: ${h.value}`).join("\n") +
        "\n\n" + (data.body || "");
    } catch (e) {
      response = `error: ${e}`;
    } finally {
      sending = false;
    }
  }
</script>

<div class="split">
  <div class="pane">
    <h3>Request</h3>
    <textarea bind:value={request}></textarea>
    <div class="actions">
      <label>scheme <select bind:value={scheme}>
        <option>https</option>
        <option>http</option>
      </select></label>
      <button on:click={send} disabled={sending}>{sending ? "Sending…" : "Send"}</button>
    </div>
  </div>
  <div class="pane">
    <h3>Response</h3>
    <pre>{response || "(no response yet)"}</pre>
  </div>
</div>

<style>
  .split {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 14px;
    height: 100%;
  }
  .pane {
    display: flex;
    flex-direction: column;
    gap: 8px;
    background: #1a1d2b;
    border: 1px solid #292d40;
    border-radius: 8px;
    padding: 12px;
  }
  .pane textarea {
    flex: 1;
    min-height: 0;
  }
  .pane pre {
    background: #0f111a;
    border-radius: 4px;
    padding: 8px;
    overflow: auto;
    flex: 1;
    margin: 0;
    font-size: 12px;
  }
  .actions {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  h3 {
    margin: 0;
    font-size: 12px;
    text-transform: uppercase;
    color: #9aa0bd;
  }
</style>
