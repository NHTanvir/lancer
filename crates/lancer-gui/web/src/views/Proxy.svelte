<script>
  import { onMount } from "svelte";
  let listening = false;
  let listen = "127.0.0.1:8080";
  let intercept = false;
  let stats = { hosts: 0, requests: 0 };

  onMount(async () => {
    try {
      const r = await fetch("/api/status");
      if (r.ok) listening = true;
    } catch {}
  });
</script>

<div class="grid">
  <div class="card">
    <h3>Listener</h3>
    <div class="row">
      <input bind:value={listen} />
      <button>{listening ? "Stop" : "Start"}</button>
    </div>
    <label>
      <input type="checkbox" bind:checked={intercept} />
      Intercept on
    </label>
  </div>
  <div class="card">
    <h3>CA certificate</h3>
    <p class="dim">
      Visit <code>http://lancer/ca</code> from the proxied browser to download the
      root certificate, then trust it in your OS keychain.
    </p>
    <button>Export DER</button>
    <button>Export PEM</button>
  </div>
  <div class="card">
    <h3>Traffic</h3>
    <p class="big">{stats.requests}</p>
    <p class="dim">requests · {stats.hosts} hosts</p>
  </div>
</div>

<style>
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 14px;
  }
  .card {
    background: #1a1d2b;
    border: 1px solid #292d40;
    border-radius: 8px;
    padding: 14px 16px;
  }
  .row {
    display: flex;
    gap: 8px;
    align-items: center;
    margin: 8px 0;
  }
  .row input {
    flex: 1;
  }
  .dim {
    color: #6a7090;
    font-size: 12px;
  }
  .big {
    font-size: 28px;
    font-weight: 600;
    margin: 0;
  }
  code {
    background: #0f111a;
    padding: 1px 6px;
    border-radius: 3px;
  }
  h3 {
    margin: 0 0 8px;
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: #9aa0bd;
  }
</style>
