<script>
  // §22 Mobile testing assistant
  let subtab = "android";

  // Android
  let androidScript = "";
  let androidErr = "";
  let androidLoading = false;

  // iOS
  let iosSteps = "";
  let iosScript = "";
  let iosErr = "";
  let iosLoading = false;

  // Frida
  let fridaKind = "android";
  let fridaScript = "";
  let fridaErr = "";
  let fridaLoading = false;

  let copied = "";

  async function getFrida(kind) {
    try {
      const r = await fetch(`/api/v1/mobile/frida-script?kind=${encodeURIComponent(kind)}`);
      if (!r.ok) throw new Error(await r.text() || `HTTP ${r.status}`);
      const d = await r.json();
      return d.script || "";
    } catch (e) {
      throw new Error(e.message || "request failed");
    }
  }

  async function loadAndroidFrida() {
    androidLoading = true; androidErr = "";
    try { androidScript = await getFrida("android"); }
    catch (e) { androidErr = e.message; }
    androidLoading = false;
  }

  async function loadIosSteps() {
    iosLoading = true; iosErr = "";
    try {
      const r = await fetch("/api/v1/mobile/ios-install-steps?ca_url=http://lancer/ca.pem");
      if (!r.ok) throw new Error(await r.text() || `HTTP ${r.status}`);
      const d = await r.json();
      iosSteps = Array.isArray(d.steps) ? d.steps.join("\n") : (d.steps || "");
    } catch (e) { iosErr = e.message; }
    iosLoading = false;
  }

  async function loadIosFrida() {
    iosLoading = true; iosErr = "";
    try { iosScript = await getFrida("ios"); }
    catch (e) { iosErr = e.message; }
    iosLoading = false;
  }

  async function loadFridaScript() {
    fridaLoading = true; fridaErr = "";
    try { fridaScript = await getFrida(fridaKind); }
    catch (e) { fridaErr = e.message; }
    fridaLoading = false;
  }

  async function copy(text, id) {
    try {
      await navigator.clipboard.writeText(text);
      copied = id;
      setTimeout(() => { if (copied === id) copied = ""; }, 1500);
    } catch {}
  }
</script>

<div class="view mobile">
  <div class="subtabs">
    <button class="subtab" class:active={subtab==="android"} on:click={() => subtab="android"}>Android</button>
    <button class="subtab" class:active={subtab==="ios"} on:click={() => subtab="ios"}>iOS</button>
    <button class="subtab" class:active={subtab==="frida"} on:click={() => subtab="frida"}>Frida</button>
  </div>

  <div class="mb-body">
    {#if subtab === "android"}
      <div class="card">
        <h3>Android proxy & CA setup</h3>
        <ol class="guide">
          <li>On the device, set the Wi-Fi proxy to your host IP and the Lancer proxy port (e.g. <code>8080</code>).</li>
          <li>Browse to <code>http://lancer/ca.pem</code> (or your proxy's CA endpoint) and download the certificate.</li>
          <li>Install it under <em>Settings → Security → Encryption &amp; credentials → Install a certificate → CA certificate</em>.</li>
          <li>Android 7+ ignores user CAs for app traffic. Either run a rooted/emulator image and move the CA into the
            system store, or repackage the APK with a <code>network_security_config</code> that trusts user certs.</li>
          <li>For certificate pinning, use the Frida SSL-pinning bypass below with a rooted device or emulator.</li>
        </ol>
      </div>

      <div class="card">
        <div class="card-bar">
          <h3>Frida SSL-pinning bypass (Android)</h3>
          <button class="btn-primary" on:click={loadAndroidFrida} disabled={androidLoading}>
            {androidLoading ? "Loading…" : "Get script"}
          </button>
        </div>
        {#if androidErr}<div class="err">{androidErr}</div>{/if}
        {#if androidScript}
          <div class="pre-wrap">
            <button class="copy" on:click={() => copy(androidScript, "android")}>{copied==="android" ? "Copied" : "Copy"}</button>
            <pre>{androidScript}</pre>
          </div>
        {/if}
      </div>

    {:else if subtab === "ios"}
      <div class="card">
        <div class="card-bar">
          <h3>iOS CA install steps</h3>
          <button class="btn-primary" on:click={loadIosSteps} disabled={iosLoading}>
            {iosLoading ? "Loading…" : "Show install steps"}
          </button>
        </div>
        {#if iosErr}<div class="err">{iosErr}</div>{/if}
        {#if iosSteps}
          <div class="pre-wrap">
            <button class="copy" on:click={() => copy(iosSteps, "iossteps")}>{copied==="iossteps" ? "Copied" : "Copy"}</button>
            <pre>{iosSteps}</pre>
          </div>
        {/if}
      </div>

      <div class="card">
        <div class="card-bar">
          <h3>Frida SSL-pinning bypass (iOS)</h3>
          <button class="btn-primary" on:click={loadIosFrida} disabled={iosLoading}>
            {iosLoading ? "Loading…" : "Frida bypass (iOS)"}
          </button>
        </div>
        {#if iosScript}
          <div class="pre-wrap">
            <button class="copy" on:click={() => copy(iosScript, "iosfrida")}>{copied==="iosfrida" ? "Copied" : "Copy"}</button>
            <pre>{iosScript}</pre>
          </div>
        {/if}
      </div>

    {:else}
      <div class="card">
        <div class="card-bar">
          <h3>Frida script generator</h3>
          <div class="kind-row">
            <select bind:value={fridaKind}>
              <option value="android">android</option>
              <option value="ios">ios</option>
              <option value="flutter">flutter</option>
            </select>
            <button class="btn-primary" on:click={loadFridaScript} disabled={fridaLoading}>
              {fridaLoading ? "Loading…" : "Get script"}
            </button>
          </div>
        </div>
        {#if fridaErr}<div class="err">{fridaErr}</div>{/if}
        {#if fridaScript}
          <div class="pre-wrap">
            <button class="copy" on:click={() => copy(fridaScript, "frida")}>{copied==="frida" ? "Copied" : "Copy"}</button>
            <pre>{fridaScript}</pre>
          </div>
        {:else if !fridaErr}
          <div class="empty-state">Pick a target runtime and generate a Frida hook script.</div>
        {/if}
      </div>
    {/if}
  </div>
</div>

<style>
  .mobile{display:flex;flex-direction:column;height:100%;font-size:13px}
  .mb-body{flex:1;overflow-y:auto;padding:14px;display:flex;flex-direction:column;gap:14px}
  .card{border:1px solid var(--border);border-radius:6px;padding:12px}
  .card h3{margin:0 0 8px;font-size:14px}
  .card-bar{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}
  .card-bar h3{margin:0}
  .kind-row{display:flex;gap:6px;align-items:center}
  .kind-row select{padding:5px 8px}
  .guide{margin:6px 0 0 18px;padding:0;line-height:1.6}
  .guide li{margin-bottom:4px}
  .guide code{font-family:monospace;background:var(--bg-hover);padding:1px 5px;border-radius:4px;font-size:11px}
  .pre-wrap{position:relative;margin-top:10px}
  .pre-wrap pre{margin:0;background:var(--bg-hover);border:1px solid var(--border);border-radius:6px;padding:12px;
    font-family:monospace;font-size:11px;line-height:1.5;white-space:pre-wrap;word-break:break-word;overflow-x:auto;max-height:480px}
  .copy{position:absolute;top:8px;right:8px;background:var(--bg);border:1px solid var(--border);
    border-radius:4px;padding:2px 10px;cursor:pointer;font-size:11px;font-weight:600}
  .copy:hover{background:var(--bg-hover)}
  .err{margin-top:8px;background:#fde8e8;color:#c0392b;padding:6px 8px;border-radius:4px;font-size:11px}
</style>
