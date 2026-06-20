<script>
  const KINDS = [
    { value: "dockerfile", label: "Dockerfile" },
    { value: "compose", label: "Docker Compose" },
    { value: "kubernetes", label: "Kubernetes" },
    { value: "terraform", label: "Terraform" },
  ];

  const PLACEHOLDERS = {
    dockerfile: "FROM nginx:latest\nEXPOSE 80\nENV DB_PASSWORD=secret\nVOLUME /data",
    compose: "services:\n  web:\n    image: nginx\n    ports:\n      - \"8080:80\"",
    kubernetes: "apiVersion: v1\nkind: Service\nmetadata:\n  name: web\nspec:\n  ports:\n    - port: 80",
    terraform: "resource \"aws_security_group\" \"web\" {\n  ingress {\n    from_port = 443\n  }\n}",
  };

  let kind = "dockerfile";
  let body = "";
  let surface = null;
  let error = "";
  let running = false;

  function prettyKey(k) {
    return k.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
  }

  function isEmpty(v) {
    if (v == null) return true;
    if (Array.isArray(v)) return v.length === 0;
    if (typeof v === "object") return Object.keys(v).length === 0;
    return v === "";
  }

  async function parse() {
    if (!body.trim()) return;
    running = true;
    error = "";
    surface = null;
    try {
      const r = await fetch("/api/v1/iac/parse", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ kind, body }),
      });
      if (r.ok) {
        surface = await r.json();
      } else {
        error = (await r.text()) || `Request failed (${r.status})`;
      }
    } catch (e) {
      error = e.message || "Request failed";
    }
    running = false;
  }
</script>

<div class="iac">
  <div class="iac-bar">
    <select bind:value={kind}>
      {#each KINDS as k}<option value={k.value}>{k.label}</option>{/each}
    </select>
    <button on:click={parse} disabled={running || !body.trim()} class="run">
      {running ? "Parsing…" : "Parse"}
    </button>
  </div>

  <div class="iac-body">
    <div class="editor">
      <textarea
        bind:value={body}
        spellcheck="false"
        placeholder={PLACEHOLDERS[kind]}
      ></textarea>
    </div>

    <div class="iac-detail">
      {#if error}
        <pre class="err">{error}</pre>
      {/if}

      {#if surface}
        <h3>Attack surface</h3>
        {#each Object.entries(surface) as [key, val]}
          <div class="field">
            <h4>{prettyKey(key)}</h4>
            {#if isEmpty(val)}
              <div class="empty">—</div>
            {:else if Array.isArray(val)}
              <ul>
                {#each val as item}
                  <li>
                    {#if item !== null && typeof item === "object"}
                      <code>{JSON.stringify(item)}</code>
                    {:else}
                      {item}
                    {/if}
                  </li>
                {/each}
              </ul>
            {:else if val !== null && typeof val === "object"}
              <ul>
                {#each Object.entries(val) as [k, v]}
                  <li><strong>{k}:</strong> {typeof v === "object" ? JSON.stringify(v) : v}</li>
                {/each}
              </ul>
            {:else}
              <div class="scalar">{val}</div>
            {/if}
          </div>
        {/each}
      {:else if !error}
        <div class="empty-state">Paste an IaC file and click Parse to extract attack surface.</div>
      {/if}
    </div>
  </div>
</div>

<style>
  .iac{display:flex;flex-direction:column;height:100%;font-size:13px}
  .iac-bar{padding:8px 12px;border-bottom:1px solid var(--border);display:flex;gap:8px;align-items:center}
  .iac-bar select{padding:4px 8px}
  .run{background:var(--accent);color:white;border:none;padding:5px 14px;border-radius:4px;cursor:pointer;font-weight:600}
  .run:disabled{opacity:0.5;cursor:default}
  .iac-body{flex:1;display:flex;overflow:hidden}
  .editor{width:50%;border-right:1px solid var(--border);display:flex}
  .editor textarea{flex:1;border:none;resize:none;padding:12px;font-family:monospace;font-size:12px;background:var(--bg);color:var(--text);outline:none}
  .iac-detail{flex:1;padding:14px;overflow-y:auto}
  .iac-detail h3{margin:0 0 10px;font-size:14px}
  .field{margin-bottom:12px}
  .field h4{margin:0 0 4px;color:var(--text-muted);font-size:12px}
  .field ul{margin:0 0 0 18px;padding:0}
  .field li{margin-bottom:2px;word-break:break-word}
  .scalar{word-break:break-word}
  .empty{color:var(--text-muted);font-style:italic}
  code{font-family:monospace;font-size:11px;background:var(--bg-hover);padding:1px 5px;border-radius:4px;word-break:break-all}
  .err{background:#fde8e8;color:#c0392b;padding:8px;border-radius:4px;font-size:11px;white-space:pre-wrap;word-break:break-word}
  .empty-state{padding:30px;text-align:center;color:var(--text-muted);font-style:italic}
</style>
