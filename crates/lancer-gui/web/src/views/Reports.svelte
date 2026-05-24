<script>
  let format = "html";
  let preview = "";
  let loading = false;
  let error = "";

  const formats = [
    { value: "html",     label: "HTML" },
    { value: "json",     label: "JSON" },
    { value: "markdown", label: "Markdown" },
    { value: "sarif",    label: "SARIF" },
    { value: "xml",      label: "XML" },
  ];

  async function render() {
    loading = true;
    error = "";
    preview = "";
    try {
      const r = await fetch(`/api/v1/report?format=${format}`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      preview = await r.text();
    } catch (e) {
      error = `Failed to render report: ${e.message || e}`;
    } finally {
      loading = false;
    }
  }

  function download() {
    if (!preview) return;
    const ext = { html: "html", json: "json", markdown: "md", sarif: "json", xml: "xml" }[format] || "txt";
    const mime = format === "html" ? "text/html" : format === "json" || format === "sarif" ? "application/json" : "text/plain";
    const blob = new Blob([preview], { type: mime });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `lancer-report.${ext}`;
    a.click();
    URL.revokeObjectURL(a.href);
  }
</script>

<div class="view">
  <div class="rep-toolbar">
    <span class="toolbar-label">Format</span>
    <div class="format-tabs">
      {#each formats as f}
        <button
          class="fmt-btn"
          class:fmt-active={format === f.value}
          on:click={() => { format = f.value; preview = ""; error = ""; }}
        >{f.label}</button>
      {/each}
    </div>
    <button class="btn-orange" on:click={render} disabled={loading}>
      {loading ? "Rendering..." : "Render report"}
    </button>
    <button class="btn-secondary" on:click={download} disabled={!preview}>
      Download
    </button>
  </div>

  <div class="preview-area">
    {#if error}
      <div class="error-state">
        <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
          <circle cx="10" cy="10" r="9" stroke="#d42c2c" stroke-width="1.5"/>
          <path d="M10 6v5" stroke="#d42c2c" stroke-width="1.5" stroke-linecap="round"/>
          <circle cx="10" cy="14" r="0.8" fill="#d42c2c"/>
        </svg>
        <span>{error}</span>
      </div>
    {:else if loading}
      <div class="empty-state">
        <div class="spinner"></div>
        <span>Generating report...</span>
      </div>
    {:else if preview && format === "html"}
      <iframe title="Report preview" srcdoc={preview} class="html-frame" sandbox="allow-same-origin"></iframe>
    {:else if preview}
      <pre class="text-preview">{preview}</pre>
    {:else}
      <div class="empty-state">
        <!-- Document icon -->
        <svg width="52" height="52" viewBox="0 0 52 52" fill="none">
          <rect x="10" y="6" width="32" height="40" rx="3" stroke="#c8c8c8" stroke-width="1.5" fill="#f5f5f5"/>
          <path d="M17 18 L35 18" stroke="#c8c8c8" stroke-width="1.3" stroke-linecap="round"/>
          <path d="M17 24 L35 24" stroke="#c8c8c8" stroke-width="1.3" stroke-linecap="round"/>
          <path d="M17 30 L28 30" stroke="#c8c8c8" stroke-width="1.3" stroke-linecap="round"/>
        </svg>
        <span style="font-weight:500;color:#444">No report generated yet</span>
        <span class="dim" style="font-size:12px">Select a format and click "Render report"</span>
      </div>
    {/if}
  </div>
</div>

<style>
  .rep-toolbar {
    display: flex; align-items: center; gap: 8px;
    padding: 6px 12px;
    background: #f5f5f5;
    border-bottom: 1px solid #dedede;
    flex-shrink: 0;
  }
  .toolbar-label { font-size: 13px; color: #444; }
  .format-tabs { display: flex; gap: 0; }
  .fmt-btn {
    font-size: 13px; padding: 4px 12px;
    background: #f0f0f0; color: #333;
    border: 1px solid #c8c8c8; border-radius: 0;
    cursor: pointer;
  }
  .fmt-btn:first-child { border-radius: 3px 0 0 3px; }
  .fmt-btn:last-child  { border-radius: 0 3px 3px 0; }
  .fmt-btn + .fmt-btn  { border-left: none; }
  .fmt-btn:hover { background: #e4e4e4; }
  .fmt-active {
    background: #fce8e2 !important;
    border-color: #e03a00 !important;
    color: #e03a00 !important;
    z-index: 1;
  }

  .btn-orange {
    background: #e03a00; color: #fff;
    border: none; border-radius: 3px;
    padding: 5px 14px; font-size: 13px; cursor: pointer;
  }
  .btn-orange:hover:not(:disabled) { background: #c73400; }
  .btn-orange:disabled { opacity: 0.5; cursor: not-allowed; }
  .btn-secondary {
    background: #f0f0f0; color: #333;
    border: 1px solid #c8c8c8; border-radius: 3px;
    padding: 5px 12px; font-size: 13px; cursor: pointer;
  }
  .btn-secondary:hover:not(:disabled) { background: #e4e4e4; }
  .btn-secondary:disabled { opacity: 0.5; cursor: not-allowed; }

  .preview-area {
    flex: 1; overflow: hidden;
    display: flex; flex-direction: column;
    background: #ffffff;
  }
  .html-frame { flex: 1; border: none; background: white; }
  .text-preview {
    flex: 1; margin: 0;
    padding: 14px 16px;
    background: #fafafa;
    color: #212121;
    font-size: 12px;
    font-family: ui-monospace, "Cascadia Code", Consolas, monospace;
    overflow: auto;
    white-space: pre-wrap;
    word-break: break-all;
    border: none;
  }

  .empty-state {
    flex: 1; display: flex; flex-direction: column;
    align-items: center; justify-content: center;
    gap: 12px; padding: 40px; text-align: center;
  }
  .error-state {
    flex: 1; display: flex;
    align-items: center; justify-content: center;
    gap: 10px; color: #d42c2c; font-size: 13px;
    padding: 24px;
  }

  .spinner {
    width: 28px; height: 28px;
    border: 2px solid #dedede;
    border-top-color: #e03a00;
    border-radius: 50%;
    animation: spin 0.7s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
