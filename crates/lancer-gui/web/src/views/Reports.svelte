<script>
  let format = "html";
  let preview = "";
  let pdfUrl = "";        // object URL for the binary PDF preview/download
  let loading = false;
  let error = "";

  const formats = [
    { value: "html",     label: "HTML" },
    { value: "pdf",      label: "PDF" },
    { value: "json",     label: "JSON" },
    { value: "markdown", label: "Markdown" },
    { value: "sarif",    label: "SARIF" },
    { value: "xml",      label: "XML" },
    { value: "jira",     label: "Jira" },
    { value: "linear",   label: "Linear" },
    { value: "github",   label: "GitHub" },
    { value: "defectdojo", label: "DefectDojo" },
    { value: "faraday",  label: "Faraday CSV" },
  ];

  function clearPdf() { if (pdfUrl) { URL.revokeObjectURL(pdfUrl); pdfUrl = ""; } }

  async function render() {
    loading = true;
    error = "";
    preview = "";
    clearPdf();
    try {
      const r = await fetch(`/api/v1/report?format=${format}`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      if (format === "pdf") {
        // PDF is binary — read as a blob and preview it via an object URL.
        const blob = await r.blob();
        pdfUrl = URL.createObjectURL(blob);
        preview = "(pdf)";
      } else {
        preview = await r.text();
      }
    } catch (e) {
      error = `Failed to render report: ${e.message || e}`;
    } finally {
      loading = false;
    }
  }

  function download() {
    if (format === "pdf") {
      if (!pdfUrl) return;
      const a = document.createElement("a");
      a.href = pdfUrl;
      a.download = "lancer-report.pdf";
      a.click();
      return;
    }
    if (!preview) return;
    const ext = { html: "html", json: "json", markdown: "md", sarif: "json", xml: "xml", jira: "json", linear: "json", github: "json", defectdojo: "json", faraday: "csv" }[format] || "txt";
    const mime = format === "html" ? "text/html" : format === "faraday" ? "text/csv" : ["json","sarif","jira","linear","github","defectdojo"].includes(format) ? "application/json" : "text/plain";
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
          on:click={() => { format = f.value; preview = ""; error = ""; clearPdf(); }}
        >{f.label}</button>
      {/each}
    </div>
    <button class="btn-orange" on:click={render} disabled={loading}>
      {loading ? "Rendering..." : "Render report"}
    </button>
    <button class="btn-secondary" on:click={download} disabled={!preview && !pdfUrl}>
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
    {:else if format === "pdf" && pdfUrl}
      <iframe title="Report preview" src={pdfUrl} class="html-frame"></iframe>
    {:else if preview && format === "html"}
      <iframe title="Report preview" srcdoc={preview} class="html-frame" sandbox="allow-same-origin"></iframe>
    {:else if preview}
      <pre class="text-preview">{preview}</pre>
    {:else}
      <div class="empty-state">
        <!-- Document icon -->
        <svg width="52" height="52" viewBox="0 0 52 52" fill="none">
          <rect x="10" y="6" width="32" height="40" rx="3" stroke="#d5dae1" stroke-width="1.5" fill="#f1f3f6"/>
          <path d="M17 18 L35 18" stroke="#d5dae1" stroke-width="1.3" stroke-linecap="round"/>
          <path d="M17 24 L35 24" stroke="#d5dae1" stroke-width="1.3" stroke-linecap="round"/>
          <path d="M17 30 L28 30" stroke="#d5dae1" stroke-width="1.3" stroke-linecap="round"/>
        </svg>
        <span style="font-weight:500;color:#434a54">No report generated yet</span>
        <span class="dim" style="font-size:12px">Select a format and click "Render report"</span>
      </div>
    {/if}
  </div>
</div>

<style>
  .rep-toolbar {
    display: flex; align-items: center; gap: 8px;
    padding: 6px 12px;
    background: var(--surface-2);
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }
  .toolbar-label { font-size: 13px; color: var(--text-2); }
  .format-tabs { display: flex; gap: 0; }
  .fmt-btn {
    font-size: 13px; padding: 4px 12px;
    background: var(--surface-2); color: var(--text);
    border: 1px solid var(--border-strong); border-radius: 0;
    cursor: pointer;
  }
  .fmt-btn:first-child { border-radius: 3px 0 0 3px; }
  .fmt-btn:last-child  { border-radius: 0 3px 3px 0; }
  .fmt-btn + .fmt-btn  { border-left: none; }
  .fmt-btn:hover { background: var(--surface-3); }
  .fmt-active {
    background: var(--accent-soft) !important;
    border-color: var(--accent) !important;
    color: var(--accent) !important;
    z-index: 1;
  }

  .btn-orange {
    background: var(--accent); color: #fff;
    border: none; border-radius: 3px;
    padding: 5px 14px; font-size: 13px; cursor: pointer;
  }
  .btn-orange:hover:not(:disabled) { background: var(--accent-hover); }
  .btn-orange:disabled { opacity: 0.5; cursor: not-allowed; }
  .btn-secondary {
    background: var(--surface-2); color: var(--text);
    border: 1px solid var(--border-strong); border-radius: 3px;
    padding: 5px 12px; font-size: 13px; cursor: pointer;
  }
  .btn-secondary:hover:not(:disabled) { background: var(--surface-3); }
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
    background: var(--surface-1);
    color: var(--text);
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
    border: 2px solid var(--border);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.7s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
