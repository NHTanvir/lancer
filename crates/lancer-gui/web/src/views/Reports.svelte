<script>
  let format = "html";
  let preview = "";
  let downloading = false;
  async function render() {
    downloading = true;
    try {
      const r = await fetch(`/api/v1/report?format=${format}`);
      if (format === "pdf") {
        const blob = await r.blob();
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = "lancer-report.pdf";
        a.click();
      } else {
        preview = await r.text();
      }
    } catch (e) {
      preview = String(e);
    } finally {
      downloading = false;
    }
  }
</script>

<div class="bar">
  <label>Format
    <select bind:value={format}>
      <option>html</option>
      <option>json</option>
      <option>markdown</option>
      <option>sarif</option>
      <option>xml</option>
      <option>pdf</option>
    </select>
  </label>
  <button on:click={render} disabled={downloading}>{downloading ? "…" : "Render"}</button>
</div>

{#if format === "html"}
  <iframe srcdoc={preview} title="report"></iframe>
{:else}
  <pre>{preview || "Render a report to preview here."}</pre>
{/if}

<style>
  .bar {
    display: flex;
    gap: 8px;
    align-items: end;
    margin-bottom: 12px;
  }
  iframe {
    width: 100%;
    height: 80vh;
    background: white;
    border: 1px solid #292d40;
    border-radius: 6px;
  }
  pre {
    background: #0f111a;
    border-radius: 6px;
    padding: 12px;
    overflow: auto;
    max-height: 80vh;
    font-size: 12px;
  }
  label {
    display: flex;
    flex-direction: column;
    font-size: 12px;
    gap: 4px;
  }
</style>
