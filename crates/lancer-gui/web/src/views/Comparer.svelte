<script>
  import { onMount, tick } from "svelte";

  let item1 = "";
  let item2 = "";
  let diffMode = "words";
  let diffOutput = [];
  let softWrap = true;
  let syncScroll = true;
  let diffIdx = -1;   // current diff chunk index for prev/next nav
  let diffEl;          // ref to diff output container
  let item1El;         // ref to left textarea
  let item2El;         // ref to right textarea

  function computeDiff() {
    if (!item1 && !item2) { diffOutput = []; diffIdx = -1; return; }
    const seqA = diffMode === "words" ? item1.split(/(\s+)/) : [...item1];
    const seqB = diffMode === "words" ? item2.split(/(\s+)/) : [...item2];
    diffOutput = computeSeqDiff(seqA, seqB);
    diffIdx = -1;
  }

  function computeSeqDiff(a, b) {
    const m = Math.min(a.length, 200);
    const n = Math.min(b.length, 200);
    const dp = Array.from({ length: m + 1 }, () => new Uint16Array(n + 1));
    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        if (a[i-1] === b[j-1]) dp[i][j] = dp[i-1][j-1] + 1;
        else dp[i][j] = Math.max(dp[i-1][j], dp[i][j-1]);
      }
    }
    const result = [];
    let i = m, j = n;
    while (i > 0 || j > 0) {
      if (i > 0 && j > 0 && a[i-1] === b[j-1]) {
        result.unshift({ type: "same", text: a[i-1] }); i--; j--;
      } else if (j > 0 && (i === 0 || dp[i][j-1] >= dp[i-1][j])) {
        result.unshift({ type: "add", text: b[j-1] }); j--;
      } else {
        result.unshift({ type: "del", text: a[i-1] }); i--;
      }
    }
    if (a.length > m) result.push({ type: "del", text: `...(${a.length - m} more)` });
    if (b.length > n) result.push({ type: "add", text: `...(${b.length - n} more)` });
    return result;
  }

  $: if (item1 !== undefined || item2 !== undefined || diffMode) computeDiff();

  $: stats = {
    same:    diffOutput.filter(d => d.type === "same").length,
    added:   diffOutput.filter(d => d.type === "add").length,
    removed: diffOutput.filter(d => d.type === "del").length,
  };

  $: diffChunkIndices = diffOutput
    .map((d, i) => d.type !== "same" ? i : -1)
    .filter(i => i >= 0);

  function paste(target) {
    navigator.clipboard.readText().then(t => {
      if (target === 1) item1 = t;
      else item2 = t;
    }).catch(() => {});
  }

  async function jumpToDiff(idx) {
    if (!diffChunkIndices.length || !diffEl) return;
    diffIdx = idx;
    await tick();
    const chunks = diffEl.querySelectorAll(".chunk-add, .chunk-del");
    const target = chunks[diffIdx];
    if (target) target.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  function prevDiff() {
    if (!diffChunkIndices.length) return;
    diffIdx = diffIdx <= 0 ? diffChunkIndices.length - 1 : diffIdx - 1;
    jumpToDiff(diffIdx);
  }
  function nextDiff() {
    if (!diffChunkIndices.length) return;
    diffIdx = diffIdx >= diffChunkIndices.length - 1 ? 0 : diffIdx + 1;
    jumpToDiff(diffIdx);
  }

  // Sync scroll between two input textareas
  function onItem1Scroll() {
    if (!syncScroll || !item2El) return;
    item2El.scrollTop = item1El.scrollTop;
    item2El.scrollLeft = item1El.scrollLeft;
  }
  function onItem2Scroll() {
    if (!syncScroll || !item1El) return;
    item1El.scrollTop = item2El.scrollTop;
    item1El.scrollLeft = item2El.scrollLeft;
  }

  onMount(() => {
    try {
      const s = localStorage.getItem("lancer.comparer");
      if (s) {
        const v = JSON.parse(s);
        if (typeof v.softWrap === "boolean") softWrap = v.softWrap;
        if (typeof v.syncScroll === "boolean") syncScroll = v.syncScroll;
      }
    } catch {}
    try {
      const raw = localStorage.getItem("lancer.send.comparer");
      if (raw) {
        const v = JSON.parse(raw);
        if (v.item1) item1 = v.item1;
        if (v.item2) item2 = v.item2;
        localStorage.removeItem("lancer.send.comparer");
      }
    } catch {}
  });

  $: try { localStorage.setItem("lancer.comparer", JSON.stringify({ softWrap, syncScroll })); } catch {}
</script>

<div class="view">
  <!-- Bottom toolbar for mode + stats -->
  <div class="bottom-toolbar">
    <div class="mode-group">
      <button class="mode-btn" class:mode-active={diffMode==="words"} on:click={() => diffMode="words"}>Words</button>
      <button class="mode-btn" class:mode-active={diffMode==="bytes"} on:click={() => diffMode="bytes"}>Bytes</button>
    </div>
    <label class="check-label"><input type="checkbox" bind:checked={softWrap} /> Soft wrap</label>
    <label class="check-label"><input type="checkbox" bind:checked={syncScroll} /> Sync scroll</label>
    <div class="nav-group">
      <button class="sm-btn" on:click={prevDiff} disabled={diffChunkIndices.length === 0} title="Previous diff">◀ Prev</button>
      <span class="dim" style="font-size:11px;padding:0 6px">
        {diffIdx >= 0 ? (diffIdx + 1) : 0} / {diffChunkIndices.length}
      </span>
      <button class="sm-btn" on:click={nextDiff} disabled={diffChunkIndices.length === 0} title="Next diff">Next ▶</button>
    </div>
    {#if diffOutput.length > 0}
      <div class="diff-stats">
        <span class="stat-same">= {stats.same} same</span>
        <span class="stat-add">+ {stats.added} added</span>
        <span class="stat-del">- {stats.removed} removed</span>
      </div>
    {/if}
  </div>

  <!-- Two input panes side by side -->
  <div class="input-row">
    <div class="input-pane">
      <div class="pane-header">
        <span>Item 1</span>
        <button class="sm-btn" on:click={() => paste(1)}>Paste</button>
      </div>
      <textarea
        class="item-area"
        class:no-wrap={!softWrap}
        bind:value={item1}
        bind:this={item1El}
        on:scroll={onItem1Scroll}
        placeholder="Paste first item here..."
        spellcheck="false"
      ></textarea>
    </div>
    <div class="input-pane">
      <div class="pane-header">
        <span>Item 2</span>
        <button class="sm-btn" on:click={() => paste(2)}>Paste</button>
      </div>
      <textarea
        class="item-area"
        class:no-wrap={!softWrap}
        bind:value={item2}
        bind:this={item2El}
        on:scroll={onItem2Scroll}
        placeholder="Paste second item here..."
        spellcheck="false"
      ></textarea>
    </div>
  </div>

  <!-- Diff output pane -->
  <div class="diff-section">
    <div class="diff-header">
      <span class="diff-header-label">Diff output</span>
      {#if !item1 && !item2}
        <span class="dim" style="font-size:12px">Enter text in both panes above to compare</span>
      {:else if diffOutput.every(d => d.type === "same")}
        <span style="color:#1b8c1b;font-size:12px">Items are identical</span>
      {/if}
    </div>
    <div class="diff-output" bind:this={diffEl}>
      {#if diffOutput.length > 0}
        <div class="diff-inline" class:no-wrap={!softWrap}>
          {#each diffOutput as chunk, ci}
            {@const navIdx = diffChunkIndices.indexOf(ci)}
            {#if chunk.type === "same"}
              <span class="chunk-same">{chunk.text}</span>
            {:else if chunk.type === "add"}
              <span class="chunk-add" class:chunk-current={navIdx === diffIdx}>{chunk.text}</span>
            {:else}
              <span class="chunk-del" class:chunk-current={navIdx === diffIdx}>{chunk.text}</span>
            {/if}
          {/each}
        </div>
      {:else if item1 || item2}
        <div class="empty-state-sm">
          <span style="color:#1b8c1b">Items are identical</span>
        </div>
      {:else}
        <div class="empty-state-sm dim">No comparison yet</div>
      {/if}
    </div>
  </div>
</div>

<style>
  /* Bottom mode toolbar */
  .bottom-toolbar {
    display: flex; align-items: center; gap: 12px;
    padding: 6px 12px;
    background: #f5f5f5;
    border-bottom: 1px solid #dedede;
    flex-shrink: 0;
  }
  .mode-group { display: flex; gap: 0; }
  .mode-btn {
    font-size: 13px; padding: 4px 14px;
    background: #f0f0f0; color: #333;
    border: 1px solid #c8c8c8; border-radius: 0;
    cursor: pointer;
  }
  .mode-btn:first-child { border-radius: 3px 0 0 3px; }
  .mode-btn:last-child  { border-radius: 0 3px 3px 0; border-left: none; }
  .mode-btn:hover { background: #e4e4e4; }
  .mode-active { background: #fce8e2 !important; color: #e03a00 !important; border-color: #e03a00 !important; z-index: 1; }

  .diff-stats { display: flex; gap: 12px; font-size: 12px; }
  .stat-same { color: #767676; }
  .stat-add  { color: #1b8c1b; font-weight: 600; }
  .stat-del  { color: #d42c2c; font-weight: 600; }

  /* Input panes */
  .input-row {
    display: grid; grid-template-columns: 1fr 1fr;
    flex: 1; overflow: hidden; min-height: 0;
  }
  .input-pane {
    display: flex; flex-direction: column;
    border-right: 1px solid #dedede;
    overflow: hidden;
  }
  .input-pane:last-child { border-right: none; }
  .pane-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 5px 10px;
    background: #f5f5f5;
    border-bottom: 1px solid #dedede;
    font-size: 12px; font-weight: 600; color: #444;
    flex-shrink: 0;
  }
  .sm-btn {
    font-size: 11px; padding: 2px 8px;
    background: #f0f0f0; color: #333;
    border: 1px solid #c8c8c8; border-radius: 3px; cursor: pointer;
    font-weight: 400;
  }
  .sm-btn:hover { background: #e4e4e4; }
  .item-area {
    flex: 1; resize: none;
    border: none; border-radius: 0;
    background: #ffffff; color: #212121;
    font-size: 12px; padding: 10px;
    min-height: 0; outline: none;
    font-family: ui-monospace, "Cascadia Code", Consolas, monospace;
    height: 100%;
  }
  .item-area:focus { outline: none; }

  /* Diff output */
  .diff-section {
    height: 200px; flex-shrink: 0;
    display: flex; flex-direction: column;
    overflow: hidden;
    border-top: 2px solid #dedede;
  }
  .diff-header {
    display: flex; align-items: center; gap: 12px;
    padding: 5px 12px;
    background: #f5f5f5;
    border-bottom: 1px solid #dedede;
    flex-shrink: 0;
  }
  .diff-header-label {
    font-size: 11px; font-weight: 700;
    text-transform: uppercase; letter-spacing: 0.06em;
    color: #767676;
  }
  .diff-output {
    flex: 1; overflow-y: auto;
    padding: 10px 14px;
    background: #ffffff;
  }
  .diff-inline {
    font-size: 12px;
    font-family: ui-monospace, Consolas, monospace;
    line-height: 1.7;
    word-break: break-all;
    white-space: pre-wrap;
  }
  .chunk-same { color: #444; }
  .chunk-add  { background: #eaf5ea; color: #1b8c1b; border-radius: 2px; }
  .chunk-del  { background: #fde8e8; color: #d42c2c; border-radius: 2px; text-decoration: line-through; }
  .chunk-current { outline: 2px solid #e03a00; box-shadow: 0 0 0 2px rgba(224,58,0,0.15); }
  .empty-state-sm {
    display: flex; align-items: center; justify-content: center;
    height: 80px; color: #767676; font-size: 13px;
  }
  .no-wrap { white-space: pre !important; word-break: normal !important; overflow-x: auto !important; }
  .check-label { display: flex; align-items: center; gap: 4px; font-size: 12px; color: #444; cursor: pointer; }
  .check-label input { accent-color: #e03a00; cursor: pointer; }
  .nav-group { display: flex; align-items: center; gap: 2px; margin-left: auto; }
  .nav-group .sm-btn { font-size: 11px; padding: 2px 8px; }
  .nav-group .sm-btn:disabled { opacity: 0.4; cursor: not-allowed; }
</style>
