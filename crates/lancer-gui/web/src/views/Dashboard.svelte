<script>
  import { onMount, onDestroy } from "svelte";

  let tasks = [
    { id: 1, label: "Live passive crawl from Proxy (all traffic)", type: "passive", status: "running" },
  ];
  let selectedTask = tasks[0];
  let historyRows = [];
  let issues = [];
  let pollInterval = null;
  let issueCounts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  let requestCount = 0;
  let taskLogOpen = true;
  let eventLog = [];

  function statusClass(s) {
    if (!s) return "dim";
    if (s >= 500) return "status-5";
    if (s >= 400) return "status-4";
    if (s >= 300) return "status-3";
    if (s >= 200) return "status-2";
    return "dim";
  }

  function methodClass(m) {
    return "method-" + (m || "GET");
  }

  async function fetchHistory() {
    try {
      const r = await fetch("/api/v1/history?limit=200");
      if (r.ok) {
        historyRows = await r.json();
        requestCount = historyRows.length;
      }
    } catch {
      historyRows = [];
    }
  }

  async function fetchIssues() {
    try {
      const r = await fetch("/api/v1/issues");
      if (r.ok) {
        const data = await r.json();
        const arr = Array.isArray(data) ? data : (data.issues || data || []);
        issues = arr;
        issueCounts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
        for (const iss of issues) {
          if (issueCounts[iss.severity] !== undefined) issueCounts[iss.severity]++;
        }
      }
    } catch {
      issues = [];
    }
  }

  async function newScan() {
    try {
      await fetch("/api/v1/scan/passive", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({}) });
      const id = tasks.length + 1;
      tasks = [...tasks, { id, label: `Passive scan #${id}`, type: "passive", status: "running" }];
      addEvent("Started passive scan #" + id);
    } catch (e) {
      addEvent("Failed to start scan: " + e.message);
    }
  }

  async function newLiveTask() {
    const id = tasks.length + 1;
    tasks = [...tasks, { id, label: `Live task #${id}`, type: "live", status: "running" }];
    addEvent("Started live task #" + id);
  }

  function addEvent(msg) {
    const now = new Date().toLocaleTimeString();
    eventLog = [{ time: now, msg }, ...eventLog].slice(0, 50);
  }

  onMount(() => {
    fetchHistory();
    fetchIssues();
    pollInterval = setInterval(() => {
      fetchHistory();
      fetchIssues();
    }, 5000);
    addEvent("Dashboard loaded — polling every 5s");
  });

  onDestroy(() => {
    if (pollInterval) clearInterval(pollInterval);
  });
</script>

<div class="view dash-view">
  <div class="dash-body">
    <!-- LEFT: Tasks panel -->
    <div class="dash-left">
      <div class="panel-header">Tasks</div>
      <div class="dash-btns">
        <button class="btn-orange" on:click={newScan}>New scan</button>
        <button class="btn-secondary" on:click={newLiveTask}>New live task</button>
      </div>
      <div class="task-divider"></div>
      <div class="task-list">
        {#each tasks as task}
          <div
            class="task-item"
            class:task-selected={selectedTask === task}
            on:click={() => selectedTask = task}
            role="button"
            tabindex="0"
            on:keydown={e => e.key === "Enter" && (selectedTask = task)}
          >
            <div class="task-bullet">
              <span class="task-dot {task.status === 'running' ? 'dot-on' : 'dot-off'}"></span>
            </div>
            <div class="task-info">
              <span class="task-num">{task.id}.</span>
              <span class="task-label">{task.label}</span>
            </div>
            <div class="task-toggle-wrap">
              <span class="task-toggle {task.status === 'running' ? 'toggle-on' : 'toggle-off'}">
                {task.status === "running" ? "ON" : "OFF"}
              </span>
            </div>
          </div>
        {/each}
      </div>
    </div>

    <!-- CENTER: History / Site map -->
    <div class="dash-center">
      {#if selectedTask}
        <div class="center-topbar">
          <span class="breadcrumb dim">← back</span>
          <span class="center-title">{selectedTask.label}</span>
        </div>
        <div class="subtabs">
          <button class="subtab active">Summary</button>
        </div>
        <div class="center-section-label">
          Items added to site map
          <a class="view-link" href="#sitemap">View site map →</a>
        </div>
        <div class="table-wrap">
          {#if historyRows.length > 0}
            <table class="data-table">
              <thead>
                <tr>
                  <th>Host</th>
                  <th>Method</th>
                  <th>URL</th>
                  <th>Status</th>
                  <th>MIME type</th>
                </tr>
              </thead>
              <tbody>
                {#each historyRows as row, i}
                  <tr class:row-even={i % 2 === 0}>
                    <td>{row.host || "-"}</td>
                    <td class={methodClass(row.method)}>{row.method || "-"}</td>
                    <td class="url-cell" title={row.path}>{row.path && row.path.length > 60 ? row.path.slice(0, 60) + "..." : (row.path || "/")}</td>
                    <td class={statusClass(row.status)}>{row.status || "-"}</td>
                    <td class="dim">{row.mime_type || "-"}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          {:else}
            <div class="empty-state">
              <!-- Stacked boxes SVG -->
              <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
                <rect x="8" y="20" width="32" height="20" rx="2" stroke="#c8c8c8" stroke-width="1.5" fill="#f5f5f5"/>
                <rect x="12" y="14" width="24" height="8" rx="2" stroke="#c8c8c8" stroke-width="1.5" fill="#f5f5f5"/>
                <rect x="16" y="8" width="16" height="8" rx="2" stroke="#c8c8c8" stroke-width="1.5" fill="#f5f5f5"/>
              </svg>
              <span style="font-weight:500;color:#444">No items to show</span>
              <span class="dim" style="font-size:12px">Items found in the crawl will display here.</span>
            </div>
          {/if}
        </div>

        <div class="center-section-divider">— HISTORY —</div>
        <div class="history-note dim" style="font-size:12px;padding:6px 14px">
          {historyRows.length} requests captured · polling every 5s
        </div>
      {:else}
        <div class="empty-state">
          <span>Select a task to view details</span>
        </div>
      {/if}
    </div>

    <!-- RIGHT: Task configuration -->
    <div class="dash-right">
      <div class="right-section">
        <div class="right-header">
          Task configuration
          <a class="view-link" href="#config">View configuration →</a>
        </div>
        {#if selectedTask}
          <div class="config-row">
            <span class="config-label">Task type</span>
            <span class="config-value">{selectedTask.type === "passive" ? "Live passive crawl" : "Live capture"}</span>
          </div>
          <div class="config-row">
            <span class="config-label">Scope</span>
            <span class="config-value">Proxy (all traffic)</span>
          </div>
          <div class="config-row">
            <span class="config-label">Capturing</span>
            <span class="config-toggle {selectedTask.status === 'running' ? 'toggle-on' : 'toggle-off'}">
              {selectedTask.status === "running" ? "ON" : "OFF"}
            </span>
          </div>
        {:else}
          <div class="dim" style="font-size:12px;padding:8px 0">No task selected</div>
        {/if}
      </div>

      <div class="right-divider"></div>

      <div class="right-section">
        <div class="right-header">Task progress</div>
        <div class="stat-row">
          <span class="stat-label">Site map items added</span>
          <span class="stat-value">0</span>
        </div>
        <div class="stat-row">
          <span class="stat-label">Responses processed</span>
          <span class="stat-value">{requestCount}</span>
        </div>
        <div class="stat-row">
          <span class="stat-label">Responses queued</span>
          <span class="stat-value">0</span>
        </div>
        <div class="stat-row">
          <span class="stat-label">Issues found</span>
          <span class="stat-value">{issues.length}</span>
        </div>
      </div>

      <div class="right-divider"></div>

      <div class="right-section">
        <div
          class="right-header collapsible"
          on:click={() => taskLogOpen = !taskLogOpen}
          role="button"
          tabindex="0"
          on:keydown={e => e.key === "Enter" && (taskLogOpen = !taskLogOpen)}
        >
          Task log
          <span class="collapse-arrow">{taskLogOpen ? "▲" : "▼"}</span>
        </div>
        {#if taskLogOpen}
          <div class="task-log">
            {#each eventLog as ev}
              <div class="log-item">
                <span class="dim log-time">{ev.time}</span>
                <span class="log-msg">{ev.msg}</span>
              </div>
            {/each}
            {#if eventLog.length === 0}
              <span class="dim" style="font-size:12px">No events</span>
            {/if}
          </div>
        {/if}
      </div>
    </div>
  </div>
</div>

<style>
  .dash-view { overflow: hidden; }
  .dash-body {
    display: flex;
    flex: 1;
    overflow: hidden;
    min-height: 0;
  }

  /* LEFT */
  .dash-left {
    width: 220px;
    flex-shrink: 0;
    background: #ffffff;
    border-right: 1px solid #dedede;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  .panel-header {
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.07em;
    color: #767676;
    padding: 10px 12px 6px;
    flex-shrink: 0;
  }
  .dash-btns {
    display: flex; flex-direction: column; gap: 5px;
    padding: 0 10px 8px;
    flex-shrink: 0;
  }
  .btn-orange {
    background: #e03a00;
    color: #ffffff;
    border: none;
    border-radius: 3px;
    padding: 5px 12px;
    font-size: 13px;
    cursor: pointer;
    text-align: left;
  }
  .btn-orange:hover { background: #c73400; }
  .btn-secondary {
    background: #f0f0f0;
    color: #333;
    border: 1px solid #c8c8c8;
    border-radius: 3px;
    padding: 5px 12px;
    font-size: 13px;
    cursor: pointer;
    text-align: left;
  }
  .btn-secondary:hover { background: #e4e4e4; }
  .task-divider {
    height: 1px; background: #dedede;
    margin: 0; flex-shrink: 0;
  }
  .task-list {
    flex: 1; overflow-y: auto;
  }
  .task-item {
    display: flex; align-items: flex-start; gap: 6px;
    padding: 8px 10px;
    cursor: pointer;
    border-bottom: 1px solid #f0f0f0;
    font-size: 12px;
    line-height: 1.4;
  }
  .task-item:hover { background: #f0f7ff; }
  .task-selected { background: #daeeff !important; }
  .task-bullet { padding-top: 3px; flex-shrink: 0; }
  .task-dot {
    display: inline-block;
    width: 8px; height: 8px;
    border-radius: 50%;
  }
  .dot-on  { background: #1a75c4; }
  .dot-off { background: #c8c8c8; }
  .task-info { flex: 1; display: flex; gap: 4px; flex-wrap: wrap; }
  .task-num { color: #767676; flex-shrink: 0; }
  .task-label { color: #212121; }
  .task-toggle-wrap { flex-shrink: 0; }
  .task-toggle {
    font-size: 10px; font-weight: 700;
    padding: 1px 6px; border-radius: 3px;
  }
  .toggle-on  { background: #e6f0fb; color: #1a75c4; }
  .toggle-off { background: #f0f0f0; color: #767676; }

  /* CENTER */
  .dash-center {
    flex: 1; display: flex; flex-direction: column;
    overflow: hidden; min-width: 0;
    background: #ffffff;
  }
  .center-topbar {
    display: flex; align-items: center; gap: 12px;
    padding: 6px 14px;
    background: #f5f5f5;
    border-bottom: 1px solid #dedede;
    flex-shrink: 0;
  }
  .breadcrumb { font-size: 12px; cursor: pointer; }
  .center-title {
    font-size: 12px; font-weight: 600;
    color: #212121;
    flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  .center-section-label {
    display: flex; align-items: center; justify-content: space-between;
    padding: 6px 14px;
    font-size: 12px; font-weight: 600;
    color: #444;
    background: #fafafa;
    border-bottom: 1px solid #dedede;
    flex-shrink: 0;
  }
  .view-link {
    color: #1a75c4; text-decoration: none; font-size: 12px; font-weight: 400;
  }
  .view-link:hover { text-decoration: underline; }
  .table-wrap {
    flex: 1; overflow-y: auto; min-height: 0;
  }
  .data-table {
    width: 100%; border-collapse: collapse; font-size: 12px;
  }
  .data-table th, .data-table td {
    text-align: left;
    padding: 5px 12px;
    border-bottom: 1px solid #e8e8e8;
    white-space: nowrap;
  }
  .data-table thead th {
    background: #f5f5f5;
    color: #767676;
    font-size: 11px;
    font-weight: 600;
    position: sticky; top: 0; z-index: 1;
    border-bottom: 1px solid #dedede;
  }
  .data-table tbody tr:hover { background: #f0f7ff; }
  .row-even { background: #fafafa; }
  .url-cell { max-width: 300px; overflow: hidden; text-overflow: ellipsis; }
  .center-section-divider {
    padding: 5px 14px;
    font-size: 11px; color: #767676;
    background: #f5f5f5;
    border-bottom: 1px solid #dedede;
    border-top: 1px solid #dedede;
    flex-shrink: 0;
    text-align: center;
    letter-spacing: 0.04em;
  }
  .history-note { flex-shrink: 0; }

  /* RIGHT */
  .dash-right {
    width: 280px;
    flex-shrink: 0;
    background: #ffffff;
    border-left: 1px solid #dedede;
    display: flex;
    flex-direction: column;
    overflow-y: auto;
  }
  .right-section {
    padding: 10px 14px;
  }
  .right-divider {
    height: 1px; background: #dedede; flex-shrink: 0;
  }
  .right-header {
    font-size: 12px; font-weight: 600;
    color: #212121;
    margin-bottom: 8px;
    display: flex; align-items: center; justify-content: space-between;
  }
  .right-header.collapsible { cursor: pointer; }
  .right-header.collapsible:hover { color: #e03a00; }
  .collapse-arrow { font-size: 10px; color: #767676; }
  .config-row {
    display: flex; justify-content: space-between; align-items: center;
    padding: 4px 0;
    border-bottom: 1px solid #f0f0f0;
    font-size: 12px;
  }
  .config-row:last-child { border-bottom: none; }
  .config-label { color: #767676; }
  .config-value { color: #212121; }
  .config-toggle {
    font-size: 10px; font-weight: 700;
    padding: 1px 6px; border-radius: 3px;
  }
  .stat-row {
    display: flex; justify-content: space-between;
    padding: 4px 0;
    font-size: 12px;
    border-bottom: 1px solid #f0f0f0;
  }
  .stat-row:last-child { border-bottom: none; }
  .stat-label { color: #767676; }
  .stat-value { color: #212121; font-weight: 600; }

  .task-log {
    max-height: 160px; overflow-y: auto;
    display: flex; flex-direction: column; gap: 3px;
  }
  .log-item {
    display: flex; gap: 8px;
    font-size: 11px;
    font-family: ui-monospace, Consolas, monospace;
  }
  .log-time { flex-shrink: 0; width: 70px; }
  .log-msg { color: #444; }
</style>
