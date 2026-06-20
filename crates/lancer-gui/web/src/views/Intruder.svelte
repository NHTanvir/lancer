<script>
  import { onMount } from "svelte";

  let subtab = "payloads";
  let requestLoaded = false;

  // Target
  let host   = "example.com";
  let port   = "443";
  let scheme = "https";
  let updateHostHeader = true;

  // Positions
  let attackType      = "Sniper";
  let requestTemplate = `GET /users?id=§1§ HTTP/1.1\nHost: example.com\nUser-Agent: Lancer/1.0\nAccept: */*\n\n`;
  // Pristine copy of the request as first loaded (or last applied), so the
  // Refresh button can restore the original request after editing/auto-marking.
  let originalTemplate = requestTemplate;
  let reqEditorMode   = "raw";
  let editorSearch    = "";

  // Restore the request template to the pristine original (Burp's "Refresh").
  function refreshTemplate() { requestTemplate = originalTemplate; }

  $: positionCount = (requestTemplate.match(/§/g) || []).length / 2 | 0;

  function buildHighlightHtml(text) {
    let s = text.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
    let open = false;
    s = s.replace(/§/g, () => { open = !open; return open ? '<span class="pos-hl">§' : '§</span>'; });
    if (open) s += "</span>";
    return s;
  }
  $: highlightedTemplate = buildHighlightHtml(requestTemplate);

  let overlayEl = null;
  function syncOverlay(e) {
    if (overlayEl) { overlayEl.scrollTop = e.target.scrollTop; overlayEl.scrollLeft = e.target.scrollLeft; }
  }

  function addMarker() {
    const ta = document.getElementById("req-editor");
    if (!ta) { requestTemplate += "§§"; return; }
    const s = ta.selectionStart, e = ta.selectionEnd, v = requestTemplate;
    if (s === e) requestTemplate = v.slice(0,s)+"§§"+v.slice(s);
    else         requestTemplate = v.slice(0,s)+"§"+v.slice(s,e)+"§"+v.slice(e);
  }
  function clearMarkers() { requestTemplate = requestTemplate.replace(/§/g,""); }
  function autoMarkers()  {
    requestTemplate = requestTemplate.replace(/=([^&\r\n§]+)/g, (_,val) => `=§${val.replace(/§/g,"")}§`);
  }

  // Payloads
  let payloadSet  = 1;
  let payloadType = "Simple list";
  let payloadText = `1\n2\n3\nadmin\nroot\ntest\nguest\n' OR 1=1--\n../etc/passwd`;
  $: payloadList  = payloadText.split("\n").map(s=>s.trim()).filter(Boolean);
  let payloadEncodeEnabled = true;
  let payloadEncodeChars   = " ,+,=,@,|,/,\\,;,:,#,$,%,^,&,*,(,)";

  // Numbers config
  let numFrom="1"; let numTo="100"; let numStep="1"; let numHowMany=""; let numFmt="Dec";
  let numMinInt="1"; let numMaxInt=""; let numMinFrac="0"; let numMaxFrac="0";
  // Brute forcer
  let bruteCharSet="abcdefghijklmnopqrstuvwxyz0123456789"; let bruteMinLen="1"; let bruteMaxLen="4";
  // Null payloads
  let nullMode="count"; let nullCount="10";
  // Case modification
  let caseMod="Uppercase first letter";
  // Dates
  let dateFrom="2024-01-01"; let dateTo="2024-12-31"; let dateFmt="yyyy-MM-dd";
  // Username / char sub
  let userGenBase="John Smith"; let charSubBase="admin";
  // Username generator — first/last NAME LISTS (one per line, like Burp).
  let userGenFirsts="John\nJane\nAdmin"; let userGenLasts="Smith\nDoe"; let userGenSep=".";
  // Character frobber / bit flipper base string (backend-supported types).
  let frobberBase="password"; let bitFlipBase="password";

  // Attack / Results
  let results=[]; let running=false; let showResults=false; let attackNum=0;
  let selectedResult=null; let resultReqTab="request";
  let filterStatus=""; let filterPayload="";

  // Column sorting for the results table (click a header to sort).
  let sortKey=""; let sortDir=1;
  function sortBy(key) { if (sortKey===key) sortDir=-sortDir; else { sortKey=key; sortDir=1; } }
  function sortVal(r,key) {
    switch (key) {
      case "index":  return r.index??0;
      case "payload":return (r.payload||(r.payloads||[]).join(", ")||"").toLowerCase();
      case "status": return r.status||0;
      case "length": return r.length??0;
      case "time":   return r.time_ms??0;
      case "started":return r.started_at||"";
      default:       return "";
    }
  }
  // Max number of payload positions across all results — drives one column per
  // position for multi-position (Pitchfork/Cluster bomb) attacks.
  $: maxPositions = results.reduce((m,r)=>Math.max(m,(r.payloads||[]).length),0);

  $: filteredResults = (() => {
    let out = results.filter(r => {
      if (filterStatus  && !String(r.status||"").includes(filterStatus)) return false;
      if (filterPayload && !((r.payload||(r.payloads||[]).join(", ")||"").toLowerCase().includes(filterPayload.toLowerCase()))) return false;
      return true;
    });
    if (sortKey) {
      out = out.slice().sort((a,b) => {
        const va=sortVal(a,sortKey), vb=sortVal(b,sortKey);
        if (va<vb) return -sortDir; if (va>vb) return sortDir; return 0;
      });
    }
    return out;
  })();

  function fmtTime(r) {
    if (!r.started_at) return "";
    try { return new Date(r.started_at).toLocaleTimeString(); } catch { return ""; }
  }

  // ── Export / save-load helpers ────────────────────────────────────────
  function downloadBlob(name, text, mime) {
    try {
      const blob = new Blob([text], { type: mime || "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = name; document.body.appendChild(a); a.click();
      a.remove(); setTimeout(()=>URL.revokeObjectURL(url), 1000);
    } catch {}
  }
  function csvCell(v) {
    const s = v == null ? "" : String(v);
    return /[",\n]/.test(s) ? '"' + s.replace(/"/g,'""') + '"' : s;
  }
  // Save the visible results table as CSV (Burp's "Save results table").
  function saveResultsCsv() {
    const head = ["#","Payload","Status","Length","Response time (ms)","Timestamp","Error"];
    const lines = [head.map(csvCell).join(",")];
    for (const r of filteredResults) {
      lines.push([
        r.index, (r.payload||(r.payloads||[]).join(" | ")), r.status, r.length,
        r.time_ms, r.started_at, r.error||""
      ].map(csvCell).join(","));
    }
    downloadBlob(`intruder-attack-${attackNum||1}.csv`, lines.join("\n"), "text/csv");
  }
  // Save the whole attack (config + results) as a portable .lancer JSON file.
  function saveAttack() {
    const data = {
      _format:"lancer.intruder", version:1, savedAt:new Date().toISOString(),
      target:{host,port,scheme,updateHostHeader},
      attackType, requestTemplate,
      payload:{ type:payloadType, text:payloadText, encodeEnabled:payloadEncodeEnabled, encodeChars:payloadEncodeChars },
      grep:{
        matchEnabled:grepMatchEnabled, matchRules:grepMatchRules,
        extractEnabled:grepExtractEnabled, extractRules:grepExtractRules,
        payloadsEnabled:grepPayloadsEnabled, payloadsExpr:grepPayloadsExpr,
      },
      processingRules, results,
    };
    downloadBlob(`intruder-attack-${attackNum||1}.lancer`, JSON.stringify(data,null,2), "application/json");
  }
  // Restore an attack previously saved with saveAttack().
  function loadAttackFile(e) {
    const f = e.target.files && e.target.files[0];
    if (!f) return;
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const d = JSON.parse(String(reader.result));
        if (d.target) { if(d.target.host)host=d.target.host; if(d.target.port)port=String(d.target.port); if(d.target.scheme)scheme=d.target.scheme; if(typeof d.target.updateHostHeader==="boolean")updateHostHeader=d.target.updateHostHeader; }
        if (d.attackType) attackType=d.attackType;
        if (d.requestTemplate) { requestTemplate=d.requestTemplate; originalTemplate=d.requestTemplate; }
        if (d.payload) { if(d.payload.type)payloadType=d.payload.type; if(d.payload.text!=null)payloadText=d.payload.text; if(typeof d.payload.encodeEnabled==="boolean")payloadEncodeEnabled=d.payload.encodeEnabled; if(d.payload.encodeChars!=null)payloadEncodeChars=d.payload.encodeChars; }
        if (d.grep) { grepMatchEnabled=!!d.grep.matchEnabled; if(Array.isArray(d.grep.matchRules))grepMatchRules=d.grep.matchRules; grepExtractEnabled=!!d.grep.extractEnabled; if(Array.isArray(d.grep.extractRules))grepExtractRules=d.grep.extractRules; grepPayloadsEnabled=!!d.grep.payloadsEnabled; if(d.grep.payloadsExpr!=null)grepPayloadsExpr=d.grep.payloadsExpr; }
        if (Array.isArray(d.processingRules)) processingRules=d.processingRules;
        if (Array.isArray(d.results)) { results=d.results; if(results.length){ showResults=true; attackNum+=1; } }
      } catch (err) { attackError="Could not load attack file: "+err; }
    };
    reader.readAsText(f);
    e.target.value="";
  }
  // Send two selected results to the Comparer (response bodies if available).
  let compareSel=[];
  function toggleCompare(r) {
    if (compareSel.includes(r)) compareSel=compareSel.filter(x=>x!==r);
    else compareSel=[...compareSel, r].slice(-2);
  }
  function sendToComparer() {
    if (compareSel.length<2) return;
    const [a,b]=compareSel;
    const txt=(r)=> r.raw_response || resultResponse(r);
    try {
      localStorage.setItem("lancer.send.comparer", JSON.stringify({ item1:txt(a), item2:txt(b) }));
      window.dispatchEvent(new CustomEvent("lancer:navigate", { detail:"comparer" }));
    } catch {}
  }

  onMount(() => {
    try {
      const raw = localStorage.getItem("lancer.send.intruder");
      if (raw) {
        const p = JSON.parse(raw);
        if (p.scheme) scheme=p.scheme; if (p.host) host=p.host;
        if (p.port) port=String(p.port); if (p.raw) { requestTemplate=p.raw; originalTemplate=p.raw; }
        requestLoaded=true; localStorage.removeItem("lancer.send.intruder"); subtab="positions";
      }
    } catch {}
  });

  let attackError="";
  // GUI label → API attack-kind token (the API also accepts these case/separator-insensitively).
  // Keys MUST match the <option> label casing ("Battering ram"/"Cluster bomb"),
  // else the lookup misses and silently falls back to Sniper.
  const KIND_MAP={"Sniper":"Sniper","Battering ram":"BatteringRam","Pitchfork":"Pitchfork","Cluster bomb":"ClusterBomb"};
  // Map the selected payload type + its config to a backend payload_spec.
  // Returns null for "Simple list" (falls back to the literal payload list).
  function buildPayloadSpec() {
    switch (payloadType) {
      case "Numbers": return { type:"numbers", from:numFrom, to:numTo, step:parseInt(numStep,10)||1 };
      case "Dates": return { type:"dates", from:dateFrom, to:dateTo };
      case "Brute forcer": return { type:"bruteforce", charset:bruteCharSet, min_len:parseInt(bruteMinLen,10)||1, max_len:parseInt(bruteMaxLen,10)||3 };
      case "Null payloads": return { type:"null", count:parseInt(nullCount,10)||10 };
      case "Username generator": {
        const firsts=userGenFirsts.split("\n").map(s=>s.trim()).filter(Boolean);
        const lasts =userGenLasts.split("\n").map(s=>s.trim()).filter(Boolean);
        return { type:"usernamegenerator", firsts:firsts.length?firsts:[""], lasts:lasts.length?lasts:[""], sep:userGenSep||"." };
      }
      case "Case modification": return { type:"casemodification", base:charSubBase||"" };
      case "Character frobber": return { type:"charfrobber", base:frobberBase||"" };
      case "Bit flipper": return { type:"bitflipper", base:bitFlipBase||"" };
      default: return null;
    }
  }

  // Map the freeform processing-rule rows to backend processors (best-effort).
  function buildProcessors() {
    return processingRules.filter(r=>r.enabled).map(r=>{
      const s=(r.rule||"").toLowerCase();
      if (s.includes("base64")) return "Base64Encode";
      if (s.includes("url")) return "UrlEncode";
      if (s.includes("upper")) return "ToUpper";
      if (s.includes("lower")) return "ToLower";
      if (s.startsWith("prefix:")) return { Prefix: r.rule.slice(7) };
      if (s.startsWith("suffix:")) return { Suffix: r.rule.slice(7) };
      return "UrlEncode";
    });
  }

  async function startAttack() {
    requestLoaded=true; running=true; results=[]; selectedResult=null; attackError="";
    attackNum+=1; showResults=true; filterStatus=""; filterPayload="";
    // The request template carries the §…§ markers; payloadList is one payload set.
    // Pitchfork/Cluster Bomb need one payload set PER position (the backend
    // rejects a mismatch with 500 "needs one payload set per position"), and the
    // UI exposes a single set — so replicate it across positions for those modes.
    const setCount = (attackType === "Pitchfork" || attackType === "Cluster bomb")
      ? Math.max(1, positionCount) : 1;
    const sets = Array.from({ length: setCount }, () => payloadList);
    // Grep config the results table renders as dynamic columns (start/end
    // boundaries compile to a regex server-side).
    const grep={
      match_strings: grepMatchEnabled ? grepMatchRules.filter(r=>r.enabled&&r.expr).map(r=>r.expr) : [],
      extracts: grepExtractEnabled ? grepExtractRules.filter(r=>r.enabled).map(r=>({label:r.desc||"extract",start:r.start||"",end:r.end||""})) : [],
      reflect_payload: grepPayloadsEnabled,
    };
    activeGrepCols={ matches: grep.match_strings.slice(), extracts: grep.extracts.map(e=>e.label) };
    // Typed payload set drives the backend generator for non-list types.
    const spec = buildPayloadSpec();
    const procs = buildProcessors();
    // Resource pool: when a dedicated pool is selected, its max-concurrent /
    // delay override the global request-engine threads/throttle.
    const maxConc = (rpMode==="new" ? parseInt(rpMaxConcurrent,10) : parseInt(sThreads,10)) || 10;
    const throttle = (rpMode==="new" ? parseInt(rpDelay,10) : parseInt(sThrottle,10)) || 0;
    const reqBody = {host,port:parseInt(port,10),scheme,request:requestTemplate,kind:KIND_MAP[attackType]||"Sniper",grep,max_concurrency:maxConc,throttle_ms:throttle,max_retries:parseInt(sRetries,10)||0};
    if (spec) reqBody.payload_specs=Array.from({ length: setCount }, () => spec); else reqBody.payloads=sets;
    if (procs.length) reqBody.processors=procs;
    try {
      const r = await fetch("/api/v1/intruder",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(reqBody)});
      if (r.ok) { results=await r.json(); }
      else { attackError=`Attack failed (${r.status}): ${(await r.text())||"see server log"}`; results=[]; }
    } catch (e) {
      attackError=`Could not reach Lancer API — is it running? (${e})`; results=[];
    } finally { running=false; }
  }

  function statusClass(s) { if(!s)return"dim"; if(s>=500)return"status-5"; if(s>=400)return"status-4"; if(s>=300)return"status-3"; return"status-2"; }
  function resultRequest(r)  { if(r.raw_request)return r.raw_request; return`${r.method||"GET"} ${r.path||"/"} HTTP/1.1\r\nHost: ${host}\r\n\r\n`; }
  function resultResponse(r) { if(r.raw_response)return r.raw_response; if(!r.status)return"(no response)"; return`HTTP/1.1 ${r.status}\r\nContent-Length: ${r.length||0}\r\n\r\n`; }

  let processingRules=[];
  function addRule()        { processingRules=[...processingRules,{enabled:true,rule:"URL-encode all characters"}]; }
  function removeRule(i)    { processingRules=processingRules.filter((_,j)=>j!==i); }
  function moveRule(i,dir)  { const a=[...processingRules],t=i+dir; if(t<0||t>=a.length)return; [a[i],a[t]]=[a[t],a[i]]; processingRules=a; }
  let newPayloadItem="";
  function addPayloadItem() { const v=newPayloadItem.trim(); if(!v)return; payloadText=payloadText?payloadText+"\n"+v:v; newPayloadItem=""; }
  function handleAddItemKey(e) { if(e.key==="Enter")addPayloadItem(); }

  // Grep
  let grepMatchEnabled=false; let grepMatchRules=[];
  let grepExtractEnabled=false; let grepExtractRules=[];
  let grepPayloadsEnabled=false; let grepPayloadsExpr="";
  // Dynamic grep result columns derived from the config sent with each attack.
  let activeGrepCols={matches:[],extracts:[]};
  // Fixed columns: compare, #, payload(s), status, error, timeout, length, time, timestamp, comment.
  $: atkColCount=10+(maxPositions>1?maxPositions-1:0)+activeGrepCols.matches.length+activeGrepCols.extracts.length+(grepPayloadsEnabled?1:0);

  // Settings
  let sThreads=10; let sRetries=3; let sPause=2000; let sThrottle=0;
  let sTimeout=120; let sFollowRedirects=true; let sMakeUnique=false;

  // Resource pool
  let rpMode="shared"; let rpName=""; let rpMaxConcurrent=10; let rpDelay=0;
  let rpSaved=false;
  function savePool() { rpSaved=true; setTimeout(()=>rpSaved=false, 2000); }
</script>

<!-- ══════════════════════════════════════════════════════════════════════ -->
<div class="intruder-root">

  <!-- TOP TOOLBAR -->
  <div class="top-toolbar">
    <div class="tab-pills">
      <div class="tab-pill">
        <span class="tab-pill-num">1</span>
        <span class="tab-pill-x">×</span>
      </div>
      <button class="tab-add" title="New tab">+</button>
    </div>
    <div class="toolbar-right">
      <button class="btn-start" on:click={startAttack} disabled={running}>
        {#if running}<span class="spinner"></span> Running…{:else}▶ Start attack{/if}
      </button>
      <label class="load-attack-btn" title="Load a saved .lancer attack">
        Load attack
        <input type="file" accept=".lancer,application/json,.json" on:change={loadAttackFile} style="display:none" />
      </label>
      <button class="btn-gear" title="Intruder settings">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none">
          <circle cx="12" cy="12" r="3" stroke="#666" stroke-width="2"/>
          <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" stroke="#666" stroke-width="2"/>
        </svg>
      </button>
    </div>
  </div>

  <!-- TARGET BAR -->
  <div class="target-bar">
    <span class="target-label">Target:</span>
    <span class="target-url">{scheme}://{host}:{port}</span>
    <button class="change-target-link">Change target</button>
    <span class="target-sep">|</span>
    <label class="target-check-label">
      <input type="checkbox" bind:checked={updateHostHeader} />
      <span>Update Host header to match target</span>
    </label>
  </div>

  <!-- MAIN AREA: editor | content panel | vertical tab strip -->
  <div class="main-area">

    <!-- ── LEFT: request editor (always visible) ─────────────────────── -->
    <div class="editor-pane">
      <div class="editor-toolbar">
        <div class="editor-modetabs">
          <button class="mode-tab" class:active={reqEditorMode==="pretty"} on:click={()=>reqEditorMode="pretty"}>Pretty</button>
          <button class="mode-tab" class:active={reqEditorMode==="raw"}    on:click={()=>reqEditorMode="raw"}>Raw</button>
          <button class="mode-tab" class:active={reqEditorMode==="hex"}    on:click={()=>reqEditorMode="hex"}>Hex</button>
          <button class="mode-tab mode-tab-nl" title="Non-printing chars">&#x23ce;</button>
        </div>
        <input type="text" class="editor-search" placeholder="Search…" bind:value={editorSearch} />
        <div class="pos-btns">
          <button class="pos-btn" on:click={addMarker}>Add §</button>
          <button class="pos-btn" on:click={clearMarkers}>Clear §</button>
          <button class="pos-btn" on:click={autoMarkers}>Auto §</button>
          <button class="pos-btn" on:click={refreshTemplate} title="Reload the original request">Refresh</button>
        </div>
      </div>
      <div class="editor-body">
        <pre class="req-hl-overlay" bind:this={overlayEl} aria-hidden="true">{@html highlightedTemplate}</pre>
        <textarea
          id="req-editor"
          class="req-textarea"
          style="background:transparent;caret-color:#1b2026"
          bind:value={requestTemplate}
          spellcheck="false"
          on:scroll={syncOverlay}
        ></textarea>
      </div>
    </div>

    <!-- ── MIDDLE: content panel (changes per subtab) ────────────────── -->
    <div class="content-pane">

      <!-- PAYLOADS content (includes payload positions at top, like Burp) -->
      {#if subtab === "payloads"}
        <div class="cp-scroll">

          <!-- Payload positions section (top of Payloads panel) -->
          <div class="ps-section">
            <div class="ps-header">Payload positions</div>
            <div class="ps-row" style="margin-bottom:8px">
              <label class="ps-label">Attack type:</label>
              <select class="cp-select" bind:value={attackType}>
                <option>Sniper</option>
                <option>Battering ram</option>
                <option>Pitchfork</option>
                <option>Cluster bomb</option>
              </select>
            </div>
            {#if positionCount === 0}
              <div class="no-pos-banner">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" style="flex-shrink:0"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" stroke="#856404" stroke-width="2" fill="#fff3cd"/><line x1="12" y1="9" x2="12" y2="13" stroke="#856404" stroke-width="2" stroke-linecap="round"/><circle cx="12" cy="17" r="1" fill="#856404"/></svg>
                <span>No payload positions configured. Use <strong>Add §</strong> in the editor above to mark positions.</span>
              </div>
            {:else}
              <div class="pos-count-badge">{positionCount} payload position{positionCount===1?"":"s"} configured</div>
            {/if}
            {#if results.length > 0 || running}
              <button class="view-results-btn" style="margin-top:8px" on:click={()=>showResults=true}>
                {running ? "⏳ Running — view results" : `▶ View attack results (${results.length})`}
              </button>
            {/if}
          </div>

          <div class="ps-section">
            <div class="ps-header">Payload sets</div>
            <div class="ps-row">
              <label class="ps-label">Payload set:</label>
              <input type="number" class="ps-num" bind:value={payloadSet} min="1" max="10" />
              <span class="ps-spacer"></span>
              <label class="ps-label">Payload count:</label>
              <span class="ps-count">{payloadList.length}</span>
            </div>
            <div class="ps-row" style="margin-top:6px">
              <label class="ps-label">Payload type:</label>
              <select class="cp-select" style="width:210px" bind:value={payloadType}>
                <option>Simple list</option>
                <option>Runtime file</option>
                <option>Custom iterator</option>
                <option>Character substitution</option>
                <option>Case modification</option>
                <option>Recursive grep</option>
                <option>Numbers</option>
                <option>Dates</option>
                <option>Brute forcer</option>
                <option>Null payloads</option>
                <option>Username generator</option>
                <option>Character frobber</option>
                <option>Bit flipper</option>
                <option>ECB block shuffler</option>
              </select>
            </div>
          </div>

          <div class="ps-section">
            <div class="ps-header">Payload configuration</div>

            {#if payloadType === "Simple list"}
              <div class="ps-desc">This provides you with a simple list of strings that are used as payloads.</div>
              <div class="payload-layout">
                <textarea class="payload-ta" bind:value={payloadText} placeholder="One payload per line…" spellcheck="false"></textarea>
                <div class="payload-btns">
                  <button class="btn-sec" on:click={()=>navigator.clipboard.readText().then(t=>{payloadText=payloadText?payloadText+"\n"+t:t}).catch(()=>{})}>Paste</button>
                  <button class="btn-sec">Load…</button>
                  <button class="btn-sec" on:click={()=>{const l=payloadList;if(l.length)payloadText=l.slice(0,-1).join("\n")}}>Remove</button>
                  <button class="btn-sec" on:click={()=>payloadText=""}>Clear</button>
                  <button class="btn-sec" on:click={()=>payloadText=[...new Set(payloadList)].join("\n")}>Deduplicate</button>
                </div>
              </div>
              <div class="add-item-row">
                <input type="text" class="add-item-input" placeholder="Add a new item" bind:value={newPayloadItem} on:keydown={handleAddItemKey} />
                <button class="btn-sec" on:click={addPayloadItem}>Add</button>
              </div>
              <div class="ps-hint dim">Add from list: <button class="link-btn" on:click={()=>navigator.clipboard.readText().then(t=>{payloadText=payloadText?payloadText+"\n"+t:t}).catch(()=>{})}>Paste from clipboard</button></div>

            {:else if payloadType === "Numbers"}
              <div class="ps-desc">Generates numeric payloads within a specified range.</div>
              <div class="num-grid">
                <label class="num-label">From:</label>          <input type="number" class="num-in" bind:value={numFrom} />
                <label class="num-label">To:</label>            <input type="number" class="num-in" bind:value={numTo} />
                <label class="num-label">Step:</label>          <input type="number" class="num-in" bind:value={numStep} />
                <label class="num-label">How many:</label>      <input type="number" class="num-in" placeholder="(auto)" bind:value={numHowMany} />
                <label class="num-label">Format:</label>
                <select class="cp-select" style="width:90px" bind:value={numFmt}><option>Dec</option><option>Hex</option><option>Oct</option><option>Bin</option></select>
                <label class="num-label">Min integer digits:</label>  <input type="number" class="num-in" bind:value={numMinInt} min="1" />
                <label class="num-label">Max integer digits:</label>  <input type="number" class="num-in" placeholder="(none)" bind:value={numMaxInt} />
                <label class="num-label">Min fraction digits:</label> <input type="number" class="num-in" bind:value={numMinFrac} min="0" />
                <label class="num-label">Max fraction digits:</label> <input type="number" class="num-in" bind:value={numMaxFrac} min="0" />
              </div>

            {:else if payloadType === "Brute forcer"}
              <div class="ps-desc">Generates payloads of specified lengths from a character set.</div>
              <div class="ps-row" style="margin-bottom:6px"><label class="ps-label">Character set:</label></div>
              <textarea class="payload-ta" style="min-height:54px;resize:none" bind:value={bruteCharSet} spellcheck="false"></textarea>
              <div class="num-grid" style="margin-top:8px">
                <label class="num-label">Min length:</label> <input type="number" class="num-in" bind:value={bruteMinLen} min="1" />
                <label class="num-label">Max length:</label> <input type="number" class="num-in" bind:value={bruteMaxLen} min="1" />
              </div>

            {:else if payloadType === "Null payloads"}
              <div class="ps-desc">Generates empty (null) payloads — useful for timing attacks.</div>
              <div class="null-opts">
                <label class="radio-label">
                  <input type="radio" name="null-mode" value="count" bind:group={nullMode} />
                  <span>Generate</span>
                  <input type="number" class="num-in" style="width:56px;margin:0 6px" bind:value={nullCount} min="1" disabled={nullMode!=="count"} />
                  <span>payloads</span>
                </label>
                <label class="radio-label" style="margin-top:8px">
                  <input type="radio" name="null-mode" value="continue" bind:group={nullMode} />
                  <span>Continue generating indefinitely</span>
                </label>
              </div>

            {:else if payloadType === "Case modification"}
              <div class="ps-desc">Applies case transformations to existing payloads.</div>
              <div class="ps-row" style="margin-top:8px">
                <label class="ps-label">Type:</label>
                <select class="cp-select" style="width:240px" bind:value={caseMod}>
                  <option>Uppercase first letter</option>
                  <option>Uppercase first letter, lowercase rest</option>
                  <option>Uppercase all</option>
                  <option>Lowercase all</option>
                  <option>Initial caps</option>
                  <option>Initial caps, lowercase rest</option>
                  <option>Toggle case</option>
                </select>
              </div>

            {:else if payloadType === "Username generator"}
              <div class="ps-desc">Generates usernames by combining first and last names (one per line).</div>
              <div class="payload-layout">
                <div style="flex:1">
                  <div class="ps-label" style="margin-bottom:4px">First names:</div>
                  <textarea class="payload-ta" style="min-height:96px" bind:value={userGenFirsts} placeholder="One first name per line…" spellcheck="false"></textarea>
                </div>
                <div style="flex:1">
                  <div class="ps-label" style="margin-bottom:4px">Last names:</div>
                  <textarea class="payload-ta" style="min-height:96px" bind:value={userGenLasts} placeholder="One last name per line…" spellcheck="false"></textarea>
                </div>
              </div>
              <div class="ps-row" style="margin-top:8px">
                <label class="ps-label">Separator:</label>
                <input type="text" class="num-in" style="width:60px" bind:value={userGenSep} placeholder="." />
              </div>

            {:else if payloadType === "Character substitution"}
              <div class="ps-desc">Applies character substitutions (l33t speak) to a base string.</div>
              <div class="ps-row" style="margin-top:8px">
                <label class="ps-label">Base string:</label>
                <input type="text" class="add-item-input" style="flex:1" bind:value={charSubBase} placeholder="e.g. password" />
              </div>
              <table class="proc-table" style="margin-top:10px">
                <thead><tr><th>Sub.</th><th>Char</th><th>Replacements</th></tr></thead>
                <tbody>
                  {#each [["a","@, 4"],["e","3"],["i","1, !"],["o","0"],["s","$, 5"],["t","7"]] as [ch,rep]}
                    <tr><td style="text-align:center"><input type="checkbox" checked /></td><td style="font-family:monospace">{ch}</td><td class="dim">{rep}</td></tr>
                  {/each}
                </tbody>
              </table>

            {:else if payloadType === "Dates"}
              <div class="ps-desc">Generates date payloads within a specified range.</div>
              <div class="num-grid" style="margin-top:8px">
                <label class="num-label">From:</label> <input type="date" class="num-in" style="width:130px" bind:value={dateFrom} />
                <label class="num-label">To:</label>   <input type="date" class="num-in" style="width:130px" bind:value={dateTo} />
                <label class="num-label">Format:</label>
                <select class="cp-select" bind:value={dateFmt}><option>yyyy-MM-dd</option><option>dd/MM/yyyy</option><option>MM/dd/yyyy</option><option>ddMMyyyy</option></select>
              </div>

            {:else if payloadType === "Character frobber"}
              <div class="ps-desc">Iterates through each character of the base string, mutating one position at a time.</div>
              <div class="ps-row" style="margin-top:8px">
                <label class="ps-label">Base string:</label>
                <input type="text" class="add-item-input" style="flex:1" bind:value={frobberBase} placeholder="e.g. password" />
              </div>

            {:else if payloadType === "Bit flipper"}
              <div class="ps-desc">Generates payloads by flipping each bit of the base string in turn.</div>
              <div class="ps-row" style="margin-top:8px">
                <label class="ps-label">Base string:</label>
                <input type="text" class="add-item-input" style="flex:1" bind:value={bitFlipBase} placeholder="e.g. password" />
              </div>

            {:else}
              <div class="ps-desc dim">Configuration for <strong>{payloadType}</strong>.</div>
              <div class="pro-notice"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" style="flex-shrink:0"><circle cx="12" cy="12" r="10" stroke="#1a75c4" stroke-width="2"/><line x1="12" y1="8" x2="12" y2="12" stroke="#1a75c4" stroke-width="2" stroke-linecap="round"/><circle cx="12" cy="16" r="1" fill="#1a75c4"/></svg><span>Supported when backed by a Lancer scan engine.</span></div>
            {/if}
          </div>

          <div class="ps-section">
            <div class="ps-header">Payload processing</div>
            <div class="ps-desc">Define rules to process each payload before it is used.</div>
            <table class="proc-table">
              <thead><tr><th style="width:50px">Enabled</th><th>Rule</th></tr></thead>
              <tbody>
                {#each processingRules as rule, i}
                  <tr>
                    <td style="text-align:center"><input type="checkbox" bind:checked={rule.enabled} /></td>
                    <td>
                      {rule.rule}
                      <span class="rule-acts">
                        <button class="rule-btn" on:click={()=>moveRule(i,-1)} disabled={i===0}>▲</button>
                        <button class="rule-btn" on:click={()=>moveRule(i,1)}  disabled={i===processingRules.length-1}>▼</button>
                        <button class="rule-btn" on:click={()=>removeRule(i)}>✕</button>
                      </span>
                    </td>
                  </tr>
                {/each}
                {#if processingRules.length===0}
                  <tr><td colspan="2" class="proc-empty dim">No rules configured</td></tr>
                {/if}
              </tbody>
            </table>
            <div class="proc-btns">
              <button class="btn-sec" on:click={addRule}>Add</button>
              <button class="btn-sec" on:click={()=>removeRule(processingRules.length-1)} disabled={!processingRules.length}>Remove</button>
            </div>
          </div>

          <div class="ps-section">
            <div class="ps-header">Payload encoding</div>
            <div class="encode-row">
              <input type="checkbox" id="enc-cb" bind:checked={payloadEncodeEnabled} />
              <label for="enc-cb" class="encode-label">URL-encode these characters:</label>
            </div>
            <input type="text" class="encode-input" bind:value={payloadEncodeChars} disabled={!payloadEncodeEnabled} />
          </div>

        </div>

      <!-- RESOURCE POOL content -->
      {:else if subtab === "resource-pool"}
        <div class="cp-scroll">
          <div class="ps-section">
            <div class="ps-header">Resource pool</div>
            <div class="ps-desc">Control the concurrency of Intruder attacks and other automated tasks.</div>
            <div class="null-opts" style="margin-top:8px">
              <label class="radio-label">
                <input type="radio" name="rp" value="shared" bind:group={rpMode} />
                <span>Use the existing pool with default settings</span>
              </label>
              <label class="radio-label" style="margin-top:8px">
                <input type="radio" name="rp" value="new" bind:group={rpMode} />
                <span>Create a new resource pool</span>
              </label>
            </div>
            {#if rpMode === "new"}
              <div class="num-grid" style="margin-top:12px">
                <label class="num-label">Pool name:</label>
                <input type="text" class="add-item-input" style="width:180px" bind:value={rpName} placeholder="My pool" />
                <label class="num-label">Max concurrent requests:</label>
                <input type="number" class="num-in" bind:value={rpMaxConcurrent} min="1" max="100" />
                <label class="num-label">Delay between requests (ms):</label>
                <input type="number" class="num-in" bind:value={rpDelay} min="0" />
              </div>
            {/if}
            <div style="margin-top:12px">
              <button class="btn-sec" on:click={savePool}>Save pool settings</button>
              {#if rpSaved}<span class="dim" style="margin-left:8px;font-size:12px">✓ Applied to next attack</span>{/if}
            </div>
            {#if rpMode === "new"}<div class="ps-hint dim" style="margin-top:6px">Max concurrent and delay override the global request-engine settings for the next attack.</div>{/if}
          </div>
        </div>

      <!-- SETTINGS content -->
      {:else if subtab === "settings"}
        <div class="cp-scroll">

          <div class="ps-section">
            <div class="ps-header">Request engine</div>
            <div class="srow"><label class="slabel">Number of threads:</label>                    <input type="number" class="snum" bind:value={sThreads} min="1" max="100" /></div>
            <div class="srow"><label class="slabel">Number of retries on network failure:</label> <input type="number" class="snum" bind:value={sRetries} min="0" max="10" /></div>
            <div class="srow"><label class="slabel">Pause before retry (ms):</label>              <input type="number" class="snum" bind:value={sPause} min="0" /></div>
            <div class="srow"><label class="slabel">Throttle between requests (ms):</label>       <input type="number" class="snum" bind:value={sThrottle} min="0" /></div>
            <div class="srow"><label class="slabel">Network timeout (seconds):</label>            <input type="number" class="snum" bind:value={sTimeout} min="1" /></div>
            <div class="srow"><input type="checkbox" id="follow-rd" bind:checked={sFollowRedirects} /><label for="follow-rd" class="slabel" style="margin-left:6px">Follow redirections</label></div>
            <div class="srow"><input type="checkbox" id="make-uniq"  bind:checked={sMakeUnique}      /><label for="make-uniq"  class="slabel" style="margin-left:6px">Make unique baseline request</label></div>
          </div>

          <div class="ps-section">
            <div class="ps-header">Grep — Match</div>
            <div class="ps-desc">Flag results that contain the specified expression in the response.</div>
            <div class="srow" style="margin-top:6px"><input type="checkbox" id="gm-en" bind:checked={grepMatchEnabled} /><label for="gm-en" class="slabel" style="margin-left:6px">Enable grep — match</label></div>
            <table class="proc-table" style="margin-top:6px">
              <thead><tr><th>Enabled</th><th>Match condition</th></tr></thead>
              <tbody>
                {#each grepMatchRules as r}<tr><td style="text-align:center"><input type="checkbox" bind:checked={r.enabled} /></td><td>{r.expr}</td></tr>{/each}
                {#if !grepMatchRules.length}<tr><td colspan="2" class="proc-empty dim">No match conditions configured</td></tr>{/if}
              </tbody>
            </table>
            <div class="proc-btns">
              <button class="btn-sec" on:click={()=>grepMatchRules=[...grepMatchRules,{enabled:true,expr:"error"}]}>Add</button>
              <button class="btn-sec" on:click={()=>grepMatchRules=grepMatchRules.slice(0,-1)} disabled={!grepMatchRules.length}>Remove</button>
              <button class="btn-sec" on:click={()=>grepMatchRules=[]}>Clear</button>
            </div>
          </div>

          <div class="ps-section">
            <div class="ps-header">Grep — Extract</div>
            <div class="ps-desc">Extract data from each response and add as extra columns in attack results.</div>
            <div class="srow" style="margin-top:6px"><input type="checkbox" id="ge-en" bind:checked={grepExtractEnabled} /><label for="ge-en" class="slabel" style="margin-left:6px">Enable grep — extract</label></div>
            <table class="proc-table" style="margin-top:6px">
              <thead><tr><th>Enabled</th><th>Description</th><th>Start expression</th><th>End expression</th></tr></thead>
              <tbody>
                {#each grepExtractRules as r}<tr><td style="text-align:center"><input type="checkbox" bind:checked={r.enabled} /></td><td>{r.desc||""}</td><td class="dim">{r.start||""}</td><td class="dim">{r.end||""}</td></tr>{/each}
                {#if !grepExtractRules.length}<tr><td colspan="4" class="proc-empty dim">No extract items configured</td></tr>{/if}
              </tbody>
            </table>
            <div class="proc-btns">
              <button class="btn-sec" on:click={()=>grepExtractRules=[...grepExtractRules,{enabled:true,desc:"Value",start:"value=",end:"&"}]}>Add</button>
              <button class="btn-sec" on:click={()=>grepExtractRules=grepExtractRules.slice(0,-1)} disabled={!grepExtractRules.length}>Remove</button>
              <button class="btn-sec" on:click={()=>grepExtractRules=[]}>Clear</button>
            </div>
          </div>

          <div class="ps-section">
            <div class="ps-header">Grep — Payloads</div>
            <div class="ps-desc">Flag results where the response contains the submitted payload.</div>
            <div class="srow" style="margin-top:6px"><input type="checkbox" id="gp-en" bind:checked={grepPayloadsEnabled} /><label for="gp-en" class="slabel" style="margin-left:6px">Enable grep — payloads</label></div>
            <div class="srow" style="margin-top:6px">
              <label class="slabel">Match condition:</label>
              <input type="text" class="add-item-input" style="width:200px" bind:value={grepPayloadsExpr} placeholder="e.g. payload reflected" disabled={!grepPayloadsEnabled} />
            </div>
          </div>

        </div>
      {/if}
    </div>

    <!-- ── RIGHT: vertical tab strip (3 tabs, like Burp) ────────────── -->
    <div class="vtab-strip">
      {#each [["payloads","Payloads"],["resource-pool","Resource pool"],["settings","Settings"]] as [id,label]}
        <button class="vtab" class:active={subtab===id} on:click={()=>subtab=id}>
          <span class="vtab-label">{label}</span>
        </button>
      {/each}
    </div>

  </div><!-- end .main-area -->

  <!-- ATTACK RESULTS OVERLAY -->
  {#if showResults}
  <div class="attack-overlay">
    <div class="attack-header">
      <span class="attack-title">Intruder attack {attackNum}</span>
      <div class="attack-hright">
        {#if running}<span class="atk-running">⏳ Running…</span>{:else}<span class="atk-done">{results.length} requests completed</span>{/if}
        <button class="btn-sec" on:click={sendToComparer} disabled={compareSel.length<2} title="Send 2 selected responses to Comparer">Compare ({compareSel.length})</button>
        <button class="btn-sec" on:click={saveResultsCsv} disabled={!results.length} title="Save results table as CSV">Save CSV</button>
        <button class="btn-sec" on:click={saveAttack} disabled={!results.length} title="Save attack (config + results)">Save attack</button>
        <button class="attack-close" on:click={()=>showResults=false}>✕ Close</button>
      </div>
    </div>
    <div class="attack-filter-bar">
      <input class="atk-filter" bind:value={filterPayload} placeholder="Filter payload…" />
      <input class="atk-filter" bind:value={filterStatus}  placeholder="Filter status…" style="width:100px" />
      <span class="dim" style="font-size:11px;margin-left:auto">{filteredResults.length} / {results.length} rows</span>
    </div>
    {#if attackError}
      <div class="atk-error-banner">⚠ {attackError}</div>
    {/if}
    <div class="attack-body">
      <div class="attack-table-wrap">
        <table class="attack-table">
          <thead><tr>
            <th class="atk-cmp-th" title="Select two rows to compare"></th>
            <th class="atk-sort" on:click={()=>sortBy("index")}>#{sortKey==="index"?(sortDir>0?" ▲":" ▼"):""}</th>
            {#if maxPositions > 1}
              {#each Array(maxPositions) as _p, pi}<th>Payload {pi+1}</th>{/each}
            {:else}
              <th class="atk-sort" on:click={()=>sortBy("payload")}>Payload{sortKey==="payload"?(sortDir>0?" ▲":" ▼"):""}</th>
            {/if}
            <th class="atk-sort" on:click={()=>sortBy("status")}>Status{sortKey==="status"?(sortDir>0?" ▲":" ▼"):""}</th>
            <th>Error</th><th>Timeout</th>
            <th class="atk-sort" on:click={()=>sortBy("length")}>Length{sortKey==="length"?(sortDir>0?" ▲":" ▼"):""}</th>
            <th class="atk-sort" on:click={()=>sortBy("time")}>Time (ms){sortKey==="time"?(sortDir>0?" ▲":" ▼"):""}</th>
            <th class="atk-sort" on:click={()=>sortBy("started")}>Timestamp{sortKey==="started"?(sortDir>0?" ▲":" ▼"):""}</th>
            <th>Comment</th>
            {#each activeGrepCols.matches as m}<th title={"grep-match: "+m}>≈ {m.length>12?m.slice(0,12)+"…":m}</th>{/each}
            {#each activeGrepCols.extracts as e}<th title={"grep-extract: "+e}>⌑ {e}</th>{/each}
            {#if grepPayloadsEnabled}<th title="payload reflected in response">Reflected</th>{/if}
          </tr></thead>
          <tbody>
            {#if running && results.length===0}<tr><td colspan={atkColCount} class="dim" style="text-align:center;padding:18px">Sending requests…</td></tr>{/if}
            {#if !running && results.length===0 && !attackError}<tr><td colspan={atkColCount} class="dim" style="text-align:center;padding:18px">No results.</td></tr>{/if}
            {#each filteredResults as r}
              <tr class:atk-sel={selectedResult===r} on:click={()=>{selectedResult=r;resultReqTab="request"}}>
                <td class="atk-cmp-td" on:click|stopPropagation><input type="checkbox" checked={compareSel.includes(r)} on:change={()=>toggleCompare(r)} title="Select for compare" /></td>
                <td class="dim atk-num">{r.index}</td>
                {#if maxPositions > 1}
                  {#each Array(maxPositions) as _p, pi}<td class="atk-pl">{(r.payloads||[])[pi]??""}</td>{/each}
                {:else}
                  <td class="atk-pl">{r.payload||(r.payloads||[]).join(", ")||"—"}</td>
                {/if}
                <td class={statusClass(r.status)}>{r.status||"—"}</td>
                <td class={r.error?"atk-err":"dim"}>{r.error?"✓":""}</td>
                <td class={r.timeout?"atk-warn":"dim"}>{r.timeout?"✓":""}</td>
                <td class="dim atk-num">{r.length??"—"}</td>
                <td class="dim atk-num">{r.time_ms??""}</td>
                <td class="dim">{fmtTime(r)}</td>
                <td class="dim">{r.comment||""}</td>
                {#each activeGrepCols.matches as _m, gi}<td class="dim" style="text-align:center">{(r.grep&&r.grep.matches&&r.grep.matches[gi])?"✓":""}</td>{/each}
                {#each activeGrepCols.extracts as _e, gi}<td class="atk-pl">{(r.grep&&r.grep.extracts&&r.grep.extracts[gi])||""}</td>{/each}
                {#if grepPayloadsEnabled}<td class="dim" style="text-align:center">{(r.grep&&r.grep.payload_reflected)?"✓":""}</td>{/if}
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      {#if selectedResult}
        <div class="attack-detail">
          <div class="attack-detail-tabs">
            <button class="atk-tab" class:active={resultReqTab==="request"}  on:click={()=>resultReqTab="request"}>Request</button>
            <button class="atk-tab" class:active={resultReqTab==="response"} on:click={()=>resultReqTab="response"}>Response</button>
          </div>
          <div class="attack-detail-body"><pre class="atk-editor">{resultReqTab==="request"?resultRequest(selectedResult):resultResponse(selectedResult)}</pre></div>
        </div>
      {:else}
        <div class="attack-detail attack-detail-empty dim">Select a request to view details</div>
      {/if}
    </div>
  </div>
  {/if}

</div><!-- end .intruder-root -->

<!-- ══════════════════════════════════════════════════════════════════════ -->
<style>
  .intruder-root {
    display: flex; flex-direction: column; height: 100%;
    background: var(--surface-2); font-family: system-ui, -apple-system, sans-serif;
    font-size: 13px; color: var(--text); overflow: hidden; position: relative;
  }

  /* ── Top toolbar ─────────────────────────────────────────────────────── */
  .top-toolbar {
    display: flex; align-items: center; background: var(--surface-2);
    border-bottom: 1px solid var(--border); padding: 4px 8px; gap: 6px; flex-shrink: 0;
  }
  .tab-pills { display: flex; align-items: center; gap: 4px; }
  .tab-pill {
    display: flex; align-items: center; gap: 4px;
    background: var(--accent); border: 1px solid var(--accent-hover);
    border-radius: 3px 3px 0 0; padding: 3px 10px;
    font-size: 12px; color: #fff; border-bottom-color: var(--accent);
  }
  .tab-pill-num { font-weight: 600; }
  .tab-pill-x   { font-size: 11px; opacity: 0.7; cursor: pointer; }
  .tab-add {
    background: none; border: 1px solid var(--border-strong); border-radius: 3px;
    width: 22px; height: 22px; font-size: 16px; line-height: 1;
    cursor: pointer; color: var(--text-2); padding: 0;
  }
  .tab-add:hover { background: var(--border); }
  .toolbar-right { margin-left: auto; display: flex; align-items: center; gap: 6px; }
  .btn-start {
    display: flex; align-items: center; gap: 6px;
    background: var(--accent); color: #fff; border: none; border-radius: 3px;
    padding: 5px 16px; font-size: 13px; font-weight: 600; cursor: pointer; white-space: nowrap;
  }
  .btn-start:hover:not(:disabled) { background: var(--accent-hover); }
  .btn-start:disabled { opacity: 0.55; cursor: not-allowed; }
  .btn-gear {
    display: flex; align-items: center; justify-content: center;
    background: none; border: 1px solid var(--border-strong); border-radius: 3px;
    width: 28px; height: 28px; cursor: pointer; padding: 0;
  }
  .btn-gear:hover { background: var(--border); }
  .load-attack-btn {
    display: inline-flex; align-items: center;
    background: #fff; border: 1px solid var(--border-strong); border-radius: 3px;
    padding: 5px 12px; font-size: 12px; cursor: pointer; color: var(--text); white-space: nowrap;
  }
  .load-attack-btn:hover { background: var(--surface-2); }
  .spinner { display: inline-block; width: 10px; height: 10px; border: 2px solid rgba(255,255,255,0.4); border-top-color:#fff; border-radius:50%; animation:spin 0.7s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* ── Target bar ──────────────────────────────────────────────────────── */
  .target-bar {
    display: flex; align-items: center; gap: 8px; background: #ffffff;
    border-bottom: 1px solid var(--border); padding: 5px 12px; font-size: 12px; flex-shrink: 0;
  }
  .target-label { color: var(--text-muted); font-weight: 500; }
  .target-url   { font-family: ui-monospace, Consolas, monospace; color: var(--text); }
  .change-target-link { background:none;border:none;padding:0;color:#1a75c4;cursor:pointer;font-size:12px; }
  .change-target-link:hover { text-decoration:underline; }
  .target-sep   { color: var(--border-strong); }
  .target-check-label { display:flex;align-items:center;gap:5px;cursor:pointer; }
  .target-check-label input { accent-color:var(--accent);cursor:pointer; }

  /* ── Main area: editor | content panel | vertical tabs ──────────────── */
  .main-area {
    display: flex; flex: 1; overflow: hidden; min-height: 0;
  }

  /* ── Left: editor pane ───────────────────────────────────────────────── */
  .editor-pane {
    display: flex; flex-direction: column;
    flex: 0 0 55%; border-right: 1px solid var(--border);
    background: #ffffff; overflow: hidden; min-height: 0;
  }
  .editor-toolbar {
    display: flex; align-items: center; gap: 6px;
    background: var(--surface-2); border-bottom: 1px solid var(--border);
    padding: 3px 8px; flex-shrink: 0; flex-wrap: wrap;
  }
  .editor-modetabs { display: flex; }
  .mode-tab {
    background: none; border: 1px solid var(--border); border-radius: 0;
    padding: 2px 10px; font-size: 12px; cursor: pointer; color: var(--text-2);
  }
  .mode-tab:first-child { border-radius: 3px 0 0 3px; }
  .mode-tab:last-child  { border-left: none; border-radius: 0 3px 3px 0; }
  .mode-tab.active { background: var(--accent); border-color: var(--accent); color: #fff; }
  .mode-tab-nl { border-left: none; padding: 2px 7px; font-family: monospace; }
  .editor-search {
    border: 1px solid var(--border-strong); border-radius: 3px;
    padding: 2px 8px; font-size: 12px; outline: none; width: 130px;
  }
  .editor-search:focus { border-color: var(--accent); }
  .pos-btns { display: flex; gap: 3px; margin-left: 4px; }
  .pos-btn {
    background: #fff; border: 1px solid var(--border-strong); border-radius: 3px;
    padding: 2px 9px; font-size: 12px; cursor: pointer; color: var(--text); white-space: nowrap;
  }
  .pos-btn:hover { background: var(--surface-2); }

  .editor-body {
    flex: 1; position: relative; overflow: hidden; min-height: 0;
  }
  .req-hl-overlay {
    position: absolute; top:0;left:0;right:0;bottom:0; margin:0;
    padding: 10px 12px; font-family: ui-monospace,Consolas,"Courier New",monospace;
    font-size: 12px; line-height: 1.5; white-space: pre-wrap; word-break: normal;
    overflow: hidden; pointer-events: none; color: transparent; background: transparent;
    border: none; z-index: 0;
  }
  :global(.pos-hl) {
    background: rgba(224,58,0,0.18); border-radius: 2px;
    color: transparent; outline: 1px solid rgba(224,58,0,0.45);
  }
  .req-textarea {
    position: absolute; top:0;left:0;right:0;bottom:0;
    background: transparent; caret-color: var(--text); z-index: 1;
    resize: none; border: none; outline: none;
    font-family: ui-monospace,Consolas,"Courier New",monospace;
    font-size: 12px; line-height: 1.5; padding: 10px 12px; color: var(--text);
  }

  /* ── Middle: content pane ────────────────────────────────────────────── */
  .content-pane {
    flex: 1; display: flex; flex-direction: column;
    overflow: hidden; min-height: 0; background: #f9f9f9;
  }
  .cp-scroll {
    flex: 1; overflow-y: auto; padding: 12px 14px;
  }

  /* Positions content */
  .cp-section { margin-bottom: 12px; }
  .cp-section-title { font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--text-muted);margin-bottom:10px; }
  .cp-row { display:flex;align-items:center;gap:8px;margin-bottom:8px; }
  .cp-label { font-size:13px;color:var(--text-2);white-space:nowrap; }
  .cp-select { border:1px solid var(--border-strong);border-radius:3px;padding:3px 6px;font-size:12px;background:#fff;color:var(--text); }
  .pos-count-badge { font-size:12px;color:var(--text-2);background:var(--surface-2);border:1px solid var(--border);border-radius:3px;padding:5px 10px;margin-bottom:10px; }
  .cp-hint { font-size:12px;color:var(--text-muted);line-height:1.5;margin:0; }
  .view-results-btn { background:var(--surface-2);color:var(--text);border:1px solid var(--border-strong);border-radius:3px;padding:5px 14px;font-size:12px;cursor:pointer;width:100%; }
  .view-results-btn:hover { background:var(--surface-3); }

  /* Payloads content */
  .no-pos-banner { display:flex;align-items:flex-start;gap:8px;background:#fff3cd;border:1px solid #ffc107;border-radius:3px;padding:8px 12px;font-size:12px;color:#856404;margin-bottom:8px;line-height:1.4; }
  .ps-section { background:#fff;border:1px solid var(--border);border-radius:3px;padding:10px 12px;margin-bottom:8px; }
  .ps-header { font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--text-muted);margin-bottom:8px;border-bottom:1px solid var(--border);padding-bottom:5px; }
  .ps-row { display:flex;align-items:center;gap:8px; }
  .ps-label { font-size:13px;color:var(--text-2);white-space:nowrap; }
  .ps-num { width:50px;border:1px solid var(--border-strong);border-radius:3px;padding:2px 5px;font-size:12px; }
  .ps-spacer { flex:1; }
  .ps-count { font-size:13px;font-weight:600;color:var(--text); }
  .ps-desc { font-size:12px;color:var(--text-muted);margin-bottom:8px;line-height:1.4; }
  .ps-hint { font-size:11px;margin-top:5px; }
  .payload-layout { display:flex;gap:6px;align-items:flex-start; }
  .payload-ta { flex:1;min-height:140px;resize:vertical;border:1px solid var(--border-strong);border-radius:3px;font-family:ui-monospace,Consolas,monospace;font-size:12px;padding:6px 8px;background:var(--surface-1);color:var(--text);box-sizing:border-box; }
  .payload-btns { display:flex;flex-direction:column;gap:3px;flex-shrink:0;min-width:82px; }
  .add-item-row { display:flex;gap:6px;margin-top:8px;align-items:center; }
  .add-item-input { flex:1;border:1px solid var(--border-strong);border-radius:3px;padding:3px 8px;font-size:12px;background:#fff;outline:none; }
  .add-item-input:focus { border-color:var(--accent); }
  .num-grid { display:grid;grid-template-columns:auto 1fr;gap:5px 10px;align-items:center; }
  .num-label { font-size:12px;color:var(--text-2);white-space:nowrap; }
  .num-in { width:80px;border:1px solid var(--border-strong);border-radius:3px;padding:2px 6px;font-size:12px; }
  .null-opts { display:flex;flex-direction:column; }
  .radio-label { display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer;color:var(--text-2); }
  .radio-label input[type=radio] { accent-color:var(--accent);cursor:pointer; }
  .pro-notice { display:flex;align-items:flex-start;gap:8px;background:#e8f4fd;border:1px solid #b3d7f5;border-radius:3px;padding:8px 12px;font-size:12px;color:#1a75c4;margin-top:8px;line-height:1.4; }
  .proc-table { width:100%;border-collapse:collapse;font-size:12px;border:1px solid var(--border);border-radius:3px; }
  .proc-table th,.proc-table td { text-align:left;padding:4px 8px;border-bottom:1px solid #efefef; }
  .proc-table thead th { background:var(--surface-2);color:var(--text-muted);font-size:11px;font-weight:600; }
  .proc-empty { text-align:center;padding:10px; }
  .proc-btns { display:flex;gap:4px;margin-top:6px; }
  .rule-acts { float:right;display:flex;gap:2px; }
  .rule-btn { background:none;border:1px solid var(--border);border-radius:2px;padding:0 4px;font-size:11px;cursor:pointer;color:var(--text-2); }
  .rule-btn:disabled { opacity:.35;cursor:not-allowed; }
  .encode-row { display:flex;align-items:center;gap:6px;margin-bottom:6px; }
  .encode-label { font-size:13px;color:var(--text-2);cursor:pointer; }
  .encode-input { width:100%;border:1px solid var(--border-strong);border-radius:3px;padding:4px 8px;font-size:12px;font-family:ui-monospace,Consolas,monospace;background:var(--surface-1);box-sizing:border-box; }
  .encode-input:disabled { color:var(--text-dim);background:var(--surface-2); }

  /* Settings content */
  .srow { display:flex;align-items:center;gap:10px;margin-bottom:6px; }
  .slabel { font-size:13px;color:var(--text-2);white-space:nowrap; }
  .snum { width:68px;border:1px solid var(--border-strong);border-radius:3px;padding:2px 6px;font-size:12px; }

  /* Shared */
  .btn-sec { background:#fff;border:1px solid var(--border-strong);border-radius:3px;padding:3px 10px;font-size:12px;cursor:pointer;color:var(--text); }
  .btn-sec:hover:not(:disabled) { background:var(--surface-2); }
  .btn-sec:disabled { opacity:.45;cursor:not-allowed; }
  .dim { color:var(--text-muted); }
  .link-btn { background:none;border:none;padding:0;color:#1a75c4;font-size:inherit;cursor:pointer;text-decoration:underline; }
  .link-btn:hover { color:#0055a5; }

  /* ── Vertical tab strip (far right) ─────────────────────────────────── */
  .vtab-strip {
    display: flex; flex-direction: column;
    width: 26px; flex-shrink: 0;
    background: var(--border); border-left: 1px solid #d4d4d4;
  }
  .vtab {
    display: flex; align-items: center; justify-content: center;
    writing-mode: vertical-rl; text-orientation: mixed;
    transform: rotate(180deg);
    padding: 12px 5px; border: none; background: none;
    cursor: pointer; font-size: 11px; color: var(--text-2); font-weight: 500;
    white-space: nowrap; border-top: 1px solid #d4d4d4;
    flex-shrink: 0; letter-spacing: 0.02em;
  }
  .vtab:first-child { border-top: none; }
  .vtab:hover { background: var(--border); color: var(--text); }
  .vtab.active {
    background: var(--accent); color: #ffffff; font-weight: 600;
  }
  .vtab-label { pointer-events: none; }

  /* ── Attack results overlay ──────────────────────────────────────────── */
  .attack-overlay {
    position: absolute; top:0;left:0;right:0;bottom:0;
    background:#fff; z-index:200; display:flex;flex-direction:column; border:1px solid var(--border);
  }
  .attack-header { display:flex;align-items:center;justify-content:space-between;padding:8px 14px;background:var(--surface-2);border-bottom:1px solid var(--border);flex-shrink:0; }
  .attack-title  { font-size:13px;font-weight:600;color:var(--text); }
  .attack-hright { display:flex;align-items:center;gap:14px; }
  .atk-running   { font-size:12px;color:#e86c00; }
  .atk-done      { font-size:12px;color:#1b8c1b; }
  .attack-close  { background:var(--accent);color:#fff;border:none;border-radius:3px;padding:4px 12px;font-size:12px;cursor:pointer; }
  .attack-close:hover { background:var(--accent-hover); }
  .atk-error-banner { padding:7px 12px;background:#fde8e8;color:#b3231f;border-bottom:1px solid #f5b8b8;font-size:12px;flex-shrink:0; }
  .attack-filter-bar { display:flex;align-items:center;gap:8px;padding:5px 10px;background:var(--surface-1);border-bottom:1px solid var(--border);flex-shrink:0; }
  .atk-filter { font-size:12px;padding:3px 8px;border:1px solid var(--border-strong);border-radius:3px;width:180px; }
  .attack-body { flex:1;display:grid;grid-template-rows:minmax(120px,55%) 1fr;overflow:hidden; }
  .attack-table-wrap { overflow:auto;border-bottom:1px solid var(--border); }
  .attack-table { width:100%;border-collapse:collapse;font-size:12px; }
  .attack-table th { text-align:left;padding:4px 10px;background:var(--surface-2);color:var(--text-muted);font-size:11px;font-weight:600;border-bottom:1px solid var(--border);position:sticky;top:0;z-index:1;white-space:nowrap; }
  .attack-table th.atk-sort { cursor:pointer;user-select:none; }
  .attack-table th.atk-sort:hover { color:var(--text); }
  .atk-cmp-th { width:24px; }
  .atk-cmp-td { text-align:center;width:24px; }
  .atk-cmp-td input { accent-color:var(--accent);cursor:pointer; }
  .attack-table td { padding:3px 10px;border-bottom:1px solid var(--surface-2);white-space:nowrap; }
  .attack-table tbody tr { cursor:pointer; }
  .attack-table tbody tr:hover { background:var(--row-hover); }
  .attack-table tbody tr.atk-sel { background:var(--row-active); }
  .atk-num { text-align:right;font-variant-numeric:tabular-nums;color:var(--text-muted); }
  .atk-pl { max-width:260px;overflow:hidden;text-overflow:ellipsis; }
  .atk-err  { color:#d42c2c;font-weight:600; }
  .atk-warn { color:#c98a00;font-weight:600; }
  .status-2 { color:#2e7d32;font-weight:600; }
  .status-3 { color:#0277bd;font-weight:600; }
  .status-4 { color:#e65100;font-weight:600; }
  .status-5 { color:#b71c1c;font-weight:600; }
  .attack-detail { display:flex;flex-direction:column;overflow:hidden; }
  .attack-detail-empty { flex:1;display:flex;align-items:center;justify-content:center;font-size:12px; }
  .attack-detail-tabs { display:flex;padding:0 0 0 10px;background:var(--surface-2);border-bottom:1px solid var(--border);flex-shrink:0; }
  .atk-tab { background:transparent;border:none;padding:6px 14px;font-size:12px;color:var(--text-2);cursor:pointer;border-bottom:2px solid transparent; }
  .atk-tab:hover { color:var(--text); }
  .atk-tab.active { color:var(--accent);border-bottom-color:var(--accent);font-weight:600; }
  .attack-detail-body { flex:1;overflow:auto;padding:10px 12px; }
  .atk-editor { margin:0;padding:0;font-size:11.5px;font-family:ui-monospace,"Cascadia Code",Consolas,monospace;white-space:pre-wrap;word-break:break-all;color:var(--text);line-height:1.6; }
</style>
