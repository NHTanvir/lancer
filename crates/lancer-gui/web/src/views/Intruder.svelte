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
  let reqEditorMode   = "raw";
  let editorSearch    = "";

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

  // Attack / Results
  let results=[]; let running=false; let showResults=false; let attackNum=0;
  let selectedResult=null; let resultReqTab="request";
  let filterStatus=""; let filterPayload="";

  $: filteredResults = results.filter(r => {
    if (filterStatus  && !String(r.status||"").includes(filterStatus)) return false;
    if (filterPayload && !(r.payload||"").toLowerCase().includes(filterPayload.toLowerCase())) return false;
    return true;
  });

  onMount(() => {
    try {
      const raw = localStorage.getItem("lancer.send.intruder");
      if (raw) {
        const p = JSON.parse(raw);
        if (p.scheme) scheme=p.scheme; if (p.host) host=p.host;
        if (p.port) port=String(p.port); if (p.raw) requestTemplate=p.raw;
        requestLoaded=true; localStorage.removeItem("lancer.send.intruder"); subtab="positions";
      }
    } catch {}
  });

  let attackError="";
  // GUI label → API attack-kind token (the API also accepts these case/separator-insensitively).
  const KIND_MAP={"Sniper":"Sniper","Battering Ram":"BatteringRam","Pitchfork":"Pitchfork","Cluster Bomb":"ClusterBomb"};
  async function startAttack() {
    requestLoaded=true; running=true; results=[]; selectedResult=null; attackError="";
    attackNum+=1; showResults=true; filterStatus=""; filterPayload="";
    // The request template carries the §…§ markers; payloadList is one payload set.
    // Cluster Bomb/Pitchfork with multiple positions reuse this set per position.
    const sets=[payloadList];
    // Grep config the results table renders as dynamic columns (start/end
    // boundaries compile to a regex server-side).
    const grep={
      match_strings: grepMatchEnabled ? grepMatchRules.filter(r=>r.enabled&&r.expr).map(r=>r.expr) : [],
      extracts: grepExtractEnabled ? grepExtractRules.filter(r=>r.enabled).map(r=>({label:r.desc||"extract",start:r.start||"",end:r.end||""})) : [],
      reflect_payload: grepPayloadsEnabled,
    };
    activeGrepCols={ matches: grep.match_strings.slice(), extracts: grep.extracts.map(e=>e.label) };
    try {
      const r = await fetch("/api/v1/intruder",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({host,port:parseInt(port,10),scheme,request:requestTemplate,kind:KIND_MAP[attackType]||"Sniper",payloads:sets,grep,max_concurrency:parseInt(sThreads,10)||10,throttle_ms:parseInt(sThrottle,10)||0,max_retries:parseInt(sRetries,10)||0})});
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
  $: atkColCount=7+activeGrepCols.matches.length+activeGrepCols.extracts.length+(grepPayloadsEnabled?1:0);

  // Settings
  let sThreads=10; let sRetries=3; let sPause=2000; let sThrottle=0;
  let sTimeout=120; let sFollowRedirects=true; let sMakeUnique=false;

  // Resource pool
  let rpMode="shared"; let rpName=""; let rpMaxConcurrent=10; let rpDelay=0;
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
        </div>
      </div>
      <div class="editor-body">
        <pre class="req-hl-overlay" bind:this={overlayEl} aria-hidden="true">{@html highlightedTemplate}</pre>
        <textarea
          id="req-editor"
          class="req-textarea"
          style="background:transparent;caret-color:#212121"
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
              <div class="ps-desc">Generates a list of usernames derived from a supplied name.</div>
              <div class="ps-row" style="margin-top:8px">
                <label class="ps-label">Name:</label>
                <input type="text" class="add-item-input" style="flex:1" bind:value={userGenBase} placeholder="e.g. John Smith" />
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
            <div style="margin-top:12px"><button class="btn-sec">Save pool settings</button></div>
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
          <thead><tr><th>#</th><th>Payload</th><th>Status</th><th>Error</th><th>Timeout</th><th>Length</th><th>Comment</th>
            {#each activeGrepCols.matches as m}<th title={"grep-match: "+m}>≈ {m.length>12?m.slice(0,12)+"…":m}</th>{/each}
            {#each activeGrepCols.extracts as e}<th title={"grep-extract: "+e}>⌑ {e}</th>{/each}
            {#if grepPayloadsEnabled}<th title="payload reflected in response">Reflected</th>{/if}
          </tr></thead>
          <tbody>
            {#if running && results.length===0}<tr><td colspan={atkColCount} class="dim" style="text-align:center;padding:18px">Sending requests…</td></tr>{/if}
            {#if !running && results.length===0 && !attackError}<tr><td colspan={atkColCount} class="dim" style="text-align:center;padding:18px">No results.</td></tr>{/if}
            {#each filteredResults as r}
              <tr class:atk-sel={selectedResult===r} on:click={()=>{selectedResult=r;resultReqTab="request"}}>
                <td class="dim atk-num">{r.index}</td>
                <td class="atk-pl">{r.payload||(r.payloads||[]).join(", ")||"—"}</td>
                <td class={statusClass(r.status)}>{r.status||"—"}</td>
                <td class={r.error?"atk-err":"dim"}>{r.error?"✓":""}</td>
                <td class={r.timeout?"atk-warn":"dim"}>{r.timeout?"✓":""}</td>
                <td class="dim atk-num">{r.length??"—"}</td>
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
    background: #f5f5f5; font-family: system-ui, -apple-system, sans-serif;
    font-size: 13px; color: #212121; overflow: hidden; position: relative;
  }

  /* ── Top toolbar ─────────────────────────────────────────────────────── */
  .top-toolbar {
    display: flex; align-items: center; background: #f0f0f0;
    border-bottom: 1px solid #dedede; padding: 4px 8px; gap: 6px; flex-shrink: 0;
  }
  .tab-pills { display: flex; align-items: center; gap: 4px; }
  .tab-pill {
    display: flex; align-items: center; gap: 4px;
    background: #e03a00; border: 1px solid #c73400;
    border-radius: 3px 3px 0 0; padding: 3px 10px;
    font-size: 12px; color: #fff; border-bottom-color: #e03a00;
  }
  .tab-pill-num { font-weight: 600; }
  .tab-pill-x   { font-size: 11px; opacity: 0.7; cursor: pointer; }
  .tab-add {
    background: none; border: 1px solid #c8c8c8; border-radius: 3px;
    width: 22px; height: 22px; font-size: 16px; line-height: 1;
    cursor: pointer; color: #555; padding: 0;
  }
  .tab-add:hover { background: #e8e8e8; }
  .toolbar-right { margin-left: auto; display: flex; align-items: center; gap: 6px; }
  .btn-start {
    display: flex; align-items: center; gap: 6px;
    background: #e03a00; color: #fff; border: none; border-radius: 3px;
    padding: 5px 16px; font-size: 13px; font-weight: 600; cursor: pointer; white-space: nowrap;
  }
  .btn-start:hover:not(:disabled) { background: #c73400; }
  .btn-start:disabled { opacity: 0.55; cursor: not-allowed; }
  .btn-gear {
    display: flex; align-items: center; justify-content: center;
    background: none; border: 1px solid #c8c8c8; border-radius: 3px;
    width: 28px; height: 28px; cursor: pointer; padding: 0;
  }
  .btn-gear:hover { background: #e8e8e8; }
  .spinner { display: inline-block; width: 10px; height: 10px; border: 2px solid rgba(255,255,255,0.4); border-top-color:#fff; border-radius:50%; animation:spin 0.7s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* ── Target bar ──────────────────────────────────────────────────────── */
  .target-bar {
    display: flex; align-items: center; gap: 8px; background: #ffffff;
    border-bottom: 1px solid #dedede; padding: 5px 12px; font-size: 12px; flex-shrink: 0;
  }
  .target-label { color: #767676; font-weight: 500; }
  .target-url   { font-family: ui-monospace, Consolas, monospace; color: #212121; }
  .change-target-link { background:none;border:none;padding:0;color:#1a75c4;cursor:pointer;font-size:12px; }
  .change-target-link:hover { text-decoration:underline; }
  .target-sep   { color: #c8c8c8; }
  .target-check-label { display:flex;align-items:center;gap:5px;cursor:pointer; }
  .target-check-label input { accent-color:#e03a00;cursor:pointer; }

  /* ── Main area: editor | content panel | vertical tabs ──────────────── */
  .main-area {
    display: flex; flex: 1; overflow: hidden; min-height: 0;
  }

  /* ── Left: editor pane ───────────────────────────────────────────────── */
  .editor-pane {
    display: flex; flex-direction: column;
    flex: 0 0 55%; border-right: 1px solid #dedede;
    background: #ffffff; overflow: hidden; min-height: 0;
  }
  .editor-toolbar {
    display: flex; align-items: center; gap: 6px;
    background: #f5f5f5; border-bottom: 1px solid #dedede;
    padding: 3px 8px; flex-shrink: 0; flex-wrap: wrap;
  }
  .editor-modetabs { display: flex; }
  .mode-tab {
    background: none; border: 1px solid #dedede; border-radius: 0;
    padding: 2px 10px; font-size: 12px; cursor: pointer; color: #555;
  }
  .mode-tab:first-child { border-radius: 3px 0 0 3px; }
  .mode-tab:last-child  { border-left: none; border-radius: 0 3px 3px 0; }
  .mode-tab.active { background: #e03a00; border-color: #e03a00; color: #fff; }
  .mode-tab-nl { border-left: none; padding: 2px 7px; font-family: monospace; }
  .editor-search {
    border: 1px solid #c8c8c8; border-radius: 3px;
    padding: 2px 8px; font-size: 12px; outline: none; width: 130px;
  }
  .editor-search:focus { border-color: #e03a00; }
  .pos-btns { display: flex; gap: 3px; margin-left: 4px; }
  .pos-btn {
    background: #fff; border: 1px solid #c8c8c8; border-radius: 3px;
    padding: 2px 9px; font-size: 12px; cursor: pointer; color: #333; white-space: nowrap;
  }
  .pos-btn:hover { background: #f0f0f0; }

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
    background: transparent; caret-color: #212121; z-index: 1;
    resize: none; border: none; outline: none;
    font-family: ui-monospace,Consolas,"Courier New",monospace;
    font-size: 12px; line-height: 1.5; padding: 10px 12px; color: #212121;
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
  .cp-section-title { font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#767676;margin-bottom:10px; }
  .cp-row { display:flex;align-items:center;gap:8px;margin-bottom:8px; }
  .cp-label { font-size:13px;color:#444;white-space:nowrap; }
  .cp-select { border:1px solid #c8c8c8;border-radius:3px;padding:3px 6px;font-size:12px;background:#fff;color:#212121; }
  .pos-count-badge { font-size:12px;color:#555;background:#f0f0f0;border:1px solid #dedede;border-radius:3px;padding:5px 10px;margin-bottom:10px; }
  .cp-hint { font-size:12px;color:#767676;line-height:1.5;margin:0; }
  .view-results-btn { background:#f0f0f0;color:#333;border:1px solid #c8c8c8;border-radius:3px;padding:5px 14px;font-size:12px;cursor:pointer;width:100%; }
  .view-results-btn:hover { background:#e4e4e4; }

  /* Payloads content */
  .no-pos-banner { display:flex;align-items:flex-start;gap:8px;background:#fff3cd;border:1px solid #ffc107;border-radius:3px;padding:8px 12px;font-size:12px;color:#856404;margin-bottom:8px;line-height:1.4; }
  .ps-section { background:#fff;border:1px solid #dedede;border-radius:3px;padding:10px 12px;margin-bottom:8px; }
  .ps-header { font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#767676;margin-bottom:8px;border-bottom:1px solid #eee;padding-bottom:5px; }
  .ps-row { display:flex;align-items:center;gap:8px; }
  .ps-label { font-size:13px;color:#444;white-space:nowrap; }
  .ps-num { width:50px;border:1px solid #c8c8c8;border-radius:3px;padding:2px 5px;font-size:12px; }
  .ps-spacer { flex:1; }
  .ps-count { font-size:13px;font-weight:600;color:#212121; }
  .ps-desc { font-size:12px;color:#767676;margin-bottom:8px;line-height:1.4; }
  .ps-hint { font-size:11px;margin-top:5px; }
  .payload-layout { display:flex;gap:6px;align-items:flex-start; }
  .payload-ta { flex:1;min-height:140px;resize:vertical;border:1px solid #c8c8c8;border-radius:3px;font-family:ui-monospace,Consolas,monospace;font-size:12px;padding:6px 8px;background:#fafafa;color:#212121;box-sizing:border-box; }
  .payload-btns { display:flex;flex-direction:column;gap:3px;flex-shrink:0;min-width:82px; }
  .add-item-row { display:flex;gap:6px;margin-top:8px;align-items:center; }
  .add-item-input { flex:1;border:1px solid #c8c8c8;border-radius:3px;padding:3px 8px;font-size:12px;background:#fff;outline:none; }
  .add-item-input:focus { border-color:#e03a00; }
  .num-grid { display:grid;grid-template-columns:auto 1fr;gap:5px 10px;align-items:center; }
  .num-label { font-size:12px;color:#444;white-space:nowrap; }
  .num-in { width:80px;border:1px solid #c8c8c8;border-radius:3px;padding:2px 6px;font-size:12px; }
  .null-opts { display:flex;flex-direction:column; }
  .radio-label { display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer;color:#444; }
  .radio-label input[type=radio] { accent-color:#e03a00;cursor:pointer; }
  .pro-notice { display:flex;align-items:flex-start;gap:8px;background:#e8f4fd;border:1px solid #b3d7f5;border-radius:3px;padding:8px 12px;font-size:12px;color:#1a75c4;margin-top:8px;line-height:1.4; }
  .proc-table { width:100%;border-collapse:collapse;font-size:12px;border:1px solid #dedede;border-radius:3px; }
  .proc-table th,.proc-table td { text-align:left;padding:4px 8px;border-bottom:1px solid #efefef; }
  .proc-table thead th { background:#f5f5f5;color:#767676;font-size:11px;font-weight:600; }
  .proc-empty { text-align:center;padding:10px; }
  .proc-btns { display:flex;gap:4px;margin-top:6px; }
  .rule-acts { float:right;display:flex;gap:2px; }
  .rule-btn { background:none;border:1px solid #dedede;border-radius:2px;padding:0 4px;font-size:11px;cursor:pointer;color:#555; }
  .rule-btn:disabled { opacity:.35;cursor:not-allowed; }
  .encode-row { display:flex;align-items:center;gap:6px;margin-bottom:6px; }
  .encode-label { font-size:13px;color:#444;cursor:pointer; }
  .encode-input { width:100%;border:1px solid #c8c8c8;border-radius:3px;padding:4px 8px;font-size:12px;font-family:ui-monospace,Consolas,monospace;background:#fafafa;box-sizing:border-box; }
  .encode-input:disabled { color:#aaa;background:#f0f0f0; }

  /* Settings content */
  .srow { display:flex;align-items:center;gap:10px;margin-bottom:6px; }
  .slabel { font-size:13px;color:#444;white-space:nowrap; }
  .snum { width:68px;border:1px solid #c8c8c8;border-radius:3px;padding:2px 6px;font-size:12px; }

  /* Shared */
  .btn-sec { background:#fff;border:1px solid #c8c8c8;border-radius:3px;padding:3px 10px;font-size:12px;cursor:pointer;color:#333; }
  .btn-sec:hover:not(:disabled) { background:#f0f0f0; }
  .btn-sec:disabled { opacity:.45;cursor:not-allowed; }
  .dim { color:#767676; }
  .link-btn { background:none;border:none;padding:0;color:#1a75c4;font-size:inherit;cursor:pointer;text-decoration:underline; }
  .link-btn:hover { color:#0055a5; }

  /* ── Vertical tab strip (far right) ─────────────────────────────────── */
  .vtab-strip {
    display: flex; flex-direction: column;
    width: 26px; flex-shrink: 0;
    background: #ebebeb; border-left: 1px solid #d4d4d4;
  }
  .vtab {
    display: flex; align-items: center; justify-content: center;
    writing-mode: vertical-rl; text-orientation: mixed;
    transform: rotate(180deg);
    padding: 12px 5px; border: none; background: none;
    cursor: pointer; font-size: 11px; color: #555; font-weight: 500;
    white-space: nowrap; border-top: 1px solid #d4d4d4;
    flex-shrink: 0; letter-spacing: 0.02em;
  }
  .vtab:first-child { border-top: none; }
  .vtab:hover { background: #e0e0e0; color: #212121; }
  .vtab.active {
    background: #e03a00; color: #ffffff; font-weight: 600;
  }
  .vtab-label { pointer-events: none; }

  /* ── Attack results overlay ──────────────────────────────────────────── */
  .attack-overlay {
    position: absolute; top:0;left:0;right:0;bottom:0;
    background:#fff; z-index:200; display:flex;flex-direction:column; border:1px solid #dedede;
  }
  .attack-header { display:flex;align-items:center;justify-content:space-between;padding:8px 14px;background:#f5f5f5;border-bottom:1px solid #dedede;flex-shrink:0; }
  .attack-title  { font-size:13px;font-weight:600;color:#212121; }
  .attack-hright { display:flex;align-items:center;gap:14px; }
  .atk-running   { font-size:12px;color:#e86c00; }
  .atk-done      { font-size:12px;color:#1b8c1b; }
  .attack-close  { background:#e03a00;color:#fff;border:none;border-radius:3px;padding:4px 12px;font-size:12px;cursor:pointer; }
  .attack-close:hover { background:#c73400; }
  .atk-error-banner { padding:7px 12px;background:#fde8e8;color:#b3231f;border-bottom:1px solid #f5b8b8;font-size:12px;flex-shrink:0; }
  .attack-filter-bar { display:flex;align-items:center;gap:8px;padding:5px 10px;background:#fafafa;border-bottom:1px solid #e8e8e8;flex-shrink:0; }
  .atk-filter { font-size:12px;padding:3px 8px;border:1px solid #c8c8c8;border-radius:3px;width:180px; }
  .attack-body { flex:1;display:grid;grid-template-rows:minmax(120px,55%) 1fr;overflow:hidden; }
  .attack-table-wrap { overflow:auto;border-bottom:1px solid #dedede; }
  .attack-table { width:100%;border-collapse:collapse;font-size:12px; }
  .attack-table th { text-align:left;padding:4px 10px;background:#f5f5f5;color:#767676;font-size:11px;font-weight:600;border-bottom:1px solid #dedede;position:sticky;top:0;z-index:1;white-space:nowrap; }
  .attack-table td { padding:3px 10px;border-bottom:1px solid #f0f0f0;white-space:nowrap; }
  .attack-table tbody tr { cursor:pointer; }
  .attack-table tbody tr:hover { background:#f0f7ff; }
  .attack-table tbody tr.atk-sel { background:#daeeff; }
  .atk-num { text-align:right;font-variant-numeric:tabular-nums;color:#767676; }
  .atk-pl { max-width:260px;overflow:hidden;text-overflow:ellipsis; }
  .atk-err  { color:#d42c2c;font-weight:600; }
  .atk-warn { color:#c98a00;font-weight:600; }
  .status-2 { color:#2e7d32;font-weight:600; }
  .status-3 { color:#0277bd;font-weight:600; }
  .status-4 { color:#e65100;font-weight:600; }
  .status-5 { color:#b71c1c;font-weight:600; }
  .attack-detail { display:flex;flex-direction:column;overflow:hidden; }
  .attack-detail-empty { flex:1;display:flex;align-items:center;justify-content:center;font-size:12px; }
  .attack-detail-tabs { display:flex;padding:0 0 0 10px;background:#f5f5f5;border-bottom:1px solid #dedede;flex-shrink:0; }
  .atk-tab { background:transparent;border:none;padding:6px 14px;font-size:12px;color:#555;cursor:pointer;border-bottom:2px solid transparent; }
  .atk-tab:hover { color:#212121; }
  .atk-tab.active { color:#e03a00;border-bottom-color:#e03a00;font-weight:600; }
  .attack-detail-body { flex:1;overflow:auto;padding:10px 12px; }
  .atk-editor { margin:0;padding:0;font-size:11.5px;font-family:ui-monospace,"Cascadia Code",Consolas,monospace;white-space:pre-wrap;word-break:break-all;color:#212121;line-height:1.6; }
</style>
