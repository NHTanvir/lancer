<script>
  import { onMount, onDestroy } from "svelte";

  let subtab = "sitemap";
  let issues = [];

  // Site map state
  let history = [];
  let selectedEntry = null;
  let selectedHost = null;      // when a host node is selected, table shows that host's entries
  let expandedHosts = {};
  let reqTab = "pretty";
  let respTab = "pretty";
  let ctxMenu = null; // { x, y, entry }
  let pollTimer;
  let tableFilter = "";
  let hideOutOfScope = false;
  let inScopeSet = new Set();   // hosts considered in scope (populated from /v1/scope)

  // ── Site-map extra filters (Burp parity) ──────────────────────────────
  let showFilterRow = false;
  let paramOnly = false;        // "show only parametrized"
  let hideErrors = false;       // hide 4xx/5xx
  let noteFilter = "";          // annotation substring filter
  const MIME_GROUPS = ["HTML", "Script", "XML", "CSS", "Image", "Other"];
  let mimeShow = { HTML: true, Script: true, XML: true, CSS: true, Image: true, Other: true };

  function mimeGroupOf(e) {
    const m = (mimeOf(e) || "").toLowerCase();
    if (!m) return "Other";
    if (m.includes("html")) return "HTML";
    if (m.includes("javascript") || m.includes("ecmascript") || m.includes("/json")) return "Script";
    if (m.includes("xml")) return "XML";
    if (m.includes("css")) return "CSS";
    if (m.startsWith("image/")) return "Image";
    return "Other";
  }

  // Sort state
  let sortKey = "time";
  let sortDir = "desc"; // "asc" | "desc"

  // Group history by host
  $: siteTree = buildTree(history);

  // Filtered entries shown in the request table (right-top)
  $: tableEntries = filterAndSort(history, selectedHost, tableFilter, hideOutOfScope, inScopeSet, sortKey, sortDir, paramOnly, hideErrors, noteFilter, mimeShow);

  function filterAndSort(rows, host, filterText, hideOOS, scopeSet, key, dir, paramOnlyF, hideErrorsF, noteF, mimeShowF) {
    let out = rows;
    if (host) out = out.filter(r => (r.host || hostFromUrl(r.url)) === host);
    if (filterText) {
      const f = filterText.toLowerCase();
      out = out.filter(r =>
        (r.url || "").toLowerCase().includes(f) ||
        (r.host || "").toLowerCase().includes(f) ||
        (r.path || "").toLowerCase().includes(f) ||
        String(r.status || "").includes(f)
      );
    }
    if (hideOOS && scopeSet.size > 0) {
      out = out.filter(r => scopeSet.has(r.host || hostFromUrl(r.url)));
    }
    if (paramOnlyF) out = out.filter(r => paramsCount(r) > 0);
    if (hideErrorsF) out = out.filter(r => { const s = parseInt(r.status, 10) || 0; return s < 400; });
    if (noteF) {
      const nf = noteF.toLowerCase();
      out = out.filter(r => (r.comment || "").toLowerCase().includes(nf));
    }
    if (mimeShowF && MIME_GROUPS.some(g => !mimeShowF[g])) {
      out = out.filter(r => mimeShowF[mimeGroupOf(r)] !== false);
    }
    out = [...out].sort((a, b) => {
      const va = sortValue(a, key);
      const vb = sortValue(b, key);
      if (va === vb) return 0;
      const cmp = va < vb ? -1 : 1;
      return dir === "asc" ? cmp : -cmp;
    });
    return out;
  }

  function sortValue(e, k) {
    switch (k) {
      case "host":   return e.host || "";
      case "method": return e.method || "";
      case "url":    return e.url || e.path || "";
      case "params": return paramsCount(e);
      case "status": return parseInt(e.status, 10) || 0;
      case "length": return responseLength(e);
      case "mime":   return mimeOf(e) || "";
      case "title":  return titleOf(e) || "";
      case "time":   return e.captured_at || 0;
      case "notes":  return e.comment || "";
      default:       return "";
    }
  }

  function setSort(k) {
    if (sortKey === k) sortDir = sortDir === "asc" ? "desc" : "asc";
    else { sortKey = k; sortDir = "asc"; }
  }

  function hostFromUrl(u) {
    if (!u) return "";
    return u.replace(/https?:\/\//, "").split("/")[0];
  }

  function paramsCount(e) {
    const url = e.url || e.path || "";
    const q = url.split("?")[1];
    if (!q) return 0;
    return q.split("&").filter(Boolean).length;
  }

  function findHeader(headers, name) {
    if (!Array.isArray(headers)) return "";
    const n = name.toLowerCase();
    const h = headers.find(h => (h.name || "").toLowerCase() === n);
    return h ? (h.value || "") : "";
  }

  function mimeOf(e) {
    const ct = e.mime || findHeader(e.response?.headers, "content-type") || "";
    return ct.split(";")[0].trim();
  }

  function responseLength(e) {
    if (typeof e.response_length === "number") return e.response_length;
    if (typeof e.length === "number") return e.length;
    const cl = findHeader(e.response?.headers, "content-length");
    if (cl) return parseInt(cl, 10) || 0;
    const body = bytesToText(e.response?.body);
    return body ? body.length : 0;
  }

  function titleOf(e) {
    if (e.title) return e.title;
    const body = bytesToText(e.response?.body);
    if (!body) return "";
    const m = body.match(/<title[^>]*>([^<]*)<\/title>/i);
    return m ? m[1].trim() : "";
  }

  function bytesToText(b) {
    if (b == null) return "";
    if (typeof b === "string") return b;
    if (Array.isArray(b)) {
      try { return new TextDecoder("utf-8").decode(new Uint8Array(b)); } catch { return ""; }
    }
    return String(b);
  }

  function fmtTime(t) {
    if (!t) return "";
    const d = typeof t === "number" ? new Date(t) : new Date(t);
    if (isNaN(d.getTime())) return String(t);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }

  function portOf(e) {
    if (e.port) return e.port;
    const sc = (e.scheme || "").toLowerCase();
    if (sc === "https") return 443;
    if (sc === "http") return 80;
    // try to derive from url
    const u = e.url || "";
    const m = u.match(/:\/\/[^/:]+:(\d+)/);
    if (m) return parseInt(m[1], 10);
    return u.startsWith("https") ? 443 : 80;
  }

  function buildTree(entries) {
    // 3-level tree: host -> port -> items
    const hosts = {};
    for (const e of entries) {
      const host = e.host || e.url?.replace(/https?:\/\//, "").split("/")[0] || "unknown";
      const port = portOf(e);
      if (!hosts[host]) hosts[host] = {};
      if (!hosts[host][port]) hosts[host][port] = [];
      hosts[host][port].push(e);
    }
    return Object.entries(hosts).map(([host, ports]) => {
      const portList = Object.entries(ports)
        .map(([port, items]) => ({ port, items }))
        .sort((a, b) => (parseInt(a.port, 10) || 0) - (parseInt(b.port, 10) || 0));
      const items = portList.flatMap(p => p.items);
      return { host, ports: portList, items };
    });
  }

  // ── Per-branch severity circle (joins host/path against issues[]) ──────
  const SEV_RANK = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };
  function normSev(s) {
    if (!s) return "Info";
    const t = String(s);
    return t.charAt(0).toUpperCase() + t.slice(1).toLowerCase();
  }
  function severityForHost(host) {
    let best = null, rank = -1;
    for (const iss of issues) {
      if ((iss.host || "") !== host) continue;
      const sv = normSev(iss.severity);
      const rk = SEV_RANK[sv] ?? 0;
      if (rk > rank) { rank = rk; best = sv; }
    }
    return best;
  }
  function severityForPath(host, path) {
    let best = null, rank = -1;
    for (const iss of issues) {
      if ((iss.host || "") !== host) continue;
      if ((iss.path || "") !== path) continue;
      const sv = normSev(iss.severity);
      const rk = SEV_RANK[sv] ?? 0;
      if (rk > rank) { rank = rk; best = sv; }
    }
    return best;
  }
  function sevColor(sv) {
    switch (sv) {
      case "Critical": return "#9b1d1d";
      case "High":     return "#d42c2c";
      case "Medium":   return "#e86c00";
      case "Low":      return "#1a75c4";
      case "Info":     return "#69707b";
      default:         return null;
    }
  }

  // ── Requested vs inferred URL distinction ──────────────────────────────
  // Entries captured by the proxy are "requested" and render in normal text;
  // entries flagged as discovered-but-not-requested render muted.
  function isInferred(e) {
    if (e.inferred === true) return true;
    if (e.requested === false) return true;
    return false; // proxy traffic is requested by default
  }

  function toggleHost(host) {
    expandedHosts = { ...expandedHosts, [host]: !expandedHosts[host] };
  }

  function selectHostNode(host) {
    selectedHost = selectedHost === host ? null : host;
    expandedHosts = { ...expandedHosts, [host]: true };
    ctxMenu = null;
  }

  function selectEntry(e) {
    selectedEntry = e;
    selectedHost = e.host || hostFromUrl(e.url);
    ctxMenu = null;
  }

  function onRightClick(event, entry) {
    event.preventDefault();
    ctxMenu = { x: event.clientX, y: event.clientY, entry };
  }

  function closeCtx() { ctxMenu = null; }

  function entryToSendPayload(e) {
    const raw = formatRequest(e);
    return {
      method: e.method || "GET",
      scheme: e.scheme || "http",
      host: e.host || "",
      port: e.port || (e.scheme === "https" ? 443 : 80),
      path: e.path || e.url || "/",
      raw,
    };
  }

  function ctxSendToRepeater() {
    if (!ctxMenu) return;
    const payload = entryToSendPayload(ctxMenu.entry);
    localStorage.setItem("repeater_prefill", JSON.stringify(payload));
    localStorage.setItem("lancer.send.repeater", JSON.stringify(payload));
    window.dispatchEvent(new CustomEvent("lancer:navigate", { detail: "repeater" }));
    closeCtx();
  }

  function ctxSendToIntruder() {
    if (!ctxMenu) return;
    const payload = entryToSendPayload(ctxMenu.entry);
    localStorage.setItem("lancer.send.intruder", JSON.stringify(payload));
    window.dispatchEvent(new CustomEvent("lancer:navigate", { detail: "intruder" }));
    closeCtx();
  }

  function ctxSendToComparer(role) {
    if (!ctxMenu) return;
    const e = ctxMenu.entry;
    const item = role === "response" ? formatResponse(e) : formatRequest(e);
    const existing = JSON.parse(localStorage.getItem("lancer.send.comparer") || "{}");
    if (!existing.item1) existing.item1 = item;
    else existing.item2 = item;
    localStorage.setItem("lancer.send.comparer", JSON.stringify(existing));
    window.dispatchEvent(new CustomEvent("lancer:navigate", { detail: "comparer" }));
    closeCtx();
  }

  function ctxSendToDecoder() {
    if (!ctxMenu) return;
    const e = ctxMenu.entry;
    const text = bytesToText(e.response?.body) || formatResponse(e);
    localStorage.setItem("lancer.send.decoder", JSON.stringify({ input: text }));
    window.dispatchEvent(new CustomEvent("lancer:navigate", { detail: "decoder" }));
    closeCtx();
  }

  async function ctxSendToScanner() {
    if (!ctxMenu) return;
    const e = ctxMenu.entry;
    const url = e.url || `${e.scheme || "http"}://${e.host}${e.path || "/"}`;
    try {
      await fetch("/api/v1/scan/full", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ url }),
      });
    } catch {}
    closeCtx();
  }

  function ctxCopyAsCurl() {
    if (!ctxMenu) return;
    const e = ctxMenu.entry;
    const url = e.url || `${e.scheme || "http"}://${e.host}${e.path || "/"}`;
    let curl = `curl -X ${e.method || "GET"} '${url}'`;
    if (e.request && Array.isArray(e.request.headers)) {
      for (const h of e.request.headers) {
        if (["host","content-length","accept-encoding"].includes(h.name.toLowerCase())) continue;
        curl += ` \\\n  -H '${h.name}: ${h.value.replace(/'/g,"'\\''")}'`;
      }
    }
    navigator.clipboard.writeText(curl).catch(() => {});
    closeCtx();
  }

  function ctxCopyUrl() {
    if (!ctxMenu) return;
    const url = ctxMenu.entry.url || `${ctxMenu.entry.host}${ctxMenu.entry.path || ""}`;
    navigator.clipboard.writeText(url).catch(() => {});
    closeCtx();
  }

  async function ctxAddScope() {
    if (!ctxMenu) return;
    const e = ctxMenu.entry;
    const rule = {
      kind: "Include",
      protocol: e.scheme || null,
      host: e.host || "",
      port: e.port || null,
      path: null,
      enabled: true,
      regex: false,
    };
    if (!rule.host) { closeCtx(); return; }
    scopeRules = [...scopeRules, rule];
    await saveScope();
    closeCtx();
  }
  function ctxDelete() {
    if (!ctxMenu) return;
    history = history.filter(h => h !== ctxMenu.entry);
    if (selectedEntry === ctxMenu.entry) selectedEntry = null;
    closeCtx();
  }

  // ── Branch-level (tree node) context actions ───────────────────────────
  function branchEntries(host) {
    return history.filter(r => (r.host || hostFromUrl(r.url)) === host);
  }

  async function ctxSpiderBranch() {
    if (!ctxMenu) return;
    const e = ctxMenu.entry;
    const host = e.host || hostFromUrl(e.url);
    const url = e.url || `${e.scheme || "http"}://${host}${e.path || "/"}`;
    try {
      await fetch("/api/v1/crawl/deep", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ url, host }),
      });
    } catch {}
    closeCtx();
  }

  async function ctxScanBranch() {
    if (!ctxMenu) return;
    const e = ctxMenu.entry;
    const host = e.host || hostFromUrl(e.url);
    const targets = branchEntries(host);
    closeCtx();
    for (const r of targets) {
      const url = r.url || `${r.scheme || "http"}://${host}${r.path || "/"}`;
      try {
        await fetch("/api/v1/scan/full", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ url }),
        });
      } catch {}
    }
  }

  async function ctxRemoveScope() {
    if (!ctxMenu) return;
    const e = ctxMenu.entry;
    const host = e.host || hostFromUrl(e.url);
    if (!host) { closeCtx(); return; }
    // Drop matching Include rules and add an Exclude rule for the host.
    scopeRules = scopeRules.filter(r => !(r.kind === "Include" && r.host === host));
    scopeRules = [...scopeRules, {
      kind: "Exclude",
      protocol: e.scheme || null,
      host,
      port: null,
      path: null,
      enabled: true,
      regex: false,
    }];
    await saveScope();
    closeCtx();
  }

  function ctxCopyBranchUrls() {
    if (!ctxMenu) return;
    const e = ctxMenu.entry;
    const host = e.host || hostFromUrl(e.url);
    const urls = branchEntries(host)
      .map(r => r.url || `${r.scheme || "http"}://${host}${r.path || "/"}`);
    navigator.clipboard.writeText([...new Set(urls)].join("\n")).catch(() => {});
    closeCtx();
  }

  function ctxExpandBranch(open) {
    if (!ctxMenu) return;
    const e = ctxMenu.entry;
    const host = e.host || hostFromUrl(e.url);
    expandedHosts = { ...expandedHosts, [host]: open };
    closeCtx();
  }

  // ── §2.4 Engagement tools ──────────────────────────────────────────────────
  let engResult = null; // { title, kind, data }
  async function eng(title, run) {
    closeCtx();
    engResult = { title, kind: "loading", data: null };
    try { engResult = { title, ...(await run()) }; }
    catch (err) { engResult = { title, kind: "error", data: String(err) }; }
  }
  function engEntry() { return ctxMenu ? ctxMenu.entry : selectedEntry; }
  function engUrl(e) { return e.url || `${e.scheme || "http"}://${e.host || ""}${e.path || "/"}`; }

  function ctxFindComments() {
    const e = engEntry(); if (!e) return;
    const body = bytesToText(e.response?.body), url = engUrl(e);
    eng("HTML/JS comments", async () => {
      const r = await fetch("/api/v1/engagement/find-comments", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ url, body }) });
      return { kind: "list", data: await r.json() };
    });
  }
  function ctxFindScripts() {
    const e = engEntry(); if (!e) return;
    const body = bytesToText(e.response?.body), base_url = engUrl(e);
    eng("Referenced scripts", async () => {
      const r = await fetch("/api/v1/engagement/find-scripts", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ base_url, body }) });
      return { kind: "list", data: await r.json() };
    });
  }
  function ctxFindReferences() {
    const e = engEntry(); if (!e) return;
    const url = engUrl(e);
    eng("Find references", async () => {
      const r = await fetch("/api/v1/engagement/find-references", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ url }) });
      return { kind: "list", data: await r.json() };
    });
  }
  function ctxCsrfPoc() {
    const e = engEntry(); if (!e) return;
    const request = formatRequest(e);
    eng("CSRF PoC", async () => {
      const r = await fetch("/api/v1/engagement/csrf-poc", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ request }) });
      const d = await r.json();
      return { kind: "html", data: typeof d === "string" ? d : (d.html || JSON.stringify(d)) };
    });
  }
  function ctxClickBandit() {
    const e = engEntry(); if (!e) return;
    const url = engUrl(e);
    eng("ClickBandit (clickjacking PoC)", async () => {
      const r = await fetch("/api/v1/engagement/clickbandit", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ url }) });
      const d = await r.json();
      return { kind: "html", data: typeof d === "string" ? d : (d.html || JSON.stringify(d)) };
    });
  }
  function ctxAnalyzeTarget() {
    eng("Target analysis", async () => {
      const r = await fetch("/api/v1/engagement/analyze-target");
      return { kind: "json", data: await r.json() };
    });
  }
  function ctxSearchAcross() {
    const needle = prompt("Search across all captured responses for:");
    if (!needle) { closeCtx(); return; }
    eng(`Search: "${needle}"`, async () => {
      const r = await fetch("/api/v1/engagement/search", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ needle }) });
      return { kind: "list", data: await r.json() };
    });
  }
  function engItemText(it) { return typeof it === "string" ? it : (it.snippet || it.url || it.path || JSON.stringify(it)); }
  function copyEng() {
    if (!engResult) return;
    const t = engResult.kind === "list" ? (engResult.data || []).map(engItemText).join("\n")
      : typeof engResult.data === "string" ? engResult.data : JSON.stringify(engResult.data, null, 2);
    navigator.clipboard.writeText(t).catch(() => {});
  }

  function formatRequest(e) {
    if (e.raw_request) return e.raw_request;
    const req = e.request;
    if (req && Array.isArray(req.headers)) {
      const method = e.method || req.method || "GET";
      const path = req.path || e.path || "/";
      const version = req.version === "Http10" ? "HTTP/1.0" : "HTTP/1.1";
      let out = `${method} ${path} ${version}\r\n`;
      let hasHost = false;
      for (const h of req.headers) {
        if ((h.name || "").toLowerCase() === "host") hasHost = true;
        out += `${h.name}: ${h.value}\r\n`;
      }
      if (!hasHost && (e.host || req.host)) out += `Host: ${e.host || req.host}\r\n`;
      out += "\r\n";
      out += bytesToText(req.body);
      return out;
    }
    const method = e.method || "GET";
    const path = e.path || "/";
    const host = e.host || "";
    return `${method} ${path} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: Lancer/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n`;
  }

  function formatResponse(e) {
    if (e.raw_response) return e.raw_response;
    const status = e.status || "?";
    const body = bytesToText(e.response?.body) || "";
    return `HTTP/1.1 ${status}\r\n\r\n${body}`;
  }

  function hexDump(str) {
    return str.split("").map((c, i) => {
      const h = c.charCodeAt(0).toString(16).padStart(2, "0");
      return (i > 0 && i % 16 === 0 ? "\n" : "") + h + " ";
    }).join("");
  }

  // Issues detail state
  let selectedIssue = null;
  let issueDetailTab = "advisory";

  function severityClass(s) {
    const m = { Critical: "badge-Critical", High: "badge-High", Medium: "badge-Medium", Low: "badge-Low", Info: "badge-Info", INFO: "badge-Info", LOW: "badge-Low", MEDIUM: "badge-Medium", HIGH: "badge-High" };
    return m[s] || "badge-Info";
  }

  function selectIssue(iss) {
    selectedIssue = iss;
    issueDetailTab = "advisory";
  }

  function issueRequest(iss) {
    if (iss.raw_request) return iss.raw_request;
    if (iss.request) return typeof iss.request === "string" ? iss.request : JSON.stringify(iss.request, null, 2);
    return "No request captured.";
  }

  function issueResponse(iss) {
    if (iss.raw_response) return iss.raw_response;
    if (iss.response) return typeof iss.response === "string" ? iss.response : JSON.stringify(iss.response, null, 2);
    return "No response captured.";
  }

  const ISSUE_DESCRIPTIONS = {
    "Missing or weak security headers": {
      desc: "The application is missing one or more security-related HTTP response headers. These headers help defend against common web attacks such as clickjacking, MIME sniffing, and cross-site scripting.",
      fix: "Configure the web server or application framework to include headers such as Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Strict-Transport-Security.",
    },
    "Server-side template injection": {
      desc: "User-supplied input is embedded within a server-side template and evaluated as template code. This can allow an attacker to execute arbitrary code on the server.",
      fix: "Never concatenate user input directly into template strings. Use safe template rendering APIs that treat user data as plain data, not code.",
    },
    "Clickjacking — framing not denied": {
      desc: "The application does not set an X-Frame-Options or Content-Security-Policy frame-ancestors directive to prevent it from being embedded in an iframe on an attacker-controlled site.",
      fix: "Set X-Frame-Options: DENY or Content-Security-Policy: frame-ancestors 'none' on all responses.",
    },
    "Cache poisoning via X-Forwarded-Host": {
      desc: "The X-Forwarded-Host header value is reflected in the response or used in cache keys, allowing an attacker to poison the cache with a malicious host value.",
      fix: "Validate and whitelist the X-Forwarded-Host header. Do not use its value to construct URLs or cache keys without sanitisation.",
    },
    "CORS misconfiguration": {
      desc: "The application reflects the Origin header back in Access-Control-Allow-Origin, or allows credentials from arbitrary origins. This can permit cross-origin requests from attacker-controlled sites.",
      fix: "Explicitly whitelist trusted origins. Never set Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true.",
    },
    "Host-header injection": {
      desc: "The HTTP Host header is reflected in the application response without validation, enabling phishing links, cache poisoning, or password-reset poisoning attacks.",
      fix: "Whitelist acceptable Host header values in the application or web server configuration. Do not trust the Host header for constructing absolute URLs.",
    },
    "Reflected XSS (likely)": {
      desc: "User-supplied input appears to be reflected in the HTTP response in a context where it may be interpreted as executable script by the browser.",
      fix: "HTML-encode all user-supplied output. Implement a Content-Security-Policy header to restrict script execution.",
    },
    "Server-side request forgery": {
      desc: "The application makes outbound requests to a URL derived from user-supplied input, potentially allowing an attacker to probe internal services or read sensitive data from the server.",
      fix: "Validate and whitelist all URLs that the application fetches on behalf of users. Block requests to private IP ranges and the metadata service.",
    },
  };

  // ── Static issue-definitions catalog (independent of observed findings) ──
  const ISSUE_DEFINITIONS = [
    { name: "SQL injection", severity: "High", desc: "User-controllable data is incorporated into a database query in an unsafe way, allowing an attacker to interfere with the queries the application makes.", fix: "Use parameterised queries (prepared statements) for all database access. Never build SQL by concatenating user input." },
    { name: "Cross-site scripting (reflected)", severity: "High", desc: "Input received in an HTTP request is reflected into the response without adequate encoding, allowing script injection in the victim's browser.", fix: "HTML-encode all user input on output and apply a strict Content-Security-Policy." },
    { name: "Cross-site scripting (stored)", severity: "High", desc: "User input is stored by the application and later rendered to other users without encoding, allowing persistent script injection.", fix: "Validate input on entry and encode on output. Apply context-aware escaping for HTML, attributes, and JavaScript." },
    { name: "OS command injection", severity: "Critical", desc: "User-controllable data is passed to a system shell, allowing an attacker to execute arbitrary operating-system commands.", fix: "Avoid calling the shell. Use APIs that pass arguments as an array and validate input against an allow-list." },
    { name: "Server-side template injection", severity: "Critical", desc: "User input is embedded in a server-side template and evaluated as template code, potentially leading to remote code execution.", fix: "Never concatenate user input into templates. Use sandboxed rendering and treat user data as data, not code." },
    { name: "Server-side request forgery", severity: "High", desc: "The application makes outbound requests to a URL derived from user input, allowing probing of internal services.", fix: "Validate and allow-list target URLs. Block requests to private IP ranges and the cloud metadata service." },
    { name: "XML external entity (XXE) injection", severity: "High", desc: "An XML parser processes external entity references from untrusted input, enabling file disclosure or SSRF.", fix: "Disable external entity and DTD processing in the XML parser configuration." },
    { name: "Path traversal", severity: "High", desc: "User input is used to construct a file path without validation, allowing access to files outside the intended directory.", fix: "Canonicalise and validate paths against an allow-list of permitted files or directories." },
    { name: "Open redirection", severity: "Low", desc: "The application redirects users to a URL taken from user-controllable input, which can be abused for phishing.", fix: "Avoid redirecting to user-supplied URLs. Use an allow-list of permitted redirect targets." },
    { name: "Cross-site request forgery (CSRF)", severity: "Medium", desc: "State-changing requests can be triggered from other origins because they lack an unpredictable token.", fix: "Implement anti-CSRF tokens and verify them server-side; use SameSite cookies." },
    { name: "CORS misconfiguration", severity: "Medium", desc: "The application reflects the Origin header or allows credentials from arbitrary origins, permitting cross-origin attacks.", fix: "Explicitly allow-list trusted origins. Never combine wildcard origins with credentialed requests." },
    { name: "Clickjacking — framing not denied", severity: "Low", desc: "Responses can be framed by other sites, enabling UI-redress (clickjacking) attacks.", fix: "Send X-Frame-Options: DENY or Content-Security-Policy: frame-ancestors 'none'." },
    { name: "Host-header injection", severity: "Medium", desc: "The Host header is reflected or trusted without validation, enabling cache poisoning and password-reset poisoning.", fix: "Validate the Host header against an allow-list and avoid using it to build absolute URLs." },
    { name: "Cache poisoning via X-Forwarded-Host", severity: "Medium", desc: "The X-Forwarded-Host value is reflected and used in cache keys, allowing cache poisoning.", fix: "Do not trust forwarded headers for URL construction or cache keying without validation." },
    { name: "Missing or weak security headers", severity: "Info", desc: "One or more recommended security response headers are absent, weakening defence in depth.", fix: "Add Content-Security-Policy, X-Content-Type-Options, Referrer-Policy, and Strict-Transport-Security." },
    { name: "Insecure cookie (missing Secure/HttpOnly)", severity: "Low", desc: "Session cookies lack the Secure and/or HttpOnly attributes, exposing them to theft over HTTP or via script.", fix: "Set Secure, HttpOnly, and SameSite attributes on sensitive cookies." },
    { name: "TLS certificate / protocol issues", severity: "Medium", desc: "The server presents an invalid certificate or supports weak TLS protocols or ciphers.", fix: "Use a valid certificate, disable legacy protocols (SSLv3/TLS 1.0/1.1) and weak ciphers." },
    { name: "Information disclosure", severity: "Low", desc: "The application discloses sensitive information such as stack traces, internal paths, or version banners.", fix: "Suppress detailed error messages in production and remove version banners." },
    { name: "Directory listing enabled", severity: "Low", desc: "The web server returns directory contents when no index file is present, exposing file structure.", fix: "Disable automatic directory listing in the web server configuration." },
    { name: "Reflected XSS (likely)", severity: "High", desc: "User-supplied input appears to be reflected in a context where it may execute as script.", fix: "HTML-encode all user output and apply a Content-Security-Policy." },
  ];
  let defSearch = "";
  let selectedDef = null;
  $: filteredDefs = ISSUE_DEFINITIONS.filter(d => {
    if (!defSearch) return true;
    const f = defSearch.toLowerCase();
    return d.name.toLowerCase().includes(f) || (d.desc || "").toLowerCase().includes(f);
  });

  async function fetchHistory() {
    try {
      const r = await fetch("/api/v1/history");
      if (r.ok) {
        const d = await r.json();
        history = Array.isArray(d) ? d : (d.entries || d.history || []);
      }
    } catch {}
  }

  async function fetchIssues() {
    try {
      const r = await fetch("/api/v1/issues");
      if (r.ok) {
        const d = await r.json();
        issues = Array.isArray(d) ? d : (d.issues || []);
      }
    } catch {}
  }

  // ── Scope state ──────────────────────────────────────────
  let scopeRules = [];
  let scopeSaving = false;
  let scopeError = "";
  let advancedControl = false;  // Burp "Use advanced control (regex)" suite-wide toggle
  let scopeFileInput;           // <input type=file> ref for import
  let newRule = { kind: "Include", protocol: "", host: "", port: "", path: "", enabled: true, regex: false };

  // When advanced control turns on, new rules default to regex mode.
  $: if (advancedControl && !newRule.regex) newRule = { ...newRule, regex: true };

  // Parse a URL into a scope rule (mirrors ScopeRule::from_str in lancer-core).
  function ruleFromUrl(raw) {
    let s = (raw || "").trim();
    if (!s) return null;
    let protocol = "", host = "", port = "", path = "";
    const m = s.match(/^(\w+):\/\/([^/:]+)(?::(\d+))?(\/.*)?$/);
    if (m) {
      protocol = m[1] || "";
      host = m[2] || "";
      port = m[3] || "";
      path = m[4] || "";
    } else {
      // bare host[:port][/path]
      const m2 = s.match(/^([^/:]+)(?::(\d+))?(\/.*)?$/);
      if (!m2) return null;
      host = m2[1] || "";
      port = m2[2] || "";
      path = m2[3] || "";
    }
    if (!host) return null;
    return {
      kind: "Include",
      protocol: protocol || null,
      host,
      port: port ? parseInt(port, 10) : null,
      path: path || null,
      enabled: true,
      regex: advancedControl,
    };
  }

  async function pasteUrlAsRule() {
    scopeError = "";
    let txt = "";
    try { txt = await navigator.clipboard.readText(); } catch { txt = ""; }
    if (!txt) { txt = prompt("Paste URL to add as scope rule:") || ""; }
    const rule = ruleFromUrl(txt);
    if (!rule) { scopeError = "Could not parse a URL from the clipboard."; return; }
    scopeRules = [...scopeRules, rule];
    saveScope();
  }

  function exportScope() {
    const blob = new Blob([JSON.stringify(scopeRules, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "lancer-scope.json";
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function importScope(ev) {
    const file = ev.target.files && ev.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const parsed = JSON.parse(String(reader.result));
        const rules = Array.isArray(parsed) ? parsed : (parsed.rules || []);
        scopeRules = rules;
        saveScope();
        scopeError = "";
      } catch (e) {
        scopeError = "Import failed: " + e.message;
      }
    };
    reader.readAsText(file);
    ev.target.value = "";
  }

  async function fetchScope() {
    try {
      const r = await fetch("/api/v1/scope");
      if (r.ok) {
        const d = await r.json();
        scopeRules = Array.isArray(d) ? d : (d.rules || []);
        // Build quick in-scope host set for the "Hide out of scope" toggle
        const s = new Set();
        for (const r of scopeRules) {
          if (r.enabled !== false && r.kind === "Include" && r.host) s.add(r.host);
        }
        inScopeSet = s;
      }
    } catch {}
  }

  async function saveScope() {
    scopeSaving = true; scopeError = "";
    try {
      const r = await fetch("/api/v1/scope", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(scopeRules),
      });
      if (!r.ok) scopeError = "Save failed: " + (await r.text());
    } catch (e) {
      scopeError = "Save failed: " + e.message;
    }
    scopeSaving = false;
  }

  function addScopeRule() {
    if (!newRule.host) { scopeError = "Host is required"; return; }
    const rule = {
      kind: newRule.kind,
      protocol: newRule.protocol || null,
      host: newRule.host,
      port: newRule.port ? parseInt(newRule.port, 10) : null,
      path: newRule.path || null,
      enabled: newRule.enabled,
      regex: newRule.regex,
    };
    scopeRules = [...scopeRules, rule];
    newRule = { kind: "Include", protocol: "", host: "", port: "", path: "", enabled: true, regex: false };
    saveScope();
  }

  function removeScopeRule(idx) {
    scopeRules = scopeRules.filter((_, i) => i !== idx);
    saveScope();
  }

  function toggleScopeRule(idx) {
    scopeRules[idx].enabled = !scopeRules[idx].enabled;
    scopeRules = scopeRules;
    saveScope();
  }

  function moveScopeRule(idx, dir) {
    const j = idx + dir;
    if (j < 0 || j >= scopeRules.length) return;
    const tmp = scopeRules[idx];
    scopeRules[idx] = scopeRules[j];
    scopeRules[j] = tmp;
    scopeRules = scopeRules;
    saveScope();
  }

  onMount(() => {
    fetchHistory();
    fetchIssues();
    fetchScope();
    pollTimer = setInterval(fetchHistory, 4000);
    window.addEventListener("click", closeCtx);
  });

  onDestroy(() => {
    clearInterval(pollTimer);
    window.removeEventListener("click", closeCtx);
  });
</script>

<div class="view">
  <div class="subtabs">
    <button class="subtab" class:active={subtab==="sitemap"} on:click={() => subtab="sitemap"}>Site map</button>
    <button class="subtab" class:active={subtab==="scope"}   on:click={() => subtab="scope"}>Scope</button>
    <button class="subtab" class:active={subtab==="issues"}  on:click={() => subtab="issues"}>Issues</button>
    <button class="subtab" class:active={subtab==="definitions"} on:click={() => subtab="definitions"}>Issue definitions</button>
  </div>

  <!-- ── SITE MAP ── -->
  {#if subtab === "sitemap"}
    {#if history.length === 0}
      <div class="empty-state">
        <svg width="56" height="56" viewBox="0 0 56 56" fill="none">
          <rect x="6" y="28" width="44" height="22" rx="3" stroke="#d5dae1" stroke-width="1.5" fill="#f1f3f6"/>
          <rect x="12" y="18" width="32" height="12" rx="3" stroke="#d5dae1" stroke-width="1.5" fill="#f1f3f6"/>
          <rect x="18" y="8"  width="20" height="12" rx="3" stroke="#d5dae1" stroke-width="1.5" fill="#f1f3f6"/>
        </svg>
        <p class="empty-title">Site map URL view is empty</p>
        <p class="empty-desc dim">
          Browse through Lancer's proxy to populate the site map.<br>
          All observed hosts and URLs will appear here.
        </p>
        <div class="empty-actions">
          <button class="btn-secondary">Learn more</button>
          <button class="btn-orange" on:click={async () => { try { await fetch("/api/browser/open", {method:"POST"}); } catch {} }}>Open browser</button>
        </div>
      </div>
    {:else}
      <!-- Burp-style site map: left tree + right vertical split (table on top, req|resp on bottom) -->
      <div class="sitemap-layout">

        <!-- LEFT: site tree -->
        <div class="tree-panel">
          <div class="tree-toolbar">
            <span class="tree-label">Site map filter:</span>
            <span class="tree-count dim">{history.length} items</span>
          </div>
          <div class="tree-scroll">
            <!-- root "Hosts" pseudo node -->
            <div
              class="tree-host root-node"
              class:selected={selectedHost === null}
              on:click={() => { selectedHost = null; ctxMenu = null; }}
            >
              <span class="tree-arrow">▾</span>
              <span class="tree-host-name">Site map</span>
              <span class="tree-badge dim">{history.length}</span>
            </div>
            {#each siteTree as node}
              <!-- Host row -->
              {@const hostSev = severityForHost(node.host)}
              <div
                class="tree-host"
                class:selected={selectedHost === node.host}
                on:click={() => selectHostNode(node.host)}
                on:contextmenu={(e) => onRightClick(e, node.items[0])}
              >
                <span class="tree-arrow" on:click|stopPropagation={() => toggleHost(node.host)}>
                  {expandedHosts[node.host] !== false ? '▾' : '▸'}
                </span>
                <svg width="14" height="14" viewBox="0 0 14 14" fill="none" style="flex-shrink:0">
                  <circle cx="7" cy="7" r="6" stroke="#69707b" stroke-width="1.2"/>
                  <ellipse cx="7" cy="7" rx="2.5" ry="6" stroke="#69707b" stroke-width="1"/>
                  <path d="M1 7h12" stroke="#69707b" stroke-width="1" stroke-dasharray="2 1"/>
                </svg>
                {#if hostSev}
                  <span class="sev-circle" style="background:{sevColor(hostSev)}" title="{hostSev} issue(s)"></span>
                {/if}
                <span class="tree-host-name">{node.host}</span>
                <span class="tree-badge dim">{node.items.length}</span>
              </div>
              <!-- Port + URL rows under host -->
              {#if expandedHosts[node.host] !== false}
                {#each node.ports as portNode}
                  {#if node.ports.length > 1}
                    <div class="tree-port">
                      <span class="tree-arrow">▾</span>
                      <span class="tree-port-name dim">port {portNode.port}</span>
                      <span class="tree-badge dim">{portNode.items.length}</span>
                    </div>
                  {/if}
                  {#each portNode.items as item}
                    {@const urlSev = severityForPath(item.host || hostFromUrl(item.url), item.path || "")}
                    <div
                      class="tree-url"
                      class:selected={selectedEntry === item}
                      class:inferred={isInferred(item)}
                      class:multiport={node.ports.length > 1}
                      on:click={() => selectEntry(item)}
                      on:contextmenu={(e) => onRightClick(e, item)}
                    >
                      <span class="method-dot method-{item.method || 'GET'}">{item.method || "GET"}</span>
                      {#if urlSev}
                        <span class="sev-circle sm" style="background:{sevColor(urlSev)}" title="{urlSev}"></span>
                      {/if}
                      <span class="url-path" class:dim={isInferred(item)}>{item.path || item.url || "/"}</span>
                      {#if item.status}
                        <span class="status-chip status-{String(item.status)[0]}">{item.status}</span>
                      {/if}
                    </div>
                  {/each}
                {/each}
              {/if}
            {/each}
          </div>
        </div>

        <!-- RIGHT: vertical split — table on top, req+resp on bottom -->
        <div class="right-split" class:with-issues={selectedHost}>

          <!-- TOP: requests table -->
          <div class="req-table-wrap">
            <div class="req-table-toolbar">
              <input
                class="table-filter"
                bind:value={tableFilter}
                placeholder="Filter (host, URL, status…)"
              />
              <label class="check-inline">
                <input type="checkbox" bind:checked={hideOutOfScope} />
                Hide out-of-scope
              </label>
              <label class="check-inline">
                <input type="checkbox" bind:checked={paramOnly} />
                Show only parametrized
              </label>
              <label class="check-inline">
                <input type="checkbox" bind:checked={hideErrors} />
                Hide 4xx/5xx
              </label>
              <button class="sm-btn" class:active-filter={showFilterRow} on:click={() => showFilterRow = !showFilterRow} title="More filters">Filters ▾</button>
              <span class="dim" style="margin-left:auto;font-size:11px">{tableEntries.length} of {history.length}</span>
            </div>
            {#if showFilterRow}
              <div class="req-filter-row">
                <span class="filter-row-label dim">MIME:</span>
                {#each MIME_GROUPS as g}
                  <label class="check-inline">
                    <input type="checkbox" bind:checked={mimeShow[g]} />
                    {g}
                  </label>
                {/each}
                <span class="filter-row-sep"></span>
                <input
                  class="table-filter note-filter"
                  bind:value={noteFilter}
                  placeholder="Filter by annotation/note…"
                />
              </div>
            {/if}
            <div class="req-table-scroll">
              <table class="req-table">
                <thead>
                  <tr>
                    {#each [
                      {k:"host",label:"Host"},
                      {k:"method",label:"Method"},
                      {k:"url",label:"URL"},
                      {k:"params",label:"Params"},
                      {k:"status",label:"Status code"},
                      {k:"length",label:"Length"},
                      {k:"mime",label:"MIME type"},
                      {k:"title",label:"Title"},
                      {k:"time",label:"Time"},
                      {k:"notes",label:"Notes"},
                    ] as col}
                      <th on:click={() => setSort(col.k)} class:sorted={sortKey===col.k}>
                        {col.label}{#if sortKey===col.k}<span class="sort-arrow">{sortDir==="asc"?"▲":"▼"}</span>{/if}
                      </th>
                    {/each}
                  </tr>
                </thead>
                <tbody>
                  {#each tableEntries as e}
                    <tr
                      class:selected={selectedEntry === e}
                      on:click={() => selectEntry(e)}
                      on:contextmenu={(ev) => onRightClick(ev, e)}
                    >
                      <td class="cell-host">{e.host || hostFromUrl(e.url)}</td>
                      <td class="cell-method method-{e.method || 'GET'}">{e.method || "GET"}</td>
                      <td class="cell-url" title={e.url || e.path}>{e.path || e.url || "/"}</td>
                      <td class="cell-params">{paramsCount(e) || ""}</td>
                      <td class="cell-status"><span class="status-chip status-{String(e.status||"")[0]}">{e.status || ""}</span></td>
                      <td class="cell-num">{responseLength(e) || ""}</td>
                      <td class="cell-mime dim">{mimeOf(e)}</td>
                      <td class="cell-title dim" title={titleOf(e)}>{titleOf(e)}</td>
                      <td class="cell-time dim">{fmtTime(e.captured_at)}</td>
                      <td class="cell-notes dim">{e.comment || ""}</td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          </div>

          <!-- BOTTOM: request | response side-by-side -->
          <div class="req-resp-split">
            <div class="req-pane">
              <div class="pane-title">Request</div>
              <div class="subtabs inner-tabs">
                {#each ["pretty","raw","hex"] as t}
                  <button class="subtab" class:active={reqTab===t} on:click={() => reqTab=t}>
                    {t.charAt(0).toUpperCase()+t.slice(1)}
                  </button>
                {/each}
              </div>
              <div class="editor-scroll">
                {#if !selectedEntry}
                  <p class="dim" style="padding:14px;font-size:12px">Select a request from the table or site map.</p>
                {:else if reqTab === "hex"}
                  <pre class="editor hex">{hexDump(formatRequest(selectedEntry))}</pre>
                {:else}
                  <pre class="editor">{formatRequest(selectedEntry)}</pre>
                {/if}
              </div>
            </div>

            <div class="resp-pane">
              <div class="pane-title">Response</div>
              <div class="subtabs inner-tabs">
                {#each ["pretty","raw","hex","render"] as t}
                  <button class="subtab" class:active={respTab===t} on:click={() => respTab=t}>
                    {t.charAt(0).toUpperCase()+t.slice(1)}
                  </button>
                {/each}
              </div>
              <div class="editor-scroll">
                {#if !selectedEntry}
                  <p class="dim" style="padding:14px;font-size:12px">Select a request to see the response.</p>
                {:else if respTab === "hex"}
                  <pre class="editor hex">{hexDump(formatResponse(selectedEntry))}</pre>
                {:else if respTab === "render"}
                  <iframe
                    title="Rendered response"
                    sandbox=""
                    class="render-frame"
                    srcdoc={bytesToText(selectedEntry.response?.body) || ""}
                  ></iframe>
                {:else}
                  <pre class="editor">{formatResponse(selectedEntry)}</pre>
                {/if}
              </div>
            </div>
          </div>

          <!-- BOTTOM STRIP: issues for the selected host -->
          {#if selectedHost}
            {@const hostIssues = issues.filter(iss => (iss.host || "") === selectedHost)}
            <div class="host-issues-strip">
              <div class="host-issues-head">
                Issues for {selectedHost}
                <span class="tree-badge dim">{hostIssues.length}</span>
              </div>
              <div class="host-issues-body">
                {#if hostIssues.length === 0}
                  <span class="dim" style="font-size:12px">No issues for this host.</span>
                {:else}
                  {#each hostIssues as iss}
                    <div class="host-issue-row" on:click={() => { subtab = "issues"; selectIssue(iss); }}>
                      <span class="badge {severityClass(iss.severity)}">{(iss.severity||"INFO").charAt(0).toUpperCase()+(iss.severity||"INFO").slice(1).toLowerCase()}</span>
                      <span class="host-issue-name">{iss.name || iss.type || "-"}</span>
                      <span class="host-issue-path dim">{iss.path || ""}</span>
                    </div>
                  {/each}
                {/if}
              </div>
            </div>
          {/if}

        </div>

      </div>
    {/if}
  {/if}

  <!-- ── SCOPE ── -->
  {#if subtab === "scope"}
    <div class="panel">
      <div class="scope-wrap">
        <div class="scope-section">
          <div class="scope-toolbar">
            <div class="scope-title" style="margin-bottom:0">Scope rules</div>
            <div class="scope-toolbar-actions">
              <label class="check-inline">
                <input type="checkbox" bind:checked={advancedControl} />
                Use advanced control (regex)
              </label>
              <button class="sm-btn" on:click={pasteUrlAsRule} title="Paste a URL from the clipboard as a new Include rule">Paste URL as rule</button>
              <button class="sm-btn" on:click={exportScope} title="Download scope as JSON">Export</button>
              <button class="sm-btn" on:click={() => scopeFileInput && scopeFileInput.click()} title="Import scope JSON">Import</button>
              <input type="file" accept="application/json,.json" bind:this={scopeFileInput} on:change={importScope} style="display:none" />
            </div>
          </div>
          {#if scopeError}<div class="scope-err">{scopeError}</div>{/if}
          {#if scopeRules.length === 0}
            <div class="scope-empty dim">No scope rules. Add one below to limit which hosts Lancer treats as in-scope.</div>
          {:else}
            <table class="scope-table">
              <thead>
                <tr>
                  <th>On</th>
                  <th>Kind</th>
                  <th>Protocol</th>
                  <th>Host</th>
                  <th>Port</th>
                  <th>Path</th>
                  <th>Regex</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {#each scopeRules as r, i}
                  <tr class:rule-disabled={!r.enabled}>
                    <td><input type="checkbox" checked={r.enabled} on:change={() => toggleScopeRule(i)} /></td>
                    <td class={r.kind === "Include" ? "kind-include" : "kind-exclude"}>{r.kind}</td>
                    <td>{r.protocol || "*"}</td>
                    <td><code>{r.host}</code></td>
                    <td>{r.port ?? "*"}</td>
                    <td><code>{r.path || "*"}</code></td>
                    <td>{r.regex ? "yes" : ""}</td>
                    <td class="rule-actions">
                      <button class="sm-btn" on:click={() => moveScopeRule(i, -1)} disabled={i === 0} title="Move up">▲</button>
                      <button class="sm-btn" on:click={() => moveScopeRule(i, 1)} disabled={i === scopeRules.length - 1} title="Move down">▼</button>
                      <button class="sm-btn danger" on:click={() => removeScopeRule(i)} title="Delete">×</button>
                    </td>
                  </tr>
                {/each}
              </tbody>
            </table>
          {/if}
          <div class="scope-status dim">
            {scopeRules.length} rule{scopeRules.length === 1 ? "" : "s"} · {scopeSaving ? "saving..." : "synced"}
          </div>
        </div>

        <div class="scope-section">
          <div class="scope-title">Add rule</div>
          <div class="scope-form">
            <label>Kind
              <select bind:value={newRule.kind}>
                <option value="Include">Include</option>
                <option value="Exclude">Exclude</option>
              </select>
            </label>
            <label>Protocol
              <select bind:value={newRule.protocol}>
                <option value="">any</option>
                <option value="http">http</option>
                <option value="https">https</option>
                <option value="ws">ws</option>
                <option value="wss">wss</option>
              </select>
            </label>
            <label class="grow">Host (literal or pattern)
              <input bind:value={newRule.host} placeholder="example.com or *.example.com" />
            </label>
            <label>Port
              <input bind:value={newRule.port} placeholder="any" style="width:80px" />
            </label>
            <label class="grow">Path
              <input bind:value={newRule.path} placeholder="/ or /api/*" />
            </label>
            <label class="check-inline">
              <input type="checkbox" bind:checked={newRule.regex} />
              Regex
            </label>
            <button class="btn-primary" on:click={addScopeRule}>Add rule</button>
          </div>
        </div>
      </div>
    </div>
  {/if}

  <!-- ── ISSUES ── -->
  {#if subtab === "issues"}
    {#if issues.length === 0}
      <div class="empty-state">
        <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
          <circle cx="24" cy="24" r="20" stroke="#d5dae1" stroke-width="1.5" fill="#f1f3f6"/>
          <path d="M24 16v12" stroke="#d5dae1" stroke-width="2" stroke-linecap="round"/>
          <circle cx="24" cy="33" r="1.2" fill="#d5dae1"/>
        </svg>
        <span class="empty-title">No issues found</span>
        <span class="dim" style="font-size:12px">Run a scan to discover vulnerabilities</span>
      </div>
    {:else}
      <div class="issues-layout">
        <!-- Left: issues list -->
        <div class="issues-list-pane">
          <table class="issues-table">
            <thead>
              <tr><th>Severity</th><th>Issue type</th><th>Host</th><th>Path</th></tr>
            </thead>
            <tbody>
              {#each issues as iss, i}
                <tr
                  class:row-sel={selectedIssue === iss}
                  on:click={() => selectIssue(iss)}
                >
                  <td><span class="badge {severityClass(iss.severity)}">{(iss.severity||"INFO").charAt(0).toUpperCase()+(iss.severity||"INFO").slice(1).toLowerCase()}</span></td>
                  <td class="iss-name">{iss.name || iss.type || "-"}</td>
                  <td class="dim iss-host">{iss.host || "-"}</td>
                  <td class="dim url-cell">{iss.path || "-"}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>

        <!-- Right: detail panel -->
        <div class="issues-detail-pane">
          {#if !selectedIssue}
            <div class="issue-no-sel dim">Select an issue to see details</div>
          {:else}
            <div class="issue-detail-header">
              <span class="badge {severityClass(selectedIssue.severity)}" style="font-size:11px">
                {(selectedIssue.severity||"INFO").charAt(0).toUpperCase()+(selectedIssue.severity||"INFO").slice(1).toLowerCase()}
              </span>
              <span class="issue-detail-title">{selectedIssue.name || selectedIssue.type || "Issue"}</span>
            </div>
            <div class="issue-detail-meta dim">
              {#if selectedIssue.host}<span>Host: {selectedIssue.host}</span>{/if}
              {#if selectedIssue.path}<span style="margin-left:12px">Path: {selectedIssue.path}</span>{/if}
            </div>
            <div class="subtabs" style="padding: 0 0 0 12px; border-bottom: 1px solid #e6e9ee; flex-shrink:0">
              {#each ["advisory","request","response"] as t}
                <button class="subtab" class:active={issueDetailTab===t} on:click={() => issueDetailTab=t}>
                  {t.charAt(0).toUpperCase()+t.slice(1)}
                </button>
              {/each}
            </div>
            <div class="issue-detail-body">
              {#if issueDetailTab === "advisory"}
                {@const info = ISSUE_DESCRIPTIONS[selectedIssue.name || selectedIssue.type] || {}}
                <div class="advisory-section">
                  <div class="advisory-label">Description</div>
                  <p class="advisory-text">
                    {selectedIssue.description || info.desc || "No description available."}
                  </p>
                </div>
                <div class="advisory-section">
                  <div class="advisory-label">Remediation</div>
                  <p class="advisory-text">
                    {selectedIssue.remediation || info.fix || "Refer to OWASP guidelines for remediation advice."}
                  </p>
                </div>
                {#if selectedIssue.confidence}
                  <div class="advisory-section">
                    <div class="advisory-label">Confidence</div>
                    <p class="advisory-text">{selectedIssue.confidence}</p>
                  </div>
                {/if}
              {:else if issueDetailTab === "request"}
                <pre class="issue-raw">{issueRequest(selectedIssue)}</pre>
              {:else}
                <pre class="issue-raw">{issueResponse(selectedIssue)}</pre>
              {/if}
            </div>
          {/if}
        </div>
      </div>
    {/if}
  {/if}

  <!-- ── ISSUE DEFINITIONS ── -->
  {#if subtab === "definitions"}
    <div class="issues-layout">
      <!-- Left: definitions list -->
      <div class="issues-list-pane">
        <div class="def-toolbar">
          <input class="table-filter" bind:value={defSearch} placeholder="Search issue definitions…" />
          <span class="dim" style="margin-left:auto;font-size:11px">{filteredDefs.length} of {ISSUE_DEFINITIONS.length}</span>
        </div>
        <table class="issues-table">
          <thead>
            <tr><th>Severity</th><th>Issue type</th></tr>
          </thead>
          <tbody>
            {#each filteredDefs as d}
              <tr class:row-sel={selectedDef === d} on:click={() => selectedDef = d}>
                <td><span class="badge {severityClass(d.severity)}">{d.severity}</span></td>
                <td class="iss-name">{d.name}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>

      <!-- Right: definition detail -->
      <div class="issues-detail-pane">
        {#if !selectedDef}
          <div class="issue-no-sel dim">Select an issue type to see its definition</div>
        {:else}
          <div class="issue-detail-header">
            <span class="badge {severityClass(selectedDef.severity)}" style="font-size:11px">{selectedDef.severity}</span>
            <span class="issue-detail-title">{selectedDef.name}</span>
          </div>
          <div class="issue-detail-body">
            <div class="advisory-section">
              <div class="advisory-label">Description</div>
              <p class="advisory-text">{selectedDef.desc}</p>
            </div>
            <div class="advisory-section">
              <div class="advisory-label">Remediation</div>
              <p class="advisory-text">{selectedDef.fix}</p>
            </div>
            <div class="advisory-section">
              <div class="advisory-label">Typical severity</div>
              <p class="advisory-text">{selectedDef.severity}</p>
            </div>
          </div>
        {/if}
      </div>
    </div>
  {/if}
</div>

<!-- RIGHT-CLICK CONTEXT MENU -->
{#if ctxMenu}
  <div class="ctx-menu" style="left:{ctxMenu.x}px;top:{ctxMenu.y}px" on:click|stopPropagation>
    <div class="ctx-item" on:click={ctxAddScope}>Add to scope</div>
    <div class="ctx-sep"></div>
    <div class="ctx-item" on:click={ctxSendToRepeater}>Send to Repeater <span class="ctx-shortcut">Ctrl+R</span></div>
    <div class="ctx-item" on:click={ctxSendToIntruder}>Send to Intruder <span class="ctx-shortcut">Ctrl+I</span></div>
    <div class="ctx-item" on:click={() => ctxSendToComparer("request")}>Send request to Comparer</div>
    <div class="ctx-item" on:click={() => ctxSendToComparer("response")}>Send response to Comparer</div>
    <div class="ctx-item" on:click={ctxSendToDecoder}>Send to Decoder</div>
    <div class="ctx-item" on:click={ctxSendToScanner}>Send to Scanner</div>
    <div class="ctx-sep"></div>
    <div class="ctx-item" on:click={ctxSpiderBranch}>Spider this branch</div>
    <div class="ctx-item" on:click={ctxScanBranch}>Actively scan this branch</div>
    <div class="ctx-item" on:click={ctxRemoveScope}>Remove from scope</div>
    <div class="ctx-item" on:click={ctxCopyBranchUrls}>Copy URLs in this branch</div>
    <div class="ctx-item" on:click={() => ctxExpandBranch(true)}>Expand branch</div>
    <div class="ctx-item" on:click={() => ctxExpandBranch(false)}>Collapse branch</div>
    <div class="ctx-sep"></div>
    <div class="ctx-item ctx-eng" on:click={ctxFindComments}>Find comments</div>
    <div class="ctx-item ctx-eng" on:click={ctxFindScripts}>Find scripts</div>
    <div class="ctx-item ctx-eng" on:click={ctxFindReferences}>Find references</div>
    <div class="ctx-item ctx-eng" on:click={ctxCsrfPoc}>Generate CSRF PoC</div>
    <div class="ctx-item ctx-eng" on:click={ctxClickBandit}>ClickBandit PoC</div>
    <div class="ctx-item ctx-eng" on:click={ctxAnalyzeTarget}>Analyze target</div>
    <div class="ctx-item ctx-eng" on:click={ctxSearchAcross}>Search across responses…</div>
    <div class="ctx-sep"></div>
    <div class="ctx-item" on:click={ctxCopyUrl}>Copy URL</div>
    <div class="ctx-item" on:click={ctxCopyAsCurl}>Copy as curl</div>
    <div class="ctx-sep"></div>
    <div class="ctx-item ctx-danger" on:click={ctxDelete}>Delete item</div>
  </div>
{/if}

{#if engResult}
  <div class="eng-overlay" on:click={() => (engResult = null)}>
    <div class="eng-modal" on:click|stopPropagation>
      <div class="eng-head">
        <span class="eng-title">{engResult.title}</span>
        <div class="eng-head-actions">
          <button class="sm-btn" on:click={copyEng}>Copy</button>
          <button class="sm-btn" on:click={() => (engResult = null)}>×</button>
        </div>
      </div>
      <div class="eng-body">
        {#if engResult.kind === "loading"}
          <div class="dim">Running…</div>
        {:else if engResult.kind === "error"}
          <div class="eng-err">{engResult.data}</div>
        {:else if engResult.kind === "list"}
          {#if (engResult.data || []).length === 0}
            <div class="dim">No results.</div>
          {:else}
            <ul class="eng-list">
              {#each engResult.data as it}<li><code>{engItemText(it)}</code></li>{/each}
            </ul>
          {/if}
        {:else if engResult.kind === "html"}
          <div class="eng-html-tabs">
            <iframe class="eng-iframe" title="PoC preview" sandbox="" srcdoc={engResult.data}></iframe>
          </div>
          <pre class="eng-pre">{engResult.data}</pre>
        {:else}
          <pre class="eng-pre">{JSON.stringify(engResult.data, null, 2)}</pre>
        {/if}
      </div>
    </div>
  </div>
{/if}

<style>
  /* Empty state */
  .empty-state {
    flex: 1; display: flex; flex-direction: column;
    align-items: center; justify-content: center;
    gap: 10px; padding: 40px; text-align: center;
  }
  .empty-title { font-size: 14px; font-weight: 600; color: var(--text); margin: 0; }
  .empty-desc { font-size: 13px; color: var(--text-muted); line-height: 1.6; max-width: 440px; margin: 0; }
  .empty-actions { display: flex; gap: 8px; margin-top: 8px; }
  .btn-orange { background: var(--accent); color: #fff; border: none; border-radius: 3px; padding: 5px 14px; font-size: 13px; cursor: pointer; }
  .btn-orange:hover { background: var(--accent-hover); }
  .btn-secondary { background: var(--surface-2); color: var(--text); border: 1px solid var(--border-strong); border-radius: 3px; padding: 5px 14px; font-size: 13px; cursor: pointer; }
  .btn-secondary:hover { background: var(--surface-3); }

  /* Burp-style site map: tree | (table over req+resp) */
  .sitemap-layout {
    display: grid;
    grid-template-columns: 240px 1fr;
    flex: 1; overflow: hidden;
    border-top: 1px solid var(--border);
  }
  .right-split {
    display: grid;
    grid-template-rows: minmax(140px, 38%) 1fr;
    overflow: hidden;
  }
  .req-resp-split {
    display: grid;
    grid-template-columns: 1fr 1fr;
    overflow: hidden;
    border-top: 1px solid var(--border);
  }

  /* Request table */
  .req-table-wrap { display: flex; flex-direction: column; overflow: hidden; }
  .req-table-toolbar {
    display: flex; align-items: center; gap: 10px;
    padding: 4px 10px;
    background: var(--surface-2);
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }
  .table-filter {
    font-size: 12px; padding: 3px 8px;
    border: 1px solid var(--border-strong); border-radius: 3px;
    width: 260px;
  }
  .check-inline { display: flex; align-items: center; gap: 5px; font-size: 12px; color: var(--text-2); cursor: pointer; }
  .check-inline input { accent-color: var(--accent); }

  /* collapsible MIME / annotation filter row */
  .req-filter-row {
    display: flex; align-items: center; flex-wrap: wrap; gap: 12px;
    padding: 5px 10px;
    background: var(--surface-1);
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }
  .filter-row-label { font-size: 11px; font-weight: 600; }
  .filter-row-sep { width: 1px; align-self: stretch; background: var(--border); margin: 0 2px; }
  .note-filter { width: 220px; }
  .sm-btn.active-filter { background: var(--row-active); border-color: var(--accent); color: var(--accent); }

  /* per-host issues bottom strip */
  .right-split.with-issues { grid-template-rows: minmax(120px, 32%) 1fr auto; }
  .host-issues-strip {
    display: flex; flex-direction: column;
    border-top: 1px solid var(--border);
    background: var(--surface-1);
    max-height: 160px; overflow: hidden;
  }
  .host-issues-head {
    display: flex; align-items: center; gap: 8px;
    padding: 4px 10px;
    background: var(--surface-2);
    border-bottom: 1px solid var(--border);
    font-size: 12px; font-weight: 600; color: var(--text-2);
    flex-shrink: 0;
  }
  .host-issues-body { overflow-y: auto; padding: 4px 0; }
  .host-issue-row {
    display: flex; align-items: center; gap: 8px;
    padding: 3px 10px;
    cursor: pointer; font-size: 12px;
  }
  .host-issue-row:hover { background: var(--row-hover); }
  .host-issue-name { color: var(--text); }
  .host-issue-path { font-family: ui-monospace, Consolas, monospace; font-size: 11px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .req-table-scroll { flex: 1; overflow: auto; }
  .req-table {
    width: 100%; border-collapse: collapse; font-size: 12px;
    table-layout: auto;
  }
  .req-table th {
    text-align: left; padding: 4px 8px;
    background: var(--surface-2); color: var(--text-2);
    font-size: 11px; font-weight: 600;
    border-bottom: 1px solid var(--border);
    position: sticky; top: 0; z-index: 2;
    cursor: pointer; white-space: nowrap; user-select: none;
  }
  .req-table th:hover { background: var(--border); }
  .req-table th.sorted { color: var(--accent); }
  .sort-arrow { font-size: 9px; margin-left: 4px; }
  .req-table td {
    padding: 3px 8px; border-bottom: 1px solid var(--surface-2);
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
    max-width: 280px;
  }
  .req-table tbody tr { cursor: pointer; }
  .req-table tbody tr:hover { background: var(--row-hover); }
  .req-table tbody tr.selected { background: var(--row-active); }
  .req-table .cell-host { font-family: ui-monospace, Consolas, monospace; font-size: 11.5px; max-width: 200px; }
  .req-table .cell-method { font-weight: 700; font-size: 11px; }
  .req-table .cell-url { font-family: ui-monospace, Consolas, monospace; font-size: 11.5px; max-width: 360px; }
  .req-table .cell-num,
  .req-table .cell-params { text-align: right; font-variant-numeric: tabular-nums; }
  .req-table .cell-time { font-variant-numeric: tabular-nums; }

  /* Tree panel */
  .tree-panel {
    border-right: 1px solid var(--border);
    display: flex; flex-direction: column;
    overflow: hidden;
  }
  .tree-toolbar {
    display: flex; align-items: center; justify-content: space-between;
    padding: 5px 10px;
    background: var(--surface-2);
    border-bottom: 1px solid var(--border);
    font-size: 11px; flex-shrink: 0;
  }
  .tree-label { color: var(--text-2); font-weight: 500; }
  .tree-count { font-size: 11px; }
  .tree-scroll { flex: 1; overflow-y: auto; }

  .tree-host {
    display: flex; align-items: center; gap: 5px;
    padding: 5px 8px;
    cursor: pointer;
    font-size: 12px; font-weight: 600; color: var(--text);
    border-bottom: 1px solid var(--surface-2);
    user-select: none;
  }
  .tree-host:hover { background: var(--row-hover); }
  .tree-host.selected { background: var(--row-active); }
  .tree-host.root-node { font-weight: 700; color: var(--text); background: var(--surface-1); }
  .tree-arrow { font-size: 10px; color: var(--text-muted); width: 10px; cursor: pointer; }
  .tree-host-name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .tree-badge { font-size: 10px; background: var(--border); padding: 1px 5px; border-radius: 8px; }

  /* severity circle on tree branches */
  .sev-circle { width: 9px; height: 9px; border-radius: 50%; flex-shrink: 0; box-shadow: 0 0 0 1px rgba(0,0,0,0.08); }
  .sev-circle.sm { width: 7px; height: 7px; }

  /* port grouping row */
  .tree-port {
    display: flex; align-items: center; gap: 5px;
    padding: 3px 8px 3px 22px;
    font-size: 11px; font-weight: 600; color: var(--text-2);
    border-bottom: 1px solid var(--surface-2);
    user-select: none;
  }
  .tree-port-name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

  .tree-url {
    display: flex; align-items: center; gap: 6px;
    padding: 3px 8px 3px 26px;
    cursor: pointer;
    font-size: 12px; color: var(--text-2);
    border-bottom: 1px solid var(--surface-2);
    user-select: none;
  }
  .tree-url:hover { background: var(--row-hover); }
  .tree-url.selected { background: var(--row-active); }
  .tree-url.multiport { padding-left: 38px; }
  .tree-url.inferred .url-path { color: var(--text-muted); font-style: italic; }
  .url-path { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: ui-monospace, Consolas, monospace; font-size: 11px; }
  .status-chip { font-size: 10px; padding: 1px 4px; border-radius: 2px; flex-shrink: 0; }
  .status-2 { background: #eaf5ea; color: #1b8c1b; }
  .status-3 { background: #e6f0fb; color: #1a75c4; }
  .status-4 { background: #fef8e6; color: #c98a00; }
  .status-5 { background: #fde8e8; color: #d42c2c; }
  .method-dot { font-size: 10px; font-weight: 700; flex-shrink: 0; width: 32px; }
  .method-GET    { color: #1b8c1b; }
  .method-POST   { color: #e86c00; }
  .method-PUT    { color: #1a75c4; }
  .method-DELETE { color: #d42c2c; }
  .method-PATCH  { color: #7b5ea7; }

  /* Request/Response panes */
  .req-pane, .resp-pane {
    display: flex; flex-direction: column;
    overflow: hidden;
    border-right: 1px solid var(--border);
  }
  .resp-pane { border-right: none; }
  .pane-title {
    padding: 4px 10px;
    background: var(--surface-2);
    border-bottom: 1px solid var(--border);
    font-size: 12px; font-weight: 600; color: var(--text-2);
    flex-shrink: 0;
  }
  .inner-tabs { height: 30px; }
  .editor-scroll { flex: 1; overflow: auto; }
  .editor {
    margin: 0; padding: 10px 12px;
    font-size: 11.5px;
    font-family: ui-monospace, "Cascadia Code", Consolas, monospace;
    white-space: pre-wrap; word-break: break-all;
    color: var(--text); line-height: 1.6;
  }
  .editor.hex { color: var(--text-2); }
  .render-frame {
    flex: 1; width: 100%; height: 100%;
    border: none; background: #ffffff;
  }

  /* Scope notice */
  .scope-notice {
    display: flex; gap: 10px; align-items: flex-start;
    background: var(--surface-2); border: 1px solid var(--border); border-radius: 4px;
    padding: 12px 14px; font-size: 13px; color: var(--text-2); max-width: 600px;
  }
  .scope-notice p { margin: 0; }

  .scope-wrap { display: flex; flex-direction: column; gap: 18px; max-width: 1100px; }
  .scope-section { border: 1px solid var(--border); border-radius: 4px; background: #ffffff; padding: 12px 14px; }
  .scope-title { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-muted); margin-bottom: 10px; }
  .scope-toolbar { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px; margin-bottom: 10px; }
  .scope-toolbar-actions { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .def-toolbar { display: flex; align-items: center; gap: 10px; padding: 6px 10px; background: var(--surface-2); border-bottom: 1px solid var(--border); position: sticky; top: 0; z-index: 2; }
  .scope-empty { font-size: 13px; padding: 10px 4px; }
  .scope-err { background: #fde8e8; color: #d42c2c; border: 1px solid #f5b8b8; padding: 6px 10px; border-radius: 3px; font-size: 12px; margin-bottom: 8px; }
  .scope-status { margin-top: 8px; font-size: 11px; }
  .scope-table { width: 100%; border-collapse: collapse; font-size: 12px; }
  .scope-table th, .scope-table td { padding: 5px 9px; border-bottom: 1px solid var(--border); text-align: left; }
  .scope-table thead th { background: var(--surface-2); color: var(--text-muted); font-size: 11px; font-weight: 600; }
  .scope-table .rule-disabled td { opacity: 0.45; }
  .scope-table .kind-include { color: #1b8c1b; font-weight: 600; }
  .scope-table .kind-exclude { color: #d42c2c; font-weight: 600; }
  .scope-table .rule-actions { display: flex; gap: 4px; }
  .scope-table code { font-family: ui-monospace, Consolas, monospace; }
  .sm-btn { font-size: 11px; padding: 2px 8px; background: var(--surface-2); color: var(--text); border: 1px solid var(--border-strong); border-radius: 3px; cursor: pointer; }
  .sm-btn:hover:not(:disabled) { background: var(--surface-3); }
  .sm-btn:disabled { opacity: 0.4; cursor: not-allowed; }
  .sm-btn.danger { color: #d42c2c; border-color: #f5b8b8; }
  .sm-btn.danger:hover:not(:disabled) { background: #fde8e8; }

  .scope-form { display: flex; flex-wrap: wrap; align-items: flex-end; gap: 10px; }
  .scope-form label { display: flex; flex-direction: column; gap: 4px; font-size: 11px; color: var(--text-muted); font-weight: 500; }
  .scope-form label.grow { flex: 1; min-width: 200px; }
  .scope-form input, .scope-form select { font-size: 13px; padding: 4px 8px; }
  .scope-form .check-inline { flex-direction: row; align-items: center; }
  .scope-form .check-inline input { margin-right: 4px; }
  .btn-primary { background: var(--accent); color: #ffffff; border: none; border-radius: 3px; padding: 5px 14px; font-size: 13px; font-weight: 500; cursor: pointer; }
  .btn-primary:hover { background: var(--accent-hover); }

  /* Issues two-panel layout */
  .issues-layout {
    flex: 1; display: grid;
    grid-template-columns: minmax(300px, 45%) 1fr;
    overflow: hidden;
    border-top: 1px solid var(--border);
  }
  .issues-list-pane {
    overflow-y: auto;
    border-right: 1px solid var(--border);
  }
  .issues-table {
    width: 100%; border-collapse: collapse; font-size: 12px;
  }
  .issues-table th {
    text-align: left; padding: 5px 10px;
    background: var(--surface-2); color: var(--text-muted);
    font-size: 11px; font-weight: 600;
    border-bottom: 1px solid var(--border);
    position: sticky; top: 0; z-index: 1;
    white-space: nowrap;
  }
  .issues-table td { padding: 5px 10px; border-bottom: 1px solid var(--surface-2); }
  .issues-table tbody tr { cursor: pointer; }
  .issues-table tbody tr:hover { background: var(--row-hover); }
  .issues-table tbody tr.row-sel { background: var(--row-active); }
  .iss-name { font-size: 12px; max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .iss-host { max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 11.5px; }

  .issues-detail-pane {
    display: flex; flex-direction: column;
    overflow: hidden; background: #ffffff;
  }
  .issue-no-sel {
    flex: 1; display: flex; align-items: center; justify-content: center;
    font-size: 13px;
  }
  .issue-detail-header {
    display: flex; align-items: center; gap: 10px;
    padding: 10px 14px 4px;
    flex-shrink: 0;
  }
  .issue-detail-title {
    font-size: 14px; font-weight: 600; color: var(--text);
  }
  .issue-detail-meta {
    padding: 0 14px 8px;
    font-size: 11px; flex-shrink: 0;
  }
  .issue-detail-body {
    flex: 1; overflow-y: auto;
    padding: 14px;
  }
  .advisory-section { margin-bottom: 16px; }
  .advisory-label {
    font-size: 11px; font-weight: 700; text-transform: uppercase;
    letter-spacing: 0.06em; color: var(--text-muted);
    margin-bottom: 6px;
    padding-bottom: 4px;
    border-bottom: 1px solid var(--border);
  }
  .advisory-text {
    margin: 0; font-size: 13px; color: var(--text); line-height: 1.6;
  }
  .issue-raw {
    margin: 0; padding: 0;
    font-size: 11.5px;
    font-family: ui-monospace, "Cascadia Code", Consolas, monospace;
    white-space: pre-wrap; word-break: break-all;
    color: var(--text); line-height: 1.6;
  }

  /* Legacy table (kept for compatibility) */
  .table-scroll { flex: 1; overflow-y: auto; }
  .data-table { width: 100%; border-collapse: collapse; font-size: 13px; }
  .data-table th, .data-table td { text-align: left; padding: 6px 12px; border-bottom: 1px solid var(--border); white-space: nowrap; }
  .data-table thead th { background: var(--surface-2); color: var(--text-muted); font-size: 11px; font-weight: 600; position: sticky; top: 0; z-index: 1; border-bottom: 1px solid var(--border); }
  .data-table tbody tr:hover { background: var(--row-hover); }
  .row-even { background: var(--surface-1); }
  .url-cell { max-width: 280px; overflow: hidden; text-overflow: ellipsis; }

  /* Context menu */
  .ctx-menu {
    position: fixed; z-index: 9999;
    background: #ffffff;
    border: 1px solid var(--border-strong);
    border-radius: 4px;
    box-shadow: 0 4px 16px rgba(0,0,0,0.15);
    min-width: 200px;
    padding: 4px 0;
    font-size: 13px;
  }
  .ctx-item {
    padding: 6px 16px;
    cursor: pointer;
    color: var(--text);
    white-space: nowrap;
  }
  .ctx-item:hover { background: var(--row-hover); }
  .ctx-item.ctx-disabled { color: var(--text-dim); cursor: default; }
  .ctx-item.ctx-disabled:hover { background: none; }
  .ctx-item.ctx-danger { color: #d42c2c; }
  .ctx-item.ctx-danger:hover { background: #fde8e8; }
  .ctx-item.ctx-eng { color: #2e6fae; }

  .eng-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.35); z-index: 200; display: flex; align-items: center; justify-content: center; }
  .eng-modal { width: 720px; max-width: 92vw; max-height: 80vh; background: #fff; border-radius: 6px; box-shadow: 0 8px 40px rgba(0,0,0,0.3); display: flex; flex-direction: column; overflow: hidden; }
  .eng-head { display: flex; align-items: center; justify-content: space-between; padding: 10px 14px; background: var(--surface-2); border-bottom: 1px solid var(--border); }
  .eng-title { font-weight: 600; font-size: 13px; }
  .eng-head-actions { display: flex; gap: 6px; }
  .eng-body { padding: 12px 14px; overflow: auto; }
  .eng-list { margin: 0; padding-left: 18px; font-size: 12px; line-height: 1.7; }
  .eng-list code { font-family: ui-monospace, Consolas, monospace; color: var(--text); word-break: break-all; }
  .eng-pre { background: #11111b; color: #cdd6f4; padding: 10px; border-radius: 4px; font-size: 11px; overflow: auto; max-height: 300px; white-space: pre-wrap; word-break: break-all; }
  .eng-iframe { width: 100%; height: 200px; border: 1px solid var(--border); border-radius: 4px; background: #fff; margin-bottom: 8px; }
  .eng-err { color: #d42c2c; font-size: 12px; }
  .ctx-shortcut { float: right; color: var(--text-muted); font-size: 11px; padding-left: 14px; }
  .ctx-sep { height: 1px; background: var(--border); margin: 3px 0; }
</style>
