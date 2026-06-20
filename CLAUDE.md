# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

It is the code-structure map for the whole repo: **what lives where**, so you can navigate without
re-reading everything. Sections: build/run → architecture → workspace code map (every crate) →
reference surfaces (CLI / REST API / GUI) → how to extend → conventions & gotchas → repo norms.

## What this is

Lancer — a Rust-native web-application security testing suite aiming for full Burp Suite
(Community + Professional) feature parity and to surpass it on speed. It is a Cargo workspace of
**40 member crates** (+ `lancer-ebpf-probe`, built separately) plus an embedded Svelte SPA.

`plan.md` (gitignored, large) is the §-numbered feature roadmap and source of truth — most crates map
to a `plan.md` § (shown in their descriptions). Trust its section-status table and batch notes; its
granular `□` checkbox inventory is **stale** (implemented items were never re-ticked).

## Build / check / run

### IMPORTANT — never run heavy builds during dev
Verify with `cargo check` only. Do **not** run `cargo build`, `cargo test`, or `cargo test --no-run`
— heavy compile/link work pegs the user's CPU; they build and test themselves. If a change genuinely
needs a runtime build to validate, ask first.

- `cargo check -p <crate>` — fast, per-crate (preferred).
- `cargo check --workspace` — works, slower. (`check.bat`, gitignored/local, runs this with
  `--no-default-features` after loading MSVC `vcvars64`.)
- Single test (only if the user has explicitly opted into building/testing): `cargo test -p <crate> <name>`.
  Tests are inline `#[test]`/`#[tokio::test]` modules; there are no `tests/` integration dirs.

### Binaries
- `lancer` (crate `lancer-cli`) — headless CLI, the main surface for automation/CI.
- `lancer-api` — REST API server that **also runs the MITM proxy** in the same process.
- `lancer-gui` — native desktop shell (wry/tao) that spawns `lancer-api` and embeds the SPA.
- `lancer-setup` — Windows self-extracting installer. `lancer-ebpf-probe` is **excluded** from the
  workspace (built for `bpfel-unknown-none`).

### Frontend (Svelte SPA — `crates/lancer-gui/web`)
- `npm run build` (vite) is the real Svelte syntax/type check and the verification ceiling for GUI
  changes; pair with `cargo check -p lancer-gui`. `node_modules` is already present.
- `npm run dev` — vite on `:5173` (falls to `:5174`). The dev proxy rewrites `/api` → `` so the SPA's
  `/api/v1/*` calls reach lancer-api's `/v1/*` (**the backend has no `/api` prefix**).
- Live backend for dev: `cargo run -p lancer-api -- --listen 127.0.0.1:9191 --proxy 127.0.0.1:8080`
  (one process serves the proxy + the API + a temporary in-memory project).

### CLI quick start (from README / CI)
```bash
lancer cert init --dir ./ca                       # generate + manage the MITM CA
lancer proxy --listen 127.0.0.1:8080 --project ./demo.lancer
lancer scan full https://example.com/ --project ./scan.lancer
lancer report --project ./scan.lancer --format sarif --out lancer.sarif
```

### Packaging
- `build.bat` (Windows) → `build\Lancer-Setup.exe`: builds the SPA, then `lancer-gui` + `lancer-api`,
  stages files, wraps them in the `lancer-setup` self-extractor. `build-linux.sh` for Linux.
- CI (`.gitlab-ci.yml`, `.github/workflows/dast.yml`) builds `--bin lancer` and runs a DAST scan,
  emitting SARIF + HTML.

## Architecture

### Process topology (the key thing to understand)
- **`lancer-api`** is a single process running BOTH the MITM proxy listener AND a hand-rolled hyper
  REST server on `/v1/*`. In `crates/lancer-api/src/main.rs`, `main()` starts the `ProxyListener`
  (~line 230) with a `with_session_apply(Arc<dyn Fn(&mut HttpRequest)>)` hook that mutates in-flight
  requests (session/match-replace rules). All shared state hangs off one `AppState` struct of
  `RwLock`-wrapped fields. Routing is one big `match (method, path)` in `handle()` (~line 469) with a
  `dynamic_route()` fallback (~line 1121) for parameterized paths.
- **`lancer-gui`** (`src/main.rs`) opens a native wry window, spawns `lancer-api` as a child process on
  a random port, and runs its own small hyper server (`src/app.rs`) that serves the embedded SPA on `/`,
  handles a few GUI-local routes (`/api/browser/open`, `/api/palette`, `/api/status`), and
  reverse-proxies `/api/v1/*` → the child's `/v1/*`. It reaps the child on window close.
- **`lancer-cli`** (`lancer`) dispatches ~45 clap subcommands; each is a module under
  `crates/lancer-cli/src/commands/` exposing `Args` + `run()`, wired in `main.rs`.

### Request lifecycle (proxy path)
Browser → `ProxyListener` (TLS MITM via per-host leaf certs from `CertificateAuthority` + `CertCache`)
→ `mitm.rs` pipeline (scope check → `InterceptEngine` pause/forward → `MatchReplaceEngine`) → upstream
→ response back. Captured request/response flow into the project `Storage` (SQLite) and onto a
`ProxyEventSink`; passive consumers (JS mining, secret scanning) read those events. **Requests and
responses carry different `meta.id`s** — `ResponseCaptured` includes a separate `request_id` for
correlation.

### Frontend ↔ backend contract
- `App.svelte` is a single tabbed shell: a `tabs` array (the source of truth, ~44 entries) drives the
  sidebar and `{#if active===...}` renders one of ~45 views in `web/src/views/`. Views call the backend
  via `fetch("/api/v1/...")`.
- The built SPA is embedded into `lancer-gui` at compile time via
  `include_dir!("$CARGO_MANIFEST_DIR/dist")` (`src/static_assets.rs`). **`dist/` is gitignored and
  regenerated by `npm run build`** (hashed asset filenames); the canonical build runs the SPA build
  immediately before the Rust build, so always `npm run build` before building/running the GUI binary.
  There are no committed built assets to rely on.

### Crypto provider (every binary)
Each binary's `main()` must call `lancer_proxy::install_crypto_provider()` before any TLS — rustls 0.23
panics ("no process-level CryptoProvider") because both `ring` and `aws-lc-rs` (pulled by h3/quinn) are
in the tree. Already wired in all of `lancer-cli`, `lancer-api`, `lancer-gui`.

---

# Workspace code map

Crates layer roughly: **foundation** → **proxy/OOB** → **tools/scanning** → **recon/access-control** →
**AI/exploitation** → **platform/extensibility** → **entry points**. Per-crate purpose is also in each
`Cargo.toml`.

## Foundation

### `lancer-core` — `crates/lancer-core`
Shared, dependency-light core types for HTTP security testing.
- `src/lib.rs` — re-exports the key types below.
- `src/error.rs` — `Error`/`Result` (Parse, InvalidScope, InvalidRequest/Response, Url, Regex, Json…).
- `src/http_msg.rs` — stack-independent HTTP types: `HttpRequest`, `HttpResponse`, `Header`,
  `MessageMeta`, `Direction`, `HttpVersion`, `SerializableMethod`, `MimeKind` (+ wire parse/render).
- `src/inspector.rs` — parsed param view: `Inspector`, `Param`, `ParamLocation` (Url/Body/Cookie/Header/
  Json/Xml/Path/Multipart); JSON walk, form-urlencoded, multipart, cookie parsing.
- `src/project.rs` — `ProjectMeta`, `Project`, `ProjectKind` (Temporary/OnDisk).
- `src/scope.rs` — `Scope`, `ScopeRule`, `ScopeRuleKind`, `ScopeMatch` (wildcard + regex).
- `src/sitemap.rs` — `SiteMap`/`HostNode`/`PathNode`/`EndpointEntry` host→path tree + diff.
- `src/transform.rs` — `TransformOp` encode/decode/hash (URL/Base64/Hex/HTML/Gzip/MD5/SHA*/…), `chain`, `smart_decode`.
- `src/workspace.rs` — `WorkspacePreset`, `KeybindingMode`, `WorkspaceConfig` (UX presets).

### `lancer-storage` — `crates/lancer-storage`
SQLite (sqlx) persistence for `.lancer` projects.
- `src/lib.rs` — `Storage` facade + store accessors.
- `src/history.rs` — `HistoryRecord`, `HistoryFilter`, `HistoryStore` (insert_request/attach_response/list/get/comment/color).
- `src/issues.rs` — `Issue`, `IssueStore`, `Severity`, `Confidence` (insert/list/mark_false_positive/update).
- `src/migrations.rs` — embedded schema migrations (tracked in `_lancer_migrations`).
- `src/organizer.rs` — `OrganizerEntry`, `OrganizerStore` (tagged request library).
- `src/project.rs` — `ProjectStore` (project metadata row load/upsert).
- `src/snapshot.rs` — auto-snapshot loop (`run_snapshot_loop`, `take_snapshot`, `prune`).
- `src/websocket.rs` — `WsMessage`, `WsStore`, `WsDirection`, `WsFrameType` (frame history).

## Proxy & out-of-band

### `lancer-proxy` — `crates/lancer-proxy`
TLS-MITM intercepting proxy core.
- `src/lib.rs` — re-exports; `install_crypto_provider()` (call from every binary main).
- `src/ca.rs` / `src/ca_import.rs` / `src/cert_cache.rs` — `CertificateAuthority`, `CaConfig`, leaf minting; import external CA; per-host `CertCache`.
- `src/listener.rs` — `ProxyListener` (accepts MITM + forward-proxy; wires CA, intercept, match-replace, scope, history, events).
- `src/mitm.rs` — forwarding pipeline (`process_request`/`process_response`: scope → intercept → match-replace → history).
- `src/intercept.rs` / `src/intercept_queue.rs` — `InterceptEngine`/rules/decisions; `InterceptPauseQueue` (pause/list/resolve).
- `src/match_replace.rs` — `MatchReplaceRule`, `MatchTarget`, `MatchReplaceEngine`.
- `src/events.rs` — `ProxyEvent` (RequestCaptured/ResponseCaptured/…), `ProxyEventSink`.
- `src/settings.rs` — `ProxySettings`, `ListenerBind`, `UpstreamProxy`/`UpstreamRule`, `ClientTlsCert`.
- `src/upstream.rs` — upstream dialers (HTTP CONNECT, SOCKS4/5).
- `src/ntlm.rs` / `src/platform_auth.rs` — NTLMv2; Basic/Digest/NTLM/Negotiate challenge answering.
- `src/dns.rs` — `DnsTable` hostname overrides.
- `src/sse.rs` / `src/websocket.rs` — SSE parsing; WebSocket frame parse + upgrade handling.
- `src/http3.rs` — HTTP/3 (QUIC) client/server (feature-gated).
- `src/browser.rs` / `src/webview.rs` — system browser launcher; embedded wry webview (feature-gated).

### `lancer-oast` — `crates/lancer-oast`
Self-hosted Collaborator: out-of-band interaction server.
- `src/lib.rs` — `OastServer`, `OastConfig`, `Interaction`, `AllocatedPayload`, `InteractionKind`
  (Dns/Http/Smtp); DNS (UDP 15353), HTTP (TCP 8088), SMTP (TCP 1825) listeners; payload allocation +
  `poll_since` correlation. Each listener binds independently (one conflict doesn't kill the rest).

## Manual tools & scanning

### `lancer-tools` — `crates/lancer-tools`
Manual testing tools + power-user engagement helpers.
- `src/repeater.rs` — `Repeater`/`RepeaterTab`/`RepeaterGroup` (manual request sender).
- `src/intruder.rs` — `Intruder`, `AttackKind` (Sniper/BatteringRam/Pitchfork/ClusterBomb), `PayloadSet`, `AttackResult`.
- `src/decoder.rs` — `Decoder` (wraps `core::transform`). `src/comparer.rs` — `Comparer` (LCS diff). `src/sequencer.rs` — `Sequencer` (monobit/poker/runs randomness).
- `src/client.rs` — `HttpClient` (shared async hyper+TLS client used across tools/api).
- `src/positions.rs` — `ParsedTemplate`/`Position` (§…§ payload markers, `DEFAULT_MARKER`).
- `src/payload_processor.rs` / `src/payload_library.rs` — payload transform chains; bundled payload encyclopedia (`bundled`/`search`).
- `src/grep.rs` — `GrepConfig`/`GrepExtract`/`GrepResult` (Intruder result analysis).
- `src/logger.rs` — `Logger`/`LogEntry`/`LogFilter`/`Source` (all-tools HTTP log).
- `src/engagement.rs` — find_comments/find_scripts/find_references/discover_content/search_across, CSRF PoC.
- `src/api_spec.rs` — `parse_openapi`/`parse_postman` → `ImportedRequest`.
- `src/auth_matrix.rs` / `src/autorize.rs` / `src/param_miner.rs` — AuthMatrix grid; Autorize authz-bypass differ; hidden-param miner.
- `src/crawler.rs` / `src/js_crawler.rs` — BFS HTML crawler (`Crawler`/`CrawlSink`); Chromium JS crawler (feature-gated).
- `src/mass_fuzz.rs` — `MassFuzzConfig` (ffuf-equivalent, `COMMON_WORDLIST`).
- `src/saml.rs` — SAML decode/encode/strip_signature. `src/content_convert.rs` — JSON↔XML.
- `src/form_submit.rs` / `src/oauth_client.rs` / `src/cloud_metadata.rs` / `src/simulate_browse.rs` / `src/organizer_tools.rs` — form discovery; OAuth2 client-credentials refresh; cloud-metadata probe library; human-like browse; organizer wrapper.

### `lancer-scanner` — `crates/lancer-scanner`
Passive + active scanner (30+ checks).
- `src/lib.rs` — `PassiveCheck`/`ActiveCheck` traits; `find_insertion_points()`.
- `src/engine.rs` — `ScanEngine` (`run_passive`/`run_active`). `src/config.rs` — `ScanConfig`/`ScanPreset` (Lightweight/Balanced/Deep/AuditOnly/OwaspTop10).
- `src/insertion.rs` — `InsertionPoint` detection + payload `substitute()`.
- `src/passive.rs` + `src/passive/*` — registry + checks: headers, cookies, info_disclosure, js_secrets, mixed_content, software_disclosure, tls_config.
- `src/active.rs` + `src/active/*` — registry + ~30 checks: sqli, xss, traversal, open_redirect, crlf, ssrf, cmd_injection, ssti, ldap, xpath, host_header, cors, jwt, graphql, subdomain_takeover, mass_assignment, xxe, smuggling, cache_poison, clickjacking, deserialization, proto_pollution, race, oauth, web_llm, react2shell, upload, gadget_probe, backslash_powered.
- `src/bcheck.rs` — `BCheck` YAML DSL (`when`/`probes`, `parse()`). `src/waf.rs` — WAF `SIGNATURES`. `src/collaborator.rs` — `Collaborator` trait (Noop/Http).

### `lancer-script` — `crates/lancer-script`
- `src/lib.rs` — `ScriptEngine` (sandboxed Rhai = Burp "Bambda"); `ScriptKind` (FilterRequest/Response/CustomColumn/CustomAction/PassiveCheck/MatchReplace); `Library`/`LibraryItem`.

### `lancer-session` — `crates/lancer-session`
- `src/cookie_jar.rs` — `CookieJar`, `Cookie`, `SameSite` (shared per project).
- `src/macros.rs` — `Macro`/`MacroStep`/`MacroRunner` (+ `MacroExtract`/`MacroSub`).
- `src/rules.rs` — `SessionEngine`, `SessionRule`, `SessionAction`, `ToolScope` (per-tool/per-URL actions).

### `lancer-report` — `crates/lancer-report`
- `src/lib.rs` — `ReportMeta`/`ReportFilter` + `render_json()` and other format renderers.
- `src/pdf.rs` — `render_pdf()`. `src/tera_tpl.rs` — Tera templates (`DEFAULT_TEMPLATE`).
- `src/exporters.rs` — `jira()`/`linear()` issue-tracker payloads. `src/templates.rs` — `executive_summary()`/`developer_detail()` markdown.

### `lancer-templates` — `crates/lancer-templates`
- `src/lib.rs` — Nuclei v3-compatible engine: `Template`/`TemplateLibrary`/`Matcher`/`Extractor`/`TemplateResult`; `run_template()`, `eval_matcher()`, `eval_dsl()` (status/words/regex/size/dsl with `&&`/`||`).

## Recon & access-control

### `lancer-dom` — `crates/lancer-dom`
Static DOM/JS analysis (DOM Invader equivalent).
- `src/lib.rs` — exports `detect_clobbering`/`find_message_endpoints`/`find_gadgets`/`analyze_js`.
- `src/sinks.rs` — `DomSource`/`DomSink`/`DomFinding` (single-line source→sink XSS).
- `src/message.rs` — `PostMessageEndpoint` (postMessage handlers/sites, origin checks).
- `src/clobbering.rs` — `ClobberHit` (HTML name/id clobbering risky globals).
- `src/proto_gadgets.rs` — `GadgetHit` (jQuery/lodash/Object.assign/Angular prototype-pollution gadgets).

### `lancer-jsmining` — `crates/lancer-jsmining`
- `src/lib.rs` — `analyse()` over JS responses → `JsFinding`/`FindingType` (Secret/Endpoint/Sink/SourceMap) using regex + Shannon entropy.

### `lancer-secrets` — `crates/lancer-secrets`
- `src/lib.rs` — large secret catalog (50+ providers: AWS/GCP/Azure/GitHub/Slack/Stripe/OpenAI/Anthropic/…); `scan_response()` (regex + entropy fallback, placeholder filtering) → `SecretFinding`/`SecretKind`.

### `lancer-replay` — `crates/lancer-replay`
IDOR / access-control / business-logic suite.
- `src/lib.rs` — exports `dual_replay`/`fuzz_ids`/`diff_responses`/`build_flow_graph` + `token_similarity`.
- `src/dual_session.rs` — `SessionCreds`/`DualReplayResult` (replay one request under two identities → access-control verdict).
- `src/id_mutate.rs` — `IdFuzzReport`/`IdCandidate`/`IdHit` (mutate IDs ±1/±10/zero/max, score vs baseline).
- `src/resp_diff.rs` — `RespDiff` (status/headers/body line diff + similarity).
- `src/flow_graph.rs` — `FlowEntry`/`FlowNode`/`FlowEdge`/`FlowGraph` (navigation graph from history).

### `lancer-api-routes` — `crates/lancer-api-routes`
- `src/lib.rs` — `run_discovery()` (concurrent probe of 200+ `default_route_library()` routes; OpenAPI auto-detect) → `DiscoveryRequest`/`RouteResult` (interesting-status detection).

### `lancer-bulkprobe` — `crates/lancer-bulkprobe`
- `src/lib.rs` — `run_probes()` over host lists → `ProbeResult` with `detect_technologies`/`detect_cdn`/`detect_waf`/`extract_title`.

### `lancer-authbypass` — `crates/lancer-authbypass`
- `src/lib.rs` — `generate_probes()` (PathMutation/HeaderInjection/MethodSwap/VerbTunneling/ProtocolDowngrade/TrailingDot) + `run_probes()` (baseline-compared) → `BypassRequest`/`BypassProbe`.

## AI/LLM & exploitation

### `lancer-ai` — `crates/lancer-ai`
- `src/lib.rs` — `LlmProvider` trait + `OpenAi`/`Anthropic`/`Ollama` impls; `LlmMessage`/`LlmRequest`/`LlmResponse`; Explain/Investigate/Validate/Report prompts.
- `src/payload_mutation.rs` — `mutate()` (LLM-generated Intruder payload variants).

### `lancer-triage` — `crates/lancer-triage`
- `src/lib.rs` — `Finding`/`FindingStatus`/`TriageResult`; `heuristic_cvss()`, `find_duplicates()` (Jaccard), `draft_report()`.

### `lancer-llm-scan` — `crates/lancer-llm-scan`
- `src/lib.rs` — garak-equivalent probe catalog: `Probe`/`ProbeCategory`/`Verdict`/`ScanRequest`/`ProbeResult`; `run_scan()`, `estimate_cost()`, `probe_catalog()` (OpenAI-compatible runner).

### `lancer-llm-redteam` — `crates/lancer-llm-redteam`
- `src/lib.rs` — PyRIT-equivalent orchestrator: `Strategy` (SingleTurn/TreeOfAttacks/Crescendo/Pair/GCG/FLRT/ManyShot), `SessionRequest`/`Turn`/`Session`/`SessionStore`; `run_session()` + compliance scorer.

### `lancer-mcp-scan` — `crates/lancer-mcp-scan`
- `src/lib.rs` — `scan()` MCP servers (tool-poisoning/prompt-injection/hidden-instruction/homoglyph detectors), `diff_rug_pull()`, `cross_server_collision()`; `Transport`/`McpTool`/`Finding`/`ScanResult`.

### `lancer-shadow` — `crates/lancer-shadow`
- `src/lib.rs` — Shadow Repeater: `generate_variants()` (MutationFamily: AuthBypass/Idor/Injection/Encoding/ParameterPollution/PathTraversal), `score_against_baseline()`, `ShadowCache` (SHA256+TTL).

### `lancer-deser` — `crates/lancer-deser`
- `src/lib.rs` — ysoserial-equivalent: `generate()`, `known_chains()` (Java CommonsCollections/Spring/Groovy/… + .NET BinaryFormatter/WPF/…), `suggest_for_libraries()`, `substitute_collaborator()`; `Platform`/`Encoding`/`PayloadRequest`/`GeneratedPayload`.

### `lancer-exploitdb` — `crates/lancer-exploitdb`
- `src/lib.rs` — `ExploitDb` in-memory catalog; `by_cve()`/`by_keyword()`/`by_software_version()` (bundled subset; replaceable with SQLite mirror).

### `lancer-cms` — `crates/lancer-cms`
- `src/lib.rs` — `scan()`/`detect_cms()` + `wp_scan()`/`joomla_scan()`/`drupal_scan()`; `CmsKind`/`CmsScanRequest`/`CmsFinding`/`CmsScanResult`.

### `lancer-stateful-fuzz` — `crates/lancer-stateful-fuzz`
- `src/lib.rs` — RESTler-equivalent: `parse_spec()` → `infer_sequences()` (producer/consumer) → `run_fuzz()`; flaw detectors (AccessControl/UseAfterFree/WorkflowSkip/PrivilegeRetention/ServerError); `SessionStore`.

### `lancer-shodan` — `crates/lancer-shodan`
- `src/lib.rs` — `ShodanClient` (`host()`/`cve()`/`search()`/`from_env()`); Shodan API + InternetDB fallback, 24h cache, CVE/EPSS/KEV enrichment.

## Platform & extensibility

### `lancer-plugin` — `crates/lancer-plugin`
Plugin SDK + command palette.
- `src/manifest.rs` — `PluginManifest`, `PluginKind`, `Capability`.
- `src/hosts.rs` — `Host` trait + `WasmHost`(wasmtime)/`LuaHost`(mlua)/`PythonHost`(pyo3), all feature-gated; `InvocationCtx`.
- `src/palette.rs` — `CommandPalette`/`Command`/`CommandSource`; `search()`, `builtin()`.
- `src/registry.rs` — `PluginRegistry`/`LoadedPlugin` (load_directory/load_one/enable/remove).

### `lancer-modules` — `crates/lancer-modules`
- `src/lib.rs` — `LancerModule` trait (start/stop), `ModuleRegistry`, `ModuleState` (Off/On/Auto), `ModuleStatus`; built-ins `InProcessModule`/`EbpfModule`; `default_modules()` (jvm/python/wasm/collab/oast/scheduler/ebpf); `Preset`/`PresetStore`.

### `lancer-jvm` — `crates/lancer-jvm`
- `src/lib.rs` — `JvmConfig` + feature-gated `JvmHost` (JNI boot, calls `lancerInvoke(String)`); `MONTOYA_SHIM_JAVA` (Burp Montoya compat); implements `lancer_plugin::hosts::Host`.

### `lancer-ebpf` — `crates/lancer-ebpf`
- `src/lib.rs` — `Capturer` trait (start/stop/drain), `CapturedFlow`/`Direction`, `NullCapturer`, feature-gated `AyaCapturer` (kprobes tcp_sendmsg/recvmsg). Linux-only, opt-in.

### `lancer-ebpf-probe` — `crates/lancer-ebpf-probe` (excluded from workspace)
- `src/main.rs` — `no_std` BPF program (built for `bpfel-unknown-none`): `FlowEvent`, `EVENTS` PerfEventArray, `tcp_sendmsg`/`tcp_recvmsg` kprobes.

### `lancer-iac` — `crates/lancer-iac`
- `src/lib.rs` — `AttackSurface` + `parse_dockerfile`/`parse_compose`/`parse_kubernetes`/`parse_terraform` (ports/services/secret-like env/volumes) + `merge()`.

### `lancer-mobile` — `crates/lancer-mobile`
- `src/android.rs` — `Adb` (devices/install_user_ca/set_proxy). `src/ios.rs` — `install_steps()`/`make_profile()` (.mobileconfig). `src/frida.rs` — `ANDROID_SSL_PIN_BYPASS`/`IOS_SSL_PIN_BYPASS`/`FLUTTER_BYPASS` snippets.

### `lancer-collab` — `crates/lancer-collab`
- `src/lib.rs` — `CollabHub` (broadcast); `Peer`, `ObjectKind`, `CollabEvent` (PeerJoined/Object*/Cursor/Chat); `subscribe()`/`publish()`/`replay()`.

### `lancer-scheduler` — `crates/lancer-scheduler`
- `src/lib.rs` — `Job` trait, `Scheduler` (`register`/`run_forever`, 60s tick), `matches_cron()` (5-field cron).

## Entry points

### `lancer-api` — `crates/lancer-api`  (REST + proxy, single process)
`main()` starts the proxy listener AND the hyper REST server. `AppState` is the shared-state surface;
every field is one subsystem's store/engine. CLI args: `--listen` (`127.0.0.1:9191`), `--proxy`
(`127.0.0.1:8080`), `--project <path>` (omit = in-memory temporary), `--token`/`LANCER_API_TOKEN`.

`AppState` holds (abbrev.): `project`/`project_path` (Storage), `proxy_settings`, `client`,
`intercept_engine`/`intercept_queue`, `match_replace(+engine)`, `scope`, `ca`, `cookie_jar`,
`session_engine`, `macros`, `plugins`, `templates`, `scan_config`, `oast`, `collab`, plus per-feature
result stores: `js_findings`/`js_files`, `findings`, `secrets`, `bypass_jobs`, `probe_results`,
`routes`, `deser_payloads`, `llm_results`, `redteam_store`, `mcp_results`, `shodan`, `shadow_variants`,
`fuzz_store`, `cms_results`, `exploitdb`, `modules`/`module_presets`.

Endpoints (all under `/v1`; the GUI calls them as `/api/v1`):
- **Core:** `GET /status`, `GET /openapi.json`.
- **History:** `GET /history`(?limit), `GET|DELETE|PATCH /history/{id}`.
- **Scan:** `POST /scan/passive|active|full`, `GET /scan/queue`, `GET|PUT /scan/config`, `POST /scan/import-spec`, `POST /scan/oob`.
- **Issues/Report:** `GET|POST /issues`, `PATCH /issues/{id}`, `GET /report?format=html|json|markdown|sarif|xml|pdf|jira|linear|github|defectdojo|faraday|tera`.
- **Repeater/Intruder/Sequencer/Transform:** `POST /repeater`, `POST /intruder`, `POST /sequencer/analyse|capture`, `POST /transform`, `POST /transform/smart-decode`.
- **Proxy:** `GET /proxy/status`, `POST /proxy/intercept/toggle|forward|drop`, `GET /proxy/intercept/queue`, `GET /proxy/ca-cert.pem|.der`, `GET|PUT /proxy/rules`, `GET|PUT /proxy/settings`, `GET|PUT /scope`.
- **Session:** `GET|POST|DELETE /cookies`, `DELETE /cookies/{key}`, `GET|POST /macros`, `GET|PUT|DELETE /macros/{id}`, `POST /macros/{id}/run`, `GET|POST /sessions/rules`, `PUT|DELETE /sessions/rules/{id}`.
- **Project/Organizer/WS/Plugins/Settings/AI:** `GET /project`, `POST /project/open|new-temporary`; `GET|POST /organizer`, `PUT|DELETE /organizer/{id}`; `GET /ws-history`; `GET /plugins`, `POST /plugins/{id}/toggle`, `POST /plugins/upload`, `DELETE /plugins/{id}`; `GET|PUT /settings`; `POST /ai`.
- **Recon/feature stores** (mostly `POST` run + `GET` results + `DELETE` clear): `/iac/parse`; `/mobile/ios-install-steps|ios-profile|frida-script`; `/templates`(+`/run`,`/{id}`); `/jsmining/findings|files|rescan`; `/findings`(+`/{id}`,`/{id}/triage`,`/draft-report`,`/duplicates`,`/stats`,`/export`); `/secrets`; `/authbypass`; `/bulkprobe`; `/api-routes`; `/deser`(+`/chains`,`/generate`); `/llm-scan/run|results|estimate`; `/llm-redteam/start|sessions|sessions/{id}`; `/mcp-scan/run|results`; `/shodan/host/{ip}|cve/{id}`; `/shadow/generate`(+`GET|DELETE /shadow`); `/stateful-fuzz/start|sessions|sessions/{id}`; `/cms-scan/run`(+`GET|DELETE /cms-scan`); `/exploits/by-cve/{id}|by-keyword/{kw}`; `/modules`(+`/{id}/start|stop|status|set-state`,`/presets`).
- **Engagement/Replay/Collab/Collaborator/Scripting:** `/engagement/*` (find-comments/scripts/anchors, csrf-poc, clickbandit, analyze-target, find-references, search, discover-content); `/replay/dual|idfuzz|respdiff|flowgraph`; `/collab/join|leave|cursor|chat|state`; `/collaborator/*` (status/generate/interactions/poll/payloads/config/server start|stop); `/bambda/test`, `/bchecks/validate`, `/crawl/deep`, `/payloads`, `/massfuzz`(+`/wordlist`).

### `lancer-cli` — `crates/lancer-cli` (binary: `lancer`)
Clap `Cmd` enum in `main.rs` → one module per subcommand in `src/commands/`.

| Subcommand | Module | Purpose |
|---|---|---|
| `cert` | cert.rs | CA management (init, export-der/pem) |
| `proxy` | proxy.rs | Start the intercepting proxy |
| `project` | project.rs | Project file utilities (new, info) |
| `history` | history.rs | Browse stored HTTP history (list/show/clear) |
| `decode` | decode.rs | Encode/decode/hash transforms (stdin→stdout) |
| `compare` | compare.rs | Word/byte diff of two files |
| `repeater` | repeater.rs | Send a single request |
| `intruder` | intruder.rs | Payload attack (sniper/battering-ram/pitchfork/cluster-bomb) |
| `sequencer` | sequencer.rs | Token randomness analysis |
| `engagement` | engagement.rs | Comments/scripts/anchors/CSRF-PoC/discovery/search |
| `organizer` | organizer.rs | Saved-request library (list/save/search) |
| `scan` | scan.rs | Passive+active scanner (passive/active/full/list-checks) |
| `report` | report.rs | Render report (html/json/markdown/sarif/xml/pdf/tera/…) |
| `palette` | palette.rs | Search the command palette |
| `plugin` | plugin.rs | Plugin management (list/load) |
| `ai` | ai.rs | Prompt the BYO-LLM provider |
| `crawl` | crawl.rs | BFS crawler from a URL |
| `import` | import.rs | Import OpenAPI 3.x / Postman 2.1 |
| `bcheck` | bcheck.rs | BCheck DSL (list/lint/run) |
| `waf` | waf.rs | WAF fingerprinting |
| `payloads` | payloads.rs | Payload encyclopedia (list/search) |
| `export` | export.rs | Export findings (jira/linear/github/defectdojo/faraday) |
| `dom` | dom.rs | DOM-XSS/postMessage/proto-gadget/clobbering static analysis |
| `mobile` | mobile.rs | Android ADB / iOS profile / Frida snippets |
| `iac` | iac.rs | Parse Dockerfile/compose/k8s/terraform |
| `miner` | miner.rs | Param Miner / Autorize / AuthMatrix |
| `saml` | saml.rs | SAML Raider (decode/encode/strip-signature/xsw) |
| `convert` | convert.rs | JSON↔XML body converter |
| `url` | urls.rs | §49 URL toolkit (qsreplace/gf/anew/uro/unfurl) |
| `ysoserial` | ysoserial.rs | §40 deserialization payload generator |
| `llm-scan` | llm_scan.rs | §42 LLM vuln scanner (run/estimate/list-probes) |
| `llm-redteam` | llm_redteam.rs | §43 LLM red-team orchestrator |
| `mcp-scan` | mcp_scan.rs | §44 MCP server scanner |
| `shadow` | shadow.rs | §47 Shadow Repeater variants |
| `stateful-fuzz` | stateful_fuzz.rs | §48 stateful API fuzzer |
| `cms-scan` | cms_scan.rs | §50 CMS scanner (WP/Joomla/Drupal) |
| `exploits` | exploits.rs | §51 Exploit-DB lookup (cve/search/software/update) |
| `shodan` | shodan.rs | §45 Shodan enrichment (host/cve/search) |
| `modules` | modules.rs | §52 modules (list/enable/disable/status/preset) |
| `fuzz` | fuzz.rs | §4.6 ffuf-equivalent content/param fuzzer |
| `bench` | bench.rs | §25 throughput benchmark |
| `mcp` | mcp.rs | §58 MCP server (expose Lancer to AI agents over stdio) |
| `infiltrator` | infiltrator.rs | §57 emit Frida sink-taint script |

### `lancer-gui` — `crates/lancer-gui`
Native wry/tao window + embedded SPA workbench.

**Rust shell (`src/`):** `main.rs` (spawn lancer-api child, open window, lifecycle) · `app.rs` (hyper
server: SPA + `/api/palette|status|browser/open` + reverse-proxy `/api/v1/*`) · `static_assets.rs`
(`include_dir!` the built `dist/` + MIME + SPA fallback) · `commands_ipc.rs` (Tauri-style IPC handlers,
currently unused/future).

**SPA (`web/src/`):** `main.js` mounts `App.svelte`. `App.svelte` is the tabbed shell: topbar
(File/Help menus, theme toggle, open-browser, Ctrl+K palette), status bar (project/proxy/plugins/scans/
memory, polls `/api/v1/status`), the `tabs` array, and the `{#if active===id}` render switch. Theme is a
`:root` light-token / `[data-theme="dark"]` system in `App.svelte`'s `<style>`.

Tab id → view (`web/src/views/`): dashboard→Dashboard · target→Target · proxy→Proxy · intruder→Intruder
· massfuzz→MassFuzz · repeater→Repeater · sequencer→Sequencer · decoder→Decoder · comparer→Comparer ·
payloads→Payloads · scanner→Scanner · collaborator→Collaborator · dualsession→DualSession ·
idmutator→IdMutator · respdiff→ResponseDiffer · flowgraph→FlowGrapher · logger→Logger ·
organizer→Organizer · findings→Findings · jsmining→JsMining · secrets→SecretScanner ·
authbypass→AuthBypass · bulkprobe→BulkProbe · apiroutes→ApiRoutes · deser→DeserPayload · llmscan→LlmScan
· redteam→LlmRedTeam · mcp→McpScan · shodan→Shodan · fuzz→StatefulFuzz · cms→CmsScan · exploits→Exploits
· mobile→Mobile · iac→Iac · modules→Modules · cookies→Cookies · sessions→SessionHandling ·
scripts→Scripts · collab→Collab · plugins→Plugins · reports→Reports · settings→Settings.
Legacy/unused views: `Palette.svelte`, `Issues.svelte`, `History.svelte` (kept but not in `tabs`).

**Shared lib (`web/src/lib/`):** `PaletteModal.svelte` (active Ctrl+K palette — fixed nav list + plugin
commands) · `Sidebar.svelte` (legacy, unused).

### `lancer-setup` — `crates/lancer-setup`
- `src/main.rs` — Windows self-extracting installer: embedded `PAYLOAD` zip (from build.rs) → extract to `%TEMP%` → run `install.ps1` via PowerShell.

---

## Extending the app (verified patterns)
- **New API endpoint:** add a field to `AppState` (the struct declaration *and* the constructor
  literal, both in `lancer-api/src/main.rs`), then a `match (method, path)` arm in `handle()` — or an
  `if` branch in `dynamic_route()` for parameterized paths.
- **New GUI view/tab:** create `web/src/views/Foo.svelte`, then in `App.svelte` add the `import`, a
  `tabs` entry, and a `{#if active==="..."}` render block. Add the tab to the `PaletteModal.svelte` nav
  list too. Rerun `npm run build`.
- **New CLI subcommand:** add a `commands/<name>.rs` (`Args` + `run()`), a variant to the `Cmd` enum,
  and a dispatch arm in `lancer-cli/src/main.rs`.
- **New scanner check:** add `active/<name>.rs` (impl `ActiveCheck`) or `passive/<name>.rs` (impl
  `PassiveCheck`) and register it in `active.rs`/`passive.rs`.

## Conventions & gotchas that will bite again
- **Crypto provider:** see Architecture — every binary `main()` calls `install_crypto_provider()`.
- **GUI labels must match backend parse keys exactly:** the GUI sends serde's capitalized enum forms
  (`"High"`/`"Firm"`; attack types `"Battering ram"`/`"Cluster bomb"`). Backend `parse`/lookup maps
  must match those strings (or parse case-insensitively) or the value silently falls back.
- **History serialization shape:** a stored record's `version` is an enum string (`"Http11"`),
  `headers` is a `[{name,value}]` array (not an object), and `body` is a byte array. Views rendering a
  request/response *from history* must map version→wire, iterate the header array, and TextDecode body.
- **Message IDs:** a captured request and its response carry DIFFERENT `meta.id`s — correlate via
  `ResponseCaptured.request_id`, never the response's own id.
- **Binary GUI exports** (e.g. PDF reports): fetch as a blob, never `.text()` (which corrupts binary).
- **In-memory project pools:** an `:memory:` SQLite pool must pin the connection
  (`min_connections(1)` + `idle_timeout(None)` + `max_lifetime(None)`) or the DB is silently recreated
  empty when the connection is reaped → `no such table` 500s after the app sits idle.
- **`/api` vs `/v1`:** the backend has no `/api` prefix; the GUI server and the vite dev proxy both
  rewrite `/api/v1/*` → `/v1/*`.

## Repo norms
- Work is batched: make a batch of changes, run `cargo check` + `npm run build`, then commit per batch
  directly to `master` and push. `origin` = `github.com/NHTanvir/lancer`.
- Gitignored / local-only: `plan.md`, `dist/` (built SPA), `node_modules/`, `/target`, `.lancer`
  project files, `.claude/`, `check.bat`.
