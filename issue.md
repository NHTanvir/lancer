# Lancer Audit — Issue List

_Generated from a full line-by-line audit of every source file (73 review units, 170 agents). 97 raw findings → **90 confirmed**, 7 rejected after adversarial verification._

**Severity:** 1 critical · 27 high · 26 medium · 36 low

Each issue has a checkbox; check it off as it is fixed. `cargo check` after each batch; `npm run build` for Svelte fixes.


---

## Index

| # | Sev | File:Line | Category | Title |
|---|-----|-----------|----------|-------|
| 1 | CRIT | `crates/lancer-ebpf/src/lib.rs:130` | parsing | Perf events parsed as JSON but the BPF probe emits a raw #[repr(C)] struct — every capture |
| 2 | HIGH | `crates/lancer-bulkprobe/src/lib.rs:124-129` | panic | extract_title can panic on a non-UTF-8-boundary slice of attacker-controlled body |
| 3 | HIGH | `crates/lancer-cli/src/commands/repeater.rs:49-51` | logic-error | HTTPS repeater connects to port 80 when Host header has no explicit port |
| 4 | HIGH | `crates/lancer-cli/src/commands/scan.rs:97-102` | logic-error | `scan active --scheme https` connects to port 80 (port never derived from scheme) |
| 5 | HIGH | `crates/lancer-gui/web/src/views/Findings.svelte:96-114` | api-contract | New findings are never persisted server-side: GUI sends a non-UUID `id`, backend rejects t |
| 6 | HIGH | `crates/lancer-gui/web/src/views/Intruder.svelte:49-51` | correctness | Auto-§ regex captures the HTTP version into the payload position on the request line |
| 7 | HIGH | `crates/lancer-gui/web/src/views/JsMining.svelte:17, 24, 30, 143, 237` | api-contract | Frontend uses "source-map" but backend serializes the type as "source_map" |
| 8 | HIGH | `crates/lancer-gui/web/src/views/Payloads.svelte:21-28` | api-contract | Payloads 'Send to Repeater' writes a key/shape Repeater never reads — payload silently dro |
| 9 | HIGH | `crates/lancer-gui/web/src/views/Payloads.svelte:29-34` | api-contract | Payloads 'Use in Intruder' sends {payload} but Intruder onMount only reads {raw/scheme/hos |
| 10 | HIGH | `crates/lancer-gui/web/src/views/Proxy.svelte:13-24` | api-contract | Intercept "Action → Send to Repeater" is a no-op (writes a key Repeater never reads, and n |
| 11 | HIGH | `crates/lancer-gui/web/src/views/Proxy.svelte:181-196` | api-contract | "Send to Repeater" from HTTP history never transfers the request (wrong localStorage key) |
| 12 | HIGH | `crates/lancer-gui/web/src/views/Repeater.svelte:187` | parsing | Malformed percent-escape in request URL throws URIError in reactive parser, breaking the I |
| 13 | HIGH | `crates/lancer-gui/web/src/views/Scanner.svelte:91-99` | api-contract | "Active only" scan sends wrong request body — backend always rejects it with 400 |
| 14 | HIGH | `crates/lancer-gui/web/src/views/Target.svelte:1054-1060` | api-contract | Response 'Render' tab reads selectedEntry.body/response_body, which don't exist; iframe is |
| 15 | HIGH | `crates/lancer-gui/web/src/views/Target.svelte:68, 94, 1010` | api-contract | Notes column and annotation filter read e.notes, but the record field is `comment` |
| 16 | HIGH | `crates/lancer-gui/web/src/views/Target.svelte:93, 1009` | api-contract | Time column and time-sort read a non-existent field (e.ts/e.timestamp) instead of e.captur |
| 17 | HIGH | `crates/lancer-llm-scan/src/lib.rs:351` | resource-leak | concurrency == 0 makes run_scan hang forever (buffer_unordered(0) never makes progress) |
| 18 | HIGH | `crates/lancer-mcp-scan/src/lib.rs:199-214` | api-contract | SSE transport calls plain HTTP JSON-RPC and parses response as JSON, silently returning no |
| 19 | HIGH | `crates/lancer-proxy/src/listener.rs:433-440, 464-477, 516` | logic-error | Outbound TLS advertises ALPN h2 but the origin connection always uses an HTTP/1-only hands |
| 20 | HIGH | `crates/lancer-replay/src/id_mutate.rs:93` | logic-error | URL ID mutation does a raw substring replace over the entire URL, can corrupt host/scheme  |
| 21 | HIGH | `crates/lancer-scanner/src/active/upload.rs:22` | correctness | PHP_MARKER_HASH is md5 of the empty string, so server-side-execution detection can never f |
| 22 | HIGH | `crates/lancer-scanner/src/passive/info_disclosure.rs:89` | panic | Snippet slicing can panic on a non-UTF-8-char-boundary |
| 23 | HIGH | `crates/lancer-secrets/src/lib.rs:250-254` | panic | snippet_around byte-slices a &str at non-char-boundary offsets → panic on multi-byte UTF-8 |
| 24 | HIGH | `crates/lancer-setup/src/main.rs:51-64` | security | Zip Slip: archive entry name used unsanitized allows path traversal outside the temp dir |
| 25 | HIGH | `crates/lancer-storage/src/snapshot.rs:36` | correctness | Snapshot copies only the main DB file while WAL mode is active, losing recent committed tr |
| 26 | HIGH | `crates/lancer-templates/src/lib.rs:277-287` | logic-error | DSL contains() helper never works: trailing ')' stripped before the contains() branch can  |
| 27 | HIGH | `crates/lancer-tools/src/autorize.rs:50-60` | logic-error | Low-privilege authz replay does not strip the original Authorization header |
| 28 | HIGH | `crates/lancer-tools/src/intruder.rs:570` | compile-error | sniper_combos test calls function with wrong argument type (won't compile under cfg(test)) |
| 29 | MEDI | `crates/lancer-api-routes/src/lib.rs:272` | panic | buffer_unordered(0) hangs/panics when concurrency is 0 from external input |
| 30 | MEDI | `crates/lancer-api/src/main.rs:1247-1258` | api-contract | DELETE /v1/templates/{id} returns ok:true but never deletes the template |
| 31 | MEDI | `crates/lancer-bulkprobe/src/lib.rs:219-227` | correctness | Client-supplied concurrency:0 makes run_probes silently probe nothing |
| 32 | MEDI | `crates/lancer-cli/src/commands/intruder.rs:19-20, 110-113` | parsing | `--payloads list:a,b,c` is broken: comma value_delimiter splits it, and the list parser us |
| 33 | MEDI | `crates/lancer-cli/src/commands/urls.rs:181-184` | logic-error | uro trailing-slash normalization fails (and breaks dedup) whenever a query/fragment is pre |
| 34 | MEDI | `crates/lancer-dom/src/message.rs:34-67` | logic-error | Closely-spaced postMessage listeners are silently dropped (single-slot buffer overwritten) |
| 35 | MEDI | `crates/lancer-gui/web/src/views/Findings.svelte:136-141` | api-contract | "PDF" export option downloads JSON content saved with a .md extension |
| 36 | MEDI | `crates/lancer-gui/web/src/views/Intruder.svelte:230` | api-contract | Case modification payload spec sends the wrong base string (charSubBase instead of a Case- |
| 37 | MEDI | `crates/lancer-gui/web/src/views/Plugins.svelte:90-103, 538` | api-contract | Binary plugin uploads are read with file.text() and corrupted (and the backend only accept |
| 38 | MEDI | `crates/lancer-gui/web/src/views/Repeater.svelte:186-187` | parsing | Query/body param parsing splits on '=' once via destructuring, truncating values that cont |
| 39 | MEDI | `crates/lancer-gui/web/src/views/Repeater.svelte:480` | correctness | Error/cancel result is written to the wrong tab when the user switches tabs during an in-f |
| 40 | MEDI | `crates/lancer-gui/web/src/views/Target.svelte:139, 462, 470, 307` | api-contract | Title extraction and engagement tools read non-existent e.body/e.response_body, sending em |
| 41 | MEDI | `crates/lancer-gui/web/src/views/Target.svelte:524-530` | correctness | formatRequest discards captured headers/body; Send-to-Repeater/Intruder/Comparer/CSRF get  |
| 42 | MEDI | `crates/lancer-llm-redteam/src/lib.rs:275` | security | TLS certificate validation disabled while sending the LLM API key as a bearer token |
| 43 | MEDI | `crates/lancer-proxy/src/ca_import.rs:21-28` | correctness | import_from_pem does not actually verify the imported cert and key match |
| 44 | MEDI | `crates/lancer-proxy/src/sse.rs:52` | parsing | SSE chunk tail drops already-parsed fields of an in-progress event |
| 45 | MEDI | `crates/lancer-replay/src/id_mutate.rs:103` | correctness | Body ID mutation lossily round-trips through UTF-8, corrupting non-UTF-8 request bodies |
| 46 | MEDI | `crates/lancer-scanner/src/active/host_header.rs:65-69` | logic-error | is_first_point() throttle is effectively always-true, so Host-header probes fire for every |
| 47 | MEDI | `crates/lancer-scanner/src/active/race.rs:23-51` | resource-leak | Point-agnostic active check fires once per insertion point, multiplying concurrent state-c |
| 48 | MEDI | `crates/lancer-scanner/src/passive/cookies.rs:34-36` | correctness | Cookie security-flag detection uses substring match over the whole header (false negatives |
| 49 | MEDI | `crates/lancer-stateful-fuzz/src/lib.rs:191-192` | panic | replace_range can panic on a spec path where '}' precedes '{' |
| 50 | MEDI | `crates/lancer-tools/src/auth_matrix.rs:46-56` | logic-error | Matrix replay leaks the original request's Authorization for cookie-only identities |
| 51 | MEDI | `crates/lancer-tools/src/crawler.rs:103-138` | logic-error | Crawler is serial: `concurrency` config is silently ignored |
| 52 | MEDI | `crates/lancer-tools/src/engagement.rs:118-129` | correctness | CSRF PoC double-encodes form values from urlencoded bodies |
| 53 | MEDI | `crates/lancer-tools/src/repeater.rs:123-144` | correctness | Repeater redirect-following downgrades 307/308 to GET and drops the request body |
| 54 | MEDI | `crates/lancer-tools/src/simulate_browse.rs:75-78` | panic | gen_range panics when min_delay_ms > max_delay_ms (attacker/operator-supplied config) |
| 55 | LOW | `crates/lancer-api/src/main.rs:2599-2601` | parsing | parse_query does not URL-decode values, corrupting encoded query parameters |
| 56 | LOW | `crates/lancer-api/src/main.rs:399-407` | correctness | Passive JS-file entry always records findings: 0 even when findings were mined |
| 57 | LOW | `crates/lancer-authbypass/src/lib.rs:168-178` | logic-error | Trailing-dot probe places the dot after the port, producing an invalid URL |
| 58 | LOW | `crates/lancer-cli/src/commands/mcp_scan.rs:109-111` | logic-error | sse:// always forced to plaintext http://, cannot reach a TLS-secured SSE MCP server |
| 59 | LOW | `crates/lancer-core/src/inspector.rs:210-221` | parsing | Multipart name extraction matches "filename=" when a part has no name= attribute |
| 60 | LOW | `crates/lancer-core/src/scope.rs:152-161` | parsing | ScopeRule::from_str misparses bracketed IPv6 hosts, rejecting valid input |
| 61 | LOW | `crates/lancer-deser/src/lib.rs:137` | logic-error | TC_STRING length prefix silently truncated by u16 cast for cmd > 65535 bytes |
| 62 | LOW | `crates/lancer-dom/src/message.rs:50-66` | logic-error | Listener within the last 8 lines of the file uses a shorter validation window than intende |
| 63 | LOW | `crates/lancer-gui/src/main.rs:130-136` | logic-error | Dead/duplicated 'dev fallback' branch in locate_api never executes |
| 64 | LOW | `crates/lancer-gui/web/src/App.svelte:131` | logic-error | Persisted hotkeys can fully shadow new defaults, leaving rebound actions unreachable |
| 65 | LOW | `crates/lancer-gui/web/src/views/Decoder.svelte:525` | logic-error | Output char-count footer references non-existent row properties, so it never renders |
| 66 | LOW | `crates/lancer-gui/web/src/views/Organizer.svelte:237-268` | parsing | renderMarkdown corrupts multi-line fenced code blocks in the Notes preview |
| 67 | LOW | `crates/lancer-gui/web/src/views/Organizer.svelte:67` | correctness | formatRequest/formatResponse mislabel HTTP/1.0 and HTTP/3 as HTTP/1.1 |
| 68 | LOW | `crates/lancer-gui/web/src/views/Plugins.svelte:70-84, 32-42, 167` | logic-error | moveUp/moveDown reorder only local state and are silently reverted by the 8s poll |
| 69 | LOW | `crates/lancer-gui/web/src/views/Settings.svelte:332` | api-contract | Persisting theme="system" breaks theme on next app load (App.svelte forces light) |
| 70 | LOW | `crates/lancer-iac/src/lib.rs:126` | correctness | Kubernetes service port truncated via `as u16` instead of range-checked, producing wrong p |
| 71 | LOW | `crates/lancer-jvm/src/lib.rs:63` | logic-error | JAVA_HOME set one directory too deep — points at <JDK>/bin (or <JDK>/lib) instead of <JDK> |
| 72 | LOW | `crates/lancer-mobile/src/android.rs:64` | panic | install_user_ca panics on non-UTF-8 cert path |
| 73 | LOW | `crates/lancer-proxy/src/intercept.rs:57-62` | logic-error | Invalid url_regex silently broadens an intercept rule instead of failing it |
| 74 | LOW | `crates/lancer-proxy/src/match_replace.rs:111-126` | logic-error | RequestFirstLine match/replace ignores any edit to the HTTP version segment |
| 75 | LOW | `crates/lancer-proxy/src/platform_auth.rs:89-121` | logic-error | Digest non-MD5 algorithm branch is unreachable dead code |
| 76 | LOW | `crates/lancer-proxy/src/upstream.rs:92-109` | parsing | SOCKS5 username/password length cast can truncate, producing a malformed/auth-bypassing fr |
| 77 | LOW | `crates/lancer-replay/src/id_mutate.rs:53-58` | parsing | Integer detector matches digit runs inside UUIDs, creating spurious int candidates |
| 78 | LOW | `crates/lancer-report/src/exporters.rs:185-191` | parsing | faraday_csv field-quoting omits carriage return, can corrupt CSV records |
| 79 | LOW | `crates/lancer-scanner/src/active/mass_assignment.rs:45-62` | logic-error | Mass-assignment dedup still matches two insertion points (JsonKey + JsonValue) with the sa |
| 80 | LOW | `crates/lancer-scanner/src/active/xss.rs:60-67` | api-contract | Canary-reflection XSS issue is created without check_id (and without notes) |
| 81 | LOW | `crates/lancer-scanner/src/collaborator.rs:108` | correctness | Collaborator poll cursor advances to post-response time, dropping interactions that arrive |
| 82 | LOW | `crates/lancer-session/src/cookie_jar.rs:71` | correctness | Cookie path matching lacks a path-boundary check (RFC 6265 path-match) |
| 83 | LOW | `crates/lancer-shadow/src/lib.rs:161-164` | parsing | url_encode_body produces invalid percent-encoding for non-ASCII (multibyte) body character |
| 84 | LOW | `crates/lancer-stateful-fuzz/src/lib.rs:170` | off-by-one | infer_sequences returns one sequence even when max is 0 |
| 85 | LOW | `crates/lancer-storage/src/history.rs:156-185` | api-contract | HistoryFilter.mime is a declared public filter field that list() never applies |
| 86 | LOW | `crates/lancer-templates/src/lib.rs:304-309` | correctness | Numeric DSL variable compared against non-numeric RHS falls through to a wrong string comp |
| 87 | LOW | `crates/lancer-tools/src/engagement.rs:108-117` | correctness | CSRF PoC emits invalid enctype and empty form for multipart requests |
| 88 | LOW | `crates/lancer-tools/src/engagement.rs:202-204` | resource-leak | discover_content aborts entire run if any single wordlist entry fails URL join |
| 89 | LOW | `crates/lancer-tools/src/intruder.rs:168-195` | logic-error | CharFrobberIter emits the unchanged base string once per position (delta == 0 case) |
| 90 | LOW | `crates/lancer-tools/src/sequencer.rs:124-127` | correctness | Runs-test statistic uses wrong denominator (2*sqrt(n) instead of 2*sqrt(2n)) |

---

## Issues


### CRITICAL

#### [x] #1 · `crates/lancer-ebpf/src/lib.rs:130` · CRITICAL · parsing
**Perf events parsed as JSON but the BPF probe emits a raw #[repr(C)] struct — every captured flow is silently dropped**

**Problem:** The kernel side (crates/lancer-ebpf-probe/src/main.rs lines 13-43) writes a raw little-endian `#[repr(C)] FlowEvent { pid:u32, direction:u32, payload_bytes:u32, comm:[u8;16] }` into the perf-event array via `EVENTS.output(&ctx, &ev, 0)`. The consumer here calls `serde_json::from_slice::<CapturedFlow>(b)` on those raw struct bytes. Raw C-struct bytes are not valid JSON, so `from_slice` returns `Err` for every single event and the `if let Ok(f)` branch is never taken. The result: the eBPF capturer attaches its kprobes, spawns reader tasks, and consumes events, but `drain()` always returns an empty Vec — the feature produces zero output while appearing to work. Beyond the encoding mismatch, the structs are also shape-incompatible: `FlowEvent` has `direction: u32` and `comm: [u8;16]` and no `src`/`dst`, whereas `CapturedFlow` expects `comm: String`, `src: String`, `dst: String`, and `direction: Direction` (Tx/Rx enum). Even a corrected binary decode must map these fields explicitly.

**Evidence:**
````
for b in buffers.iter().take(events.read) {
    if let Ok(f) = serde_json::from_slice::<CapturedFlow>(b) {
        flows.lock().push(f);
    }
}
````

**Fix:** Replace the JSON parse with a binary decode of the raw FlowEvent struct, mapping fields explicitly. Since the probe records have no padding (4+4+4+16 = 28 bytes) decode via byte offsets to avoid alignment/repr assumptions and avoid adding bytemuck/zerocopy deps:

```rust
const EVENT_LEN: usize = 28; // u32*3 + [u8;16]
for b in buffers.iter().take(events.read) {
    if b.len() < EVENT_LEN { continue; }
    let pid = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let dir = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
    let payload_bytes = u32::from_le_bytes([b[8], b[9], b[10], b[11]]) as usize;
    let comm_raw = &b[12..28];
    let end = comm_raw.iter().position(|&c| c == 0).unwrap_or(comm_raw.len());
    let comm = String::from_utf8_lossy(&comm_raw[..end]).into_owned();
    let direction = if dir == 0 { Direction::Tx } else { Direction::Rx };
    flows.lock().push(CapturedFlow {
        pid,
        comm,
        src: String::new(), // probe does not currently capture endpoints
        dst: String::new(),
        direction,
        payload_bytes,
    });
}
```

Notes: read_events fills each BytesMut with the perf record, so b starts at the FlowEvent bytes; the length guard handles short/empty records. src/dst stay empty until the probe is extended to capture socket endpoints. Drop the serde_json dependency for this path. (Optional: define a shared FlowEvent layout / constant to keep producer and consumer in sync.)

_Verified (high): Verified both sides. Producer crates/lancer-ebpf-probe/src/main.rs:13-43 emits a raw #[repr(C)] FlowEvent{pid:u32, direction:u32, payload_bytes:u32, comm:[u8;16]} via EVENTS.output(&ctx,&ev,0) — i.e. ~28 bytes of raw little-endian struct data per perf record. Consumer crates/lancer-ebpf/src/lib.rs:130 calls serde_json::from_slice::<CapturedFlow>(b) on those raw bytes. Binary C-struct bytes are not valid JSON, so from_slice returns Err for every record, the `if let Ok(f)` branch never executes, and drain() always returns empty. The shapes are also incompatible (FlowEvent has direction:u32 and comm:[u8;16] and no src/dst; CapturedFlow expects direction:Direction enum, comm:String, src:String, dst:String). Rust's type system does NOT prevent this — from_slice is a runtime fallible parse that just silently yields Err. One important nuance: the code is gated behind #[cfg(feature=\"linux\")] AND start() bails out early because PROG_OBJECT is the empty placeholder &[] (line 103-107), so the reader task currently never spawns — the bug is presently UNREACHABLE at runtime. It is a real, correctly-described latent defect that activates the instant someone wires in the real BPF object, which is the documented intended next step (lines 76-85). Severity \"critical\" is overstated given current unreachability, but the parsing defect itself is genuine._


---


### HIGH

#### [x] #2 · `crates/lancer-bulkprobe/src/lib.rs:124-129` · HIGH · panic
**extract_title can panic on a non-UTF-8-boundary slice of attacker-controlled body**

**Problem:** `start` and `end` are byte offsets located in `lower` (the result of `body.to_lowercase()`), but the final slice `body[start..end]` is taken from the ORIGINAL `body`. `to_lowercase()` is not length-preserving: some code points lowercase to a different UTF-8 byte length (e.g. 'İ' U+0130 = 2 bytes lowercases to 'i̇' = 3 bytes). When such a character appears in the response body before the `<title>` marker, the offsets computed on `lower` no longer correspond to the same positions in `body`, so `body[start..end]` can land in the middle of a multi-byte UTF-8 sequence. Slicing a `&str` at a non-char-boundary panics. The body here is fully attacker/remote-server-controlled (the probed host's HTTP response), so a malicious or merely unusual server can crash the probe task / thread.

**Evidence:**
````
let lower = body.to_lowercase();
    let start = lower.find("<title>")? + 7;
    let end = start + lower[start..].find("</title>")?;
    Some(body[start..end].trim().chars().take(120).collect())
````

**Fix:** Search and slice on the SAME string so all byte offsets are valid for the string being indexed. Robust fix that preserves original-case title and avoids the lossy `body[..]` mismatch:

fn extract_title(body: &str) -> Option<String> {
    let lower = body.to_lowercase();
    let open = lower.find("<title>")?;
    let start = open + "<title>".len();
    let end = start + lower[start..].find("</title>")?;
    // `start`/`end` are valid char boundaries within `lower`; slice `lower`, not `body`.
    Some(lower[start..end].trim().chars().take(120).collect())
}

This is panic-safe because `find()` returns byte offsets at char boundaries of `lower`, and `+ "<title>".len()` (7 ASCII bytes) stays on a boundary, so `lower[start..end]` is always valid. The only behavioral change is the title is lowercased.

If preserving the original case is desired, search `body` case-insensitively without allocating a lowercased copy, e.g.:

fn ci_find(hay: &str, needle_lower: &str) -> Option<usize> {
    let hl = hay.to_lowercase();
    // map a lower-offset back is unsafe; instead scan char_indices on `hay`:
    let bytes_lower: Vec<u8> = hay.to_lowercase().into_bytes();
    let _ = bytes_lower; // not boundary-safe; prefer iterating windows on hay directly
    hay.char_indices().find_map(|(i, _)| {
        if hay[i..].len() >= needle_lower.len()
            && hay[i..i + needle_lower.len()].eq_ignore_ascii_case(needle_lower) {
            Some(i)
        } else { None }
    })
}

then:

fn extract_title(body: &str) -> Option<String> {
    let open = ci_find(body, "<title>")?;
    let start = open + "<title>".len();
    let rel_end = ci_find(&body[start..], "</title>")?;
    let end = start + rel_end;
    Some(body[start..end].trim().chars().take(120).collect())
}

All indices here come from `char_indices()`/`find` on `body` itself, so every slice is boundary-valid and the original case is preserved. The simpler `lower[start..end]` version is sufficient to eliminate the panic if a lowercased title is acceptable.

_Verified (high): The cited code at lines 124-129 is present exactly as reported. `extract_title(&body)` is called at line 179 with `body = resp.text().await.unwrap_or_default()` — the probed host's HTTP response body, fully remote/attacker-controlled and a valid UTF-8 String. The function computes `start`/`end` as byte offsets into `lower = body.to_lowercase()`, then slices the ORIGINAL `body[start..end]`. Rust's `to_lowercase()` is NOT byte-length-preserving: e.g. 'İ' (U+0130, 2 bytes) lowercases to "i̇" (U+0069 U+0307, 3 bytes). When such an expanding character appears in the body before the `<title>` tag, offsets derived from `lower` are shifted relative to `body`, so `body[start..end]` can land mid-UTF-8-codepoint (or `end` can exceed `body.len()`). Slicing a &str at a non-char-boundary or out-of-range index panics, crashing the probe task. Nothing in the type system or surrounding code prevents this — the only guard would be that find() returns char boundaries IN `lower`, which do not transfer to `body`. The code is reachable on every successful probe. This is a genuine remotely-triggerable panic._


---

#### [x] #3 · `crates/lancer-cli/src/commands/repeater.rs:49-51` · HIGH · logic-error
**HTTPS repeater connects to port 80 when Host header has no explicit port**

**Problem:** When `--target` is not given, the port is taken from `HttpRequest::parse_wire`. That parser resolves the port from the Host header via `split_host_port(&host, 80)`, which hardcodes a default of 80 when the Host header has no `:port` (see crates/lancer-core/src/http_msg.rs:301 and :422-429). It NEVER returns 0. Therefore the `else if req.meta.port == 0` branch here is effectively dead code, and the scheme-based default (443) is never applied. Result: `lancer repeater --request req.http --scheme https` against a request whose Host header is just `example.com` (no port) sets `req.meta.scheme = "https"` but leaves `req.meta.port = 80`. HttpClient::send (crates/lancer-tools/src/client.rs:40-48) then opens a TCP connection to port 80 and performs a TLS handshake on it, so the request fails (or talks TLS to a cleartext port).

**Evidence:**
````
} else if req.meta.port == 0 {
        req.meta.port = if args.scheme == "https" { 443 } else { 80 };
    }
````

**Fix:** Don't rely on `port == 0`. Detect whether the Host header carried an explicit `:port`; if it did not, derive the port from the scheme. Replace the `else if` branch (and keep the `--target` branch as-is):

```rust
} else {
    // parse_wire defaults a port-less Host header to 80; honor an explicit
    // Host-header port, but otherwise pick the scheme's default port.
    let host_had_explicit_port = req
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("host"))
        .map(|h| {
            // a trailing ":<digits>" means an explicit port (ignore "[::1]" IPv6 w/o port)
            h.value
                .rsplit_once(':')
                .map_or(false, |(_, p)| p.parse::<u16>().is_ok())
        })
        .unwrap_or(false);
    if !host_had_explicit_port {
        req.meta.port = if args.scheme == "https" { 443 } else { 80 };
    }
}
```

This preserves an explicit Host-header port, applies 443 for https / 80 for http when the Host header has no port, and is safe (no behavior change for the `--target` path or for requests whose Host header already includes a port).

_Verified (high): Verified against the actual source. repeater.rs lines 49-51 are exactly as cited: the fallback `else if req.meta.port == 0` sets the scheme-based default port. But HttpRequest::parse_wire (http_msg.rs:301) calls split_host_port(&host, 80), and split_host_port (http_msg.rs:422-429) returns the supplied default (80) when the Host header has no ":port" — it never returns 0. So req.meta.port after parse_wire is always either an explicit Host-header port or 80; the `== 0` branch is dead code and the https→443 default is never applied. Combined with `--scheme` defaulting to "https" (line 19), the common invocation `lancer repeater --request req.http` against a request with `Host: example.com` (no port) yields scheme="https", port=80. HttpClient::send (client.rs:40-51) then TCP-connects to port 80 and, because scheme=="https", runs a TLS handshake on that cleartext port, so the request fails. The defect and its stated consequence are genuine. (Note: when --target is given without a port, that branch at lines 43-45 correctly applies 443/80, so only the no-target path is affected.)_


---

#### [x] #4 · `crates/lancer-cli/src/commands/scan.rs:97-102` · HIGH · logic-error
**`scan active --scheme https` connects to port 80 (port never derived from scheme)**

**Problem:** The Active branch parses the request with `HttpRequest::parse_wire`, which sets `req.meta.port` to 80 whenever the Host header has no explicit port (crates/lancer-core/src/http_msg.rs:301, split_host_port default 80). The code then overrides only `req.meta.scheme = scheme` and never adjusts the port. So `lancer scan active req.http --scheme https` runs active checks over TLS against port 80, causing every probe request to fail to connect (TLS on a port the server serves in cleartext, or the wrong port entirely). Same root cause as the repeater bug, but here there is no port-correction logic at all.

**Evidence:**
````
let mut req = HttpRequest::parse_wire(&raw)?;
            req.meta.scheme = scheme;
            let engine = build_engine(preset, project).await?;
            let issues = engine.run_active(&req).await?;
````

**Fix:** After `req.meta.scheme = scheme;`, derive the port from the scheme when the Host header carried no explicit port. Since parse_wire discards the "had explicit port?" info, only bump when the port is still the http default (80) and the scheme is https, which fixes the broken case without clobbering a deliberately non-standard explicit port:

    req.meta.scheme = scheme;
    if req.meta.scheme == "https" && req.meta.port == 80 {
        req.meta.port = 443;
    }

(For full correctness one could parse the Host header for an explicit port before calling parse_wire and only default-correct when absent; but the conditional above is safe and resolves the reported HTTPS-to-port-80 failure.)

_Verified (high): Verified end-to-end. crates/lancer-cli/src/commands/scan.rs:96-102 is exactly as cited: it parses the wire request, overrides only req.meta.scheme = scheme, never touches req.meta.port. The `scheme` arg defaults to "https" (scan.rs:33-34). HttpRequest::parse_wire (http_msg.rs:301) calls split_host_port(&host, 80), which (http_msg.rs:422-429) returns the default 80 whenever the Host header has no explicit ":port". The shared HttpClient::send (lancer-tools/src/client.rs:40) connects to (req.meta.host, req.meta.port) and (line 45) performs a TLS handshake when req.meta.scheme == "https". So `lancer scan active req.http --scheme https` (or the default) with a Host lacking an explicit port connects TCP to port 80 and attempts a TLS handshake against it — which fails for every active probe (run_active drives this same client across ~30 checks, e.g. active/*.rs client.send(...)). The consequence is real and Rust's types do not prevent it. The code is reachable (it is the Active subcommand handler). Same connect-time port/scheme coupling as the documented repeater bug, but with no port-correction logic here at all._


---

#### [x] #5 · `crates/lancer-gui/web/src/views/Findings.svelte:96-114` · HIGH · api-contract
**New findings are never persisted server-side: GUI sends a non-UUID `id`, backend rejects the whole POST**

**Problem:** saveFinding() builds the entry with `id: "f" + Date.now()` (e.g. "f1718000000000") and POSTs it to /api/v1/findings. The backend's `Incoming` struct types `id` as `Option<uuid::Uuid>` (lancer-api/src/main.rs:1035). serde fails to parse "f1718..." as a UUID, so deserialization of the ENTIRE body fails and the handler returns 400 "bad json" (main.rs:1049-1051) — the finding is never stored. The GUI ignores the fetch result (the call is wrapped in try/catch with an empty catch) and unconditionally prepends the entry to the local `findings` array, so the UI looks successful, but the finding vanishes on the next loadFindings()/reload. Worse, every later action keyed on that id — runTriage (POST /findings/{id}/triage), updateStatus (PUT /findings/{id}) — also requires `id.parse::<uuid::Uuid>()` server-side (main.rs:1170, 1198) and silently no-ops/404s for these GUI-minted ids.

**Evidence:**
````
const entry = {
  id: "f" + Date.now(),
  title: nfTitle, severity: nfSeverity, ...
};
try {
  await fetch("/api/v1/findings", { method:"POST", headers:{"content-type":"application/json"}, body: JSON.stringify(entry) });
} catch {}
findings = [entry, ...findings];
````

**Fix:** In saveFinding() (Findings.svelte): do not mint a client-side id; let the server assign the UUID and adopt it locally. Build the POST body without `id`, then on success read the returned id and use it for the local entry. Replace lines 98-109 with:

  const payload = {
    title: nfTitle, severity: nfSeverity, cvss: nfCvss,
    program: nfProgram, endpoint: nfEndpoint, impact: nfImpact,
    repro: nfRepro, tags: nfTags, status: "draft",
    raw_request: nfRequest, raw_response: nfResponse,
  };
  let entry = { ...payload, created_at: new Date().toISOString() };
  try {
    const r = await fetch("/api/v1/findings", { method:"POST", headers:{"content-type":"application/json"}, body: JSON.stringify(payload) });
    if (r.ok) { const { id } = await r.json(); entry = { ...entry, id }; }
  } catch {}
  if (entry.id) findings = [entry, ...findings];

This makes the local id equal the persisted UUID, so subsequent runTriage (POST /findings/{id}/triage) and updateStatus (PUT /findings/{id}) match server-side. (Backend already defaults absent id to uuid::Uuid::new_v4() at main.rs:1053 and returns { ok, id } at main.rs:1077, so dropping the id field is safe.) Note `created_at` is sent but ignored server-side (the backend always sets chrono::Utc::now() at main.rs:1073) — harmless. Optionally, to avoid showing an unsaved entry when the POST fails, the guard `if (entry.id)` skips the local prepend on failure; if you prefer to keep optimistic UI, drop that guard but be aware that entry will then lack a server id and break triage/PUT just as before.

_Verified (high): Verified against the real code. Findings.svelte:99 mints `id: "f" + Date.now()` and POSTs it (line 107) with an empty catch, then unconditionally prepends to `findings` (line 109). Backend (lancer-api/src/main.rs:1035) types `id: Option<uuid::Uuid>` — when the field is PRESENT with a non-UUID value ("f1718..."), serde fails to deserialize the whole Incoming struct, so the `let Ok(i) = serde_json::from_slice::<Incoming>(body) else { return text(BAD_REQUEST, "bad json") }` (lines 1049-1051) fires and nothing is stored (`#[serde(default)]` only supplies None when the field is ABSENT, not when it is present-but-unparseable). The GUI never checks the response, so the entry appears in the UI but vanishes on the next loadFindings()/reload (line 83 overwrites `findings` from the server). Downstream confirmed: runTriage POSTs /findings/{id}/triage which requires `id_str.parse::<uuid::Uuid>()` (main.rs:1170) and updateStatus PUTs /findings/{id} requiring the same (main.rs:1198) — both fall through / 404 for the GUI-minted ids, so triage silently uses a hardcoded fallback (Findings.svelte:121/123) and status PUT no-ops. The backend already defaults absent ids to uuid::Uuid::new_v4() (line 1053) and returns `{ ok, id }` (line 1077), so the proposed fix is correct and safe. No type system or existing handling prevents the consequence; the code is reachable (saveFinding is the New-finding dialog handler)._


---

#### [x] #6 · `crates/lancer-gui/web/src/views/Intruder.svelte:49-51` · HIGH · correctness
**Auto-§ regex captures the HTTP version into the payload position on the request line**

**Problem:** autoMarkers() wraps each `=value` with §…§ using the character class `[^&\r\n§]+`, which does NOT exclude the space character. On an HTTP request line such as `GET /users?id=1 HTTP/1.1`, the value match therefore runs from after `=` to the end of the line, i.e. `1 HTTP/1.1`, producing `GET /users?id=§1 HTTP/1.1§`. The payload position now spans the parameter value AND ` HTTP/1.1`, so when Intruder substitutes a payload it destroys the HTTP version, sending a malformed request line. This misfires on the tool's own default template (line 15: `GET /users?id=§1§ HTTP/1.1`) after Clear §/Auto §.

**Evidence:**
````
function autoMarkers()  {
    requestTemplate = requestTemplate.replace(/=([^&\r\n§]+)/g, (_,val) => `=§${val.replace(/§/g,"")}§`);
  }
````

**Fix:** Exclude all whitespace from the captured value so the match stops before ` HTTP/1.1` (and at any space/tab). In autoMarkers() change the character class from `[^&\r\n§]+` to `[^&\s§]+`:

  function autoMarkers() {
    requestTemplate = requestTemplate.replace(/=([^&\s§]+)/g, (_, val) => `=§${val.replace(/§/g, "")}§`);
  }

`\s` is a superset of the existing `\r\n` exclusions, so it preserves the current line-boundary behavior while additionally stopping at the space before the HTTP version. Query-string and form-urlencoded values encode literal spaces (as + or %20), so this does not truncate legitimate parameter values.

_Verified (high): Verified the cited code at crates/lancer-gui/web/src/views/Intruder.svelte:49-51. autoMarkers() uses /=([^&\r\n§]+)/g, whose character class excludes &, \r, \n, § but NOT the space character. On the tool's own default template (line 15: `GET /users?id=§1§ HTTP/1.1`), after Clear § (line 48) yields `GET /users?id=1 HTTP/1.1`, then Auto § matches `1 HTTP/1.1` (greedy to end of line) producing `GET /users?id=§1 HTTP/1.1§`. The marked template is sent verbatim as `request: requestTemplate` to the backend (line 276), which substitutes payloads into the §…§ span — so the payload replaces `1 HTTP/1.1`, destroying the HTTP version and producing a malformed request line. Consequence confirmed. Svelte/JS has no type system protection here; the function is reachable via the Auto § button and is the documented workflow._


---

#### [x] #7 · `crates/lancer-gui/web/src/views/JsMining.svelte:17, 24, 30, 143, 237` · HIGH · api-contract
**Frontend uses "source-map" but backend serializes the type as "source_map"**

**Problem:** The JS-mining FindingType enum in lancer-jsmining uses `#[serde(rename_all = "snake_case")]`, so `FindingType::SourceMap` (produced by `analyse()` at lib.rs:161) serializes to the JSON string "source_map" (underscore). This view consistently uses the hyphenated "source-map" everywhere: in the TYPES filter list, the TYPE_COLOR / TYPE_BG lookup maps, the filter-type <option value>, and the guidance switch. With real backend data (f.type === "source_map"): (a) the type filter `<option value="source-map">` can never match, so source-map findings can't be filtered; (b) `TYPE_COLOR[f.type]` and `TYPE_BG[f.type]` return undefined, so the type tag renders with no color/background in both the list and detail header; (c) the detail `{:else if selected.type === "source-map"}` branch never fires, so source maps show no guidance text. The bug is masked by the demo/fallback data (lines 67) which fabricates "source-map", but disappears the moment the live backend supplies findings. The other three types (secret/endpoint/sink) happen to be single words so they match.

**Evidence:**
````
const TYPES = ["secret","endpoint","sink","source-map"];
  const TYPE_COLOR = { ... "source-map": "#7b5ea7", };
  ...
  {:else if selected.type === "source-map"}
````

**Fix:** In crates/lancer-gui/web/src/views/JsMining.svelte, replace the hyphenated "source-map" with the serde snake_case wire value "source_map" at all four code sites: TYPES array (line 17), TYPE_COLOR key (line 24), TYPE_BG key (line 30), and the guidance branch condition (line 237: `{:else if selected.type === "source_map"}`). Additionally update the demo/fallback fixture at line 67 (`type:"source-map"` → `type:"source_map"`) so the demo data stays consistent with the new keys and continues to render colored/filterable/with-guidance. No other files need changes (the backend already emits "source_map").

_Verified (high): Confirmed against the real code. lancer-jsmining/src/lib.rs:13 declares `#[serde(rename_all = "snake_case")]` on FindingType, so FindingType::SourceMap serializes to "source_map" (underscore). JsFinding.kind is renamed to "type" (lib.rs:35), matching the frontend's f.type. lancer-api/src/main.rs:1005 serves Vec<JsFinding> directly via json() with no remapping, so live data has type:"source_map". The Svelte view uses the hyphenated "source-map" at lines 17 (TYPES → filter option line 143), 24 (TYPE_COLOR key), 30 (TYPE_BG key), and 237 (guidance branch). Consequences hold: (a) filter option value "source-map" never equals "source_map"; (b) TYPE_COLOR[f.type]/TYPE_BG[f.type] at lines 169/187 return undefined → no color/bg; (c) the guidance else-if never fires → no guidance text. The bug is masked only by the fallback demo data (lines 67-68) which fabricates "source-map". The other three types are single words and match. Type system does not prevent this — it's a plain string-equality mismatch across the wire contract._


---

#### [x] #8 · `crates/lancer-gui/web/src/views/Payloads.svelte:21-28` · HIGH · api-contract
**Payloads 'Send to Repeater' writes a key/shape Repeater never reads — payload silently dropped**

**Problem:** sendToRepeater stores its raw request under localStorage key 'lancer.send.repeater' with a field named 'raw'. But Repeater.svelte's onMount only reads the key 'repeater_prefill' and only honors a field named 'request' (Repeater.svelte lines 703-714); it never reads 'lancer.send.repeater' nor any 'raw' field. As a result, clicking '→ R' navigates to the Repeater tab but prefills nothing — the chosen payload is lost. (Compare Organizer.svelte, which correctly writes BOTH 'lancer.send.repeater' and 'repeater_prefill' with a 'request' field.)

**Evidence:**
````
function sendToRepeater(p) {
  localStorage.setItem("lancer.send.repeater", JSON.stringify({
    raw: `GET /?q=${encodeURIComponent(p.payload)} HTTP/1.1\r\nHost: target.com\r\n\r\n`,
  }));
  window.dispatchEvent(new CustomEvent("lancer:navigate", { detail: "repeater" }));
}
````

**Fix:** In Payloads.svelte sendToRepeater, write the key/shape Repeater actually consumes (matching the Organizer/Target pattern), keeping the existing write for any future consumer:

function sendToRepeater(p) {
  try {
    const request = `GET /?q=${encodeURIComponent(p.payload)} HTTP/1.1\r\nHost: target.com\r\n\r\n`;
    const payload = { request, raw: request, scheme: "http", host: "target.com", port: 80 };
    localStorage.setItem("lancer.send.repeater", JSON.stringify(payload));
    localStorage.setItem("repeater_prefill", JSON.stringify(payload));
    window.dispatchEvent(new CustomEvent("lancer:navigate", { detail: "repeater" }));
  } catch {}
}

This makes Repeater.svelte's onMount pick up `data.request` (and scheme/host/port), so the chosen payload is actually prefilled. Safe: it only adds the correct key; the extra `raw` field is harmless to other consumers.

_Verified (high): Verified in the actual files. Payloads.svelte lines 21-28 write only localStorage key "lancer.send.repeater" with field `raw`. Repeater.svelte's onMount (lines 702-716) is the sole consumer of repeater prefill and reads ONLY key "repeater_prefill", honoring only `data.request` (with optional scheme/host/port). It never reads "lancer.send.repeater" nor any `raw` field. A grep confirms no other code consumes "lancer.send.repeater". The working sibling views (Organizer line 173-176, Logger 138-139, Proxy 195-196, Target 278-279) all write BOTH keys with a `request` field. Therefore clicking "→ R" in Payloads navigates to Repeater but prefills nothing — the payload is silently dropped. No Rust/type system involvement; this is pure frontend localStorage contract mismatch. Code is reachable (button wired to sendToRepeater)._


---

#### [x] #9 · `crates/lancer-gui/web/src/views/Payloads.svelte:29-34` · HIGH · api-contract
**Payloads 'Use in Intruder' sends {payload} but Intruder onMount only reads {raw/scheme/host/port} — payload silently dropped**

**Problem:** sendToIntruder stores { payload: p.payload } under 'lancer.send.intruder'. Intruder.svelte's onMount (lines 200-209) reads that same key but only consumes p.scheme/p.host/p.port/p.raw and sets requestTemplate from p.raw; it never reads p.payload and never populates the payload list (payloadText). The result: clicking '→ I' navigates to Intruder, sets requestLoaded=true and switches to the positions subtab, but neither the request template nor the payload list contains the selected payload — the payload is silently discarded.

**Evidence:**
````
function sendToIntruder(p) {
  localStorage.setItem("lancer.send.intruder", JSON.stringify({ payload: p.payload }));
  window.dispatchEvent(new CustomEvent("lancer:navigate", { detail: "intruder" }));
}
````

**Fix:** Fix both sides so the chosen payload reaches Intruder. In Payloads.svelte, send a usable request template (with a §marker§ like sendToRepeater does) plus the payload as the payload set:

  function sendToIntruder(p) {
    try {
      localStorage.setItem("lancer.send.intruder", JSON.stringify({
        raw: `GET /?q=§${p.payload}§ HTTP/1.1\r\nHost: target.com\r\n\r\n`,
        payloadText: p.payload,
      }));
      window.dispatchEvent(new CustomEvent("lancer:navigate", { detail: "intruder" }));
    } catch {}
  }

In Intruder.svelte onMount, honor an incoming payload list (gated on presence so existing flows are unaffected):

  if (p.scheme) scheme=p.scheme; if (p.host) host=p.host;
  if (p.port) port=String(p.port); if (p.raw) { requestTemplate=p.raw; originalTemplate=p.raw; }
  if (p.payloadText != null) payloadText = p.payloadText;
  requestLoaded=true; localStorage.removeItem("lancer.send.intruder"); subtab="positions";

Notes: variable is `payloadText` (not `payloadList`, which is the derived $: split). The `if (p.payloadText != null)` guard keeps any other producer of this key unaffected, and the loadAttackFile path (line 175) uses a different shape and is untouched.

_Verified (high): Verified against the real code. Payloads.svelte:29-34 stores only { payload: p.payload } under "lancer.send.intruder". Intruder.svelte's onMount (lines 200-209) reads that exact key but consumes only p.scheme/p.host/p.port/p.raw; it never reads p.payload and never sets the payload list (variable is `payloadText`, line 56). Since none of scheme/host/port/raw are present, the only effects are requestLoaded=true, key removal, and subtab="positions". The selected payload is silently dropped: requestTemplate keeps its hardcoded default (`GET /users?id=§1§ ...`, line 15) and payloadText keeps its default list. Contrast sendToRepeater (lines 21-27), which correctly builds a `raw` template. No Rust types are involved (pure JS), the code is reachable (wired to the "→ I" button at line 63), and the only other p.payload-shaped read (line 175) is in the unrelated loadAttackFile upload path with a different data shape. Consequence as stated holds._


---

#### [x] #10 · `crates/lancer-gui/web/src/views/Proxy.svelte:13-24` · HIGH · api-contract
**Intercept "Action → Send to Repeater" is a no-op (writes a key Repeater never reads, and not repeater_prefill)**

**Problem:** actionSend("repeater") stores the paused request only under `lancer.send.repeater` (JSON `{ raw }`) and dispatches navigate to the repeater tab. Repeater.svelte never reads `lancer.send.repeater` — its onMount only consults `repeater_prefill` (Repeater.svelte:703). It also does not set `repeater_prefill`. As a result, sending an intercepted/paused request to Repeater from the intercept Action menu does nothing: the Repeater tab opens unchanged. (Note actionSend("intruder") happens to work only because Intruder.svelte:202-206 does read `lancer.send.intruder` and uses the `raw` key.)

**Evidence:**
````
function actionSend(tab) {
    const raw = pausedWire();
    if (tab === "comparer") { ... }
    else {
      localStorage.setItem(`lancer.send.${tab}`, JSON.stringify({ raw }));
    }
    window.dispatchEvent(new CustomEvent("lancer:navigate", { detail: tab }));
````

**Fix:** In Proxy.svelte's `actionSend(tab)`, special-case the repeater target so it writes the key/field Repeater's onMount actually consumes. Replace the function body's else-branch with a repeater-specific branch:

  function actionSend(tab) {
    const raw = pausedWire();
    if (tab === "comparer") {
      const existing = JSON.parse(localStorage.getItem("lancer.send.comparer") || "{}");
      if (!existing.item1) existing.item1 = raw; else existing.item2 = raw;
      localStorage.setItem("lancer.send.comparer", JSON.stringify(existing));
    } else if (tab === "repeater") {
      const host = selectedPaused?.request?.meta?.host;
      const payload = { request: raw, raw, host };
      localStorage.setItem("repeater_prefill", JSON.stringify(payload));
      localStorage.setItem("lancer.send.repeater", JSON.stringify(payload)); // keep for consistency
    } else {
      localStorage.setItem(`lancer.send.${tab}`, JSON.stringify({ raw }));
    }
    window.dispatchEvent(new CustomEvent("lancer:navigate", { detail: tab }));
    actionMenuOpen = false;
  }

This sets `repeater_prefill.request = raw`, which Repeater.onMount (line 707) reads and applies to `tabStates[activeTab].request`. The `intruder` path is unchanged (still uses `lancer.send.intruder` with `raw`, which Intruder reads). Including `host` is safe because onMount only applies it when truthy.

_Verified (high): Confirmed against the real code. Proxy.svelte actionSend (lines 13-24) writes ONLY `lancer.send.${tab}` as `{ raw }` and dispatches a navigate event. Repeater.svelte's onMount (line 702-720) reads ONLY `localStorage.getItem("repeater_prefill")` and prefills from `data.request` — it never reads `lancer.send.repeater` and never reads a `raw` field. A workspace grep confirms `repeater_prefill` is the consumed key and `data.request` the consumed field; every working sender (Organizer line 176, Logger line 176, Target, Proxy's own ctxSendToRepeater) writes `repeater_prefill` with a `request` field. So actionSend("repeater") is a no-op: the Repeater tab opens unchanged. The reported note that actionSend("intruder") works is also correct — Intruder.svelte line 202-207 reads `lancer.send.intruder` and uses `raw`. Nothing in the type system or other listeners prevents the consequence (Svelte/JS, no compile-time guard). The proposed fix writes the correct key (`repeater_prefill`) with the correct field (`request`), and the host accessor `selectedPaused?.request?.meta?.host` matches existing usage at Proxy.svelte line 684; host is optional in onMount so undefined is safe._


---

#### [x] #11 · `crates/lancer-gui/web/src/views/Proxy.svelte:181-196` · HIGH · api-contract
**"Send to Repeater" from HTTP history never transfers the request (wrong localStorage key)**

**Problem:** ctxSendToRepeater writes the prefill object produced by payloadFromRow() into localStorage under "repeater_prefill". payloadFromRow() emits the request wire under the key `raw` ({method,scheme,host,port,path,raw}). But Repeater.svelte's onMount reads `repeater_prefill` and applies `data.request` (Repeater.svelte:707-712: `if (data.request) { tabStates[...].request = data.request; ... }`) and never looks at `data.raw`. Because there is no `request` key, the whole `if (data.request)` block is skipped: scheme/host/port are also inside that block, so NOTHING is applied — the Repeater tab opens with its blank default template. The history request the user picked is silently lost. (Organizer.svelte:176 documents the correct shape and writes `{ request: raw, ... }`; Proxy is the broken outlier.)

**Evidence:**
````
function payloadFromRow(row) {
    return { method: row.method || "GET", scheme: row.scheme || "http", host: row.host || "", port: row.port || (...), path: row.path || "/", raw: formatRequest(row) };
  }
  function ctxSendToRepeater() {
    ...
    const payload = payloadFromRow(ctxMenu.row);
    localStorage.setItem("repeater_prefill", JSON.stringify(payload));
````

**Fix:** In crates/lancer-gui/web/src/views/Proxy.svelte, ctxSendToRepeater() must store the wire under the key Repeater actually reads (`request`), not `raw`. Replace the repeater_prefill write (line 195) so the object matches Repeater's onMount contract:

  function ctxSendToRepeater() {
    if (!ctxMenu) return;
    const row = ctxMenu.row;
    localStorage.setItem("repeater_prefill", JSON.stringify({
      request: formatRequest(row),
      scheme: row.scheme || "http",
      host: row.host || "",
      port: row.port || (row.scheme === "https" ? 443 : 80),
    }));
    window.dispatchEvent(new CustomEvent("lancer:navigate", { detail: "repeater" }));
    closeCtxMenu();
  }

(The existing `lancer.send.repeater` write at line 196 can be dropped since Repeater never reads it; leaving it is harmless but dead.) This mirrors Organizer.svelte:176 exactly and is safe — payloadFromRow() with its `raw` key is still used unchanged by ctxSendToIntruder (Intruder reads `raw`), so other consumers are unaffected. Optionally, as defense-in-depth, also harden Repeater.svelte:707 to `const req = data.request || data.raw; if (req) { tabStates[activeTab].request = req; ... }` so the other broken producers (Target.svelte, Logger.svelte, Findings/JsMining/IdMutator which write `{raw}`) also work.

_Verified (high): Verified against actual code. Proxy.svelte:181-196: payloadFromRow() emits the request wire under key `raw` and ctxSendToRepeater() stores that object under localStorage "repeater_prefill". Repeater.svelte:702-716 onMount reads only "repeater_prefill", parses it, and gates the entire apply on `if (data.request)` (line 707), then applies data.request/scheme/host/port. Because the stored object has no `request` key, the whole block is skipped and the Repeater tab keeps its blank default — the picked history request is silently lost. The second write at Proxy:196 ("lancer.send.repeater") is dead: a Grep of Repeater.svelte shows it never reads that key (only repeater_prefill at line 703 and unrelated lancer.ai.* keys), so it does not rescue the flow. formatRequest exists (Proxy:100) so `raw` is genuinely populated — the sole defect is the key-name mismatch. Organizer.svelte:176 confirms the correct shape `{ request: raw, scheme, host, port }`. JS/no type system to prevent this. Note: Target.svelte:278 and Logger.svelte:138 share the identical bug but are out of scope for this finding._


---

#### [x] #12 · `crates/lancer-gui/web/src/views/Repeater.svelte:187` · HIGH · parsing
**Malformed percent-escape in request URL throws URIError in reactive parser, breaking the Inspector**

**Problem:** parseInspector() runs reactively on every keystroke in the request editor ($: inspectorData = parseInspector(state?.request || ""), line 161). For each query-string pair it calls decodeURIComponent(k) / decodeURIComponent(v) with no try/catch. decodeURIComponent throws a URIError on any malformed percent sequence (e.g. a lone '%' or '%zz'). As soon as a user types '%' into the request line's query string, the reactive statement throws, the assignment to inspectorData fails, and the whole Inspector / derived rendering for that tab breaks until the text is fixed. Same unguarded calls exist at line 216 (body params) and line 629 (ctxChangeBodyEncoding fallback).

**Evidence:**
````
if (k) queryParams.push({ name: decodeURIComponent(k || ""), value: decodeURIComponent(v || "") });
````

**Fix:** Add a safe decode helper at the top of the <script> (module-level inside the component) and use it at all three sites:

  const safeDecode = (s) => { try { return decodeURIComponent(s); } catch { return s; } };

Then replace:
- line 187: if (k) queryParams.push({ name: safeDecode(k || ""), value: safeDecode(v || "") });
- line 216: if (k) bodyParams.push({ name: safeDecode(k || ""), value: safeDecode(v || "") });
- line 629: if (k) params.push({ name: safeDecode(k), value: safeDecode(v || "") });

This makes a malformed percent-escape fall back to the raw string instead of throwing, keeping the reactive parseInspector() (line 161) total so the Inspector keeps rendering while the user is mid-edit.

_Verified (high): Verified against the actual file. Lines 187 and 216 call decodeURIComponent(k)/decodeURIComponent(v) with no try/catch, inside parseInspector(), which is invoked by the reactive statement at line 161 ($: inspectorData = parseInspector(state?.request || "")). decodeURIComponent throws URIError on a malformed percent sequence (lone '%' or '%zz') — a single '%' typed into the request line's query string after a '?' is enough (line 183-188 enters the query-parsing branch). A throw inside a Svelte reactive assignment aborts the assignment, leaving inspectorData stale and propagating the error, which breaks the entire Inspector panel that renders from inspectorData (lines 1095-1200) until the text is corrected. Nothing in the surrounding code guards these calls (the JSON.parse paths have try/catch, but the urlencoded decode paths do not). Line 629 is the same unguarded pattern but in an event handler (ctxChangeBodyEncoding), so it throws only on user action rather than every keystroke — still a genuine defect. Nothing prevents the consequence; the code is live and reachable. The proposed dec() helper is correct and safe: returning the raw string on malformed input is appropriate for a lenient editor-side parser and does not change happy-path behavior._


---

#### [x] #13 · `crates/lancer-gui/web/src/views/Scanner.svelte:91-99` · HIGH · api-contract
**"Active only" scan sends wrong request body — backend always rejects it with 400**

**Problem:** startScan() builds the body as JSON.stringify({ url }) for every scan type, including the active path. But the backend's POST /v1/scan/active handler (scan_active in lancer-api/src/main.rs:2240-2244) deserializes `struct R { request: String, scheme: Option<String> }` and parses `r.request` as a raw HTTP wire request — it does NOT accept a `url` field. Sending `{ "url": "..." }` makes serde fail on the missing required `request` field, so the endpoint returns `400 "bad json"`. The frontend then calls `await r.json()` on the plain-text "bad json" body, which throws, lands in the catch block, and pushes a queue entry with status "error". Result: the GUI's "Active only" scan never works. (Full and Passive both POST `{ url }` and match their handlers, so only the active path is broken.)

**Evidence:**
````
const endpoint = scanType === "full" ? "full" : scanType === "passive" ? "passive" : "active";
...
body: JSON.stringify({ url }),
...
const data = await r.json();
````

**Fix:** In Scanner.svelte startScan(), send the body the active endpoint expects (a raw wire request + scheme) when scanType==="active", and keep { url } for full/passive. Replace the single body with a branch:

```js
async function startScan() {
  scanning = true;
  const endpoint = scanType === "full" ? "full" : scanType === "passive" ? "passive" : "active";
  try {
    let body;
    if (endpoint === "active") {
      const u = new URL(url);
      const path = (u.pathname || "/") + (u.search || "");
      const wire = `GET ${path} HTTP/1.1\r\nHost: ${u.host}\r\n\r\n`;
      const scheme = u.protocol.replace(":", "");
      body = JSON.stringify({ request: wire, scheme });
    } else {
      body = JSON.stringify({ url });
    }
    const r = await fetch(`/api/v1/scan/${endpoint}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
    });
    const data = await r.json();
    queue = [
      { id: queue.length + 1, url, type: endpoint, status: "running",
        issues: Array.isArray(data) ? data : (data.issues || data || []),
        started: new Date().toLocaleTimeString() },
      ...queue,
    ];
  } catch {
    queue = [
      { id: queue.length + 1, url, type: endpoint, status: "error", issues: [], started: new Date().toLocaleTimeString() },
      ...queue,
    ];
  } finally {
    scanning = false;
    setTimeout(() => { queue = queue.map((q, i) => i === 0 ? { ...q, status: "done" } : q); }, 2000);
  }
}
```

This matches scan_active's R { request, scheme } and uses Host derived from the URL so parse_wire builds a valid request and meta.scheme is set correctly. It does not change the full/passive behavior, which already works. After editing, run `npm run build` to verify the Svelte compiles. (Alternative backend-side fix — adding a URL-accepting active handler — is also valid but is a larger change; the frontend fix is minimal and safe.)

_Verified (high): Verified both sides of the contract. Frontend Scanner.svelte:91-99 builds the body as JSON.stringify({ url }) for all three scan types; line 93 routes scanType==="active" to /api/v1/scan/active. Backend routing (main.rs:484) sends that to scan_active (main.rs:2240), which deserializes `struct R { request: String, scheme: Option<String> }`. Since `request` is a required (non-Option) field, serde_json::from_slice on { "url": "..." } fails → returns 400 "bad json" (line 2243). The frontend then runs `await r.json()` (line 100) on the plain-text body "bad json", which throws on invalid JSON, landing in the catch block (line 110) that pushes a status:"error" queue entry. There is an actual reachable "active" button (lines 176-177) that sets scanType="active". Full and passive both correctly POST { url } matching their { url } handlers (scan_full 2255, scan_passive 2230). The active path is genuinely broken. Rust's type system does not save it — the missing required field is exactly what breaks deserialization. The code is reachable, not dead._


---

#### [x] #14 · `crates/lancer-gui/web/src/views/Target.svelte:1054-1060` · HIGH · api-contract
**Response 'Render' tab reads selectedEntry.body/response_body, which don't exist; iframe is always blank**

**Problem:** The response body in the /v1/history JSON lives at `selectedEntry.response.body` (a byte array, serialized via bytes_serde on HttpResponse.body). There is no top-level `body` or `response_body` field on the record. The Render tab feeds `bytesToText(selectedEntry.body || selectedEntry.response_body)` to the iframe srcdoc, both undefined, so bytesToText returns "" and the rendered-response view is permanently empty regardless of the captured HTML.

**Evidence:**
````
srcdoc={bytesToText(selectedEntry.body || selectedEntry.response_body) || ""}
````

**Fix:** Replace line 1059 with the nested field and optional chaining:

  srcdoc={bytesToText(selectedEntry.response?.body) || ""}

bytesToText already handles the byte-array (Array.isArray → TextDecoder) and null/undefined cases, so this is safe. (Note: the same `e.body || e.response_body` mistake appears at lines 133, 139, 307, 462, 470, and in formatResponse at 535 — they should likewise read `e.response?.body`, since formatResponse currently also produces an empty body for history records.)

_Verified (high): Confirmed by reading the real code. Target.svelte line 1059 sets the Render-tab iframe srcdoc to `bytesToText(selectedEntry.body || selectedEntry.response_body)`. `selectedEntry` is a raw `/v1/history` record assigned without transformation (line 643 `history = Array.isArray(d) ? d : (d.entries||d.history||[])`; line 251 `selectedEntry = e`). The serialized record is `HistoryRecord` (crates/lancer-storage/src/history.rs:10-29): it has top-level `status`, `mime`, `response_length` but the body lives only at the nested `response: Option<HttpResponse>` whose `body` field (crates/lancer-core/src/http_msg.rs:321-322) serializes via `bytes_serde` as a JSON number array. There is NO top-level `body` or `response_body` field. So both operands are `undefined`, and `bytesToText` returns "" for null/undefined (line 146), leaving the iframe permanently blank regardless of captured HTML. The consequence as stated is accurate. Notably the file already correctly reads nested data elsewhere (e.g. line 124/131 use `e.response?.headers`), confirming the right path is `response.*`. The same broken `e.body || e.response_body` pattern recurs across the file (lines 133,139,307,462,470,535) so it is systemic, but the cited Render-tab consequence is genuinely caused by it._


---

#### [x] #15 · `crates/lancer-gui/web/src/views/Target.svelte:68, 94, 1010` · HIGH · api-contract
**Notes column and annotation filter read e.notes, but the record field is `comment`**

**Problem:** HistoryRecord exposes the analyst annotation as `comment` (HistoryRecord.comment / MessageMeta.comment); there is no `notes` field on the JSON returned by /v1/history. The Notes table column (line 1010 `{e.notes || ""}`) is therefore always blank, sorting by Notes (line 94) always returns empty, and most importantly the annotation/note filter (line 68 `out = out.filter(r => (r.notes || "").toLowerCase().includes(nf))`) filters on an always-undefined field, so typing any text in the 'Filter by annotation/note' box removes every row even when matching comments exist.

**Evidence:**
````
out = out.filter(r => (r.notes || "").toLowerCase().includes(nf));
...
case "notes":  return e.notes || "";
...
<td class="cell-notes dim">{e.notes || ""}</td>
````

**Fix:** Reference the actual backend field `comment` in all three places: line 68 `out = out.filter(r => (r.comment || "").toLowerCase().includes(nf));`, line 94 `case "notes":  return e.comment || "";`, line 1010 `<td class="cell-notes dim">{e.comment || ""}</td>`. A defensive variant tolerant of a future rename is `(e.comment || e.notes || "")` in each spot, but `comment` alone is correct and matches the serialized JSON.

_Verified (high): Verified all three cited lines exist exactly as described in Target.svelte (line 68 filter `r.notes`, line 94 sort `e.notes`, line 1010 column `{e.notes}`). The backend `HistoryRecord` (crates/lancer-storage/src/history.rs:24) exposes the annotation as `comment: Option<String>` with default serde (no rename), so the JSON key from `/v1/history` is `comment`, not `notes`. history_list (lancer-api/src/main.rs:2204) serializes the records directly via `json(&rows)`, and fetchHistory (Target.svelte:640-643) stores them raw with no field remapping. There is no `notes` field/alias anywhere in core, storage, or the API. Consequence is exactly as stated: the Notes column always renders blank, sorting by Notes always yields empty strings, and the annotation/note filter (line 68) filters on an always-undefined field, so typing any text removes every row even when matching comments exist. Nothing in JS prevents this (undefined `|| ""` silently yields empty), and the code is reachable (noteF bound to the filter input, "notes" is a real sort key and table column)._


---

#### [x] #16 · `crates/lancer-gui/web/src/views/Target.svelte:93, 1009` · HIGH · api-contract
**Time column and time-sort read a non-existent field (e.ts/e.timestamp) instead of e.captured_at**

**Problem:** The /v1/history endpoint serializes lancer-storage HistoryRecord directly (lancer-api history_list -> json(&rows)). The timestamp field on each record is captured_at (DateTime serialized as an ISO string), and there is no `ts` or `timestamp` field anywhere on the record or its MessageMeta. The site-map table's Time column (line 1009 `fmtTime(e.ts || e.timestamp)`) therefore always renders empty, and sorting by the Time column (line 93 `case "time": return e.ts || e.timestamp || 0;`) always returns 0 for every row, so the default `sortKey="time"` ordering is a no-op (rows keep arbitrary order rather than newest-first).

**Evidence:**
````
case "time":   return e.ts || e.timestamp || 0;
...
<td class="cell-time dim">{fmtTime(e.ts || e.timestamp)}</td>
````

**Fix:** In crates/lancer-gui/web/src/views/Target.svelte: line 93 change to `case "time": return e.captured_at || 0;` and line 1009 change to `<td class="cell-time dim">{fmtTime(e.captured_at)}</td>`. fmtTime already handles the ISO-string input via `new Date(t)`, and lexicographic ordering of the ISO-8601 UTC strings sorts chronologically.

_Verified (high): Verified against real code. crates/lancer-storage/src/history.rs line 13: HistoryRecord has `pub captured_at: DateTime<Utc>` and derives Serialize with NO serde rename, so the JSON field name is `captured_at` (an ISO-8601 string). There is no `ts` or `timestamp` field anywhere on the record. lancer-api/src/main.rs history_list (line 2199-2204) serializes the records directly via `json(&rows)`, and Target.svelte loads them at line 640-643 (`fetch("/api/v1/history")`). Both cited lines exist exactly as reported: line 93 `case "time": return e.ts || e.timestamp || 0;` and line 1009 `{fmtTime(e.ts || e.timestamp)}`. Both `e.ts` and `e.timestamp` are undefined on every row, so: (1) the Time column always renders empty (fmtTime(undefined) returns "" since `if(!t) return ""`), and (2) time-sort returns 0 for every row, making `va===vb` always true so the comparator is a no-op. Default sortKey is "time" (line 40). The DB query does ORDER BY captured_at DESC so rows still arrive newest-first, but the user cannot actually re-sort by time and the Time column is blank. The proposed fix is correct and safe: e.captured_at is the real field; fmtTime handles ISO strings via new Date(t); lexicographic comparison of same-format ISO-8601 UTC strings is chronologically correct._


---

#### [x] #17 · `crates/lancer-llm-scan/src/lib.rs:351` · HIGH · resource-leak
**concurrency == 0 makes run_scan hang forever (buffer_unordered(0) never makes progress)**

**Problem:** `concurrency` comes straight from the deserialized ScanRequest. The serde default (`default_concurrency` = 4) only applies when the field is ABSENT from the JSON body. A client that POSTs `{"concurrency": 0, ...}` to /v1/llm-scan/run (req: LlmScanRequest = serde_json::from_slice(&body), lancer-api/src/main.rs:1439), or runs the CLI with `--concurrency 0` (clap accepts 0 for usize, lancer-cli/src/commands/llm_scan.rs:64/95), passes 0 straight into `.buffer_unordered(concurrency)`. With max == 0, futures-util 0.3.32 BufferUnordered::poll_next never spawns any future (the `while in_progress_queue.len() < max` loop with max=0 never executes) and therefore never polls the underlying probe stream, so `stream.is_done()` stays false and poll_next returns Poll::Pending with no waker registered. The `.collect().await` future deadlocks: run_scan never returns, no probes run, and the awaiting task (an API request handler or CLI invocation) hangs indefinitely.

**Evidence:**
````
.buffer_unordered(concurrency)
        .collect()
        .await
````

**Fix:** In crates/lancer-llm-scan/src/lib.rs, change line 324 from `let concurrency = req.concurrency;` to `let concurrency = req.concurrency.max(1);`. This is the single choke point used by both the API and CLI call sites, so the one-line clamp fixes both. It preserves the serde/clap default of 4 when the field is present-and-positive or absent, and only coerces the degenerate 0 to a working minimum of 1. Optionally, for stronger UX, also reject 0 at the input boundaries (clap `value_parser` range and an API 400), but the run_scan clamp is sufficient and safe.

_Verified (high): Verified against the real code. crates/lancer-llm-scan/src/lib.rs:324 reads `let concurrency = req.concurrency;` and line 351 calls `.buffer_unordered(concurrency)`. The `concurrency: usize` field (lib.rs:45-46) uses `#[serde(default = "default_concurrency")]` which returns 4 — but serde defaults only apply when the field is ABSENT, so a body of `{"concurrency": 0, ...}` deserializes to 0. The API handler (lancer-api/src/main.rs:1439) does `serde_json::from_slice(&body)` with no clamping and passes req straight to run_scan. The CLI (lancer-cli/src/commands/llm_scan.rs:63-64, 95) uses clap `#[arg(long, default_value_t = 4)] concurrency: usize` with no range validation, so `--concurrency 0` passes through. Cargo.lock confirms futures-util 0.3.32. In that version, BufferUnordered::poll_next fills its internal FuturesUnordered up to `max` (a no-op when max=0) then polls the empty, non-terminated queue, returning Poll::Pending without registering a waker and without ever draining the source stream — a permanent hang (the well-known buffer_unordered(0) deadlock). Consequence holds: for the CLI the awaiting invocation hangs indefinitely; for the API the work is tokio::spawn'd (main.rs:1443) so the HTTP handler returns, but the spawned task never completes — a leaked task that hangs forever (matches the resource-leak category). The repo already uses the defensive pattern elsewhere (main.rs:2568: `.filter(|&c| c > 0).unwrap_or(10)`), confirming the maintainer's intent. No type-system guard prevents 0 for usize, and the code is reachable/live._


---

#### [x] #18 · `crates/lancer-mcp-scan/src/lib.rs:199-214` · HIGH · api-contract
**SSE transport calls plain HTTP JSON-RPC and parses response as JSON, silently returning no tools for real SSE servers**

**Problem:** enumerate_tools (and enumerate_resources) route Transport::Sse into http_rpc, which does client.post(server).json(&body).send() then resp.json().await. A real MCP SSE endpoint replies with a text/event-stream (lines prefixed `event:`/`data:`), not a single JSON object. resp.json() will fail to parse the event-stream body and return None, so enumerate_tools returns an empty Vec. The scanner therefore reports zero tools and zero findings for any genuine SSE server while appearing to succeed (no error surfaced), producing a false-clean scan result.

**Evidence:**
````
Transport::Http | Transport::Sse => http_rpc(&req.server, "tools/list", serde_json::json!({})).await,
...
    let resp = client.post(server).json(&body).send().await.ok()?;
    let v: serde_json::Value = resp.json().await.ok()?;
````

**Fix:** Do not lump Sse into the plain-JSON http_rpc. Make http_rpc tolerant of an event-stream response body, or give Sse its own path. Minimal, safe change to http_rpc:

async fn http_rpc(server: &str, method: &str, params: serde_json::Value) -> Option<serde_json::Value> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .danger_accept_invalid_certs(true)
        .build()
        .ok()?;
    let body = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let resp = client
        .post(server)
        .header(reqwest::header::ACCEPT, "application/json, text/event-stream")
        .json(&body)
        .send()
        .await
        .ok()?;
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let text = resp.text().await.ok()?;
    let v: serde_json::Value = if ct.contains("text/event-stream") || text.trim_start().starts_with("event:") {
        // Parse SSE: find the last `data:` line that is valid JSON-RPC.
        text.lines()
            .filter_map(|l| l.strip_prefix("data:").map(str::trim))
            .filter_map(|d| serde_json::from_str::<serde_json::Value>(d).ok())
            .last()?
    } else {
        serde_json::from_str(&text).ok()?
    };
    v.get("result").cloned()
}

This preserves the existing plain-JSON Http path unchanged while also handling a streamed event-stream POST response. Note a fully spec-correct legacy-SSE handshake (GET endpoint event + POST to that endpoint, result delivered over the GET stream) is more involved; if that level of coverage is out of scope, the honest alternative is to make Sse return None (like WebSocket) so callers do not assume coverage. Either way, the silent Http/Sse conflation must be removed.

_Verified (medium): Verified against the real file (crates/lancer-mcp-scan/src/lib.rs). The cited code is present exactly: enumerate_tools (line 201) and enumerate_resources (line 218) both route Transport::Sse into http_rpc, which at line 188-189 does client.post(server).json(&body).send() then resp.json().await.ok()?. If the body is a text/event-stream (lines prefixed event:/data:), serde_json parsing of the whole body fails, .ok()? yields None, raw is None, and both functions return an empty Vec. scan() (lines 233-249) derives findings exclusively from the enumerated tools/resources, so empty tools => zero findings => a false-clean result with no error surfaced. The MCP SSE/streamable-HTTP transports legitimately return event-stream bodies (or even a 202 with the result delivered out-of-band over the GET stream), so a genuine SSE server will not return a single parseable JSON object here. The type system does not save this — resp.json::<Value>() simply errors and is swallowed by .ok(). The code is reachable (Transport::Sse is a public enum variant set via ScanRequest from the API/CLI/GUI). The consequence — silent zero-tool/zero-finding scan — is real. Confidence is medium rather than high only because some HTTP MCP endpoints DO answer a POST with a plain JSON body (in which case the path works), so the impact is specific to true event-stream responses; but for those the bug holds._


---

#### [x] #19 · `crates/lancer-proxy/src/listener.rs:433-440, 464-477, 516` · HIGH · logic-error
**Outbound TLS advertises ALPN h2 but the origin connection always uses an HTTP/1-only handshake**

**Problem:** build_default_client_config sets alpn_protocols = ["h2", "http/1.1"], so during the outbound TLS handshake to the origin (dispatch, scheme=="https") the server may negotiate ALPN "h2". However send_via_hyper unconditionally performs hyper::client::conn::http1::handshake on the resulting stream and sends HTTP/1.1 framing. When an origin selects h2 (many modern servers prefer it, and some are h2-only), the proxy writes HTTP/1.1 bytes onto an HTTP/2-negotiated TLS connection. The origin rejects/garbles it, so dispatch returns an error and the client gets no/failed response for those hosts. The advertised protocol set and the actual client implementation are inconsistent.

**Evidence:**
````
cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
...
let resp = if ctx.scheme == "https" {
    let tls = connector.connect(dns, stream).await?;
    send_via_hyper(&processed, TokioIo::new(tls)).await?
} else { ... };
...
let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
````

**Fix:** In crates/lancer-proxy/src/listener.rs, build_default_client_config() (line 516), restrict the outbound client ALPN to HTTP/1.1 only so the origin can never negotiate h2 against the http1-only sender:

    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];

This matches the unconditional hyper::client::conn::http1::handshake in send_via_hyper. (A larger, optional alternative is to read tls.get_ref().1.alpn_protocol() after connector.connect at line 436 and dispatch via hyper::client::conn::http2 when it returns Some(b"h2"); but the one-line ALPN restriction is the minimal correct fix.)

_Verified (high): Verified against the real code. build_default_client_config() (line 507-518) sets cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()] at line 516. This config is created once in ProxyListener construction (line 80), stored, and threaded unchanged into dispatch (line 434), where TlsConnector::from(tls_client_config) connects to the https origin and passes the resulting tokio_rustls TLS stream to send_via_hyper. send_via_hyper (line 464-477) unconditionally calls hyper::client::conn::http1::handshake and sends HTTP/1.1 framing — there is no branch on the negotiated ALPN, and this is the sole outbound sender for both MITM and forward-proxy paths. The config is never overridden elsewhere. Therefore, when an origin selects h2 during the handshake (common for modern/h2-only servers), the proxy writes HTTP/1.1 bytes onto an h2-negotiated TLS connection, the origin garbles/rejects it, and dispatch returns an error — the client gets a failed response for those hosts. Rust's type system does not prevent this: both h2 and http/1.1 TLS streams have the identical AsyncRead+AsyncWrite type, so the mismatch is a runtime protocol error, not a compile error. The code is reachable and live. The proposed fix (drop h2 from the ALPN list) is correct and safe: it forces the origin to negotiate http/1.1 or no-ALPN, both of which the http1 sender handles; the only consequence is no HTTP/2 to origins, which already never worked. tokio_rustls also exposes the negotiated ALPN via tls.get_ref().1.alpn_protocol() if a full h2-capable sender is later desired, but that is a larger change._


---

#### [x] #20 · `crates/lancer-replay/src/id_mutate.rs:93` · HIGH · logic-error
**URL ID mutation does a raw substring replace over the entire URL, can corrupt host/scheme instead of the ID**

**Problem:** For a URL-located candidate, the mutation is applied with `base.url().replacen(&c.value, mutated, 1)` — an unanchored substring replace over the whole reconstructed URL. Integer candidates can be as short as one digit (the detector uses `\b\d{1,12}\b`), so the first textual occurrence of that digit string anywhere in the URL is replaced, including inside the scheme, host, or port. Example: for `https://api2.example.com/users/5` with candidate `2`, `replacen("2", mutated, 1)` rewrites `api2` → e.g. `api3`, producing a request to a different (likely non-existent) host while leaving the real `/users/5` ID untouched. The IDOR fuzzer then silently tests the wrong thing (errors/connection failures) instead of mutating the resource ID, yielding false negatives.

**Evidence:**
````
let new_url = base.url().replacen(&c.value, mutated, 1);
````

**Fix:** In mutate_request (crates/lancer-replay/src/id_mutate.rs), for the "url" branch, mutate only the path/query and never rebuild from the whole URL:

```rust
if c.location == "url" {
    let mut req = base.clone();
    req.path = base.path.replacen(&c.value, mutated, 1);
    return req;
}
```

This preserves scheme/host/port (carried in req.meta) so they can never be rewritten, and avoids the unnecessary builder re-parse. Best practice (eliminates even intra-path mis-targeting): have detect() record each match's byte offset and its segment (host vs path/query) via find_iter's m.start(), skip host-located integer candidates, and splice the mutation at the exact offset in base.path instead of using an unanchored replacen.

_Verified (high): Verified against crates/lancer-replay/src/id_mutate.rs line 93. mutate_request() for a "url" candidate does `base.url().replacen(&c.value, mutated, 1)` over the FULL reconstructed URL. lancer-core HttpRequest::url() (http_msg.rs:232) returns `scheme://host[:port]path`, so the host precedes the path. detect() (line 41) runs int_re = `\b\d{1,12}\b` over that same full URL, so integer candidates can be a single digit. Because replacen replaces the FIRST occurrence and the host comes first, a digit present in the host/port (e.g. `api2`, port `8080`) is rewritten before the real path ID. The report's example (https://api2.example.com/users/5, candidate "2" → api2→api3) is exact: the request goes to a wrong/nonexistent host while /users/5 is unchanged, so the IDOR fuzzer tests the wrong thing and yields false negatives. The type system does not prevent this; the code is reachable (called from the public fuzz_ids → CLI/API /replay/idfuzz). Real high-severity logic error. The proposed minimal fix (operate on base.path, clone the request to preserve scheme/host/port) correctly eliminates host/scheme corruption and is safe; a residual minor mis-target can still occur within the path/query, fully solved only by offset-based splicing._


---

#### [x] #21 · `crates/lancer-scanner/src/active/upload.rs:22` · HIGH · correctness
**PHP_MARKER_HASH is md5 of the empty string, so server-side-execution detection can never fire**

**Problem:** PHP_MARKER injects `<?php echo 'LANCER_UP_'.md5('lancer'); ?>`. If the server actually executes this, the reflected output is `LANCER_UP_b81a9dfa2a3ea350de88cac98594e40d` (md5('lancer') = b81a9dfa2a3ea350de88cac98594e40d). But PHP_MARKER_HASH is hard-coded to `LANCER_UP_d41d8cd98f00b204e9800998ecf8427e`, and d41d8cd98f00b204e9800998ecf8427e is the md5 of the EMPTY string, not of 'lancer'. The detection at line 235 (`body_text.contains(PHP_MARKER_HASH)`) therefore never matches a genuinely executed payload, so the Critical 'Upload led to server-side execution' finding is dead code for the PHP path. The inline comment even admits 'placeholder — real md5 in body'. Confirmed: `printf 'lancer'|md5sum` = b81a9dfa2a3ea350de88cac98594e40d; `printf ''|md5sum` = d41d8cd98f00b204e9800998ecf8427e.

**Evidence:**
````
const PHP_MARKER_HASH: &str = "LANCER_UP_d41d8cd98f00b204e9800998ecf8427e"; // placeholder — real md5 in body
````

**Fix:** In crates/lancer-scanner/src/active/upload.rs line 22, set the constant to the md5 of the string the injected PHP actually hashes:

const PHP_MARKER_HASH: &str = "LANCER_UP_b81a9dfa2a3ea350de88cac98594e40d"; // md5('lancer')

This makes body_text.contains(PHP_MARKER_HASH) at line 235 correctly match the reflected output of executed PHP (`LANCER_UP_` . md5('lancer')). The empty-string md5 (d41d8cd98f00b204e9800998ecf8427e) was wrong. The alternative of changing the PHP to md5('') would technically match but is worse, since hashing the empty string is a degenerate marker.

_Verified (high): Verified the actual code. Line 21 injects PHP `md5('lancer')` whose executed output is `LANCER_UP_b81a9dfa2a3ea350de88cac98594e40d` (confirmed md5('lancer')=b81a9dfa2a3ea350de88cac98594e40d). Line 22 hard-codes PHP_MARKER_HASH to `LANCER_UP_d41d8cd98f00b204e9800998ecf8427e`, and d41d8cd98f00b204e9800998ecf8427e is md5 of the EMPTY string (confirmed). The detection at line 235 (`body_text.contains(PHP_MARKER_HASH)`) therefore can never match a genuinely executed PHP payload, so the Critical 'Upload led to server-side execution' finding is unreachable for the PHP path. The `LANCER_HTML_XSS` branch on the same line is unaffected. The inline comment 'placeholder — real md5 in body' confirms the author knew it was a stub. Proposed fix (align the constant to md5('lancer')) is a one-line constant change with no type/callsite impact._


---

#### [x] #22 · `crates/lancer-scanner/src/passive/info_disclosure.rs:89` · HIGH · panic
**Snippet slicing can panic on a non-UTF-8-char-boundary**

**Problem:** The passive Information-Disclosure check truncates each regex match to 120 bytes with `body[m.start()..(m.end().min(m.start() + 120))]`. `m.start()` is a valid char boundary, but `m.start() + 120` is an arbitrary byte offset that may land in the middle of a multibyte UTF-8 character. Several patterns match unbounded, non-ASCII content longer than 120 bytes: the Python-traceback pattern `^\s*File ".+", line \d+,` (`.+` matches any non-newline chars, including multibyte file-path chars) and the .NET stack-trace pattern `at [\w.]+\.\w+\([^)]*\)\s+in\s+[A-Za-z]:\\` (`[^)]*` matches any chars except `)`). If such a match exceeds 120 bytes and contains a multibyte character spanning the byte-120 position, `&str` indexing panics (`byte index ... is not a char boundary`). Because the response body is fully attacker-controlled, a malicious/instrumented server can crash the passive scanner by returning a response that triggers one of these patterns with non-ASCII bytes around offset start+120.

**Evidence:**
````
let snippet = body[m.start()..(m.end().min(m.start() + 120))].to_string();
````

**Fix:** Clamp the slice end down to the nearest char boundary before slicing:

```rust
if let Some(m) = rx.find(body) {
    let mut end = m.end().min(m.start() + 120);
    while end > m.start() && !body.is_char_boundary(end) {
        end -= 1;
    }
    let snippet = body[m.start()..end].to_string();
    ...
}
```

(Equivalently, `body[m.start()..m.end()].chars().take(120).collect::<String>()` is panic-safe but caps by char count rather than bytes; the boundary-walk above preserves the original ~120-byte intent.)

_Verified (high): Confirmed at crates/lancer-scanner/src/passive/info_disclosure.rs:89. `body` is `&str` (from `response.body_text()` → `std::str::from_utf8`), so `body[m.start()..end]` panics when `end` is not a UTF-8 char boundary. The slice end is `m.end().min(m.start()+120)`; `m.start()`/`m.end()` are valid boundaries but `m.start()+120` is an arbitrary byte offset. Two patterns can match >120 bytes of attacker-controlled multibyte content: the Python-traceback pattern `^\s*File ".+", line \d+,` (`.+` matches any non-newline, incl. multibyte path chars) and the .NET pattern using `[^)]*`. A response with a 2/3/4-byte UTF-8 char straddling offset start+120 (and total match length >120) makes `.min()` select the non-boundary offset → panic ("byte index ... is not a char boundary"). The response body is fully attacker-controlled in a passive scan, and there is no catch_unwind in run_passive (engine.rs:46) nor anywhere on the path, so the panic crashes the scan task. Genuine attacker-triggerable panic._


---

#### [x] #23 · `crates/lancer-secrets/src/lib.rs:250-254` · HIGH · panic
**snippet_around byte-slices a &str at non-char-boundary offsets → panic on multi-byte UTF-8 response bodies**

**Problem:** `snippet_around` builds the slice `body[start..end]` where `start = pos.saturating_sub(30)` and `end = (pos + max_len).min(body.len())`. These are raw byte offsets. `pos` (a regex match start) is a char boundary, but subtracting 30 bytes or adding 120 bytes can land inside a multi-byte UTF-8 codepoint. Indexing a &str at a non-char-boundary byte offset panics ('byte index N is not a char boundary'). `scan_response` runs on EVERY HTTP response body (external, attacker/server-controlled input), so any response containing a non-ASCII character within ~30 bytes before, or ~120 bytes after, a secret match will panic the scanner (and whatever passive-scan task drives it). The `.min(body.len())` only guards the upper length bound, not codepoint alignment.

**Evidence:**
````
fn snippet_around(body: &str, pos: usize, max_len: usize) -> String {
    let start = pos.saturating_sub(30);
    let end = (pos + max_len).min(body.len());
    body[start..end].replace('\n', " ").replace('\r', "")
}
````

**Fix:** Snap both bounds to char boundaries before slicing (or use the non-panicking `str::get`). Replace lines 250-254 with:

fn snippet_around(body: &str, pos: usize, max_len: usize) -> String {
    let mut start = pos.saturating_sub(30);
    while start > 0 && !body.is_char_boundary(start) {
        start -= 1;
    }
    let mut end = (pos + max_len).min(body.len());
    while end < body.len() && !body.is_char_boundary(end) {
        end += 1;
    }
    body[start..end].replace('\n', " ").replace('\r', "")
}

This is safe: `is_char_boundary` returns true at 0 and body.len(), so the loops always terminate at a valid boundary, and start <= pos <= end is preserved. Equivalent alternative: `body.get(start..end).unwrap_or("").replace(...)`, but boundary-snapping yields the intended context window rather than an empty string on misalignment.

_Verified (high): Confirmed in real code (lines 250-254). `snippet_around(body, m.start(), 120)` is called from `scan_response` (lines 272, 297) with `pos = m.start()`, a regex-match byte offset that is a char boundary. It then computes `start = pos.saturating_sub(30)` and `end = (pos + 120).min(body.len())` and slices `body[start..end]` directly. Both raw byte offsets can land inside a multi-byte UTF-8 codepoint (the -30 before or +120 after the match), and indexing a &str at a non-char-boundary offset is a documented panic in Rust ("byte index N is not a char boundary"). `.min(body.len())` only bounds length, not alignment. `scan_response` runs on attacker/server-controlled response bodies (passive scanning), so any non-ASCII byte within ~30 bytes before or ~120 bytes after a secret/entropy match panics the scan task. Nothing in the type system or surrounding code prevents this; the function is live (two call sites). Verdict: real high-severity panic._


---

#### [x] #24 · `crates/lancer-setup/src/main.rs:51-64` · HIGH · security
**Zip Slip: archive entry name used unsanitized allows path traversal outside the temp dir**

**Problem:** In extract_payload(), each entry's name is taken verbatim from the archive (`file.name()`) and joined onto the temp dir with `tmp.join(&name)`. The zip crate does NOT sanitize entry names, so an entry named with `..` components (e.g. `..\..\Windows\System32\evil.dll`) or an absolute path causes `out` to resolve OUTSIDE `tmp`. The parent dirs are then created (line 58-60) and the file written (line 63) at the attacker-chosen location. Because this installer typically runs with elevated/installer privileges, a tampered or maliciously-crafted payload zip yields arbitrary file write anywhere on disk (classic Zip Slip / CVE-class). This is a real exploitable hole in a security tool, not theoretical: nothing constrains `name` to stay within `tmp`.

**Evidence:**
````
let name = file.name().to_string();
        let out = tmp.join(&name);
        if name.ends_with('/') {
            fs::create_dir_all(&out)?;
        } else {
            if let Some(parent) = out.parent() {
                fs::create_dir_all(parent)?;
            }
````

**Fix:** In extract_payload() replace the unsanitized name handling with zip's enclosed_name() plus a containment check:

```rust
for i in 0..archive.len() {
    let mut file = archive.by_index(i)?;
    // Reject entries with ".." / absolute paths that would escape tmp.
    let safe = match file.enclosed_name() {
        Some(p) => p,
        None => continue,
    };
    let out = tmp.join(&safe);
    // Belt-and-suspenders containment check.
    if !out.starts_with(&tmp) {
        continue;
    }
    if file.is_dir() {
        fs::create_dir_all(&out)?;
    } else {
        if let Some(parent) = out.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut buf = Vec::with_capacity(file.size() as usize);
        file.read_to_end(&mut buf)?;
        fs::File::create(&out)?.write_all(&buf)?;
    }
}
```

enclosed_name() (zip 2.x) returns None for entries containing ".." components or absolute paths, eliminating the traversal; file.is_dir() correctly replaces the fragile name.ends_with('/') directory check. This does not break legitimate relative-path entries produced by build.bat.

_Verified (high): The cited code (crates/lancer-setup/src/main.rs:51-64) is present exactly as described. extract_payload() takes each entry name verbatim via file.name() and does tmp.join(&name), then create_dir_all(parent) and File::create(&out).write_all. The zip crate (2.4.2) does NOT sanitize entry names — Path::join with a ".." path escapes the dir, and join with an absolute path replaces the base entirely. Rust's type system provides no protection here. This is a textbook Zip Slip pattern and the code is reachable (called from main at line 13). The proposed enclosed_name() fix is the canonical, correct mitigation and its API matches zip 2.x (enclosed_name -> Option<PathBuf>, is_dir() available). HOWEVER, the reporter's threat framing is overstated: the payload zip is embedded at COMPILE time via include_bytes!(OUT_DIR/lancer-payload.zip), staged by the project's own build.bat from trusted files — it is not attacker-controlled at runtime. To supply a malicious zip an attacker must already control the build pipeline or tamper with the compiled binary (at which point they could replace the binary outright). So the practical exploitability is low and "high" severity is too strong; this is really a defense-in-depth hardening issue. The code defect itself is genuine, so is_real=true, but the consequence as stated (runtime arbitrary file write from a tampered zip) requires a precondition that largely subsumes the impact._


---

#### [x] #25 · `crates/lancer-storage/src/snapshot.rs:36` · HIGH · correctness
**Snapshot copies only the main DB file while WAL mode is active, losing recent committed transactions**

**Problem:** Storage::open() opens every project (including auto-snapshotted on-disk projects) with journal_mode(Wal) (crates/lancer-storage/src/lib.rs:52). In WAL mode, committed-but-not-yet-checkpointed transactions live in the `<db>-wal` sidecar file, not the main `.lancer` file. take_snapshot() performs a plain `tokio::fs::copy(db_path, &dest)` of ONLY the main DB file, with no `PRAGMA wal_checkpoint(TRUNCATE)` first and without copying the `-wal`/`-shm` files. The resulting `.bak` is therefore a stale snapshot missing all history/issues/etc. committed since the last automatic checkpoint, and if it is ever restored the most recent data is silently gone. The whole point of the auto-snapshot feature (data-loss protection) is defeated for exactly the recent data most likely to matter.

**Evidence:**
````
tokio::fs::copy(db_path, &dest).await.context("copy db")?;
````

**Fix:** Force a WAL checkpoint into the main DB file before copying. In `take_snapshot`, un-underscore the `storage` param and add a checkpoint before the copy:

```rust
pub async fn take_snapshot(storage: &Storage, db_path: &Path, max_keep: u32) -> Result<PathBuf> {
    let ts = Utc::now().format("%Y%m%d-%H%M%S").to_string();
    let parent = db_path.parent().unwrap_or_else(|| Path::new("."));
    let snap_dir = parent.join(".lancer-snapshots");
    tokio::fs::create_dir_all(&snap_dir).await.ok();
    let dest = snap_dir.join(format!(
        "{}-{ts}.bak",
        db_path.file_name().and_then(|s| s.to_str()).unwrap_or("project")
    ));
    // Flush WAL contents into the main DB file so the plain copy is consistent.
    // TRUNCATE is best-effort: if writers are active it may not fully checkpoint,
    // but it never corrupts and we still capture all flushable committed data.
    let _ = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(storage.pool())
        .await;
    tokio::fs::copy(db_path, &dest).await.context("copy db")?;
    prune(&snap_dir, max_keep).await.ok();
    Ok(dest)
}
```

Update the caller `run_snapshot_loop` (line 22) accordingly — it already passes `&storage`, so no signature change is needed there. Ignoring the checkpoint's error (via `let _ =`) avoids aborting the snapshot if the pragma transiently returns SQLITE_BUSY; the copy still proceeds with whatever was flushed. Alternatively, a fully race-free approach is `VACUUM INTO '<dest>'` which produces a consistent copy without touching sidecars, but the wal_checkpoint approach is the smallest, lowest-risk change and matches the existing copy-based design.

_Verified (high): Verified against the real code. snapshot.rs:36 does `tokio::fs::copy(db_path, &dest)` copying ONLY the main DB file, with no checkpoint and no copy of the -wal/-shm sidecars. lib.rs:52 confirms every on-disk project is opened with journal_mode(Wal) and synchronous(Normal). In WAL mode, committed-but-uncheckpointed transactions live in the `<db>-wal` sidecar, not the main file, so a plain copy of the main file omits the most recent committed writes (those since the last checkpoint; SQLite's default wal_autocheckpoint of ~1000 pages bounds the loss to roughly the last few MB of writes, not literally all history — the detail slightly overstates the magnitude). The consequence (restoring a snapshot silently loses recent data) genuinely occurs, defeating the data-loss-protection purpose of the feature for exactly the recent data. The fix is callable: Storage exposes pool() at lib.rs:95, and _storage is already a parameter. Severity 'high' is a touch generous since it affects only the backup artifact, not the live DB, but the bug is real._


---

#### [x] #26 · `crates/lancer-templates/src/lib.rs:277-287` · HIGH · logic-error
**DSL contains() helper never works: trailing ')' stripped before the contains() branch can match it**

**Problem:** Line 277 normalizes the term with `.trim_end_matches(')')`, which removes the trailing ')' of any `contains(part, "literal")` expression, turning e.g. `contains(body, "admin")` into `contains(body, "admin"`. The contains() branch at line 282 still matches `.strip_prefix("contains(")` but its `.and_then(|s| s.strip_suffix(')'))` now fails because the closing ')' is gone, so the whole `if let Some(inner)` is skipped. The expression then falls through to the comparison loop (lines 290-311), finds no operator, and `eval_dsl_term` returns `false`. Result: every Nuclei DSL matcher using the documented `contains(part, "x")` helper silently evaluates to false, so templates relying on `contains()` never report a match (false negatives in the scanner).

**Evidence:**
````
let term = term.trim().trim_start_matches('(').trim_end_matches(')').trim();
...
if let Some(inner) = term.strip_prefix("contains(").and_then(|s| s.strip_suffix(')')) {
````

**Fix:** In `eval_dsl_term`, handle the function-call helpers BEFORE the blanket paren-stripping so the closing `)` of `contains(...)` is preserved. Replace lines 276-287:

```rust
fn eval_dsl_term(term: &str, status: u16, body: &str, headers: &str) -> bool {
    let term = term.trim();
    if term.eq_ignore_ascii_case("true") { return true; }
    if term.eq_ignore_ascii_case("false") { return false; }

    // contains(part, "literal") -- check before generic paren stripping so the
    // function call's own closing ')' is not consumed.
    if let Some(inner) = term.strip_prefix("contains(").and_then(|s| s.strip_suffix(')')) {
        if let Some((p, lit)) = inner.split_once(',') {
            let needle = lit.trim().trim_matches('"');
            return dsl_part(p, body, headers).contains(needle);
        }
    }

    // Strip a wrapping paren pair only for the bare comparison path.
    let term = term.trim_start_matches('(').trim_end_matches(')').trim();

    // ... comparison loop unchanged (operators ==, !=, <=, >=, <, >) ...
}
```

This preserves existing behavior for parenthesized comparisons like `(status_code == 200)` (still stripped before the operator loop) while fixing `contains()`. Note `true`/`false` checks are moved above the paren strip too, which is harmless since those literals never carry parens. The pre-existing greedy/unbalanced nature of trim_start/end_matches for nested parens is unchanged and out of scope.

_Verified (high): Verified in crates/lancer-templates/src/lib.rs:276-312. Line 277 applies `.trim_end_matches(')')` unconditionally, so `contains(body, "admin")` becomes `contains(body, "admin"` (trailing `)` removed). At line 282 `strip_prefix("contains(")` succeeds but the chained `.and_then(|s| s.strip_suffix(')'))` returns None because the string now ends in `"`, so the contains() branch is skipped. The term then enters the comparison loop (290-311), contains none of the operators, and the function returns false at line 312. I confirmed the exact string-op behavior empirically with a standalone rustc test: normalized term is `contains(body, "admin"` and the strip_suffix(')') yields None. eval_dsl (228-238) passes the raw term through with no compensating paren handling, so the corruption is real. Consequence holds: every documented `contains(part, "x")` DSL matcher evaluates to false, causing scanner false negatives. Not dead code — eval_dsl/eval_dsl_term are the DSL evaluation path used by run_template/eval_matcher. Rust's type system does not prevent this; it's pure string logic._


---

#### [x] #27 · `crates/lancer-tools/src/autorize.rs:50-60` · HIGH · logic-error
**Low-privilege authz replay does not strip the original Authorization header**

**Problem:** `audit()` builds the low-privilege request by cloning `base` (the captured authenticated request) and only calling `set_header("Cookie", ...)`. `set_header` replaces by name, so any `Authorization` header present on the original privileged request survives. The low-privilege replay is therefore still sent with the original (high-privilege) bearer/token, so it almost always returns a 200 with the same body length as the original — producing a false `BypassWithLowPriv` verdict (or masking a real one). Note the anon branch (lines 61-68) correctly removes both Cookie and Authorization when the cookie is empty, but the low-priv branch never does.

**Evidence:**
````
if let Some(cookie) = &cfg.low_priv_cookie {
    let mut r = base.clone();
    r.set_header("Cookie", cookie.clone());
    let resp = client.send(&r).await?;
````

**Fix:** In the low-priv branch, strip the privileged Authorization header before substituting the low-priv cookie:

    if let Some(cookie) = &cfg.low_priv_cookie {
        let mut r = base.clone();
        r.remove_header("Authorization");
        r.set_header("Cookie", cookie.clone());
        let resp = client.send(&r).await?;
        ...
    }

(Optional but recommended for consistency: also strip Authorization in the non-empty anon path at lines 66-68, since substituting a cookie there likewise leaves the original bearer token intact.)

_Verified (high): Verified at crates/lancer-tools/src/autorize.rs:50-60. The low-priv branch clones `base` (the captured authenticated request) and calls only `set_header("Cookie", cookie)`. Confirmed via crates/lancer-core/src/http_msg.rs:218-225 that `set_header` only replaces/appends a header of the same name and never removes `Authorization`. So if the original privileged request used token/bearer auth (the common case for this authz-replay module), that Authorization header survives into the low-priv replay, which then runs with the high-privilege credential and returns an indistinguishable status/body — falsely setting bypass_low=true and yielding a BypassWithLowPriv false positive (or masking a true negative). The asymmetry is real: the anon branch (lines 61-68) explicitly removes both Cookie and Authorization (but only on the empty-cookie path), confirming the substitution intent the low-priv branch fails to honor. The proposed `remove_header("Authorization")` is safe (a simple retain, no panics)._


---

#### [x] #28 · `crates/lancer-tools/src/intruder.rs:570` · HIGH · compile-error
**sniper_combos test calls function with wrong argument type (won't compile under cfg(test))**

**Problem:** The test `sniper_spreads_one_set` calls `sniper_combos(3, sets)` passing the integer `3`, but `sniper_combos` is declared at line 464 as `fn sniper_combos(template: &ParsedTemplate, sets: Vec<PayloadSet>)`. An `i32`/`usize` literal does not coerce to `&ParsedTemplate`, so the test module fails to compile, which breaks `cargo test -p lancer-tools` for the entire crate. (The sibling tests for pitchfork/cluster pass `(2, sets)` correctly because those functions take `pos_count: usize`; sniper is the odd one whose signature was changed without updating the test.)

**Evidence:**
````
let s = sniper_combos(3, sets).unwrap();
        assert_eq!(s.len(), 6); // 3 positions × 2 payloads
````

**Fix:** In the test `sniper_spreads_one_set` (crates/lancer-tools/src/intruder.rs ~line 568), build a 3-position ParsedTemplate and pass it by reference instead of the integer 3:

    #[test]
    fn sniper_spreads_one_set() {
        use lancer_core::HttpRequest;
        let req = HttpRequest::builder("GET", "https://x.com/§a§/§b§/§c§").unwrap();
        let template = ParsedTemplate::parse(req, DEFAULT_MARKER);
        let sets = vec![PayloadSet::Simple(vec!["X".into(), "Y".into()])];
        let s = sniper_combos(&template, sets).unwrap();
        assert_eq!(s.len(), 6); // 3 positions × 2 payloads
    }

(DEFAULT_MARKER is already in scope via `use super::*`; HttpRequest needs importing as shown, matching the pattern in positions.rs tests.)

_Verified (high): Verified in the actual file. Line 464 declares `fn sniper_combos(template: &ParsedTemplate, sets: Vec<PayloadSet>)`, but the test at line 570 calls `sniper_combos(3, sets)` passing integer literal `3`. Rust will not coerce an integer to `&ParsedTemplate`, so the test module fails to compile under cfg(test), breaking `cargo test -p lancer-tools` for the whole crate. The sibling tests (cluster_bomb_combos(2,...) line 551, pitchfork_combos(2,...) line 561) compile because those functions take `pos_count: usize`. Production code at line 351 calls `sniper_combos(&template, sets)`, confirming the signature is intentional and the test is stale. I confirmed the ParsedTemplate API: `HttpRequest::builder(method, url)` returns Result (needs .unwrap()), `ParsedTemplate::parse(req, DEFAULT_MARKER)` consumes the request, and §...§ markers produce positions (positions.rs test at line 172 demonstrates this exact pattern). The fix must build a 3-position template and pass it by reference._


---


### MEDIUM

#### [x] #29 · `crates/lancer-api-routes/src/lib.rs:272` · MEDIUM · panic
**buffer_unordered(0) hangs/panics when concurrency is 0 from external input**

**Problem:** `concurrency` is deserialized from the external `DiscoveryRequest` JSON and used directly as the argument to `buffer_unordered(concurrency)`. A client can send `"concurrency": 0` (it is a plain `usize` with no validation; the `#[serde(default)]` only applies when the key is absent). With an in-flight limit of 0, `buffer_unordered` can never start any of the queued futures, so the stream makes no progress and `.collect().await` never completes — `run_discovery` hangs forever on that request (and in some futures versions the zero-capacity buffer panics). Either way a single malformed API request stalls or kills the discovery task.

**Evidence:**
````
.buffer_unordered(concurrency)
        .filter_map(|r| async move { r })
        .collect()
        .await
````

**Fix:** In crates/lancer-api-routes/src/lib.rs, clamp the deserialized value before use. Replace line 255 `let concurrency = req.concurrency;` with `let concurrency = req.concurrency.max(1);` so an externally-supplied 0 falls back to a single in-flight probe. This fixes every caller (REST API and CLI). Note the consequence is an indefinite hang (a leaked tokio task per request), not a panic, with futures-util 0.3.32.

_Verified (high): Verified against the real code. `DiscoveryRequest.concurrency` is a plain `usize` with `#[serde(default = "default_concurrency")]` (lib.rs:17-18), and that default only fires when the JSON key is absent — an explicit `"concurrency": 0` deserializes to 0 with no validation. At lib.rs:255 it is taken verbatim and passed to `.buffer_unordered(concurrency)` (line 272). The crate uses futures-util 0.3.32, where `buffer_unordered(0)` does not panic but caps in-flight futures at 0, so with a non-empty `jobs` set (routes × non-empty default methods is always non-empty) no future is ever polled, the stream never yields/terminates, and `.collect().await` hangs forever. The endpoint is reachable: `POST /v1/api-routes` (lancer-api/src/main.rs:1388-1397) deserializes `DiscoveryRequest` straight from the request body and calls `run_discovery(req).await`. One nuance: the call runs inside `tokio::spawn`, so it does not block the HTTP response (which returns immediately); the consequence is a permanently-stalled, leaked background task per malformed request (a resource/task-leak vector when repeated), not a hung HTTP request. The "panics in some futures versions" part of the title does not apply to 0.3.32 (it hangs), but the detail hedges on that and the hang consequence is real. Fixing at the library level covers all callers (CLI included)._


---

#### [x] #30 · `crates/lancer-api/src/main.rs:1247-1258` · MEDIUM · api-contract
**DELETE /v1/templates/{id} returns ok:true but never deletes the template**

**Problem:** The DELETE /v1/templates/{id} handler computes the kept set but then discards it (`let _ = kept;`) and unconditionally returns {"ok": true}. The template is never removed from state.templates, so the GUI/CLI believes the delete succeeded while the template remains in the library and continues to appear in GET /v1/templates. This is a broken API contract (silent no-op masquerading as success).

**Evidence:**
````
// (Library uses internal Vec; we expose only add — so emulate by re-allocating a fresh wrapper.)
            let _ = kept; // placeholder: full delete needs library API change
            return json(&serde_json::json!({ "ok": true }));
````

**Fix:** Add a remove method to TemplateLibrary (crates/lancer-templates/src/lib.rs), mirroring the existing get/list RwLock access:

    /// Remove a template by id. Returns true if one was removed.
    pub fn remove(&self, id: &str) -> bool {
        let mut g = self.templates.write().unwrap();
        let before = g.len();
        g.retain(|t| t.id != id);
        before != g.len()
    }

Then replace the handler body at crates/lancer-api/src/main.rs:1247-1258 with an actual deletion that reports truthful status (matching the adjacent /v1/findings/{id} pattern):

    // DELETE /v1/templates/{id}
    if method == Method::DELETE {
        if let Some(id) = path.strip_prefix("/v1/templates/") {
            let removed = state.templates.remove(id);
            return json(&serde_json::json!({ "ok": removed }));
        }
    }

This returns {"ok": false} (200) when the id is not found, consistent with how DELETE /v1/findings/{id} behaves at lines 1235-1244. (Optionally return StatusCode::NOT_FOUND when !removed if a 404 contract is preferred, but matching the findings handler keeps it consistent.) The std RwLock guard is taken and dropped entirely within remove() with no .await across it, so no async-deadlock concern.

_Verified (high): Verified the cited code at crates/lancer-api/src/main.rs:1247-1258 is present exactly as reported: the DELETE /v1/templates/{id} handler computes `kept` (the list filtered to exclude the id), then discards it with `let _ = kept;` and unconditionally returns {"ok": true}. The template is never removed. Confirmed in crates/lancer-templates/src/lib.rs that TemplateLibrary stores templates in a RwLock<Vec<Template>> and exposes only add/add_yaml/load_directory/list/get/len — there is genuinely no remove/clear/retain API, so the handler cannot delete. Confirmed GET /v1/templates (main.rs:983) reads from the same state.templates.list(), so a "deleted" template keeps appearing. The stated consequence (silent no-op masquerading as success) is real. The adjacent DELETE /v1/findings/{id} handler (lines 1235-1244) already demonstrates the correct retain+removed>0 pattern. Template.id is a String, so a remove(&str) method comparing t.id is type-safe._


---

#### [x] #31 · `crates/lancer-bulkprobe/src/lib.rs:219-227` · MEDIUM · correctness
**Client-supplied concurrency:0 makes run_probes silently probe nothing**

**Problem:** `concurrency` comes from `ProbeRequest`, which is deserialized from external/API input. The `#[serde(default = "default_concurrency")]` only supplies 50 when the field is ABSENT; an explicit `"concurrency": 0` is accepted and passed straight to `buffer_unordered(0)`. With a limit of 0, `buffer_unordered` never polls any of the underlying probe futures, so `collect().await` resolves immediately to an empty Vec — every host is silently dropped and the caller gets zero results with no error. (In some futures versions a 0 buffer can instead stall.) Either way a single bad/zero value produces wrong behavior for the whole request.

**Evidence:**
````
let concurrency = req.concurrency;
    let timeout = req.timeout_secs;
    futures::stream::iter(req.hosts)
        .map(move |h| probe_one(h, timeout))
        .buffer_unordered(concurrency)
        .collect()
        .await
````

**Fix:** In run_probes, clamp concurrency to a minimum of 1 before passing to buffer_unordered:

pub async fn run_probes(req: ProbeRequest) -> Vec<ProbeResult> {
    let concurrency = req.concurrency.max(1);
    let timeout = req.timeout_secs;
    futures::stream::iter(req.hosts)
        .map(move |h| probe_one(h, timeout))
        .buffer_unordered(concurrency)
        .collect()
        .await
}

This only alters the degenerate concurrency==0 case (clamping to serial execution) and leaves all normal values unchanged, so it cannot break existing behavior. Optionally also cap an upper bound (e.g. .min(1000)) to limit resource exhaustion from an attacker-supplied huge value, but that is a separate hardening concern.

_Verified (high): Confirmed by reading the actual code. crates/lancer-bulkprobe/src/lib.rs:219-227 passes req.concurrency directly to buffer_unordered(concurrency) with no clamp. ProbeRequest derives Deserialize; #[serde(default = "default_concurrency")] (line 15) only supplies 50 when the field is ABSENT, so an explicit "concurrency": 0 deserializes to 0. The struct is fed straight from untrusted input in lancer-api/src/main.rs:1368 (serde_json::from_slice(&body)) at POST /v1/bulkprobe with no validation. futures is 0.3.32 (Cargo.lock); buffer_unordered(0) yields a stream that never polls any inner future, so collect().await resolves to an empty Vec immediately — every host is silently dropped, zero results, no error returned (the tokio::spawn just stores an empty vec). No type-system or upstream guard prevents this; usize accepts 0 and there is no other caller (no CLI usage). The consequence as stated genuinely occurs._


---

#### [x] #32 · `crates/lancer-cli/src/commands/intruder.rs:19-20, 110-113` · MEDIUM · parsing
**`--payloads list:a,b,c` is broken: comma value_delimiter splits it, and the list parser uses `|` not `,`**

**Problem:** The `payloads` arg declares `#[arg(long = "payloads", value_delimiter = ',')]`, so clap splits each `--payloads` value on commas before it reaches `parse_set`. The documented example on line 19 is `list:a,b,c`. When a user runs `--payloads "list:a,b,c"`, clap produces three separate values: `"list:a"`, `"b"`, `"c"`. `parse_set("b")` and `parse_set("c")` have no recognized prefix and hit the final `anyhow::bail!("unrecognized payload set: {s}")`, so the command errors out. Compounding this, even the surviving `"list:a"` token is split by the internal list parser on `'|'` (line 112: `rest.split('|')`), not on commas — so the only way to get a multi-item list is `list:a|b|c`, which the help text never documents and which the comma delimiter does not interfere with. Net effect: the exact documented `list:a,b,c` invocation fails, and the real list syntax is undocumented.

**Evidence:**
````
#[arg(long = "payloads", value_delimiter = ',')]
    payloads: Vec<String>,
...
    /// `list:a,b,c`, ...
...
    if let Some(rest) = s.strip_prefix("list:") {
        return Ok(PayloadSet::Simple(
            rest.split('|').map(|x| x.to_string()).collect(),
        ));
    }
````

**Fix:** Make the documented `list:a,b,c` syntax actually work by removing the comma value_delimiter so each `--payloads` flag carries one whole set string, and switch the list parser to split on commas to match the help text. Two coordinated edits in crates/lancer-cli/src/commands/intruder.rs:

1) Line 20 — drop the delimiter:
   #[arg(long = "payloads")]
   payloads: Vec<String>,

2) Line 112 — split on ',' instead of '|':
   rest.split(',').map(|x| x.to_string()).collect(),

Multiple payload sets (needed for Pitchfork/ClusterBomb) are still supplied by repeating the flag, e.g. `--payloads file:a.txt --payloads list:x,y,z`, which Vec<String> collects correctly. (If preserving '|' as the list separator is preferred instead, only remove value_delimiter and update the line-19 doc comment to `list:a|b|c`; but splitting on comma is cleaner since it matches the existing documentation.)

_Verified (high): Confirmed by reading the actual file. Line 20 declares `#[arg(long = "payloads", value_delimiter = ',')]` and line 19's doc documents `list:a,b,c`. Clap's `value_delimiter = ','` splits each argument value on commas before it reaches application code, so `--payloads "list:a,b,c"` yields three values `"list:a"`, `"b"`, `"c"`. In run() (lines 66-70) each is passed to parse_set; `parse_set("b")` and `parse_set("c")` match no prefix and hit `anyhow::bail!("unrecognized payload set")` at line 138, so the command errors out. Meanwhile the list parser at line 112 splits on `'|'`, not `','`, so the only working list syntax is the undocumented `list:a|b|c`. Nothing in the type system or surrounding code prevents this; the code path is reachable (parse_set is called for every --payloads value). The two bugs (doc/delimiter mismatch and parser-separator mismatch) compound exactly as described. Multi-set attacks (Pitchfork/ClusterBomb) are supplied via repeated --payloads flags collected into Vec<String>, so removing value_delimiter does not break them._


---

#### [x] #33 · `crates/lancer-cli/src/commands/urls.rs:181-184` · MEDIUM · logic-error
**uro trailing-slash normalization fails (and breaks dedup) whenever a query/fragment is present**

**Problem:** The trailing-slash strip operates on the full serialized URL `s` via `s.strip_suffix('/')`. The URL string only ends in `/` when there is no query and no fragment. For a URL like `https://x.com/a/?q=1`, `s` ends in `1`, so `strip_suffix('/')` returns None and the trailing slash on the path is never removed. Consequently `https://x.com/a/?q=1` and `https://x.com/a?q=1` normalize to DIFFERENT strings and are not deduplicated, defeating uro's purpose. The included unit test `uro_dedups` (line 226-228) asserts `uro_one("https://X.COM/a/?utm_source=g&q=1") == "https://x.com/a?q=1"`, which this code does not produce — it yields `https://x.com/a/?q=1`, so the test fails.

**Evidence:**
````
let mut s = u.to_string();
    if let Some(stripped) = s.strip_suffix('/') {
        if u.path().len() > 1 { s = stripped.to_string(); }
    }
    s
````

**Fix:** Strip the trailing slash from the path before re-serializing, so it is removed regardless of query/fragment, while keeping the root-path guard. Replace lines 181-184:

    let p = u.path().to_string();
    if p.len() > 1 && p.ends_with('/') {
        let _ = u.set_path(p.trim_end_matches('/'));
    }
    u.to_string()

This yields `https://x.com/a?q=1` for the test input and leaves a bare `/` root path untouched. (`trim_end_matches` collapses multiple trailing slashes, which is acceptable/desirable for dedup normalization.)

_Verified (high): Code at lines 181-184 matches the evidence exactly. `uro_one` builds `s = u.to_string()` then calls `s.strip_suffix('/')` on the FULL serialized URL. When a query (or fragment) is present, the serialized string ends with the query/fragment value (e.g. `https://x.com/a/?q=1` ends in `1`), so `strip_suffix('/')` returns None and the path's trailing slash is never removed. Thus `https://x.com/a/?q=1` and `https://x.com/a?q=1` produce different normalized strings and are NOT deduplicated — defeating uro's purpose. The inline `#[test] uro_dedups` (lines 226-228) asserts the result equals `https://x.com/a?q=1`, but the code yields `https://x.com/a/?q=1`, so that test fails (it is a plain non-ignored `#[test]`). The Rust type system does not prevent this; nothing else normalizes the path. The proposed fix (strip the slash from the path itself before re-serializing) is correct and preserves the existing `path().len() > 1` guard that keeps a bare root `/`._


---

#### [x] #34 · `crates/lancer-dom/src/message.rs:34-67` · MEDIUM · logic-error
**Closely-spaced postMessage listeners are silently dropped (single-slot buffer overwritten)**

**Problem:** `listener_buffer` is a single `Option`. When a `message` listener is found at line L, it is not emitted until the loop reaches line L+8 (the flush condition `line_idx + 1 == *l + 8`). If a second `addEventListener("message", ...)` appears within those 8 following lines, line 37 overwrites `listener_buffer` with the new listener and the FIRST listener is never pushed to `out`. JS bundles (especially minified or several handlers registered together) routinely have multiple message listeners within 8 lines of each other, so real listeners are silently lost from the report — a false-negative in a security tool. Sender endpoints are unaffected; only Listener findings are dropped.

**Evidence:**
````
if LISTENER_RX.is_match(line) {
    listener_buffer = Some((line_idx + 1, line.trim().to_string()));
}
...
if let Some((l, snip)) = &listener_buffer {
    if line_idx + 1 == *l + 8 {
````

**Fix:** Flush the pending listener before overwriting the single-slot buffer. Extract the listener-emit logic into a closure (so the early-flush, +8-flush, and end-of-file flush all stay consistent) and call it before replacing the buffer.

Replace the body of `find_message_endpoints` with:

```rust
pub fn find_message_endpoints(body: &str) -> Vec<PostMessageEndpoint> {
    let mut out = Vec::new();
    let mut listener_buffer: Option<(usize, String)> = None;

    // Emit a buffered listener, computing origin-validation over up to 9 lines
    // starting at its 1-based line number.
    let emit_listener = |out: &mut Vec<PostMessageEndpoint>, l: usize, snip: String| {
        let block = body
            .lines()
            .skip(l - 1)
            .take(9)
            .collect::<Vec<_>>()
            .join("\n");
        let validated = block.contains("event.origin") || block.contains(".origin ==");
        out.push(PostMessageEndpoint {
            kind: EndpointKind::Listener,
            line: l,
            snippet: snip,
            wildcard_origin: false,
            origin_validated: validated,
        });
    };

    for (line_idx, line) in body.lines().enumerate() {
        if LISTENER_RX.is_match(line) {
            // Flush any still-pending listener before overwriting the slot,
            // otherwise closely-spaced listeners would be silently dropped.
            if let Some((l, snip)) = listener_buffer.take() {
                emit_listener(&mut out, l, snip);
            }
            listener_buffer = Some((line_idx + 1, line.trim().to_string()));
        }
        if SENDER_RX.is_match(line) {
            out.push(PostMessageEndpoint {
                kind: EndpointKind::Sender,
                line: line_idx + 1,
                snippet: line.trim().to_string(),
                wildcard_origin: WILDCARD_RX.is_match(line),
                origin_validated: false,
            });
        }
        if let Some((l, _)) = listener_buffer {
            if line_idx + 1 == l + 8 {
                let (l, snip) = listener_buffer.take().unwrap();
                emit_listener(&mut out, l, snip);
            }
        }
    }
    // flush remaining listener if file ended before lookahead
    if let Some((l, snip)) = listener_buffer.take() {
        emit_listener(&mut out, l, snip);
    }
    out
}
```

Notes:
- The early-flush computes its validation block over the original listener's 9-line window via `skip(l-1).take(9)`; those lines still exist in `body`, so validation accuracy is unchanged versus the normal +8 path.
- Behavior is otherwise identical for the single-listener case. This only adds the previously-missing emission of overwritten listeners, so it cannot cause regressions; at worst a listener whose window overlaps the next listener gets evaluated over a slightly-overlapping 9-line block, which is acceptable and matches the existing window semantics.
- Borrow-checker: `emit_listener` borrows `body` immutably and takes `out` as a parameter, avoiding a conflicting mutable/immutable borrow of `out` while `body.lines()` is in use.

_Verified (high): Verified against the actual code in crates/lancer-dom/src/message.rs (lines 32-81). `listener_buffer` is a single `Option<(usize,String)>`. A detected listener at 1-based line L is only emitted to `out` when the loop reaches `line_idx+1 == L+8` (line 50). Line 36-38 unconditionally overwrites `listener_buffer` whenever LISTENER_RX matches. So if a second `addEventListener("message",...)` appears at any line in [L+1, L+8] before the first listener's flush, the first listener is overwritten and never pushed — a silent false-negative. I traced both sub-cases: a second listener at L+k (k=1..7) overwrites before A's flush, and one at exactly L+8 overwrites at the same iteration where LISTENER_RX (line 36) runs before the flush check (line 48), also losing A. Senders use an independent push (lines 39-47) so they are unaffected, matching the report. Rust's type system does not prevent this — it is a plain logic error. Multiple message handlers within 8 lines are common in real (especially minified/bundled) JS, so listeners are genuinely lost from the report. The defect and stated consequence are real._


---

#### [x] #35 · `crates/lancer-gui/web/src/views/Findings.svelte:136-141` · MEDIUM · api-contract
**"PDF" export option downloads JSON content saved with a .md extension**

**Problem:** The export dropdown offers a `pdf` option (line 206), but the backend /v1/findings/export only handles markdown/hackerone/bugcrowd/intigriti and falls through to `_ => json(&list)` for everything else (lancer-api/src/main.rs:1103-1113) — i.e. for `format=pdf` it returns JSON with content-type application/json. The GUI then saves the blob as `findings-pdf.md` (the filename builder only special-cases `json`, everything else gets `.md`). Result: selecting PDF yields a file named `findings-pdf.md` whose bytes are actually JSON — wrong extension and wrong content for the advertised format.

**Evidence:**
````
const r = await fetch(`/api/v1/findings/export?format=${exportFmt}`);
...
a.download = `findings-${exportFmt}.${exportFmt === "json" ? "json" : "md"}`;
````

**Fix:** Backend has no PDF renderer wired into this route, so the safe minimal fix is to remove the unsupported PDF option and make the extension robust. In Findings.svelte: (1) delete `<option value="pdf">PDF</option>` (line 206); (2) derive the download extension from the format instead of the json/else binary choice, e.g. replace line 140 with a small map: `const ext = exportFmt === "json" ? "json" : "md"; a.download = `findings-${exportFmt}.${ext}`;` (the markdown formats correctly keep .md). If a real PDF export is desired later, add a `"pdf"` arm to the backend match in main.rs (lines 1103-1112) that calls lancer-report::render_pdf over the findings, returns content-type application/pdf, re-add the option, and map pdf→.pdf in the frontend extension logic. The minimal fix (removing the pdf option) is safe and breaks nothing, since pdf was the only format that produced wrong content/extension.

_Verified (high): Verified both cited locations against the real code. In crates/lancer-gui/web/src/views/Findings.svelte the export select offers a "pdf" option (line 206) and exportFindings() (lines 134-154) builds the download name as `findings-${exportFmt}.${exportFmt === "json" ? "json" : "md"}` (line 140), so format=pdf yields filename `findings-pdf.md`. In crates/lancer-api/src/main.rs the GET /v1/findings/export handler (lines 1100-1114) only matches "markdown"|"hackerone"|"bugcrowd"|"intigriti" and falls through to `_ => json(&list)` for everything else, returning JSON with content-type application/json for format=pdf. So selecting PDF downloads a file named findings-pdf.md whose bytes are JSON — wrong extension and wrong content. Nothing in the type system or response handling prevents this; the blob fetch faithfully writes whatever the body is. The code is reachable (it's a normal export button). Severity medium is fair: it's a misleading/broken advertised feature, not a crash or data-loss._


---

#### [x] #36 · `crates/lancer-gui/web/src/views/Intruder.svelte:230` · MEDIUM · api-contract
**Case modification payload spec sends the wrong base string (charSubBase instead of a Case-modification input)**

**Problem:** buildPayloadSpec()'s `Case modification` arm sends `base: charSubBase`. `charSubBase` is bound exclusively to the Character substitution UI's base-string input (line 553, default "admin"); the Case modification UI (lines 517-530) exposes only the `caseMod` dropdown and has NO field that edits the value sent as the base. As a result, when the user selects payload type "Case modification" the backend (PayloadSet::CaseModification { base }, which generates lower/upper/capitalized/swapcase variants of `base`) operates on "admin" or whatever was last typed under the unrelated Character-substitution payload type, and there is no way for the user to set the Case-modification base. The user's selected case transformation (`caseMod`) is also never sent.

**Evidence:**
````
case "Case modification": return { type:"casemodification", base:charSubBase||"" };
````

**Fix:** In Intruder.svelte, add a dedicated base-string variable, e.g. near line 69-73: `let caseModBase="admin";`. In the Case modification UI block (lines 517-530), add an input bound to it, e.g. after the type dropdown:
  <div class="ps-row" style="margin-top:8px">
    <label class="ps-label">Base string:</label>
    <input type="text" class="add-item-input" style="flex:1" bind:value={caseModBase} placeholder="e.g. admin" />
  </div>
Then change line 230 to:
  case "Case modification": return { type:"casemodification", base:caseModBase||"" };
This is safe — it only introduces a new local and a new bound input, with no impact on the Character-substitution arm (which keeps using charSubBase). Forwarding the selected `caseMod` transformation is a separate enhancement that requires extending PayloadSet::CaseModification in lancer-tools and the deserializer in lancer-api (the backend currently has no field for it and always emits all four case variants), so do not attempt that as part of this fix unless the backend is updated in tandem.

_Verified (high): Verified in the actual source. Intruder.svelte line 230 sends `base:charSubBase||""` for the "Case modification" payload type. `charSubBase` (declared line 73, default "admin") is bound ONLY to the Character substitution UI's base input (line 553). The Case modification UI block (lines 517-530) exposes only the `caseMod` dropdown and has no base-string input; no `caseModBase` variable exists (grep confirms). The backend path is live and reachable: lancer-api/src/main.rs:2522 maps tag "casemodification" -> PayloadSet::CaseModification { base: s.base }, and lancer-tools/src/intruder.rs:92 generates lower/upper/capitalized/swapcase of `base`. So the Case-modification attack operates on whatever was typed under the unrelated Character-substitution payload type (default "admin"), and the user has no way to set the intended base. Rust's type system does not prevent this — `base` is a plain String defaulting to "" if absent, but the frontend always supplies the wrong non-empty value. The secondary observation that `caseMod` is never sent is also correct: the backend enum has no field for the transformation choice, so it currently always emits all four variants. The proposed fix (add a dedicated bound caseModBase input and reference it) is correct and safe; the caseMod-forwarding part requires backend changes and is rightly flagged as separate._


---

#### [x] #37 · `crates/lancer-gui/web/src/views/Plugins.svelte:90-103, 538` · MEDIUM · api-contract
**Binary plugin uploads are read with file.text() and corrupted (and the backend only accepts a TOML manifest)**

**Problem:** The hidden file input advertises binary plugin types: accept=".rhai,.wasm,.lua,.py,.dll,.so,.dylib,.jar,.zip". onFileSelected() reads ANY selected file with `await file.text()`, which UTF-8-decodes the bytes and irreversibly corrupts non-text files (wasm/dll/so/dylib/jar/zip). It then POSTs that decoded string as `content`. The backend (/v1/plugins/upload in lancer-api/src/main.rs:1270-1292) writes `content` verbatim into `plugin.toml` and calls load_one(), which does `toml::from_str` on it. So for every binary runtime advertised in `accept`, the upload either fails (binary bytes are not valid TOML) or silently writes garbage. Only a plain plugin.toml manifest can ever succeed, so the WASM/Lua/Python/Native/JVM upload paths the UI offers are non-functional. This is the documented 'binary read with .text() corrupts' bug class.

**Evidence:**
````
const content = await file.text();
      await fetch("/api/v1/plugins/upload", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name: file.name, content }),
      });
````

**Fix:** Minimal, safe fix: align the UI with what the backend actually accepts — a TOML plugin manifest. In crates/lancer-gui/web/src/views/Plugins.svelte change the hidden input (line 538) from accept=".rhai,.wasm,.lua,.py,.dll,.so,.dylib,.jar,.zip" to accept=".toml". Keep `await file.text()` (correct for a text manifest). Re-run `npm run build`. (Note: even a lone .rhai file would not work here because load_one reads the Rhai script as an external file beside plugin.toml, so the manifest is the only viable single-file upload.) Supporting real binary plugins is a larger, separate change: send the file as multipart/form-data or base64 (FileReader.readAsArrayBuffer), and add a binary-aware branch in the /v1/plugins/upload handler that writes raw bytes to the correct artifact path instead of plugin.toml.

_Verified (high): Verified against actual code. Plugins.svelte:90-103 reads any selected file with `await file.text()` (UTF-8 decode, corrupts binaries) and POSTs it as JSON `content`; the hidden input at line 538 advertises binary types (.wasm,.dll,.so,.dylib,.jar,.zip). The backend handler at lancer-api/src/main.rs:1270-1292 deserializes {name,content} and writes `content` verbatim into plugin.toml, then calls plugins.load_one, which (registry.rs:48-50) does `toml::from_str`. So binary uploads either fail to parse as TOML or write garbage; only a plain plugin.toml manifest can load. The advertised WASM/Lua/Python/Native/JVM upload paths are non-functional. Matches the documented 'binary read with .text() corrupts' bug class. Severity medium is reasonable (non-functional UI affordance, not data loss/security)._


---

#### [x] #38 · `crates/lancer-gui/web/src/views/Repeater.svelte:186-187` · MEDIUM · parsing
**Query/body param parsing splits on '=' once via destructuring, truncating values that contain '='**

**Problem:** `const [k, v] = pair.split("=")` keeps only the segment up to the first '='; any '=' inside the value (common in base64 padding, JWTs, signatures) is dropped, so `v` is truncated. Because the Inspector round-trips through parseInspector -> edit -> rebuildRequest, editing any unrelated field re-encodes the truncated value back into the raw request, silently corrupting the user's payload. Same pattern at line 215 (body params) and line 628 (ctxChangeBodyEncoding).

**Evidence:**
````
const [k, v] = pair.split("=");
        if (k) queryParams.push({ name: decodeURIComponent(k || ""), value: decodeURIComponent(v || "") });
````

**Fix:** Replace the destructuring split at all three sites with a split-on-first-'=' that preserves the remainder of the value.

Lines 185-188 (query params):
```js
for (const pair of qs.split("&")) {
  const eq = pair.indexOf("=");
  const k = eq < 0 ? pair : pair.slice(0, eq);
  const v = eq < 0 ? "" : pair.slice(eq + 1);
  if (k) queryParams.push({ name: decodeURIComponent(k), value: decodeURIComponent(v) });
}
```

Lines 214-217 (urlencoded body params):
```js
for (const pair of body.split("&")) {
  const eq = pair.indexOf("=");
  const k = eq < 0 ? pair : pair.slice(0, eq);
  const v = eq < 0 ? "" : pair.slice(eq + 1);
  if (k) bodyParams.push({ name: decodeURIComponent(k), value: decodeURIComponent(v) });
}
```

Lines 627-630 (ctxChangeBodyEncoding):
```js
for (const pair of trimmed.split("&")) {
  const eq = pair.indexOf("=");
  const k = eq < 0 ? pair : pair.slice(0, eq);
  const v = eq < 0 ? "" : pair.slice(eq + 1);
  if (k) params.push({ name: decodeURIComponent(k), value: decodeURIComponent(v) });
}
```

Note: the cookie split at line 203-204 (`const [cn, cv] = c.trim().split("=")`) has the same truncation pattern for cookie values containing '=' (e.g. base64 session tokens), so it would be worth applying the same fix there for completeness, though it was not in the original report.

_Verified (high): Confirmed in the actual file. At lines 186-187 (query params), 215-216 (urlencoded body params), and 628-629 (ctxChangeBodyEncoding) the code does `const [k, v] = pair.split("=")`. JS `String.split("=")` with no limit returns ALL segments, and array destructuring `[k, v]` keeps only the first two, discarding everything after the second `=`. So a value like `token=a.b.c=signature` or base64 padding `data=AAA==` is truncated: e.g. `"a=b=c".split("=") === ["a","b","c"]`, so `v` becomes `"b"` and `"=c"` is silently dropped (not just one char — the entire remainder). The corruption-on-round-trip consequence is also real: `parseInspector` (line 170) produces `queryParams`/`bodyParams`; `rebuildRequest` (line 366) unconditionally re-encodes the query string from `d.queryParams` (line 368-369) and the body from `d.bodyParams` (line 384-385) whenever those arrays are non-empty; `inspEdit` (line 390) deep-clones inspectorData, mutates any field, and calls `setRequest(rebuildRequest(d))`. Therefore editing any unrelated Inspector field re-emits the truncated param values back into the raw request, silently corrupting the user's payload. Nothing in the surrounding code prevents this; the code is reachable (the reactive `inspectorData` and the Inspector edit path are live UI). decodeURIComponent on an already-truncated `v` does not recover the lost data._


---

#### [x] #39 · `crates/lancer-gui/web/src/views/Repeater.svelte:480` · MEDIUM · correctness
**Error/cancel result is written to the wrong tab when the user switches tabs during an in-flight request**

**Problem:** send() captures `const s = tabStates[activeTab]` at the start (line 442) and the success path writes the response into `s` (lines 468-471), so it correctly targets the originating tab. The catch block instead writes to `tabStates[activeTab]` using the live activeTab. If the user switches to a different Repeater tab while a request is in flight and that request then errors or is cancelled, the error/'(request cancelled)' text is written into whatever tab is currently active, corrupting an unrelated tab's response and leaving the originating tab stuck on an empty response.

**Evidence:**
````
} catch (e) {
      tabStates[activeTab].response = cancelled ? "(request cancelled)" : `Error: ${e.message || e}`;
      tabStates = tabStates;
    } finally {
````

**Fix:** In the catch block (line 480), write to the captured tab state instead of the live active tab:

    } catch (e) {
      s.response = cancelled ? "(request cancelled)" : `Error: ${e.message || e}`;
      tabStates = tabStates;
    } finally {

`s` is the `tabStates[activeTab]` object captured at line 442 (a reference to the same object stored in the map), so writing `s.response` mutates the originating tab's state. Reassigning `tabStates = tabStates` afterward still triggers Svelte reactivity. This is safe and mirrors the success path which already uses `s`.

_Verified (high): Verified at crates/lancer-gui/web/src/views/Repeater.svelte. send() captures `const s = tabStates[activeTab]` (line 442) and the success path writes into `s` (lines 468-471), correctly targeting the originating tab. The catch block (line 480) instead writes `tabStates[activeTab].response` using the live, reactive `activeTab`. Tab switching is NOT guarded while a request is in flight: line 734 `on:click={() => (activeTab = t.id)}` changes activeTab unconditionally; only the Send button is disabled (line 757), and Cancel stays enabled (line 778, `disabled={!sending}`, sending is global). Because send() returns early when `sending` (line 441), no second request can start, so `controller`/`cancelled` unambiguously belong to the in-flight request. Thus if the user switches to another Repeater tab while the request is in flight and it then errors or is cancelled, the error/'(request cancelled)' text is written into the now-active (wrong) tab, corrupting its response, while the originating tab keeps its empty response (cleared at lines 445-446). The success path is unaffected by this only because it already uses `s`. The bug and stated consequence are genuine._


---

#### [x] #40 · `crates/lancer-gui/web/src/views/Target.svelte:139, 462, 470, 307` · MEDIUM · api-contract
**Title extraction and engagement tools read non-existent e.body/e.response_body, sending empty bodies**

**Problem:** Same shape mismatch as the Render tab: the response body is at e.response.body, not e.body/e.response_body. titleOf (line 139) therefore never derives a <title> from the response, so the Title column is blank for every entry that lacks a (non-existent) e.title field. ctxFindComments (line 462) and ctxFindScripts (line 470) POST `body: bytesToText(e.body || e.response_body)` to /v1/engagement/find-comments and /find-scripts — always an empty string, so these engagement tools analyze nothing. ctxSendToDecoder (line 307) likewise loses the real body and falls back to a synthetic formatResponse.

**Evidence:**
````
const body = bytesToText(e.body || e.response_body);   // titleOf
...
const body = bytesToText(e.body || e.response_body), url = engUrl(e);   // ctxFindComments
...
const body = bytesToText(e.body || e.response_body), base_url = engUrl(e);   // ctxFindScripts
````

**Fix:** Read the body from the nested response record at all four sites (these are all response-body consumers). Use the existing bytesToText helper to decode the byte array:
- line 133 (responseLength): const body = bytesToText(e.response?.body);
- line 139 (titleOf): const body = bytesToText(e.response?.body);
- line 462 (ctxFindComments): const body = bytesToText(e.response?.body), url = engUrl(e);
- line 470 (ctxFindScripts): const body = bytesToText(e.response?.body), base_url = engUrl(e);
- line 307 (ctxSendToDecoder): const text = bytesToText(e.response?.body) || formatResponse(e);  // raw byte array must be decoded
- line 535 (formatResponse): const body = bytesToText(e.response?.body) || "";  // same shape bug
Keep the optional chaining (e.response?.body) since response is Option and may be absent; bytesToText returns "" for null/undefined, preserving the existing empty-fallback behavior. Request-side tools (formatRequest, csrf-poc) are unaffected and need no change here.

_Verified (high): Confirmed against actual code. The backend HistoryRecord (crates/lancer-storage/src/history.rs:11-28) exposes request: HttpRequest and response: Option<HttpResponse>; HttpResponse.body is Bytes (serializes to a byte array) at e.response.body. The frontend (Target.svelte) already correctly reads e.response?.headers in mimeOf (124) and responseLength (131), proving the nested shape, yet reads the non-existent e.body / e.response_body for bodies. fetchHistory (638-645) uses entries raw with no normalization, so those fields are genuinely undefined. Consequences hold: titleOf (139) returns "" (HistoryRecord has no title field, so the Title column is always blank); ctxFindComments (462) and ctxFindScripts (470) POST an empty body string to the engagement endpoints, so they analyze nothing; ctxSendToDecoder (307) and formatResponse (535) lose the real body and fall back to a synthetic string. bytesToText (145) handles arrays, confirming a byte-array body is expected._


---

#### [x] #41 · `crates/lancer-gui/web/src/views/Target.svelte:524-530` · MEDIUM · correctness
**formatRequest discards captured headers/body; Send-to-Repeater/Intruder/Comparer/CSRF get a stripped synthetic request**

**Problem:** formatRequest only checks `e.raw_request` (which does not exist on the /v1/history record) and otherwise emits a hardcoded template containing just Host/User-Agent/Accept/Connection and no body, even though the full request is available at e.request.headers and e.request.body (ctxCopyAsCurl on line 332 already reads e.request.headers, proving the data is present). Consequently entryToSendPayload (used by Send to Repeater/Intruder), ctxSendToComparer('request') and ctxCsrfPoc all transmit a request missing the captured method-specific headers, cookies, auth, and POST/PUT body — so resending a captured POST loses its body and a session cookie is dropped.

**Evidence:**
````
function formatRequest(e) {
    if (e.raw_request) return e.raw_request;
    const method = e.method || "GET";
    const path = e.path || "/";
    const host = e.host || "";
    return `${method} ${path} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: Lancer/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n`;
  }
````

**Fix:** Reconstruct the wire request from the captured e.request when present, falling back to the synthetic template only if it is missing:

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
      if (h.name.toLowerCase() === "host") hasHost = true;
      out += `${h.name}: ${h.value}\r\n`;
    }
    if (!hasHost && (e.host || req.host)) out += `Host: ${e.host || req.host}\r\n`;
    out += "\r\n";
    out += bytesToText(req.body);
    return out;
  }
  // fallback: no captured request object
  const method = e.method || "GET";
  const path = e.path || "/";
  const host = e.host || "";
  return `${method} ${path} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: Lancer/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n`;
}

Notes: req.version is a serde enum string ("Http11"/"Http10"); bytesToText (already defined at line 145) correctly decodes the byte-array body and returns "" for empty/GET bodies. Verify with `npm run build` in crates/lancer-gui/web.

_Verified (high): Confirmed by reading the real code. Target.svelte:524-530 has formatRequest exactly as cited. It checks only `e.raw_request`, which never exists on /v1/history records: the backend HistoryRecord (crates/lancer-storage/src/history.rs:11-29) serializes with NO raw_request field; it exposes top-level method/path/host plus a nested `request: HttpRequest` whose serde shape is headers: Vec<Header> ([{name,value}]) and body: Bytes serialized via serialize_bytes → a JSON byte array (http_msg.rs:179-181, 471-472). Because raw_request is undefined, formatRequest always falls through to the hardcoded GET-style template with only Host/User-Agent/Accept/Connection and no body. That template feeds entryToSendPayload (line 264, used by ctxSendToRepeater line 277 and ctxSendToIntruder line 286), ctxSendToComparer('request') (line 295), ctxCsrfPoc (line 486), and the request display panes (lines 1033/1035). So resending a captured POST/PUT loses its body, and captured cookies/auth/content-type/method-specific headers are dropped — the stated consequence. The data is provably present: ctxCopyAsCurl (line 332) already iterates e.request.headers, and bytesToText (line 145) already decodes the byte-array body shape. None of Rust's typing prevents this (it's a frontend reconstruction gap), the code is reachable (wired into context-menu actions and the request viewer), and the proposed fix matches the verified serialization shape._


---

#### [x] #42 · `crates/lancer-llm-redteam/src/lib.rs:275` · MEDIUM · security
**TLS certificate validation disabled while sending the LLM API key as a bearer token**

**Problem:** The reqwest client used for ALL outbound LLM calls is built with `.danger_accept_invalid_certs(true)`, unconditionally disabling TLS certificate and hostname validation. Every `chat_call` then attaches the configured API key via `req.header("Authorization", format!("Bearer {k}"))` (line 82). Because the connection accepts any certificate, an active network man-in-the-middle can present a forged cert, terminate the TLS session, and capture the plaintext Authorization header — leaking the user's target/attacker LLM API key (e.g. an OpenAI/Anthropic secret). This affects the real network behaviour of the tool, not a theoretical edge case: any non-loopback endpoint becomes vulnerable to credential theft.

**Evidence:**
````
let client = reqwest::Client::builder()
    .timeout(std::time::Duration::from_secs(60))
    .danger_accept_invalid_certs(true)
    .build()
````

**Fix:** Add an explicit, default-false opt-in to LlmConfig (or SessionRequest) and only disable TLS validation when it is set, so a bearer API key is never sent over an unvalidated connection by default.

1) Add a field to LlmConfig:
   #[derive(Debug, Clone, Serialize, Deserialize)]
   pub struct LlmConfig {
       pub endpoint: String,
       pub api_key: Option<String>,
       pub model: String,
       #[serde(default)]
       pub allow_insecure_tls: bool,
   }

2) In run_session(), compute the flag from the request (e.g. either endpoint opting in) and build the client conditionally:
   let allow_insecure = req.target.allow_insecure_tls || req.attacker.allow_insecure_tls;
   let client = reqwest::Client::builder()
       .timeout(std::time::Duration::from_secs(60))
       .danger_accept_invalid_certs(allow_insecure)
       .build()
       .unwrap_or_else(|_| reqwest::Client::new());

This keeps support for self-signed/local LLM endpoints (set allow_insecure_tls = true explicitly) while restoring validated TLS — and thus protecting the bearer token — for the default remote-provider case. The other scanner crates that use the same flag against targets-under-test (authbypass, bulkprobe, cms, api-routes, stateful-fuzz) do not transmit secret credentials and are out of scope for this specific finding; only mcp-scan and llm-scan should be reviewed separately if they likewise send API keys.

_Verified (high): Verified in crates/lancer-llm-redteam/src/lib.rs. Line 273-277: the shared reqwest client in run_session() is built with .danger_accept_invalid_certs(true), unconditionally disabling TLS certificate AND hostname validation for every outbound call. chat_call() (line 80-82) attaches the configured secret as `Authorization: Bearer {api_key}` from cfg.api_key. The default target endpoint documented at line 29 is https://api.openai.com/v1/chat/completions — a real remote provider over the public internet. LlmConfig (line 28-33) and SessionRequest (line 35-47) have no opt-in field for insecure TLS, so this is hardcoded on with no escape. run_session is the public entry point and dispatches to all strategies, every one of which calls chat_call, so the path is fully reachable. Rust's type system does not mitigate this — danger_accept_invalid_certs compiles and runs as a runtime no-validation TLS config. Consequence stands: an active network MITM can present a forged certificate, terminate the TLS session, and read the plaintext Authorization header, leaking the user's OpenAI/Anthropic-style API key. Note: this danger flag appears in 8 crates repo-wide, but in the scanner/probe crates it is a defensible default (they connect to hostile targets-under-test that carry no secret credentials). lancer-llm-redteam is the genuine exception because it transmits a bearer secret to a configurable remote endpoint, which is exactly the credential-theft scenario described. The flag most likely exists to support self-signed/local test LLM endpoints, so the fix must preserve that capability via explicit opt-in rather than a blanket removal._


---

#### [x] #43 · `crates/lancer-proxy/src/ca_import.rs:21-28` · MEDIUM · correctness
**import_from_pem does not actually verify the imported cert and key match**

**Problem:** The comment-bearing call `params.self_signed(&kp)` does not check that `kp` is the private key corresponding to the imported certificate. `CertificateParams::from_ca_cert_pem` extracts only the subject/extensions from the cert, and `self_signed(&kp)` then mints a brand-new self-signed certificate from those params using whatever key is passed — it succeeds for any valid keypair. So a mismatched cert+key pair passes the `imported cert + key don't pair` guard. The mismatched pair is then written to disk; load_or_create serves the imported cert_pem to clients while signing leaf certs with the imported ca_key. If they truly don't pair, every minted leaf fails signature validation in the browser and all MITM TLS breaks, with no error at import time.

**Evidence:**
````
let kp = KeyPair::from_pem(&key_pem).context("parsing imported key")?;
let params = CertificateParams::from_ca_cert_pem(&cert_pem)
    .context("parsing imported CA certificate")?;
let _cert = params
    .self_signed(&kp)
    .context("imported cert + key don't pair")?;
````

**Fix:** In import_from_pem (crates/lancer-proxy/src/ca_import.rs), after parsing kp, actually compare the imported certificate's SubjectPublicKeyInfo against the keypair's public key instead of relying on self_signed. x509-parser is already a dependency:

use x509_parser::prelude::*;

// after: let kp = KeyPair::from_pem(&key_pem)...;
// extract the cert's SPKI and compare it to the key's public key DER
let der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
    .next()
    .ok_or_else(|| anyhow::anyhow!("imported CA pem has no certificate"))??;
let (_, parsed) = X509Certificate::from_der(der.as_ref())
    .context("parsing imported CA certificate DER")?;
let cert_spki = parsed.public_key().raw;           // full SubjectPublicKeyInfo DER
let key_spki = kp.public_key_der();                // rcgen KeyPair SPKI DER
if cert_spki != key_spki.as_slice() {
    anyhow::bail!("imported certificate and private key do not match");
}

// keep parsing params for validation, but the pairing is now actually enforced:
let params = CertificateParams::from_ca_cert_pem(&cert_pem)
    .context("parsing imported CA certificate")?;
let _ = params; // params no longer used for a misleading pairing check

This bails with a clear error on a mismatched pair before anything is written to disk. (Note: compare the raw SPKI DER on both sides; rcgen's public_key_der() returns the SPKI, which matches x509-parser's public_key().raw.) Leave the rest (writing cert.pem/key and load_or_create) unchanged.

_Verified (high): Confirmed by reading the actual code. ca_import.rs:20-25 is exactly as cited. With rcgen 0.13.2, CertificateParams::from_ca_cert_pem extracts only the cert's parameters (DN, extensions, validity) and does NOT retain the certificate's public key; params.self_signed(&kp) then mints a brand-new self-signed cert using kp's own public key and signs it with kp's private key. It succeeds for any valid keypair and never compares against the imported certificate's public key, so the `imported cert + key don't pair` guard is a no-op. The consequence is real: ca_import.rs:26-27 writes the ORIGINAL imported cert_pem and key_pem to disk; load_or_create (ca.rs:55-72) loads them, and cert_pem()/der() (ca.rs:112-128, served via lancer-api main.rs:600-609 for browser import) return the imported cert, while mint_leaf (ca.rs:130-152) signs leaves with self.ca_key and cert_cache.rs:38 builds the served chain from leaf + imported CA cert. If the imported key does not pair with the imported cert, every minted leaf fails signature validation against the CA the browser trusts, breaking all MITM TLS — with no error at import time. The dependency needed for the fix (x509-parser 0.16) is already declared in crates/lancer-proxy/Cargo.toml._


---

#### [x] #44 · `crates/lancer-proxy/src/sse.rs:52` · MEDIUM · parsing
**SSE chunk tail drops already-parsed fields of an in-progress event**

**Problem:** When a chunk ends mid-event after one or more complete field lines, `tail_start = last_blank.max(line_start)` advances past those completed lines instead of back to the start of the in-progress event (`last_blank`). Because `line_start` (start of the final incomplete line) is greater than `last_blank` (end of the last blank-line/event boundary), the returned tail begins at the last partial line and SILENTLY DISCARDS every complete field line of the current event. Example: feeding "data: x\n\nid: 7\ndata: tail" returns tail="data: tail" and the "id: 7" line is lost forever; when the next chunk arrives the event will be missing its id. The unit test only asserts tail.contains("tail"), so it does not catch the loss. This corrupts streamed SSE events whose fields straddle a network read boundary.

**Evidence:**
````
tail_start = last_blank.max(line_start);
    let tail = std::str::from_utf8(&bytes[tail_start..]).unwrap_or("").to_string();
````

**Fix:** In crates/lancer-proxy/src/sse.rs, start the tail at the last event boundary so the whole in-progress event is carried over. Remove the placeholder declaration on line 22 (`let mut tail_start = 0;`) and replace line 52 with:

    let tail_start = last_blank;
    let tail = std::str::from_utf8(&bytes[tail_start..]).unwrap_or("").to_string();

The bytes from `last_blank` onward are exactly the partially-accumulated event; the local `cur` is discarded on return, so its fields will be correctly re-parsed when this tail is prepended to the next chunk. (No separate `cur` reset is needed since `cur` is never returned.) Also recommend strengthening the unit test to assert tail == "id: 7\ndata: tail" rather than merely tail.contains("tail").

_Verified (high): The cited code at crates/lancer-proxy/src/sse.rs:52 (`tail_start = last_blank.max(line_start);`) is present exactly as described. Tracing the reported input "data: x\n\nid: 7\ndata: tail": after the loop last_blank=9 (just past the blank line) and line_start=15 (start of the final partial "data: tail"). tail_start = 9.max(15) = 15, so tail = "data: tail" and the already-parsed "id: 7" line is dropped. The parsed-but-incomplete event lives only in the local `cur`, which is NOT returned (only `events` and `tail` are), so those fields are lost forever. Rust's type system does not prevent this — it is a pure logic error. Since last_blank is always <= the current line_start, .max() always selects line_start whenever a partial event has any content after the last boundary, so the bug bites generally (e.g. it also loses a whole event with complete lines but no trailing blank). The existing test only asserts tail.contains("tail"), which the buggy output satisfies, so it does not catch the loss. Caveat lowering practical impact: `parse_chunk` has NO callers anywhere in the workspace (only the def + its own test reference it); SSE chunk-streaming is not yet wired into the proxy pipeline, so today the bug is latent/unreached. But it is a genuine defect in a public function. The proposed fix (tail_start = last_blank) is correct and safe: it returns the entire unfinished event for re-parsing on the next chunk, and `cur` need not be explicitly reset because it is a non-returned local (the report's note to "reset cur" is unnecessary but harmless). When the chunk ends exactly on a boundary, line_start == last_blank so the tail is correctly empty._


---

#### [x] #45 · `crates/lancer-replay/src/id_mutate.rs:103` · MEDIUM · correctness
**Body ID mutation lossily round-trips through UTF-8, corrupting non-UTF-8 request bodies**

**Problem:** For body-located candidates the request body is decoded with `String::from_utf8_lossy` and re-encoded with `into_bytes()`. Any non-UTF-8 bytes in the original body (binary uploads, multipart payloads with binary parts, gzip/protobuf bodies) are replaced by the U+FFFD replacement sequence on decode and that corruption is persisted back into `req.body`. The replayed request is then a corrupted version of the original, breaking the comparison against the baseline and potentially causing the server to reject every mutated request. ID candidates are ASCII, so a byte-level replacement avoids the corruption entirely.

**Evidence:**
````
let body: String = String::from_utf8_lossy(&base.body).replacen(&c.value, mutated, 1);
        req.body = bytes::Bytes::from(body.into_bytes());
````

**Fix:** Replace the lossy String round-trip with a byte-level first-occurrence splice that preserves all original bytes:

```rust
} else {
    let mut req = base.clone();
    let needle = c.value.as_bytes();
    if let Some(pos) = base
        .body
        .windows(needle.len())
        .position(|w| w == needle)
    {
        let mut new_body = Vec::with_capacity(base.body.len() + mutated.len());
        new_body.extend_from_slice(&base.body[..pos]);
        new_body.extend_from_slice(mutated.as_bytes());
        new_body.extend_from_slice(&base.body[pos + needle.len()..]);
        req.body = bytes::Bytes::from(new_body);
    }
    // else: candidate not found at byte level (shouldn't happen since it was
    // detected from the body); leave body unchanged.
    req
}
```

This preserves non-UTF-8 bytes, replaces only the first occurrence (matching `replacen(..., 1)` semantics), and works because ID candidate values are ASCII. Guard against `needle.len() == 0` is unnecessary since candidates always have length >= 1.

_Verified (high): Confirmed at crates/lancer-replay/src/id_mutate.rs:103-104. `mutate_request` for body-located candidates does `String::from_utf8_lossy(&base.body)` then `.replacen(...).into_bytes()`, persisting the lossy decode back into `req.body`. For any body containing non-UTF-8 bytes (binary uploads, multipart binary parts, protobuf/gzip), `from_utf8_lossy` substitutes U+FFFD for invalid sequences, and `into_bytes()` writes that corruption into the replayed request — the original bytes are irrecoverably lost. The baseline (line 111) is sent unmodified via `base`, so each mutated request is corrupted relative to a clean baseline, breaking the token_similarity/IDOR comparison and potentially causing the server to reject every mutation. ID candidates (int per int_re, uuid per uuid_re) are pure ASCII, so a byte-level replace is fully sufficient and lossless. The defect, mechanism, and consequence are all accurate. Severity medium is fair: pure-text bodies (JSON/form) round-trip cleanly, so only binary bodies are affected._


---

#### [x] #46 · `crates/lancer-scanner/src/active/host_header.rs:65-69` · MEDIUM · logic-error
**is_first_point() throttle is effectively always-true, so Host-header probes fire for every insertion point**

**Problem:** The check is documented as "Only run once per request" and the gate is is_first_point(). But is_first_point returns `point.name == "Host" || point.original_value.is_empty() == false`. The second clause is true for essentially every insertion point the engine offers (any query param, body param, cookie, etc. that has a non-empty value). As a result the throttle never throttles: the two Host-header probe requests (evil.example.com and evil.example.com:443) are re-sent for every insertion point on the request. This multiplies outbound traffic by the number of insertion points and can emit duplicate "Host-header injection" issues for the same finding, defeating the stated single-run intent.

**Evidence:**
````
fn is_first_point(point: &InsertionPoint) -> bool {
    // Cheap sentinel ... Run on the very first param the engine offers.
    point.name == "Host" || point.original_value.is_empty() == false
}
````

**Fix:** Gate on the unique, reliably-present Host-header insertion point only — drop the always-true second clause, and match case-insensitively since header names are stored verbatim:

fn is_first_point(point: &InsertionPoint) -> bool {
    // The Host header is offered as exactly one insertion point per HTTP/1.1
    // request, so use it as the stable single-run sentinel for this
    // request-level check (it does not depend on the insertion point).
    point.name.eq_ignore_ascii_case("Host")
}

This makes the check fire exactly once per request (no traffic amplification, no duplicate issues) while still always running when a Host header exists. Do NOT use `point.original_value.is_empty()` as suggested in the report — empty-valued points may not exist (false negatives) or may exist multiple times (still duplicated).

_Verified (high): Verified in crates/lancer-scanner/src/active/host_header.rs:65-69. The throttle gate is `point.name == "Host" || point.original_value.is_empty() == false`. The engine (engine.rs:67-85) spawns a task for every insertion point x every check, and insertion points come from Inspector (every query/body/cookie/header param). The second clause `!original_value.is_empty()` is true for essentially every populated parameter, so the "run once per request" gate fires for nearly every insertion point. Consequence confirmed: the two Host probes (evil.example.com, evil.example.com:443) are re-sent per insertion point (outbound traffic multiplied by point count), and because the in-call `return issues` only dedups within a single run() call, multiple per-point calls that detect reflection each emit a duplicate "Host-header injection" issue. Rust's type system does not prevent this; the code is reachable (registered active check). The finding's own CONCRETE proposed fix (`point.original_value.is_empty()`) is unsafe: empty-valued insertion points are not guaranteed to exist, so the check could become a false-negative (never runs) or still run multiple times if several empty params exist. The correct sentinel is the Host header param itself, which exists exactly once per HTTP/1.1 request; header param names are stored verbatim (Inspector uses h.name as-is), so the match should be case-insensitive for robustness._


---

#### [x] #47 · `crates/lancer-scanner/src/active/race.rs:23-51` · MEDIUM · resource-leak
**Point-agnostic active check fires once per insertion point, multiplying concurrent state-changing requests and emitting duplicate issues**

**Problem:** The scan engine invokes every active check once for EVERY insertion point of a request (engine.rs lines 67-85: `for point in points { for ck in active_checks { ... ck.run(&client,&base,&point) } }`), and there is no dedup of resulting issues (engine.rs collects and persists all of them; IssueStore::insert always inserts a fresh row). RaceConditionCheck ignores `_point` and, for any POST/PUT/PATCH/DELETE, fires PARALLEL=12 concurrent copies of the SAME request. A request with N insertion points (query params, JSON fields, headers, cookies) therefore triggers 12*N concurrent state-changing requests against the live target instead of 12, and emits up to N identical 'Race condition candidate' issues. The same once-per-point amplification/duplication affects every check in this batch that ignores `_point`: oauth.rs, proto_pollution.rs, react2shell.rs, smuggling.rs, subdomain_takeover.rs.

**Evidence:**
````
async fn run(&self, client: &HttpClient, base: &HttpRequest, _point: &InsertionPoint) -> Vec<Issue> {
    if !matches!(base.method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE") { return Vec::new(); }
    ... for _ in 0..PARALLEL { ... tokio::spawn(... client.send(&req) ...) }
````

**Fix:** Gate each point-agnostic active check so it fires only for the first insertion point of the base request, mirroring mass_assignment.rs's dedup intent. For race.rs, add at the top of `run` (after computing points once):

    // Point-agnostic check: run a single time per request, not once per insertion point.
    if let Some(first) = crate::insertion::find_insertion_points(base).first() {
        if first.name != _point.name || first.location != _point.location {
            return Vec::new();
        }
    }

(then rename `_point` to `point`). Apply the same guard to the other 13 point-agnostic checks (react2shell.rs, oauth.rs, proto_pollution.rs, smuggling.rs, subdomain_takeover.rs, clickjacking.rs, cache_poison.rs, cors.rs, host_header.rs, xxe.rs, gadget_probe.rs, backslash_powered.rs, upload.rs) — though only the state-changing/network-amplifying ones (race especially) are urgent.

A cleaner, less error-prone alternative (option a) is to add a `fn uses_insertion_point(&self) -> bool { true }` default method to the ActiveCheck trait, override it to `false` on point-agnostic checks, and in ScanEngine::run_active run such checks exactly once (outside the per-point loop). This avoids recomputing find_insertion_points inside every check and centralizes the dedup. Either fix is safe and does not change which targets are probed — only how many times.

_Verified (high): Verified against the actual code. engine.rs run_active (lines 67-85) nests `for point in points { for ck in active_checks { ... ck.run(&client, &base, &point) } }`, so every active check runs once per insertion point. race.rs (lines 23-51) takes `_point` (unused) and, for any POST/PUT/PATCH/DELETE, spawns PARALLEL=12 concurrent identical `client.send` calls and may emit one Issue — with no point-awareness or dedup. The engine collects every check's output into `out` and persist() calls `store.insert(i)` unconditionally for each, so duplicates become distinct rows (no dedup). Therefore a request with N insertion points yields 12*N concurrent state-changing requests and up to N identical 'Race condition candidate' issues — exactly as reported. The broader claim is also confirmed: a grep shows 14 active checks ignore the point via `_point: &InsertionPoint`, including the named race, react2shell, oauth, proto_pollution, smuggling, subdomain_takeover. mass_assignment.rs (lines 40-62) does attempt a first-point dedup guard, confirming the maintainer already uses this pattern, and race.rs lacks any equivalent. InsertionPoint has no PartialEq but ParamLocation derives PartialEq/Eq, so a first-point comparison by (name, location) is sound. The consequence (resource amplification on a live target + duplicate issues) genuinely follows._


---

#### [x] #48 · `crates/lancer-scanner/src/passive/cookies.rs:34-36` · MEDIUM · correctness
**Cookie security-flag detection uses substring match over the whole header (false negatives)**

**Problem:** `secure`, `http_only`, and `same_site_present` are derived by `lower.contains(...)` over the entire lowercased Set-Cookie header value, which includes the cookie name and value, not just the attributes. Any cookie whose name or value contains the substring `secure`, `httponly`, or `samesite=` will be treated as having that attribute set, silently suppressing the corresponding finding. For example `Set-Cookie: insecure_pref=1; Path=/` sent over HTTPS contains `secure`, so the 'Cookie without Secure flag' issue is never raised even though the Secure attribute is absent; likewise a value like `token=httponly_disabled` suppresses the HttpOnly check. This produces false negatives in a security tool.

**Evidence:**
````
let secure = lower.contains("secure");
let http_only = lower.contains("httponly");
let same_site_present = lower.contains("samesite=");
````

**Fix:** Only inspect the attribute segments (everything after the first `;`), matching whole trimmed attribute tokens case-insensitively rather than substringing the full header. Replace lines 34-36:

```rust
let mut secure = false;
let mut http_only = false;
let mut same_site_present = false;
for attr in value.split(';').skip(1) {
    let attr = attr.trim();
    if attr.eq_ignore_ascii_case("secure") {
        secure = true;
    } else if attr.eq_ignore_ascii_case("httponly") {
        http_only = true;
    } else if attr.len() >= 8 && attr[..8].eq_ignore_ascii_case("samesite") {
        // matches `SameSite` or `SameSite=Lax`
        let rest = &attr[8..];
        if rest.is_empty() || rest.starts_with('=') {
            same_site_present = true;
        }
    }
}
```

This skips the first (name=value) segment, so cookie names/values can no longer satisfy the attribute checks. Using `eq_ignore_ascii_case` on trimmed tokens avoids the need for the separate `lower` allocation for these checks (the `lower` binding may then be unused and can be removed if not referenced elsewhere). Note: this preserves the existing slightly-loose SameSite semantics by also accepting a bare `SameSite` token; if you want to keep parity with the original (which required `samesite=`), check `rest.starts_with('=')` only. The fix does not alter the `cookie_name` parsing or the issue-emission logic, so no other behavior changes.

_Verified (high): Code at crates/lancer-scanner/src/passive/cookies.rs:34-36 matches the report exactly. `lower` is the entire lowercased Set-Cookie header (name=value plus attributes), and the three flags are derived via `lower.contains(...)` over that whole string. So a cookie like `Set-Cookie: insecure_pref=1; Path=/` over HTTPS contains the substring "secure" (within "insecure") and the Secure-flag issue is suppressed; a value containing "httponly" suppresses the HttpOnly check. The check is a registered, reachable PassiveCheck; nothing in the type system prevents this. This is a genuine false-negative in a security tool. The proposed fix (parse only the attribute segments after the first `;`) is correct._


---

#### [x] #49 · `crates/lancer-stateful-fuzz/src/lib.rs:191-192` · MEDIUM · panic
**replace_range can panic on a spec path where '}' precedes '{'**

**Problem:** `path.find('{')` and `path.find('}')` are computed independently. For a path string sourced from the (attacker/third-party-controlled) OpenAPI spec that contains a '}' before the first '{' — e.g. `/a}b/{id}` — `s` (index of '{') will be greater than `e` (index of the first '}'). The inclusive range `s..=e` is then a backwards range, and `String::replace_range` panics with "slice index starts at N but ends at M". Because `run_sequence` is awaited inside `run_fuzz`, this panic propagates up through the async task and aborts the fuzz run on a single malformed path.

**Evidence:**
````
if let (Some(s), Some(e)) = (path.find('{'), path.find('}')) {
    path.replace_range(s..=e, id);
}
````

**Fix:** Replace lines 191-193 with a search for the closing brace after the opening one so the range is always well-formed:

```rust
if let Some(s) = path.find('{') {
    if let Some(rel) = path[s..].find('}') {
        let e = s + rel; // '}' is guaranteed to be at or after '{'
        path.replace_range(s..=e, id);
    }
}
```

This keeps existing behavior for normal `/resource/{id}` templates (replacing the first `{...}` segment with the produced id) while guaranteeing e >= s, eliminating the panic on malformed spec paths such as `/a}b/{id}`.

_Verified (high): Code at crates/lancer-stateful-fuzz/src/lib.rs:191-192 matches the report exactly: `if let (Some(s), Some(e)) = (path.find('{'), path.find('}')) { path.replace_range(s..=e, id); }`. The two finds are independent, so for a path with '}' before '{' (e.g. `/a}b/{id}`), s>e and the inclusive range `s..=e` is backwards. `String::replace_range` panics on a start>end range ("slice index starts at N but ends at M"). The path comes straight from the OpenAPI spec paths object (line 104, no sanitization). The consumer-op gate at line 164 only checks `contains("{") && contains("}")`, which `/a}b/{id}` satisfies — it does NOT require '{' to precede '}'. The replace runs only when `produced_id` is Some (i.e. step >0 after the producer returned a JSON `id`), which is the normal producer→consumer flow this code exists for, so it is reachable with a live target. `run_sequence` is `.await`ed directly inside `run_fuzz`'s loop (line 272) with no catch_unwind, so the panic propagates and aborts the fuzz run, matching the stated consequence. The proposed fix correctly finds '}' only within `path[s..]` so e>=s is guaranteed, slicing on the ASCII '{' byte boundary is valid, and the normal `{id}` case is unchanged._


---

#### [x] #50 · `crates/lancer-tools/src/auth_matrix.rs:46-56` · MEDIUM · logic-error
**Matrix replay leaks the original request's Authorization for cookie-only identities**

**Problem:** For an identity with `cookie: Some(non_empty)` and `authorization: None`, the match arm only calls `set_header("Cookie", c)` and the `if let Some(a) = &id.authorization` block is skipped, so any `Authorization` header carried on the captured `req` is left intact. The cell is then computed as if that identity were authenticated via the original token, corrupting the access-control grid (a low-priv/cookie-only identity appears to have privileged access). Only the empty-cookie arm removes Authorization.

**Evidence:**
````
(Some(c), _) => r.set_header("Cookie", c.clone()),
_ => {}
}
if let Some(a) = &id.authorization {
    r.set_header("Authorization", a.clone());
}
````

**Fix:** Strip all inherited credential headers at the start of each identity, then apply only what the identity declares, so no request carries another identity's (or the original capture's) credentials:

```rust
for id in identities {
    let mut r = req.clone();
    // Never inherit credentials from the captured request or a prior identity.
    r.remove_header("Cookie");
    r.remove_header("Authorization");
    if let Some(c) = &id.cookie {
        if !c.is_empty() {
            r.set_header("Cookie", c.clone());
        }
    }
    if let Some(a) = &id.authorization {
        if !a.is_empty() {
            r.set_header("Authorization", a.clone());
        }
    }
    let resp = client.send(&r).await.unwrap_or_else(|_| HttpResponse::new(0));
    row.insert(id.name.clone(), MatrixCell { status: resp.status, length: resp.body.len() });
}
```

This replaces the prior `match`/`if let` block and fixes the reported cookie-only leak plus the analogous Cookie leaks in the `(None, _)` cases.

_Verified (high): Code at crates/lancer-tools/src/auth_matrix.rs:45-56 matches the report. Each identity replay starts from `req.clone()`, which carries the captured request's original Cookie/Authorization headers. For an identity with `cookie: Some(non_empty), authorization: None`, the match arm `(Some(c), _) => r.set_header("Cookie", c)` sets the cookie but the following `if let Some(a) = &id.authorization` block is skipped, so the inherited Authorization header survives. The resulting cell reflects access granted by the original privileged token rather than by the cookie-only identity, corrupting the access-control grid — exactly the stated consequence. Rust's type system does not prevent this (None simply means "don't overwrite"). The function is reachable (AuthMatrix tool/API). The bug is actually broader: the `(None, _)` arms also leak the inherited Cookie, and `(None, None)` leaks both credentials; only the empty-cookie arm clears them. set_header/remove_header both exist on HttpRequest, so the fix is safe._


---

#### [x] #51 · `crates/lancer-tools/src/crawler.rs:103-138` · MEDIUM · logic-error
**Crawler is serial: `concurrency` config is silently ignored**

**Problem:** The crawl loop acquires a semaphore permit, spawns the fetch task, then immediately blocks on `handle.await` in the same loop iteration before popping the next URL. As a result only one request is ever in flight regardless of `config.concurrency`; the `Semaphore::new(self.config.concurrency.max(1))` and `tokio::spawn` add overhead but provide no parallelism. The advertised `concurrency` setting has no effect.

**Evidence:**
````
let permit = sem.clone().acquire_owned().await?;
...
let handle = tokio::spawn(async move { ... });
count += 1;
let (next, fingerprint) = match handle.await.ok().flatten() {
````

**Fix:** Drive concurrency with a tokio JoinSet, only awaiting completions when the in-flight set is saturated, and do the seen/queue/fingerprint bookkeeping as each task completes (not inline after spawn). Have each task return the source url+depth alongside (found, fingerprint) so the consumer can update state. Sketch:

```rust
use tokio::task::JoinSet;

let limit = self.config.concurrency.max(1);
let mut tasks: JoinSet<Option<(String, usize, Vec<String>, String)>> = JoinSet::new();

loop {
    // Fill up to `limit` in-flight fetches from the queue.
    while tasks.len() < limit {
        if count >= self.config.max_pages { break; }
        let Some((url, depth)) = queue.pop_front() else { break; };
        let req = match HttpRequest::builder("GET", &url) { Ok(r) => r, Err(_) => continue };
        if !self.scope.read().is_in_scope(&req) { continue; }
        count += 1;
        let permit = sem.clone().acquire_owned().await?;
        let client = self.client.clone();
        let throttle = self.config.throttle_ms;
        let url_clone = url.clone();
        let entry_host = url::Url::parse(entry_url).ok()
            .and_then(|u| u.host_str().map(|s| s.to_string()));
        let follow_subs = self.config.follow_subdomains;
        let include_scripts = self.config.include_scripts;
        let sink2 = sink.clone();
        tasks.spawn(async move {
            let _permit = permit;
            if throttle > 0 { tokio::time::sleep(Duration::from_millis(throttle)).await; }
            let resp = client.send(&req).await.ok()?;
            let body = resp.body_text().unwrap_or("").to_string();
            let fingerprint = location_fingerprint(&body, resp.status);
            sink2.observed(&req, &resp).await;
            let mut found = Vec::new();
            for href in find_anchors(&body, &url_clone) {
                if same_host(&href, entry_host.as_deref(), follow_subs) { found.push(href); }
            }
            if include_scripts {
                for src in find_scripts(&body, &url_clone) {
                    if same_host(&src, entry_host.as_deref(), follow_subs) { found.push(src); }
                }
            }
            Some((url_clone, depth, found, fingerprint))
        });
    }

    // Nothing running and nothing queued (or page cap hit) -> done.
    let Some(joined) = tasks.join_next().await else { break; };
    let Some((url, depth, next, fingerprint)) = joined.ok().flatten() else { continue; };

    if let Some(prev) = fingerprints.get(&fingerprint) {
        tracing::debug!(this = %url, mirrors = %prev, "skipping; same location fingerprint");
        continue;
    } else {
        fingerprints.insert(fingerprint, url.clone());
    }
    if depth + 1 > self.config.max_depth { continue; }
    for n in next {
        if seen.insert(n.clone()) { queue.push_back((n, depth + 1)); }
    }
}
Ok(count)
```

Notes: the outer `loop` terminates when `join_next()` returns `None` (no in-flight tasks) and the inner fill loop added none (queue empty or max_pages reached). The semaphore is now redundant with the JoinSet cap but harmless to keep. Returning the source `url`/`depth` from the task preserves the original per-URL bookkeeping semantics. Watch ordering: this makes traversal order non-deterministic vs the prior strict BFS, which is acceptable for a crawler but worth noting if any test asserts an exact crawl order.

_Verified (high): Confirmed by reading crates/lancer-tools/src/crawler.rs lines 91-161. The loop pops one URL, acquires a semaphore permit, spawns the fetch task, then immediately `handle.await`s that same task (line 138) before looping back to pop the next URL. Therefore only one request is ever in flight; the semaphore (capacity = config.concurrency) never holds more than one permit and tokio::spawn yields no parallelism. The seen/queue/fingerprint bookkeeping (lines 145-158) is performed inline using the just-completed task's return value, which is why it is serialized. The code is live: reachable from the CLI `crawl` subcommand (crates/lancer-cli/src/commands/crawl.rs:46) and the API endpoint `/v1/crawl/deep` (crates/lancer-api/src/main.rs:2089), and `concurrency` defaults to 8 and is user-configurable. Rust's type system does not prevent this — it is purely a control-flow logic error. The advertised `concurrency` setting has no effect._


---

#### [x] #52 · `crates/lancer-tools/src/engagement.rs:118-129` · MEDIUM · correctness
**CSRF PoC double-encodes form values from urlencoded bodies**

**Problem:** generate_csrf_poc parses the request body's name=value pairs straight out of an application/x-www-form-urlencoded body and places the raw (still percent-encoded) value into the HTML input's value attribute after only html_escape. The values in a urlencoded body are percent-encoded (e.g. body `q=a%20b` or `pass=hunter%2B2`). When the generated form auto-submits, the browser percent-encodes the field value AGAIN, so `a%20b` is sent as `a%2520b`. The reproduced request therefore does not match the original captured request, making the CSRF PoC invalid for any parameter whose value contains an encoded character (spaces, +, &, =, non-ASCII, etc.).

**Evidence:**
````
if let Ok(body) = std::str::from_utf8(&req.body) {
    for pair in body.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            html.push_str(&format!(
                "  <input type=\"hidden\" name=\"{}\" value=\"{}\" />\n",
                html_escape(k),
                html_escape(v),
            ));
````

**Fix:** Percent-decode (and handle `+`-as-space) each key and value before html_escape, so the browser re-encodes them back to the original wire form on submit. Replace lines 122-126 with:

let dk = decode_form_component(k);
let dv = decode_form_component(v);
html.push_str(&format!(
    "  <input type=\"hidden\" name=\"{}\" value=\"{}\" />\n",
    html_escape(&dk),
    html_escape(&dv),
));

and add a helper:

fn decode_form_component(s: &str) -> String {
    // application/x-www-form-urlencoded uses '+' for space
    let s = s.replace('+', " ");
    percent_encoding::percent_decode_str(&s).decode_utf8_lossy().into_owned()
}

(percent-encoding is already a workspace dep; add `percent-encoding.workspace = true` to crates/lancer-tools/Cargo.toml, or reuse lancer-core which is already a dependency. Note: handling '+' is required and is missing from the originally proposed fix.)

_Verified (high): The cited code at crates/lancer-tools/src/engagement.rs:118-129 matches the evidence exactly and is reachable (public generate_csrf_poc, used by the engagement tool/CLI/API). The defect is genuine: name=value pairs from an application/x-www-form-urlencoded body are still percent-encoded on the wire, but the code only html_escapes them before placing them in the HTML input value attribute. On auto-submit a browser percent-encodes the value attribute AGAIN for urlencoded enctype, so a captured body `q=a%20b` (literal `a b`) is emitted as value="a%20b" and re-sent as `q=a%2520b`, which does not reproduce the original request — invalidating the PoC for any value containing encoded chars. This is proven by lancer-core's own parse_form_urlencoded (inspector.rs:123-137), which correctly percent-decodes both key and value; the CSRF generator skips that step. percent-encoding is already a workspace dependency, and lancer-tools depends on lancer-core. The proposed fix is directionally correct (decode, then html_escape) but incomplete: percent_decode_str does NOT convert `+` to space, so urlencoded `+` would survive and be re-encoded as %2B; a correct fix must replace `+` with space before percent-decoding (or use the form_urlencoded crate)._


---

#### [x] #53 · `crates/lancer-tools/src/repeater.rs:123-144` · MEDIUM · correctness
**Repeater redirect-following downgrades 307/308 to GET and drops the request body**

**Problem:** The redirect loop matches 301/302/303/307/308 uniformly and always builds the next hop as `HttpRequest::builder("GET", target)` with an empty body. HTTP semantics require 307 (Temporary Redirect) and 308 (Permanent Redirect) to preserve the original method AND body. By rewriting them to a body-less GET, the Repeater silently changes the request method and discards the POST/PUT payload, so following a 307/308 produces an incorrect, non-reproducible request and a misleading final response in the tool's send history.

**Evidence:**
````
while matches!(resp.status, 301 | 302 | 303 | 307 | 308) && hops < 5 {
    ...
    let mut next = HttpRequest::builder("GET", target.as_str())?;
    for h in &req.headers {
        if h.name.eq_ignore_ascii_case("host") || h.name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        next.set_header(&h.name, h.value.clone());
    }
    resp = self.client.send(&next).await?;
    req = next;
}
````

**Fix:** Branch on the status code inside the loop. For 307/308 preserve method + body; for 301/302/303 keep the existing GET coercion (RFC-conformant for 303, and the conventional browser behavior for 301/302). Replace the `let mut next = ...` block (lines 136-144) with:

```rust
let preserve = matches!(resp.status, 307 | 308);
let method = if preserve { req.method.as_str() } else { "GET" };
let mut next = HttpRequest::builder(method, target.as_str())?;
for h in &req.headers {
    if h.name.eq_ignore_ascii_case("host") || h.name.eq_ignore_ascii_case("content-length") {
        continue;
    }
    next.set_header(&h.name, h.value.clone());
}
if preserve {
    next.body = req.body.clone();
    if !next.body.is_empty() {
        next.set_header("Content-Length", next.body.len().to_string());
    }
}
resp = self.client.send(&next).await?;
req = next;
```

Notes: `builder(method, ..)` accepts `&str` via `impl From<&str> for SerializableMethod` (which upper-cases), so `req.method.as_str()` is safe. The builder produces an empty body, so Content-Length must be re-set explicitly for the preserved body (the original CL header is intentionally skipped in the copy loop). No other behavior changes for 301/302/303.

_Verified (high): Cited code at crates/lancer-tools/src/repeater.rs:123-145 matches the evidence exactly. The redirect loop matches 301|302|303|307|308 uniformly and unconditionally rebuilds the next hop as `HttpRequest::builder("GET", target)`, whose body starts empty (builder sets `body: Bytes::new()`), and the header-copy loop skips Content-Length. So for 307 (Temporary Redirect) and 308 (Permanent Redirect) — which per RFC 7231/7538 MUST preserve the original method AND body — the Repeater silently rewrites the method to GET and discards the POST/PUT payload. The send-history (lines 147-153) records the mutated `req`/`resp`, producing a misleading, non-reproducible final entry. Rust's type system does not prevent this; the code is reachable (only gated on the tab's `follow_redirects` flag) and not dead. The HttpRequest API confirms the fix is feasible: `method: SerializableMethod` is Clone, `body: Bytes` is public/Clone, and `builder` accepts `impl Into<SerializableMethod>` via `From<&str>`, so `req.method.as_str()` can carry the original method. The proposed fix is correct in spirit; it must also set Content-Length for the preserved body since the builder drops the original Content-Length header._


---

#### [x] #54 · `crates/lancer-tools/src/simulate_browse.rs:75-78` · MEDIUM · panic
**gen_range panics when min_delay_ms > max_delay_ms (attacker/operator-supplied config)**

**Problem:** BrowseConfig is a Deserialize struct supplied from the API/GUI/CLI. simulate() builds a delay with rng.gen_range(config.min_delay_ms..=config.max_delay_ms). rand's gen_range panics ('cannot sample empty range', i.e. low > high) whenever min_delay_ms > max_delay_ms. A config with, e.g., min_delay_ms=2000, max_delay_ms=500 (easy to send through the JSON config) panics the async task / brings down the worker rather than returning an error.

**Evidence:**
````
let delay = {
    let mut rng = rand::thread_rng();
    rng.gen_range(config.min_delay_ms..=config.max_delay_ms)
};
````

**Fix:** Normalize the bounds before sampling so an inverted/empty range can never panic:

    let delay = {
        let mut rng = rand::thread_rng();
        let lo = config.min_delay_ms.min(config.max_delay_ms);
        let hi = config.min_delay_ms.max(config.max_delay_ms);
        rng.gen_range(lo..=hi)
    };

This is panic-free for all u64 inputs (lo == hi is a valid inclusive range yielding that value) and leaves behavior unchanged for well-formed configs (min <= max). Alternatively, validate up front and return Err(anyhow!("min_delay_ms must be <= max_delay_ms")) at the top of simulate() if you prefer surfacing operator misconfiguration explicitly rather than silently swapping the bounds.

_Verified (medium): Code at lines 75-78 of crates/lancer-tools/src/simulate_browse.rs is exactly as cited: `rng.gen_range(config.min_delay_ms..=config.max_delay_ms)`. BrowseConfig (lines 22-29) is a public Deserialize struct with public, unvalidated min_delay_ms/max_delay_ms u64 fields. rand's gen_range over an inclusive range where low > high panics ("cannot sample empty range"); nothing in the type system or this function guards against min > max, so a config like {min:2000,max:500} panics the async task. The bug is genuine. Caveat lowering confidence on the stated consequence: grep shows simulate()/BrowseConfig have NO callers anywhere in the repo (no lancer-api endpoint, no CLI subcommand, no GUI route), so it is currently a latent panic in an unwired public library function rather than an actively reachable worker crash. CLAUDE.md lists it as the intended "human-like browse" feature, so it is plausibly wired up later. Marked real because the defect truly exists in a public API surface and the panic is deterministic; the proposed fix is correct and safe (normalizing lo/hi; equal bounds are valid for an inclusive range and yield that single value, no behavior change for valid configs)._


---


### LOW

#### [x] #55 · `crates/lancer-api/src/main.rs:2599-2601` · LOW · parsing
**parse_query does not URL-decode values, corrupting encoded query parameters**

**Problem:** parse_query splits on '&' and strips the `key=` prefix but never percent-decodes the value. Several handlers pass these values straight through where encoding matters: GET /v1/mobile/ios-install-steps reads ca_url (URLs are commonly percent-encoded), and GET /v1/report reads host (the ReportFilter host_filter) and project. A caller sending e.g. ?host=foo%2Ebar or a percent-encoded ca_url will get the literal encoded string, so the host filter will not match and the iOS steps will embed a corrupted URL. Values containing '&' are also truncated.

**Evidence:**
````
fn parse_query(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| pair.strip_prefix(&format!("{key}=")).map(|v| v.to_string()))
}
````

**Fix:** Percent-decode the captured value (and treat '+' as space, per application/x-www-form-urlencoded query convention) before returning. Add `percent-encoding.workspace = true` to crates/lancer-api/Cargo.toml [dependencies] (it is already a workspace dep), then:

fn parse_query(query: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    query.split('&').find_map(|pair| {
        pair.strip_prefix(&prefix).map(|v| {
            // x-www-form-urlencoded: '+' means space
            let v = v.replace('+', " ");
            percent_encoding::percent_decode_str(&v)
                .decode_utf8_lossy()
                .into_owned()
        })
    })
}

This is safe: decode_utf8_lossy never panics on invalid UTF-8, and existing simple values (limit, format, min_severity, "1"/"true", android) contain no '%' or '+' so their decoded form is unchanged. If '+'→space handling is considered too aggressive for some param, it can be dropped and only percent_decode_str applied; the '%XX' decode alone already fixes the reported ca_url/host corruption.

_Verified (high): Confirmed in the real code at crates/lancer-api/src/main.rs:2599-2601: parse_query splits on '&', strips the "key=" prefix, and returns the raw slice with no percent-decoding. The query string originates from req.uri().query() (line 445), which hyper returns still-percent-encoded, so there is no upstream decoding. The cited callers exist: ca_url at line 896 (embedded into lancer_mobile::ios::install_steps), host_filter at line 2290 (ReportFilter), and project at line 2328. A client sending a percent-encoded value (e.g. a ca_url that is itself a URL with %-escapes, or host=foo%2Ebar) receives the literal encoded string, so the report host filter won't match and the iOS steps embed a corrupted URL. The '&'-truncation is the most clearly valid harm: any value containing '&' (common in a ca_url carrying a query string) is silently truncated. Type system does not prevent this; the code is reachable from live GET handlers. Severity low is fair — these are minor query params, not security-critical, and plain hostnames/most values don't require encoding. Note: percent-encoding is a workspace dep but not yet a direct dependency of lancer-api, so the fix must add it._


---

#### [x] #56 · `crates/lancer-api/src/main.rs:399-407` · LOW · correctness
**Passive JS-file entry always records findings: 0 even when findings were mined**

**Problem:** In the passive analysis consumer, when a JS response is processed, mined findings are pushed into js_findings, but the per-file JsFile entry that is created for the GUI's "files" view hardcodes findings: 0. The GET /v1/jsmining/files view therefore always reports 0 findings per file even when the same response produced findings (which ARE visible under /v1/jsmining/findings). Contrast with the /v1/jsmining/rescan handler (line 1022) which correctly sets findings: count. This is a display/correctness inconsistency between the two ingest paths.

**Evidence:**
````
let mut files = js_files.write();
 if !files.iter().any(|jf| jf.url == url) {
     files.push(lancer_jsmining::JsFile {
         url: url.clone(),
         size_kb: (body.len() / 1024) as u64,
         findings: 0,
         last_seen: chrono::Utc::now(),
     });
 }
````

**Fix:** Capture the mined-findings count before the consuming loop moves `mined`, then store it in the JsFile. Replace lines 389-408:

```rust
if is_js {
    let mined = lancer_jsmining::analyse(&url, body);
    let count = mined.len();
    if !mined.is_empty() {
        let mut store = js_findings.write();
        for f in mined {
            if !store.iter().any(|e| e.file == f.file && e.line == f.line && e.snippet == f.snippet) {
                store.push(f);
            }
        }
    }
    let mut files = js_files.write();
    if !files.iter().any(|jf| jf.url == url) {
        files.push(lancer_jsmining::JsFile {
            url: url.clone(),
            size_kb: (body.len() / 1024) as u64,
            findings: count,
            last_seen: chrono::Utc::now(),
        });
    }
}
```

This mirrors the rescan path's semantics (count of mined findings for this response, no dedup applied to the count), is type-safe (`count: usize` matches `JsFile.findings: usize`), and avoids a borrow/move error by computing `count` before `mined` is consumed.

_Verified (high): Confirmed by reading crates/lancer-api/src/main.rs:399-407. In the passive JS-mining consumer, when an is_js response yields mined findings (pushed into js_findings at 391-398), the per-URL JsFile entry created at 401-406 hardcodes `findings: 0`. The GUI endpoint GET /v1/jsmining/files (line 1006) serializes js_files directly, so the files view always reports 0 findings per file even when findings exist (visible under /v1/jsmining/findings, line 1005). The contrasting rescan handler (lines 1014-1023) correctly sets `findings: count` from `new.len()`. JsFile.findings is `usize` (lib.rs:61). Real, low-severity display/correctness inconsistency. The proposed fix is sound but must capture the count BEFORE the `for f in mined` loop at line 393 consumes `mined`._


---

#### [x] #57 · `crates/lancer-authbypass/src/lib.rs:168-178` · LOW · logic-error
**Trailing-dot probe places the dot after the port, producing an invalid URL**

**Problem:** find_host_end returns the index after the host AND any port (rest.find(['/','?','#']) stops at the first path delimiter, so the port is included in `host`). For a URL like http://example.com:8080/secret, the trailing-dot probe builds http://example.com:8080./secret -- the dot lands after the port number, which is not a valid authority. The intended bypass (a trailing dot on the hostname, e.g. http://example.com.:8080/secret) is never generated, and the malformed URL fails to parse/connect at send time, silently wasting the probe. URLs without a port are handled correctly.

**Evidence:**
````
if let Some(host_end) = find_host_end(url) {
    let host = &url[..host_end];
    let rest = &url[host_end..];
    let dotted = format!("{host}.{rest}");
````

**Fix:** Insert the trailing dot immediately after the hostname label, before any port. Replace the trailing-dot block (lines 168-179) with logic that splits the authority into host and optional port, accounting for IPv6 brackets:

if let Some(host_end) = find_host_end(url) {
    let after_scheme = url.find("://").map(|i| i + 3).unwrap_or(0);
    let authority = &url[after_scheme..host_end]; // host[:port], may be [ipv6][:port]
    // Find the port-delimiting ':' only after any IPv6 closing bracket.
    let search_from = authority.rfind(']').map(|i| i + 1).unwrap_or(0);
    let port_colon = authority[search_from..].find(':').map(|i| search_from + i);
    let (hostname, port) = match port_colon {
        Some(c) => (&authority[..c], &authority[c..]), // port includes leading ':'
        None => (authority, ""),
    };
    let scheme = &url[..after_scheme];
    let rest = &url[host_end..];
    let dotted = format!("{scheme}{hostname}.{port}{rest}");
    probes.push(probe(
        BypassCategory::TrailingDot,
        "Trailing dot on hostname",
        &dotted,
        &method,
        vec![],
    ));
}

This yields http://example.com.:8080/secret when a port is present and http://example.com./secret otherwise, matching the no-port behavior. It is safe: all slices fall on ASCII byte boundaries (scheme, ':' , '.' , brackets are ASCII), and the IPv6 guard prevents inserting the dot inside an [::1] address.

_Verified (high): Confirmed by reading the actual code (lines 168-193). find_host_end's own doc comment states it returns the index "just after the host (and optional port)" because rest.find(['/','?','#']) stops at the first path delimiter, so an explicit port is folded into `host`. For http://example.com:8080/secret the code builds dotted = "http://example.com:8080./secret" — the '.' lands after the port, yielding an invalid authority. The intended bypass (http://example.com.:8080/secret) is never produced, and the malformed URL fails to parse/connect at send time, silently wasting that single probe. URLs without a port (the common case) are handled correctly, so impact is genuinely low and limited to the TrailingDot probe. Rust's type system does not prevent this (it is pure string formatting on &str). The code is reachable (generate_probes is the crate's public entry, per CLAUDE.md). The proposed fix direction is correct; I refined it to also handle IPv6 bracketed hosts so the port-delimiting ':' is only searched after any ']'._


---

#### [x] #58 · `crates/lancer-cli/src/commands/mcp_scan.rs:109-111` · LOW · logic-error
**sse:// always forced to plaintext http://, cannot reach a TLS-secured SSE MCP server**

**Problem:** The `sse://` scheme is unconditionally rewritten to `http://{rest}`. Production MCP SSE endpoints are almost always served over HTTPS. Because there is no `sses://` branch and no way to opt into TLS, any attempt to scan an HTTPS-served SSE MCP server will dial plaintext HTTP and fail to connect (or get a protocol error). The user has no CLI lever to fix it.

**Evidence:**
````
} else if let Some(rest) = uri.strip_prefix("sse://") {
    // Hand the underlying JSON-RPC client an http(s) URL.
    Ok((Transport::Sse, format!("http://{rest}")))
````

**Fix:** Add a TLS-SSE branch in parse_server() (crates/lancer-cli/src/commands/mcp_scan.rs) immediately after the `sse://` arm, and update the error message to advertise it:

    } else if let Some(rest) = uri.strip_prefix("sse://") {
        // Hand the underlying JSON-RPC client an http URL.
        Ok((Transport::Sse, format!("http://{rest}")))
    } else if let Some(rest) = uri.strip_prefix("sses://") {
        // TLS-secured SSE endpoint.
        Ok((Transport::Sse, format!("https://{rest}")))
    } else if let Some(rest) = uri.strip_prefix("ws://") {

And update the bail! message to include `sses://`:
    "unsupported server scheme in `{uri}` — expected one of stdio://, sse://, sses://, ws://, wss://, http://, https://"

This is safe because lancer-mcp-scan treats Transport::Sse and Transport::Http identically (both route to http_rpc), and reqwest negotiates TLS purely from the `https://` scheme. No existing branch is altered.

_Verified (high): The cited code at lines 109-111 of crates/lancer-cli/src/commands/mcp_scan.rs matches the evidence exactly: `sse://` is unconditionally rewritten to `http://{rest}`, and parse_server() has no `sses://` branch. The rewritten URL string is passed straight into lancer-mcp-scan's http_rpc(), which does `reqwest::Client::post(server)` — reqwest only negotiates TLS when the URL scheme is `https://`. So a TLS-served SSE MCP server is unreachable via `sse://` (it would dial plaintext HTTP against an HTTPS port and fail). Type system does not prevent this; the code is reachable (it's the SSE arm of the user-facing CLI scheme parser). Note a mitigating workaround exists: the user can pass `https://host` directly (line 116), which works because Transport::Http and Transport::Sse are handled identically (both call http_rpc) in lancer-mcp-scan/src/lib.rs:201,218 — TLS is driven purely by the URL scheme, not the Transport variant. That makes the practical impact low, consistent with the reported severity. The core claim (`sse://` forces plaintext, no `sses://` lever) is literally true. The proposed fix is correct and safe: adding an `sses://` branch mapping to `https://{rest}` with Transport::Sse changes no existing behavior and works because http_rpc respects the scheme._


---

#### [x] #59 · `crates/lancer-core/src/inspector.rs:210-221` · LOW · parsing
**Multipart name extraction matches "filename=" when a part has no name= attribute**

**Problem:** In parse_multipart, the part name is extracted via rest.find("name="). The substring "name=" is also contained inside "filename=". For a Content-Disposition that only carries a filename (a file part without an explicit name=, which is malformed but occurs in real-world/attacker-crafted multipart bodies, or simply for any part where the filename attribute precedes name), .find("name=") will match the f-i-l-e-name= occurrence and capture the file name as if it were the field name. This yields an incorrectly-named insertion point in the Inspector/Intruder/Scanner, so payload positions can target the wrong parameter.

**Evidence:**
````
if let Some(rest) = line.strip_prefix("Content-Disposition:") {
    if let Some(i) = rest.find("name=") {
        let after = &rest[i + 5..];
````

**Fix:** Replace the substring search with per-attribute key matching so "filename=" cannot satisfy the "name=" check. In parse_multipart, replace the Content-Disposition block:

if let Some(rest) = line.strip_prefix("Content-Disposition:") {
    for attr in rest.split(';') {
        let attr = attr.trim();
        if let Some(v) = attr.strip_prefix("name=") {
            name = Some(v.trim_matches('"').to_string());
            break;
        }
    }
}

This iterates the ;-separated attributes and matches only a piece whose key is exactly "name", so a "filename=" attribute is skipped. It preserves the standard case (name="x"; filename="y") and the prior behavior of taking just the name token, while fixing the misattribution.

_Verified (high): Code at crates/lancer-core/src/inspector.rs:210-221 is present exactly as cited and is reachable: Inspector::from_request dispatches Multipart content-type to parse_multipart, and the Inspector is documented as the source of insertion points for Intruder/Scanner. The bug is real: rest.find("name=") is a substring search, and "name=" is a substring of "filename=". For a part with only a filename attribute and no name= (malformed but attacker-craftable), or any part where filename= precedes name=, find() matches the "name=" inside "filename=" and captures the file name as the field name. Trace: rest=" form-data; filename=\"evil.txt\"" → find("name=") lands inside "filename=", after=\"evil.txt\", trim/split yields name="evil.txt". This produces a mis-named Multipart Param. Consequence (wrong insertion-point name) is genuine; severity is correctly low since well-formed bodies put name= before filename= so find() hits the correct occurrence first. Rust's type system does not prevent this — it's pure string logic. The proposed attribute-iteration fix is correct and preserves standard-case behavior (the original only kept the first ;-segment anyway)._


---

#### [x] #60 · `crates/lancer-core/src/scope.rs:152-161` · LOW · parsing
**ScopeRule::from_str misparses bracketed IPv6 hosts, rejecting valid input**

**Problem:** from_str splits the optional port using host_port.rfind(':'). For a bracketed IPv6 literal without a port (e.g. "https://[::1]" or "[fe80::1]/api"), rfind(':') lands on a colon *inside* the IPv6 address rather than a real port separator. The text after that colon (e.g. "1]") is then parse::<u16>()'d, fails, and the whole rule is rejected with Error::InvalidScope("bad port"). Even when an IPv6 host DOES have a port, the host is split at the wrong colon, producing a corrupted host like "[fe80::1". So any IPv6 scope shorthand is parsed incorrectly or rejected outright, silently dropping a scope rule the user intended.

**Evidence:**
````
let (host, port) = match host_port.rfind(':') {
    Some(i) => {
        let h = host_port[..i].to_string();
        let p = host_port[i + 1..]
            .parse::<u16>()
            .map_err(|_| Error::InvalidScope(format!("bad port in {s}")))?;
        (h, Some(p))
    }
    None => (host_port, None),
};
````

**Fix:** Special-case bracketed IPv6 literals before the rfind(':') port split. Replace the port-splitting match at lines 152-161 with:

let (host, port) = if host_port.starts_with('[') {
    // Bracketed IPv6 literal: only a ':' AFTER the closing ']' is a port separator.
    match host_port.find(']') {
        Some(close) => {
            let h = host_port[..=close].to_string();
            let rest = &host_port[close + 1..];
            let port = match rest.strip_prefix(':') {
                Some(p) => Some(
                    p.parse::<u16>()
                        .map_err(|_| Error::InvalidScope(format!("bad port in {s}")))?,
                ),
                None if rest.is_empty() => None,
                None => return Err(Error::InvalidScope(format!("bad host in {s}"))),
            };
            (h, port)
        }
        None => return Err(Error::InvalidScope(format!("unterminated IPv6 literal in {s}"))),
    }
} else {
    match host_port.rfind(':') {
        Some(i) => {
            let h = host_port[..i].to_string();
            let p = host_port[i + 1..]
                .parse::<u16>()
                .map_err(|_| Error::InvalidScope(format!("bad port in {s}")))?;
            (h, Some(p))
        }
        None => (host_port, None),
    }
};

This preserves the existing behavior for hostnames/IPv4 and correctly handles "[::1]", "[fe80::1]/api", and "[fe80::1]:443". (Consider also verifying that ScopeRule::matches compares the bracketed host form consistently with req.meta.host, but that is a separate matching concern from this parse bug.)

_Verified (high): The cited code at crates/lancer-core/src/scope.rs:152-161 is present exactly as described. ScopeRule::from_str splits the optional port using host_port.rfind(':') with no special-casing for bracketed IPv6 literals. For "https://[::1]" the host_port is "[::1]"; rfind(':') lands on the colon inside "::1]", so host becomes "[::" and the substring "1]" is parse::<u16>()'d, fails, and the whole rule is rejected with Error::InvalidScope("bad port..."). For "[fe80::1]/api" the path split at '/' leaves host_port "[fe80::1]" and the same misparse occurs. Even a properly-ported "[fe80::1]:443" would split host at the wrong colon ("[fe80::1" — though that particular case happens to land the last colon before 443, the unported and most other IPv6 cases break). Nothing in the type system prevents this — port is u16 and the parse fails at runtime, returning Err. The method is a public FromStr impl on a public type (re-exported from lib.rs), so it is reachable; currently the only callers in-repo are tests (the API ingests ScopeRule as JSON and the GUI parses URLs in JS), which is why severity is correctly low. The bug and its stated consequence (IPv6 scope shorthand silently rejected / corrupted) are genuine._


---

#### [x] #61 · `crates/lancer-deser/src/lib.rs:137` · LOW · logic-error
**TC_STRING length prefix silently truncated by u16 cast for cmd > 65535 bytes**

**Problem:** java_envelope writes the command length as a 2-byte big-endian prefix via `(cmd.len() as u16)`, then appends the full `cmd.as_bytes()`. If `cmd` is longer than 65535 bytes the `as u16` cast wraps (e.g. 65536 -> 0), so the declared length no longer matches the actual appended bytes, producing a corrupted/non-deserializable envelope rather than an error. The command string is external/user-supplied input.

**Evidence:**
````
buf.extend_from_slice(&(cmd.len() as u16).to_be_bytes());
    buf.extend_from_slice(cmd.as_bytes());
````

**Fix:** Make `java_envelope` fallible and validate the length before the u16 cast, then propagate from `generate` (which already returns `Result<_, String>`):

  fn java_envelope(chain: &str, cmd: &str) -> Result<Vec<u8>, String> {
      let cmd_len = u16::try_from(cmd.len())
          .map_err(|_| "command too long for TC_STRING (max 65535 bytes)".to_string())?;
      let mut buf = Vec::new();
      buf.extend_from_slice(&[0xac, 0xed, 0x00, 0x05]);
      buf.push(0x73);
      buf.push(0x72);
      let class_name = format!("com.lancer.ysoserial.{chain}");
      buf.extend_from_slice(&(class_name.len() as u16).to_be_bytes());
      buf.extend_from_slice(class_name.as_bytes());
      buf.extend_from_slice(&[0; 8]);
      buf.push(0x02);
      buf.extend_from_slice(&[0x00, 0x00, 0x78, 0x70]);
      buf.push(0x74);
      buf.extend_from_slice(&cmd_len.to_be_bytes());
      buf.extend_from_slice(cmd.as_bytes());
      Ok(buf)
  }

And in `generate`, line ~171, change the match arm to propagate:
      Platform::Java => java_envelope(&info.name, &req.cmd)?,

(`class_name` comes from a fixed catalog so its u16 cast is bounded and safe to leave. `dotnet_envelope` has no length prefix and needs no change.)

_Verified (high): Cited code at crates/lancer-deser/src/lib.rs:137 is present verbatim: `buf.extend_from_slice(&(cmd.len() as u16).to_be_bytes()); buf.extend_from_slice(cmd.as_bytes());`. `cmd` is user-supplied (`req.cmd` in `generate`). For cmd.len() > 65535, the `as u16` cast wraps (Rust `as` is a silent truncating cast, no panic/overflow check even in debug), so the declared TC_STRING length prefix no longer matches the full body appended by `cmd.as_bytes()`, producing a corrupted envelope with no error. Rust's type system does NOT prevent this. The code is reachable via the public `generate()` -> `java_envelope()` for any Java chain. Severity is genuinely low: these are deliberately 'representative' marker envelopes (see comment lines 114-119), not valid deserializable ysoserial chains, and a 64KB+ command is unusual — but the prefix/body mismatch is real and the proposed Result-propagation fix is correct since `generate` already returns Result<_, String>._


---

#### [x] #62 · `crates/lancer-dom/src/message.rs:50-66` · LOW · logic-error
**Listener within the last 8 lines of the file uses a shorter validation window than intended**

**Problem:** The main flush path only fires when the file extends to line `*l + 8`; a listener near EOF is instead flushed by the fallback at line 70 which uses `body.lines().skip(l - 1)` (all remaining lines, no `.take(9)` cap) and checks only `block.contains("event.origin")` — it omits the `.contains(".origin ==")` check that the main path uses (line 57). So an EOF-proximate listener that validates origin via `.origin ==` (but not the literal `event.origin`) is reported as `origin_validated: false`, producing an inconsistent/false-positive 'unvalidated origin' result depending solely on how close the handler sits to end-of-file.

**Evidence:**
````
// main path (line 57):
let validated = block.contains("event.origin") || block.contains(".origin ==");
...
// EOF fallback (line 77):
origin_validated: block.contains("event.origin"),
````

**Fix:** In the EOF fallback (line 77), match the main path's predicate:

    origin_validated: block.contains("event.origin") || block.contains(".origin =="),

The block construction in the fallback (line 71, `body.lines().skip(l - 1)`) is already correct for the EOF case — by definition fewer than 9 lines remain, so adding `.take(9)` is harmless but unnecessary; the only behavioral defect is the missing `|| block.contains(".origin ==")` clause, so aligning that one predicate is the minimal, safe fix.

_Verified (high): Confirmed against the actual file crates/lancer-dom/src/message.rs. The main flush path (lines 50-66) fires when line_idx+1 == *l+8 and validates origin with `block.contains("event.origin") || block.contains(".origin ==")` (line 57). The EOF fallback (lines 70-79), which handles listeners within ~8 lines of EOF (file ends before the lookahead), validates with only `block.contains("event.origin")` (line 77), omitting the `.contains(".origin ==")` alternative. The two paths are mutually exclusive (the fallback runs only when listener_buffer was never flushed because EOF arrived first), so an EOF-proximate listener is judged by a stricter predicate. The omitted predicate `.origin ==` matters for handlers using a non-`event` param name (e.g. `function(e){ if(e.origin == origin) }`) where the literal string `event.origin` never appears but `.origin ==` does — such a listener is reported origin_validated:false near EOF but true mid-file. This produces the stated inconsistent/false-positive 'unvalidated origin' result purely as a function of file position. Nothing in the type system or control flow prevents this; the fallback is reachable (any JS file whose last message-listener sits within 8 lines of EOF hits it). Severity low is appropriate (DOM Invader recon heuristic, no security/correctness impact beyond a noisy finding)._


---

#### [x] #63 · `crates/lancer-gui/src/main.rs:130-136` · LOW · logic-error
**Dead/duplicated 'dev fallback' branch in locate_api never executes**

**Problem:** The 'dev fallback' recomputes the identical path that the previous branch already tested. `candidate` (line 126) and `dev` (line 131) are both `dir.join(exe_name)` with the same `dir` and `exe_name`, so if `candidate.exists()` was false on line 127 then `dev.exists()` is necessarily false on line 132. The branch is unreachable and the comment ('target/debug or target/release sibling') is misleading — it does not actually look in any sibling target directory. The function silently falls through to bare `PathBuf::from(exe_name)` (PATH lookup) in dev builds where lancer-api lives in the same target dir but under a different layout, instead of the intended sibling-target search.

**Evidence:**
````
// Dev fallback: target/debug or target/release sibling
    let dev = dir.join(exe_name);
    if dev.exists() {
        return Ok(dev);
    }
````

**Fix:** Remove the dead, duplicated branch so locate_api reads:

    let candidate = dir.join(exe_name);
    if candidate.exists() {
        return Ok(candidate);
    }
    // Last resort: search PATH
    Ok(PathBuf::from(exe_name))

(Drop the misleading "Dev fallback" comment and the identical `dev` recheck entirely. Do not substitute a `deps/` lookup — cargo's final binary artifacts are not placed under target/*/deps/, so that would not reliably locate lancer-api.)

_Verified (high): Confirmed in crates/lancer-gui/src/main.rs lines 122-137. `candidate` (line 126) and `dev` (line 131) are both `dir.join(exe_name)` with the same `dir` (line 124) and `exe_name` (line 125); neither variable is mutated in between. Therefore if `candidate.exists()` is false at line 127, `dev.exists()` is necessarily false at line 132 — the branch is provably dead, and its comment ("target/debug or target/release sibling") is misleading since it searches no sibling dir. The defect is real but low impact: the normal cargo/installed layout places lancer-api in the same `dir`, which the first branch already handles, and the PATH fallback covers other cases. So it is dead/duplicated code rather than a functional break. The proposed `deps/` search would be unreliable because cargo's final bin artifacts do not live in `target/*/deps/`; the safe fix is to delete the dead branch._


---

#### [x] #64 · `crates/lancer-gui/web/src/App.svelte:131` · LOW · logic-error
**Persisted hotkeys can fully shadow new defaults, leaving rebound actions unreachable**

**Problem:** On load, if localStorage "lancer.hotkeys" exists it REPLACES the defaults wholesale (hotkeys = JSON.parse(s)) rather than merging over DEFAULT_HOTKEYS. If a user (or a future release that adds new default hotkeys) has an older/partial persisted map, the newly-added default bindings are silently absent and those actions become unreachable by keyboard until the user manually resets. This is a real behavior regression across versions, not a style nit.

**Evidence:**
````
let hotkeys = { ...DEFAULT_HOTKEYS };
  try { const s = localStorage.getItem("lancer.hotkeys"); if (s) hotkeys = JSON.parse(s); } catch {}
````

**Fix:** Replace line 131 so persisted hotkeys merge over (not replace) the defaults, preserving new default bindings across versions:

  let hotkeys = { ...DEFAULT_HOTKEYS };
  try { const s = localStorage.getItem("lancer.hotkeys"); if (s) hotkeys = { ...DEFAULT_HOTKEYS, ...JSON.parse(s) }; } catch {}

The try/catch still falls back to pure defaults on a parse error. Persisted (user-customized) combos take precedence, while any newly-added default combos absent from the persisted map remain reachable.

_Verified (high): Code at crates/lancer-gui/web/src/App.svelte:131 is exactly as cited: `hotkeys` is initialized to `{...DEFAULT_HOTKEYS}` (line 130) but then wholesale-replaced by `JSON.parse(s)` (line 131) when localStorage "lancer.hotkeys" exists, discarding the default copy. Keyboard dispatch (line 267, `const action = hotkeys[combo]`) reads ONLY from this map, so any default binding absent from a persisted (older/partial) map is unreachable by keyboard until reset. The consequence is genuine and version-scoped: it manifests when a future release adds new DEFAULT_HOTKEYS while a user has an older persisted map. JS has no type system preventing this. The code is live (onKey handler is wired). The proposed merge fix is correct and safe: persisted keys win (preserving user rebinds, including the delete-old-combo logic at line 159), while new defaults survive. No regression — workspace save/load and onHotkeyCapture all persist full maps and are unaffected._


---

#### [x] #65 · `crates/lancer-gui/web/src/views/Decoder.svelte:525` · LOW · logic-error
**Output char-count footer references non-existent row properties, so it never renders**

**Problem:** The info footer tries to show the output length conditionally on `rows[0].decodeOp || rows[0].encodeOp`. Row objects are only ever created with the shape `{ input, output, opLabel, mode, viewMode }` (lines 9, 350, 355) — there is no `decodeOp` or `encodeOp` property anywhere. Both are therefore always `undefined`, the `&&` guard is always falsy, and the ` · Output: N chars` segment is dead code that never displays even after a successful decode/encode. The intended behavior (show output length once a transform has run) is silently broken.

**Evidence:**
````
{#if rows[0].output && (rows[0].decodeOp || rows[0].encodeOp)} · Output: {rows[0].output.length} chars{/if}
````

**Fix:** In crates/lancer-gui/web/src/views/Decoder.svelte line 525, replace the non-existent property guard with `opLabel` (the field set whenever a transform runs). Change:

  {#if rows[0].output && (rows[0].decodeOp || rows[0].encodeOp)} · Output: {rows[0].output.length} chars{/if}

to:

  {#if rows[0].output && rows[0].opLabel} · Output: {rows[0].output.length} chars{/if}

This guards on properties that actually exist: `opLabel` is `""` (falsy) until apply()/smartDecode set it (lines 314, 329-341), so the segment renders only after a transform has run, and `output` ensures non-empty output.

_Verified (high): Verified against the real file. Line 525 reads exactly `{#if rows[0].output && (rows[0].decodeOp || rows[0].encodeOp)} · Output: {rows[0].output.length} chars{/if}`. Row objects are only ever created/assigned with the shape `{ input, output, opLabel, mode, viewMode }` (lines 9, 350, 355) and the documented comment at line 4. The `apply()` function (lines 309-316) sets `r.output`, `r.opLabel`, `r.mode` — never `decodeOp`/`encodeOp`. `encodeOps`/`decodeOps` (lines 265/275) are operation-list arrays in script scope, not row properties. Thus `rows[0].decodeOp` and `rows[0].encodeOp` are always undefined, the `&&` guard is always false, and the Output segment never renders. Real low-severity dead-code/logic bug; consequence (output char count never shows) is correct._


---

#### [x] #66 · `crates/lancer-gui/web/src/views/Organizer.svelte:237-268` · LOW · parsing
**renderMarkdown corrupts multi-line fenced code blocks in the Notes preview**

**Problem:** Fenced code blocks are converted to a single '<pre class="md-pre">...</pre>' string at line 241 (with embedded newlines preserved). The source is then split on newlines at line 242 and processed line-by-line. The guard at line 258 (/<pre class="md-pre">/.test(line)) matches only the FIRST line of a multi-line code block. Every subsequent line of the code block, and the line containing the closing </pre>, fails that test and falls into the final else branch (lines 261-263), getting wrapped in <p class="md-p"> and run through inline() (which applies bold/italic/code/link substitutions). A multi-line code block therefore renders with broken/duplicated tags and stray Markdown processing inside the code. (Single-line code blocks happen to render correctly because the whole <pre>...</pre> stays on one line.)

**Evidence:**
````
s = s.replace(/```([\s\S]*?)```/g, (_, code) => `<pre class="md-pre">${code.replace(/\n$/, "")}</pre>`);
const lines = s.split(/\r?\n/);
...
} else if (/<pre class="md-pre">/.test(line)) {
  if (inList) { out.push("</ul>"); inList = false; }
  out.push(line);
} else {
  ...
  out.push(`<p class="md-p">${inline(line)}</p>`);
}
````

**Fix:** Protect fenced code blocks from the per-line processor by stashing each rendered block under a placeholder before the newline split, then restoring it afterward:

```js
function renderMarkdown(src) {
  if (!src) return "";
  let s = escapeHtml(src);
  // Fenced code blocks ```...``` -> stash behind a placeholder so the
  // per-line loop never splits or re-processes their (multi-line) content.
  const blocks = [];
  s = s.replace(/```([\s\S]*?)```/g, (_, code) => {
    const token = ` MDPRE${blocks.length} `;
    blocks.push(`<pre class="md-pre">${code.replace(/^\n/, "").replace(/\n$/, "")}</pre>`);
    return token;
  });
  const lines = s.split(/\r?\n/);
  const out = [];
  let inList = false;
  for (let line of lines) {
    const h = /^(#{1,4})\s+(.*)$/.exec(line);
    const li = /^\s*[-*]\s+(.*)$/.exec(line);
    const preTok = /^ MDPRE(\d+) $/.exec(line);
    if (h) {
      if (inList) { out.push("</ul>"); inList = false; }
      const lvl = h[1].length;
      out.push(`<h${lvl} class="md-h">${inline(h[2])}</h${lvl}>`);
    } else if (li) {
      if (!inList) { out.push('<ul class="md-ul">'); inList = true; }
      out.push(`<li>${inline(li[1])}</li>`);
    } else if (line.trim() === "") {
      if (inList) { out.push("</ul>"); inList = false; }
      out.push("");
    } else if (preTok) {
      if (inList) { out.push("</ul>"); inList = false; }
      out.push(blocks[Number(preTok[1])]);
    } else {
      if (inList) { out.push("</ul>"); inList = false; }
      out.push(`<p class="md-p">${inline(line)}</p>`);
    }
  }
  if (inList) out.push("</ul>");
  return out.join("\n");
}
```

Key points: the placeholder is a single token on its own line (no embedded newlines), so the `\r?\n` split never breaks it; the block HTML (which legitimately contains newlines) is reinserted verbatim only after the loop. The NUL ( ) sentinel avoids collision with user text. The leading `\n` is also stripped so the common ```` ```\ncode\n``` ```` form doesn't render an empty first line. inline() is never run over code content.

_Verified (high): Confirmed against the actual file (crates/lancer-gui/web/src/views/Organizer.svelte:237-268). Line 241 collapses each fenced block into a single `<pre class="md-pre">...</pre>` string that preserves embedded newlines. Line 242 then splits the whole document on `\r?\n`, so a multi-line code block is split into multiple lines. The guard at line 258 (`/<pre class="md-pre">/`) only matches the FIRST line (the one carrying the opening `<pre` tag). Every subsequent code line, including the line carrying the closing `</pre>`, fails the test and falls into the else branch (261-263), getting wrapped in `<p class="md-p">` and passed through `inline()`. For a two-line block this yields broken HTML like `<pre class="md-pre">line1\n<p class="md-p">line2</pre></p>` — unclosed `<pre>`, a `</pre>` nested inside a `<p>`, and inline bold/italic/code/link substitution applied to code content. Single-line blocks happen to work because the whole `<pre>...</pre>` stays on one line and matches the guard. No Rust type system involvement (this is client-side JS in a Svelte component), the function is reachable (called to render the Notes preview), and nothing upstream prevents multi-line code. The proposed placeholder approach is the standard correct fix._


---

#### [x] #67 · `crates/lancer-gui/web/src/views/Organizer.svelte:67` · LOW · correctness
**formatRequest/formatResponse mislabel HTTP/1.0 and HTTP/3 as HTTP/1.1**

**Problem:** Both formatters map only version==="Http2" to "HTTP/2" and treat every other enum string as "HTTP/1.1". The HttpVersion enum (lancer-core/src/http_msg.rs) serializes as Http10/Http11/Http2/Http3. A stored request or response captured over HTTP/1.0 or HTTP/3 is therefore displayed in the Request/Response panes (and in deriveRaw -> Send-to-Repeater) with the wrong version line "HTTP/1.1". Comparer.svelte's wireVersion() already maps all four correctly, so the Organizer is the outlier.

**Evidence:**
````
const ver = req.version === "Http2" ? "HTTP/2" : "HTTP/1.1";
````

**Fix:** In Organizer.svelte, replace the version mapping in both formatRequest and formatResponse with a full lookup matching Comparer.svelte's wireVersion(). E.g. add near the top of the script: `function wireVersion(v){ return ({Http09:"HTTP/0.9",Http10:"HTTP/1.0",Http11:"HTTP/1.1",Http2:"HTTP/2",Http3:"HTTP/3"})[v] || v || "HTTP/1.1"; }` and use `const ver = wireVersion(req.version);` (line 67) and `const ver = wireVersion(resp.version);` (line 73). This also covers Http09, which the reporter's two-entry map omits.

_Verified (high): Code is present verbatim at lines 67 and 73 of Organizer.svelte: both formatRequest and formatResponse use `req.version === "Http2" ? "HTTP/2" : "HTTP/1.1"`, defaulting every non-Http2 variant to HTTP/1.1. HttpVersion in lancer-core/src/http_msg.rs uses default serde (no rename_all), so it serializes variant names verbatim: Http09/Http10/Http11/Http2/Http3. Thus a request/response captured over HTTP/1.0, HTTP/3 (or HTTP/0.9) is mislabeled "HTTP/1.1" in the Request/Response panes. deriveRaw (line 130) calls formatRequest, so the mislabel also flows into Send-to-Repeater raw text. Comparer.svelte's wireVersion() (line 40) maps all four correctly, confirming Organizer is the outlier. Genuine low-severity correctness/display bug; nothing in the type system prevents it and the code is reachable (used in templates at lines 384/388 and in deriveRaw). The proposed fix mirrors the existing Comparer pattern and is safe._


---

#### [x] #68 · `crates/lancer-gui/web/src/views/Plugins.svelte:70-84, 32-42, 167` · LOW · logic-error
**moveUp/moveDown reorder only local state and are silently reverted by the 8s poll**

**Problem:** moveUp/moveDown mutate the local `plugins` array only; there is no API call to persist the new order. The onMount poll runs load() every 8000ms, which unconditionally reassigns `plugins` from GET /v1/plugins (PluginRegistry.list() returns load order). Any user reordering is therefore discarded within at most 8 seconds, and selectedIndex (adjusted by moveUp/moveDown) can then point at a different plugin than the one the user moved. The Up/Down buttons appear functional but have no durable effect.

**Evidence:**
````
function moveUp() {
    if (selectedIndex <= 0) return;
    const arr = [...plugins];
    [arr[selectedIndex - 1], arr[selectedIndex]] = [arr[selectedIndex], arr[selectedIndex - 1]];
    plugins = arr;
    selectedIndex = selectedIndex - 1;
  }
````

**Fix:** Plugin order has no backend semantics (list() is load-order; toggle/remove key off id), so the simplest safe fix is to remove the non-functional Up/Down controls rather than fake persistence. Delete the two buttons in the side-btns block (lines 211-212):
  <button class="side-btn" on:click={moveUp}   disabled={selectedIndex <= 0}>Up</button>
  <button class="side-btn" on:click={moveDown} disabled={selectedIndex < 0 || selectedIndex >= plugins.length - 1}>Down</button>
and the now-unused moveUp()/moveDown() functions (lines 70-84).

If the controls must stay for Burp visual parity, suppress the next poll-driven reload after a manual reorder so the change isn't immediately clobbered (still resets on upload/remove/remount, but at least the buttons appear to work):
- add `let suppressReloadUntil = 0;`
- in load(): `if (Date.now() < suppressReloadUntil) return;` at the top of the try block (before fetch), OR guard the assignment.
- in moveUp/moveDown: `suppressReloadUntil = Date.now() + 30000;`
Removing the controls is preferred since ordering is purely cosmetic and unpersisted.

_Verified (high): Verified in crates/lancer-gui/web/src/views/Plugins.svelte: moveUp (70-76) and moveDown (78-84) only mutate the local `plugins` array and adjust selectedIndex; no fetch/persist call. load() (32-42) unconditionally reassigns `plugins` from GET /api/v1/plugins, and onMount sets a setInterval(load, 8000) (167). The backend has no plugin-ordering endpoint (confirmed in lancer-api/src/main.rs — only toggle/upload/remove) and PluginRegistry.list() (registry.rs:75-77) returns the Vec in load/insertion order, which client reordering never changes. So any manual reorder is overwritten within <=8s, and because selectedIndex was decremented/incremented while the underlying array reverts, the selection can land on a different plugin. The Up/Down buttons thus have no durable effect. The consequence is exactly as stated. Severity is genuinely low: plugin order carries no functional meaning (toggle/remove operate by id), so it is a cosmetic/UX inconsistency, not a correctness hazard._


---

#### [x] #69 · `crates/lancer-gui/web/src/views/Settings.svelte:332` · LOW · api-contract
**Persisting theme="system" breaks theme on next app load (App.svelte forces light)**

**Problem:** applyTheme() writes the raw `theme` value (which can be "system") to localStorage key "lancer.theme". On the next full app load, App.svelte's onMount only honors stored values "dark" or "light" and otherwise calls applyTheme("light") (App.svelte lines 254-256). So a user who selects "System" and reloads is silently forced to Light until the Settings view happens to mount and re-run its own onMount system-theme branch. The stored "system" sentinel is not understood by the component that owns initial theme application.

**Evidence:**
````
document.body.setAttribute("data-theme", resolveTheme(theme));
      localStorage.setItem("lancer.theme", theme);
````

**Fix:** Teach App.svelte's initial theme load to understand the "system" sentinel instead of falling back to light, keeping a single localStorage key and preserving follow-OS behavior.

In App.svelte, replace the onMount block (lines 254-256):

    const saved = localStorage.getItem("lancer.theme");
    if (saved === "dark" || saved === "light") applyTheme(saved);
    else applyTheme("light");

with logic that resolves "system":

    const saved = localStorage.getItem("lancer.theme");
    if (saved === "system") {
      let resolved = "light";
      try { resolved = window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"; } catch {}
      // apply resolved to the body but keep "system" persisted
      document.body.setAttribute("data-theme", resolved);
      theme = "system";
    } else if (saved === "dark" || saved === "light") {
      applyTheme(saved);
    } else {
      applyTheme("light");
    }

Note App.svelte's applyTheme(t) sets both `theme` and persists `t`, so for the "system" case it must NOT be called with "system" (it would set data-theme="system", an unknown value). Set the body attribute to the resolved value and `theme="system"` directly, as above, so the persisted sentinel is preserved across reloads. Do NOT use the reporter's variant of writing resolveTheme(theme) into "lancer.theme" from Settings.svelte, because that discards the follow-OS preference.

_Verified (high): Confirmed in the real code. Settings.svelte applyTheme (line 332) persists the raw `theme` to localStorage "lancer.theme", which is "system" when the user picks System. App.svelte onMount (lines 254-256) only honors "dark"/"light" and otherwise calls applyTheme("light"); App.svelte's applyTheme (lines 60-63) then overwrites "lancer.theme" with "light", destroying the "system" preference on reload. The body data-theme is resolved correctly at write time, but the owning component (App.svelte) does not understand the "system" sentinel, so on a full reload the user is silently forced to Light until the Settings view re-mounts. Consequence is genuine; low severity (theme cosmetics only) is fair. The reporter's first proposed-fix variant (storing resolveTheme(theme) in "lancer.theme") would lose the follow-OS behavior, so the correct fix is to teach App.svelte to resolve "system" via matchMedia._


---

#### [x] #70 · `crates/lancer-iac/src/lib.rs:126` · LOW · correctness
**Kubernetes service port truncated via `as u16` instead of range-checked, producing wrong ports**

**Problem:** `p.get("port").and_then(|x| x.as_u64())` returns a u64, which is then narrowed with `port as u16`. For any port value outside 0..=65535 (e.g. a malformed manifest with `port: 65536` or `port: 70000`), the `as` cast silently wraps/truncates rather than rejecting the value, so a wrong port number is recorded in `exposed_ports`. Every other parser in this file (parse_dockerfile line 39, parse_compose line 74, parse_terraform line 153) uses a checked `cap[..].parse::<u16>()` whose `Ok` guard drops out-of-range values instead of corrupting them, so this path is inconsistent and yields incorrect attack-surface output on out-of-range input.

**Evidence:**
````
if let Some(port) = p.get("port").and_then(|x| x.as_u64()) {
    s.exposed_ports.push(port as u16);
}
````

**Fix:** Range-check before narrowing, matching the other parsers' drop-on-invalid behavior:

```rust
if let Some(port) = p.get("port").and_then(|x| x.as_u64()) {
    if let Ok(p16) = u16::try_from(port) {
        s.exposed_ports.push(p16);
    }
}
```

This preserves identical behavior for valid ports (0..=65535) and silently drops out-of-range values instead of truncating them, consistent with parse_dockerfile/parse_compose/parse_terraform.

_Verified (high): Confirmed against the actual file. Line 125-126 reads `if let Some(port) = p.get("port").and_then(|x| x.as_u64()) { s.exposed_ports.push(port as u16); }`. `exposed_ports` is `Vec<u16>` (line 10), so `port as u16` is a narrowing cast that silently truncates any value outside 0..=65535 (e.g. 65536 -> 0, 70000 -> 4464) rather than rejecting it. Rust's `as` does NOT panic or range-check here, so the type system does not prevent the consequence. The code is reachable (parse_kubernetes is a public entry point used by the IaC parser/CLI). The sibling parsers parse_dockerfile (line 39: `cap[1].parse()`), parse_compose, and parse_terraform (line 153: `cap[1].parse()`) all parse directly into the u16 field with an `Ok` guard, which drops out-of-range input instead of corrupting it — so this path is genuinely inconsistent. Practical impact is low: valid k8s service ports are always in range, so only a malformed manifest triggers the wrong-port output. But the defect and stated consequence are real._


---

#### [x] #71 · `crates/lancer-jvm/src/lib.rs:63` · LOW · logic-error
**JAVA_HOME set one directory too deep — points at <JDK>/bin (or <JDK>/lib) instead of <JDK>**

**Problem:** The doc comment on the `libjvm` field (lines 21-22) states the path is `<JDK>/bin/server/jvm.dll` (Windows) or `<JDK>/lib/server/libjvm.{so,dylib}` (Linux/macOS). Stripping only two path components with `.parent().and_then(|p| p.parent())` yields `<JDK>/bin` (Windows) or `<JDK>/lib` (Linux/macOS), NOT `<JDK>`. JAVA_HOME is conventionally the JDK root; setting it to the `bin`/`lib` subdirectory is wrong and can break JVM startup or any Java code that resolves resources relative to JAVA_HOME (e.g. `jvm.cfg`, modules, security policy). For `jvm.dll`: jvm.dll -> server -> bin (needs one more `.parent()` to reach the JDK root).

**Evidence:**
````
std::env::set_var("JAVA_HOME", libjvm.parent().and_then(|p| p.parent()).unwrap_or(&libjvm));
````

**Fix:** Strip three path components so JAVA_HOME points at the JDK root (libjvm is `<JDK>/{bin,lib}/server/<jvm-lib>`):

let java_home = libjvm
    .parent()
    .and_then(|p| p.parent())
    .and_then(|p| p.parent())
    .unwrap_or(&libjvm);
std::env::set_var("JAVA_HOME", java_home);

_Verified (high): The cited code at crates/lancer-jvm/src/lib.rs:63 matches the evidence exactly. Per the field's own doc comment (lines 21-22), libjvm is `<JDK>/bin/server/jvm.dll` (Windows) or `<JDK>/lib/server/libjvm.{so,dylib}` (Linux/macOS). Stripping only two path components via `.parent().and_then(|p| p.parent())` yields `<JDK>/bin` (Windows: jvm.dll -> server -> bin) or `<JDK>/lib` (Linux/macOS), NOT the JDK root `<JDK>`. JAVA_HOME conventionally is the JDK root, so the value is set one directory too deep. The code is feature-gated under `jvm` but is the live boot path when that feature is enabled, not dead. Three `.parent()` calls are needed. Severity is correctly low: JNI's JavaVM::new boots the JVM directly from the libjvm path and does not strictly require JAVA_HOME, but a wrong JAVA_HOME can mislead Java code/resources that resolve relative to it, matching the reported consequence. The proposed three-component strip is correct and the `.unwrap_or(&libjvm)` fallback keeps it safe._


---

#### [x] #72 · `crates/lancer-mobile/src/android.rs:64` · LOW · panic
**install_user_ca panics on non-UTF-8 cert path**

**Problem:** der_path.to_str() returns None for any path containing non-UTF-8 bytes, and .unwrap() then panics, aborting the async task instead of returning an error. The other use of der_path.to_str() in this file (line 105, openssl_subject_hash_old) correctly uses `?` to return None, so this is an inconsistency that turns a recoverable bad-input condition into a crash.

**Evidence:**
````
self.cmd(&["push", der_path.to_str().unwrap(), &on_device]).await?;
````

**Fix:** In `install_user_ca`, replace the panicking unwrap with error propagation consistent with the rest of the file:

```rust
let der_str = der_path
    .to_str()
    .ok_or_else(|| anyhow!("cert path is not valid UTF-8: {}", der_path.display()))?;
self.cmd(&["push", der_str, &on_device]).await?;
```

`anyhow!` is already imported (line 6), so this compiles without new imports and matches the `?`-based handling used in `openssl_subject_hash_old`.

_Verified (high): Confirmed by reading crates/lancer-mobile/src/android.rs. Line 64 is exactly `self.cmd(&["push", der_path.to_str().unwrap(), &on_device]).await?;`. `Path::to_str()` returns `Option<&str>` and yields `None` for non-UTF-8 paths, so `.unwrap()` panics. The enclosing fn `install_user_ca` returns `anyhow::Result<()>`, and `anyhow!`/`Context` are already imported (line 6), so propagating an error is the right pattern and compiles. The inconsistency is genuine: the sibling helper `openssl_subject_hash_old` (line 105) correctly uses `der_path.to_str()?` to return `None` instead of panicking. The panic unwinds/aborts the async task rather than returning a recoverable error. Severity low is appropriate: it only triggers on a non-UTF-8 cert path (an unusual input), and tokio isolates per-task panics by default (no project-wide panic=abort observed). Nothing in the type system or surrounding code prevents the panic; the code is reachable (public API). The proposed fix is correct and does not break callers (they already handle Err)._


---

#### [x] #73 · `crates/lancer-proxy/src/intercept.rs:57-62` · LOW · logic-error
**Invalid url_regex silently broadens an intercept rule instead of failing it**

**Problem:** In matches_request, when url_regex is set but fails to compile, the `if let Ok(r) = Regex::new(rx)` arm is skipped entirely, so the regex constraint is simply ignored. A rule the user authored to narrowly Pause/Drop only URLs matching a regex will instead match every URL that passes the other (possibly empty) filters. With action=Drop this can silently drop all proxied traffic; with Pause it can stall every request. The mistyped regex produces a more permissive rule, the opposite of the user's intent, with no error surfaced. (The regex is also recompiled on every request in the hot path.)

**Evidence:**
````
if let Some(rx) = &self.url_regex {
    if let Ok(r) = Regex::new(rx) {
        if !r.is_match(&url) {
            return false;
        }
    }
}
````

**Fix:** Fail closed: treat a non-compiling (or non-matching) regex as a non-match. Replace lines 57-62 with:

```rust
if let Some(rx) = &self.url_regex {
    match Regex::new(rx) {
        Ok(r) if r.is_match(&url) => {}
        _ => return false,
    }
}
```

Better still, precompile and validate the regex once when the rule is created/updated (reject invalid patterns at that point and store a compiled Regex rather than a String), so per-request evaluation neither recompiles nor depends on a String that may be invalid. The fail-closed change above is the minimal safe fix and does not affect rules without a url_regex set.

_Verified (high): The cited code at intercept.rs:57-62 is present exactly as described. In matches_request, an invalid url_regex causes `if let Ok(r) = Regex::new(rx)` to be skipped, so the regex constraint is silently dropped and the function falls through to `return true` (when other filters pass). decide_request (lines 124-130) then returns that rule's action, so a Pause/Drop rule the user intended to scope narrowly via regex would apply to every URL that satisfies the remaining (possibly empty) filters — fail-open, the opposite of intent, with no error surfaced. I confirmed there is no validation of url_regex on the API side and no PUT path that compiles/rejects it, so nothing upstream prevents an invalid pattern from being stored. The type system does not catch this (regex is a runtime String). The regex is also recompiled on every request in the hot path. Severity low is appropriate: it requires a user regex typo and only broadens within the other filters' bounds._


---

#### [x] #74 · `crates/lancer-proxy/src/match_replace.rs:111-126` · LOW · logic-error
**RequestFirstLine match/replace ignores any edit to the HTTP version segment**

**Problem:** The request first line is built as "{method} {path} {version}" and the rule may match/replace against the version token, but after replacement only parts.next() for method and path are consumed; the third segment (version) is never parsed back and req.version is never updated. A match/replace rule that targets RequestFirstLine to change the protocol version (e.g. HTTP/1.1 -> HTTP/1.0) silently has no effect, while a method/path edit on the same line works. This is an inconsistency between what the rule matches against and what it can actually change.

**Evidence:**
````
let line = format!("{} {} {}", req.method.as_str(), req.path, req.version);
if let Some(new_line) = rule.apply_to_string(&line) {
    let mut parts = new_line.splitn(3, ' ');
    if let (Some(m), Some(p)) = (parts.next(), parts.next()) {
        req.method = lancer_core::SerializableMethod::from(m);
        req.path = p.to_string();
        hits += 1;
    }
}
````

**Fix:** In the MatchTarget::RequestFirstLine arm, after assigning method and path, consume and apply the third (version) token, mirroring ResponseFirstLine. Replace the inner block with:

if let (Some(m), Some(p)) = (parts.next(), parts.next()) {
    req.method = lancer_core::SerializableMethod::from(m);
    req.path = p.to_string();
    if let Some(v) = parts.next() {
        match v.trim() {
            "HTTP/0.9" => req.version = lancer_core::HttpVersion::Http09,
            "HTTP/1.0" => req.version = lancer_core::HttpVersion::Http10,
            "HTTP/1.1" => req.version = lancer_core::HttpVersion::Http11,
            "HTTP/2" | "HTTP/2.0" => req.version = lancer_core::HttpVersion::Http2,
            "HTTP/3" => req.version = lancer_core::HttpVersion::Http3,
            _ => {}
        }
    }
    hits += 1;
}

Ensure HttpVersion is in scope (already imported as lancer_core::HttpVersion or via the existing use). Unrecognized tokens leave req.version unchanged, so the change cannot regress existing method/path-only edits. Note owned_request_to_hyper only maps Http10/Http2/_=>Http11, so an edit to HTTP/1.0 will now take effect on the wire; HTTP/0.9 and HTTP/3 fall back to HTTP/1.1 there, which is acceptable and pre-existing behavior.

_Verified (high): Code at match_replace.rs:111-126 is exactly as cited. The request first line is formatted as "{method} {path} {version}" (HttpVersion's Display yields "HTTP/1.1" etc.), so a RequestFirstLine match/replace rule can match against the version token. But after apply_to_string, only parts.next() for method (m) and path (p) are consumed and written back; the third segment (version) is parsed by splitn(3) but never read or applied, so req.version is never updated. req.version IS consumed downstream: owned_request_to_hyper (mitm.rs:247-251) maps req.version to http::Version when building the upstream request. Thus a rule editing HTTP/1.1 -> HTTP/1.0 on the first line silently has no effect, while method/path edits work — confirming the inconsistency and consequence. This mirrors the asymmetry with ResponseFirstLine (164-181), which DOES apply later tokens (status, reason). Severity low is appropriate (niche manual feature). The proposed fix is correct and safe: the _ => {} arm leaves req.version unchanged on unrecognized tokens, and reading the third token from the same splitn(3) iterator is correct._


---

#### [x] #75 · `crates/lancer-proxy/src/platform_auth.rs:89-121` · LOW · logic-error
**Digest non-MD5 algorithm branch is unreachable dead code**

**Problem:** Line 89 returns `None` for any algorithm other than "MD5", so the later block at line 119 `if algorithm != "MD5" { header.push_str(... algorithm=...) }` can never execute. The Digest header therefore never carries an `algorithm=` directive even when the server explicitly negotiated one (e.g. `algorithm=MD5-sess`), and any non-MD5 challenge silently yields no Authorization header at all. This is a real (if narrow) correctness gap in Digest auth handling.

**Evidence:**
````
if algorithm != "MD5" {
        // SHA-256 etc. would require swapping the hasher — left for a follow-up.
        return None;
    }
    ...
    if algorithm != "MD5" {
        header.push_str(&format!(", algorithm={algorithm}"));
    }
````

**Fix:** Delete the unreachable branch at lines 119-121. Do NOT remove the early `return None` at line 89 unless non-MD5 hashing (incl. the different MD5-sess HA1 derivation) is actually implemented, since the rest of the function hardcodes md5_hex. Optionally, to comply with RFC 7616's recommendation to echo the algorithm, replace the dead branch with an unconditional emission only when the challenge supplied one. Concretely, track whether the server sent an algorithm:

    let algorithm_supplied = extract(challenge, "algorithm");
    let algorithm = algorithm_supplied.clone().unwrap_or_else(|| "MD5".to_string());
    ...
    if algorithm != "MD5" {
        // SHA-256 / MD5-sess require swapping the hasher / HA1 derivation — follow-up.
        return None;
    }
    ...
    // (delete old lines 119-121; instead:)
    if algorithm_supplied.is_some() {
        header.push_str(", algorithm=MD5");
    }

If echoing is not desired, simply delete lines 119-121 with no replacement — that alone removes the false implication that an algorithm directive is ever emitted, and is fully safe.

_Verified (high): The cited code is present verbatim. At line 89 the function returns None for any algorithm != "MD5", so execution only continues when algorithm == "MD5". The block at lines 119-121 is gated on `algorithm != "MD5"`, which is therefore provably always false at that point — genuine unreachable dead code. Consequences hold: the Digest header never emits an `algorithm=` directive (the only path that could is dead), and non-MD5 challenges (e.g. MD5-sess, SHA-256) yield no Authorization header at all (acknowledged in the inline comment as a follow-up). Severity "low" is fair: per RFC 7616 the `algorithm` directive is optional and defaults to MD5, so omitting it for plain-MD5 still produces a valid header; the real gap is just unimplemented non-MD5 support plus misleading dead code. Note: the proposed fix's option to "remove the early return None" without more work would be UNSAFE — HA1/HA2 are hardcoded to md5_hex and MD5-sess requires a different HA1 (MD5(MD5(user:realm:pass):nonce:cnonce)); doing so would emit a wrong response. The safe minimal fix is to delete the dead branch and, optionally, echo back `algorithm=MD5` when the server supplied one._


---

#### [x] #76 · `crates/lancer-proxy/src/upstream.rs:92-109` · LOW · parsing
**SOCKS5 username/password length cast can truncate, producing a malformed/auth-bypassing frame**

**Problem:** `methods.len() as u8`, `u.len() as u8` and `p.len() as u8` cast lengths to u8 without bounds checking. A username or password longer than 255 bytes wraps modulo 256, writing a wrong length byte while still appending the full credential bytes. The upstream SOCKS5 server then reads a truncated/garbled credential, so authentication fails confusingly or the frame desynchronizes the stream. While 255+ char proxy passwords are uncommon, this is unvalidated external/config input written into a length-prefixed wire protocol.

**Evidence:**
````
let mut frame = vec![0x01u8, u.len() as u8];
            frame.extend_from_slice(u.as_bytes());
            frame.push(p.len() as u8);
            frame.extend_from_slice(p.as_bytes());
````

**Fix:** Bound-check before writing each one-byte length prefix in dial_socks5 (crates/lancer-proxy/src/upstream.rs). For the username/password auth frame, guard before line 106:

    0x02 if auth => {
        let u = up.username.as_ref().unwrap();
        let p = up.password.as_ref().unwrap();
        if u.len() > 255 || p.len() > 255 {
            return Err(anyhow!("socks5 username/password exceeds 255 bytes"));
        }
        let mut frame = vec![0x01u8, u.len() as u8];
        frame.extend_from_slice(u.as_bytes());
        frame.push(p.len() as u8);
        frame.extend_from_slice(p.as_bytes());
        ...

And for the ATYP=0x03 domain-name branch, guard before line 130:

    } else {
        if host.len() > 255 {
            return Err(anyhow!("socks5 destination hostname exceeds 255 bytes"));
        }
        req.push(0x03);
        req.push(host.len() as u8);
        req.extend_from_slice(host.as_bytes());
    }

(The `methods.len() as u8` at line 92 needs no guard — methods is a fixed slice of at most 2 bytes.) These early returns are safe: they only reject pathological oversized inputs that would otherwise produce a malformed wire frame, and dial_socks5 already returns Result so the error propagates cleanly to the caller.

_Verified (high): The cited code at crates/lancer-proxy/src/upstream.rs lines 106-109 matches the evidence exactly. `u.len() as u8` and `p.len() as u8` (and `host.len() as u8` at line 130, plus `methods.len() as u8` at line 92 which is harmless — methods is at most 2) cast lengths to u8 with no bounds check. SOCKS5 username/password auth (RFC 1929) and domain-name addressing (RFC 1928, ATYP=0x03) are length-prefixed with a single u8 (ULEN/PLEN/DSTLEN). For a string of 256+ bytes the length byte wraps modulo 256 while extend_from_slice still appends the full bytes, so the emitted frame's declared length disagrees with the appended payload — the upstream server reads a wrong-length field and the stream desynchronizes. username/password originate from UpstreamProxy in settings.rs as Option<String> (deserialized config, arbitrary length, no validation), confirming unvalidated external/config input. The bug is genuine. Caveats: it is a latent edge case requiring a 255+ byte credential/hostname (very uncommon; real hostnames can't exceed 253 bytes but the code doesn't enforce that). The title's "auth-bypassing" wording is overstated — the realistic outcome is a malformed/desynchronized frame causing confusing auth failure, not an actual auth bypass. The code is reachable: dial_socks5 is the SOCKS5 upstream dialer and the auth branch runs whenever a username+password are configured. Rust's type system does NOT prevent this — `as u8` is an explicit silent-truncating cast. The proposed fix (reject >255 bytes before building the frame) is correct and safe, and rightly extends to the hostname at line 130. low severity / parsing category is appropriate._


---

#### [x] #77 · `crates/lancer-replay/src/id_mutate.rs:53-58` · LOW · parsing
**Integer detector matches digit runs inside UUIDs, creating spurious int candidates**

**Problem:** `detect` first collects UUID candidates, then runs the integer regex `\b\d{1,12}\b` over the same text. A UUID such as `12345678-1234-1234-1234-123456789012` contains digit runs that the integer regex matches (e.g. `12345678`, `123456789012`), so each UUID can spawn several bogus `int` candidates. The `seen` set keys on the matched string value only (`format!("{loc}:{v}")`), not on position, so it does not suppress these; they are then mutated and replayed against the URL/body, wasting the replay budget and replacing the wrong substring (e.g. `replacen` will hit the digits inside the UUID).

**Evidence:**
````
for m in int_re.find_iter(text) {
            let v = m.as_str().to_string();
            // Skip tiny / obviously-non-id numbers handled elsewhere; keep ≥ 1.
            if v.len() >= 1 && seen.insert(format!("{loc}:{v}")) {
````

**Fix:** In `detect`, compute the UUID byte-ranges for the current `text` and skip any integer match whose range overlaps a UUID. Ranges must be collected per (loc, text) iteration, not globally, since url and body are scanned separately:

```rust
for (loc, text) in [("url", url), ("body", body)] {
    let mut uuid_ranges: Vec<std::ops::Range<usize>> = Vec::new();
    for m in uuid_re.find_iter(text) {
        uuid_ranges.push(m.range());
        let v = m.as_str().to_string();
        if seen.insert(format!("{loc}:{v}")) {
            out.push(IdCandidate { location: loc.into(), value: v, kind: "uuid".into() });
        }
    }
    for m in int_re.find_iter(text) {
        // Skip integer runs that fall inside an already-detected UUID.
        if uuid_ranges.iter().any(|r| m.start() < r.end && r.start < m.end()) {
            continue;
        }
        let v = m.as_str().to_string();
        if seen.insert(format!("{loc}:{v}")) {
            out.push(IdCandidate { location: loc.into(), value: v, kind: "int".into() });
        }
    }
}
```

This is safe: `find_iter` ranges are byte offsets into the same `text`, overlap test uses standard half-open interval overlap, and dropping the always-true `v.len() >= 1` guard changes nothing. It does not affect legitimate standalone integer IDs outside UUIDs.

_Verified (high): Cited code at lines 53-58 is present exactly as described. The integer regex `\b\d{1,12}\b` does match pure-digit runs inside a UUID because `-` is a non-word char providing word boundaries (e.g. in `12345678-1234-1234-1234-123456789012`, the runs `12345678`, `1234`, and `123456789012` all match). The `seen` set keys on `format!("{loc}:{v}")` (value only, no position), and the UUID candidate string differs from the inner int string, so dedup does not suppress them. No later filtering removes these (verified through fuzz_ids lines 119-149): each spurious int candidate is mutated and replayed, consuming the 120-replay budget, and mutate_request (line 93/103) uses `replacen(&c.value, mutated, 1)` which replaces the digit run *inside* the UUID, corrupting it. The stated consequences (wasted replay budget, wrong-substring replacement) are real. Severity is genuinely low: no panic, just noise and budget waste; spurious replays generally won't flag as interesting. The note that `v.len() >= 1` is always true is also correct since the regex requires ≥1 digit._


---

#### [x] #78 · `crates/lancer-report/src/exporters.rs:185-191` · LOW · parsing
**faraday_csv field-quoting omits carriage return, can corrupt CSV records**

**Problem:** csv_field() only quotes a field when it contains ',', '"', or '\n'. A field value containing a bare carriage return ('\r') without a following '\n' is emitted unquoted. Per RFC 4180 and most CSV parsers (including spreadsheet importers), an unquoted '\r' is treated as a record terminator, so an issue name/description/url/remediation that contains a lone '\r' (common when text was captured from HTTP responses, which use CRLF) splits one logical row into two malformed rows, shifting every subsequent column and producing a corrupt export.

**Evidence:**
````
fn csv_field(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}
````

**Fix:** In crates/lancer-report/src/exporters.rs, change csv_field to also quote on carriage return:

fn csv_field(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

_Verified (high): Code at crates/lancer-report/src/exporters.rs:185-191 matches the evidence exactly: csv_field() only quotes when a field contains ',', '"', or '\n', omitting '\r'. faraday_csv() passes issue fields (name/host/url/description/remediation) through csv_field. These fields can carry HTTP-captured text using CRLF line endings; a lone bare '\r' (or even CRLF, since unquoted CR before LF is also mishandled by RFC 4180 parsers) is emitted unquoted, and RFC 4180 / spreadsheet importers treat unquoted CR as a record terminator — splitting one logical row and shifting subsequent columns. Nothing in Rust's type system or surrounding code sanitizes/strips CR beforehand, and the function is reachable (the only quoting path for this exporter). The proposed fix only widens the quoting condition, which is always safe (over-quoting is valid CSV and round-trips correctly)._


---

#### [x] #79 · `crates/lancer-scanner/src/active/mass_assignment.rs:45-62` · LOW · logic-error
**Mass-assignment dedup still matches two insertion points (JsonKey + JsonValue) with the same name, producing duplicate issues**

**Problem:** Inspector::walk_json (lancer-core/src/inspector.rs lines 157-184) emits, for each top-level JSON field, BOTH a `ParamLocation::JsonKey` param and a `ParamLocation::JsonValue` param that share the identical `name`. The check accepts either location (line 45-50) and then dedups by requiring `point.name == first_object_key` (line 51-62). Because the chosen first key is present as two insertion points with the same name, the check passes the guard twice and emits the same 'Mass assignment' issue twice for a single triggering request. Additionally `m.keys().next()` returns the BTreeMap (alphabetically) first key, not the first-observed key as the comment on line 60 claims, so 'first JSON key we observe' is misleading and the chosen field is order-dependent.

**Evidence:**
````
if !matches!(point.location, ParamLocation::JsonValue | ParamLocation::JsonKey) { return issues; }
if point.name != base.body_text()...and_then(|m| m.keys().next().cloned())...unwrap_or_default() {
    // run only against the first JSON key we observe to dedupe
    return issues;
}
````

**Fix:** Restrict the location guard so exactly one insertion point per key passes. Replace the JsonValue|JsonKey guard with JsonKey only, since a top-level key always emits a JsonKey regardless of its value type (an object/array-valued first key has no scalar JsonValue at that name, so restricting to JsonValue could occasionally skip the run entirely). Change lines 45-50 from:

    if !matches!(
        point.location,
        lancer_core::ParamLocation::JsonValue | lancer_core::ParamLocation::JsonKey
    ) {
        return issues;
    }

to:

    if !matches!(point.location, lancer_core::ParamLocation::JsonKey) {
        return issues;
    }

Keep the existing first-key dedup check (lines 51-62) unchanged. Optionally fix the misleading comment on line 60 ('first JSON key we observe' -> 'alphabetically-first top-level JSON key') since serde_json::Map is a BTreeMap without preserve_order. The request modification (lines 63-72) ignores point.location/point.name entirely, so picking JsonKey alone is functionally complete and equivalent — no behavior is lost.

_Verified (high): Verified against real code. inspector.rs walk_json (lines 162 + 172-183) emits, for each top-level scalar JSON field, BOTH a ParamLocation::JsonKey param and a ParamLocation::JsonValue param with the identical name. insertion.rs find_insertion_points (lines 16-23) maps each Param 1:1 to an InsertionPoint preserving name+location, so two points exist for the first key. engine.rs (lines 67-84) calls each ActiveCheck::run once per insertion point and collects all results. In mass_assignment.rs the location guard (lines 45-50) accepts JsonValue OR JsonKey, and the dedup guard (lines 51-62) only checks point.name == first BTreeMap key. Both the JsonKey and JsonValue points for the first key pass both guards, so run() executes its modification + send twice and can push two identical High/Firm 'Mass assignment' issues. Issue::new assigns a fresh Uuid each time (issues.rs:102) and IssueStore::insert has no content-based dedup/ON CONFLICT (issues.rs:131-152), so both duplicates persist. The secondary claim is also correct: serde_json has no preserve_order feature in the workspace (Cargo.toml:114), so Map is a BTreeMap and m.keys().next() returns the alphabetically-first key, not the first-observed key the comment claims — the choice is order-dependent. Consequence (duplicate issue per triggering request) genuinely occurs._


---

#### [x] #80 · `crates/lancer-scanner/src/active/xss.rs:60-67` · LOW · api-contract
**Canary-reflection XSS issue is created without check_id (and without notes)**

**Problem:** In the main `body.contains(&payload)` branch the issue gets `i.check_id = Some(self.id().to_string())` (line 56). The `else if body.contains(&canary)` branch builds an Issue via Issue::new and pushes it directly, never setting check_id. The active scan engine (engine.rs run_active) does NOT backfill check_id for active issues (unlike run_passive which sets it), so this issue is persisted with check_id = None. That breaks per-check filtering/deduplication/false-positive grouping for the 'Canary reflection (possible filtered XSS)' finding, and is inconsistent with every other active check in this directory which all set check_id.

**Evidence:**
````
issues.push(Issue::new(
    base.meta.host.clone(),
    base.url(),
    "Canary reflection (possible filtered XSS)",
    Severity::Medium,
    Confidence::Tentative,
    format!("canary `{canary}` reflected but full payload was not — partial filtering"),
));
````

**Fix:** In crates/lancer-scanner/src/active/xss.rs, change the canary branch (lines 59-68) to bind the Issue to a mutable variable and set check_id (and notes, matching the sibling branch) before pushing:

} else if body.contains(&canary) {
    let mut i = Issue::new(
        base.meta.host.clone(),
        base.url(),
        "Canary reflection (possible filtered XSS)",
        Severity::Medium,
        Confidence::Tentative,
        format!("canary `{canary}` reflected but full payload was not — partial filtering"),
    );
    i.check_id = Some(self.id().to_string());
    i.notes = Some(format!("insertion point: {} ({:?})", point.name, point.location));
    issues.push(i);
}

This is safe: it mirrors the existing `if` branch and the pattern in every other active check (e.g. crlf.rs). It changes no control flow and only populates two previously-None Option fields.

_Verified (high): Verified against the actual code. In crates/lancer-scanner/src/active/xss.rs the `else if body.contains(&canary)` branch (lines 59-67) constructs an Issue via Issue::new and pushes it directly, never setting check_id (nor remediation/notes). The sibling `if body.contains(&payload)` branch sets `i.check_id = Some(self.id().to_string())` (line 56), and a grep shows all ~30 other active checks set check_id on every issue they emit. Critically, engine.rs::run_active (lines 56-96) does NOT backfill check_id — it collects task output into `out` and calls persist() directly — whereas run_passive (lines 42-54) explicitly sets `i.check_id` at line 48. So the canary Issue is persisted with check_id = None. Nothing in Rust's type system prevents this (check_id is Option<String> defaulting to None via Issue::new). The branch is reachable (a real partial-filtering scenario). Consequence stands: per-check filtering/dedup/false-positive grouping keyed on check_id breaks for the 'Canary reflection' finding. Severity low is appropriate (data-quality/consistency, not security or crash)._


---

#### [x] #81 · `crates/lancer-scanner/src/collaborator.rs:108` · LOW · correctness
**Collaborator poll cursor advances to post-response time, dropping interactions that arrive during the request**

**Problem:** poll() reads `since` (line 96), issues the HTTP request for interactions newer than `since`, and only after the response sets `last_poll = Utc::now()` (line 108). Any out-of-band interaction recorded on the collaborator server between the moment the poll request was sent and `Utc::now()` (the in-flight window) is excluded from this response (server filtered by the older `since`) AND excluded from the next poll (next `since` = the later `Utc::now()`). Such interactions are silently lost, which for an OOB detector means missed vulnerabilities (false negatives).

**Evidence:**
````
let body = resp.body_text().unwrap_or("[]");
let items: Vec<Interaction> = serde_json::from_str(body)?;
self.state.write().last_poll = Some(Utc::now());
````

**Fix:** Capture the cursor timestamp before issuing the request and advance to it after a successful parse, closing the in-flight gap:

    async fn poll(&self) -> Result<Vec<Interaction>> {
        let since = self.state.read().last_poll;
        let url = match since {
            Some(t) => format!("{}/interactions?since={}", self.base_url, t.to_rfc3339()),
            None => format!("{}/interactions", self.base_url),
        };
        let cursor = Utc::now(); // capture BEFORE sending so no interaction can slip between windows
        let req = lancer_core::HttpRequest::builder("GET", &url)?;
        let resp = self.client.send(&req).await?;
        if !(200..300).contains(&resp.status) {
            anyhow::bail!("collaborator returned {}", resp.status);
        }
        let body = resp.body_text().unwrap_or("[]");
        let items: Vec<Interaction> = serde_json::from_str(body)?;
        self.state.write().last_poll = Some(cursor);
        Ok(items)
    }

Note: advancing only on a successfully parsed response (after the `?`) is preserved, so a failed request does not move the cursor forward. If server/client clock skew is a concern, advancing instead to the max `timestamp` seen in `items` (falling back to `cursor` when empty) is more robust, but the pre-request `cursor` is the minimal safe fix and matches the existing timestamp semantics.

_Verified (high): Code at crates/lancer-scanner/src/collaborator.rs is present exactly as cited: poll() reads `since` from last_poll (line 96), sends the GET request (line 102), then sets last_poll = Some(Utc::now()) (line 108) AFTER the response. Interactions recorded on the server during the in-flight window (request-send time to post-response Utc::now()) are filtered out of this response by the older `since` AND skipped by the next poll because the next `since` is the later Utc::now() that already postdates them. They fall into a permanent gap = false negatives for an OOB detector. `since` is used only to build the query URL and parking_lot RwLock (not std, no await-across-guard issue), so nothing else depends on last_poll being post-response; the fix is safe. Real but genuinely low severity since the gap window is small._


---

#### [x] #82 · `crates/lancer-session/src/cookie_jar.rs:71` · LOW · correctness
**Cookie path matching lacks a path-boundary check (RFC 6265 path-match)**

**Problem:** `for_request` decides whether a stored cookie applies to a request using `path.starts_with(&c.path)`. A bare prefix test matches across path-segment boundaries: a cookie scoped to path `/api` is incorrectly attached to requests for `/apifoo` or `/apixyz`, and a cookie scoped to `/app` leaks onto `/application`. RFC 6265 §5.1.4 requires the request-path to either equal the cookie-path, or have the cookie-path as a prefix where the cookie-path ends in `/`, or where the next character of the request-path is `/`. The current logic over-attaches cookies to unintended sibling paths, which in a session-handling tool can leak a path-scoped session/CSRF cookie to a request it should not accompany.

**Evidence:**
````
let path_ok = path.starts_with(&c.path);
````

**Fix:** Replace line 71 with an RFC 6265 §5.1.4 path-match that requires either exact equality or a prefix ending at a path boundary:

    let path_ok = path == c.path
        || (path.starts_with(&c.path)
            && (c.path.ends_with('/')
                || path.as_bytes().get(c.path.len()) == Some(&b'/')));

Using `path.as_bytes().get(c.path.len())` avoids any char-boundary concern on multibyte paths. This attaches a cookie scoped to `/api` only to `/api`, `/api/...` (and to `/apifoo` no longer), matching RFC 6265 behavior.

_Verified (high): The cited code is present verbatim at crates/lancer-session/src/cookie_jar.rs:71: `let path_ok = path.starts_with(&c.path);`. A bare prefix test matches across path-segment boundaries, so a cookie with an explicit `Path=/api` (parsed and stored verbatim at line 119) is wrongly attached to `/apifoo`, `/apixyz`, etc. The code is live: `for_request` is the public cookie-selection method. The default cookie path is `/` (line 106), which is harmless under starts_with, so the bug only manifests for explicitly path-scoped cookies — a real but narrow case, matching the 'low' severity. Rust's type system does not prevent this; nothing else re-checks the path. The proposed fix is safe: when `path.starts_with(&c.path)` holds, `c.path.len()` is a valid char-boundary index ≤ path.len(), so `path[c.path.len()..]` cannot panic; the `.as_bytes().get(..) == Some(&b'/')` variant is also safe. The fix correctly implements RFC 6265 §5.1.4 path-match._


---

#### [x] #83 · `crates/lancer-shadow/src/lib.rs:161-164` · LOW · parsing
**url_encode_body produces invalid percent-encoding for non-ASCII (multibyte) body characters**

**Problem:** The encoder iterates over `chars()` and emits `%{:02X}` of `c as u32 & 0xff`. For any non-ASCII Unicode scalar (e.g. 'é' = U+00E9, or any char above U+00FF), `c as u32 & 0xff` truncates the codepoint to its low byte, so the emitted percent-escape neither matches the UTF-8 byte sequence of that character nor is a valid round-trippable encoding. A body containing UTF-8 multibyte text is therefore corrupted/wrongly encoded (e.g. '€' U+20AC becomes '%AC' instead of '%E2%82%AC'). The resulting variant request carries a body that does not decode back to the original, so the 'URL-encode body' and 'Double URL-encode' mutations send semantically wrong payloads for any non-ASCII input.

**Evidence:**
````
let encoded: String = body_text.chars().map(|c| {
    if c.is_ascii_alphanumeric() { c.to_string() }
    else { format!("%{:02X}", c as u32 & 0xff) }
}).collect();
````

**Fix:** Percent-encode the UTF-8 bytes of the body rather than chars. Replace the encoder body (lines 161-164) with:

let encoded: String = body_text.bytes().map(|b| {
    if b.is_ascii_alphanumeric() { (b as char).to_string() }
    else { format!("%{:02X}", b) }
}).collect();

This emits valid, round-trippable percent-encoding for all input (e.g. '€' -> %E2%82%AC). double_url_encode_body works correctly on top of this unchanged since the once-encoded output is pure ASCII.

_Verified (high): Confirmed the exact code at crates/lancer-shadow/src/lib.rs lines 161-164: `body_text.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_string() } else { format!("%{:02X}", c as u32 & 0xff) })`. Iterating over `chars()` and masking the Unicode scalar with `& 0xff` truncates any non-ASCII codepoint to its low byte. For '€' (U+20AC) `c as u32 & 0xff == 0xAC`, yielding `%AC` instead of the correct UTF-8 sequence `%E2%82%AC`; for 'é' (U+00E9) it yields `%E9` instead of `%C3%A9`. Rust's type system does not prevent this — `c as u32` is a valid cast and the mask silently discards high bytes. The function is reachable: url_encode_body and double_url_encode_body are called as Shadow Repeater mutation variants. Consequence (corrupted, non-round-trippable body for non-ASCII input) is real. Severity is appropriately low: only affects non-ASCII bodies in heuristic mutation variants, no security/crash impact. The proposed byte-iteration fix is the correct standard percent-encoding approach and is safe (is_ascii_alphanumeric on a byte guarantees < 0x80, so `b as char` is valid ASCII)._


---

#### [x] #84 · `crates/lancer-stateful-fuzz/src/lib.rs:170` · LOW · off-by-one
**infer_sequences returns one sequence even when max is 0**

**Problem:** The cap is checked with `if sequences.len() >= max { return sequences; }` only *after* a push. When `max == 0`, the function still pushes the first matching sequence (len becomes 1) before the check `1 >= 0` triggers, returning 1 sequence despite a requested limit of 0. A caller passing `max_sequences: 0` (a deserializable value, since the field accepts any usize) expects zero sequences executed but gets one HTTP request fired against the target.

**Evidence:**
````
sequences.push(Sequence {
    id: Uuid::new_v4(),
    ops: vec![producer.clone(), consumer.clone()],
});
if sequences.len() >= max { return sequences; }
````

**Fix:** Guard the whole function with an early return before the loops, so a max of 0 yields zero sequences (the inner `>= max` checks alone cannot prevent the first push). At the top of `infer_sequences`, right after `let mut sequences = Vec::new();`:

    if max == 0 { return sequences; }

This is correct and safe: for max >= 1 behavior is unchanged (the existing post-push `if sequences.len() >= max` still caps at max), and for max == 0 no Sequence is ever constructed, so run_fuzz issues no HTTP requests.

_Verified (high): Code at crates/lancer-stateful-fuzz/src/lib.rs:166-170 matches the evidence exactly: the Sequence is pushed (len becomes 1) before the cap check `if sequences.len() >= max { return sequences; }`. With max==0, the first matching push makes len 1, then 1>=0 returns, yielding 1 sequence despite a requested limit of 0. max_sequences is a deserializable `pub usize` (the serde default of 50 only applies when the field is absent; an explicit 0 passes through unchanged). run_fuzz (line 264, 271-273) iterates the returned sequences and calls run_sequence, which issues real reqwest HTTP requests, so max_sequences:0 fires one HTTP request against the target instead of zero. The consequence is genuine. Severity is correctly low — 0 is a degenerate input with no UI path forcing it, but it is reachable via the API request body._


---

#### [x] #85 · `crates/lancer-storage/src/history.rs:156-185` · LOW · api-contract
**HistoryFilter.mime is a declared public filter field that list() never applies**

**Problem:** HistoryFilter exposes a public `mime: Option<MimeKind>` field (line 36) documented as a history filter, but HistoryStore::list() builds its WHERE clause only from host/method/status/search/only_in_scope and never references `filter.mime`. Any caller that sets `mime` to constrain results will silently get unfiltered rows back. It does not currently misbehave only because every present caller uses `..Default::default()` (mime = None), but the field is part of the struct's public contract and is a latent silent no-op.

**Evidence:**
````
if let Some(search) = &filter.search {
            sql.push_str(" AND (path LIKE ? OR host LIKE ?)");
            ...
        }
        if filter.only_in_scope {
            sql.push_str(" AND in_scope = 1");
        }
        sql.push_str(" ORDER BY captured_at DESC");
````

**Fix:** Two safe options.

Option A (preferred — apply the filter without lossy SQL prefix mapping). Reuse the existing classifier so all content-types that map to a MimeKind are covered. Since `mime` is a small dimension and rows are already deserialized, filter in Rust after fetch:

  let rows = q.fetch_all(&self.pool).await?;
  let mut out = Vec::with_capacity(rows.len());
  for r in rows {
      let rec = record_from_row(&r)?;
      if let Some(want) = filter.mime {
          let got = rec.mime.as_deref().map(MimeKind::from_content_type).unwrap_or(MimeKind::Unknown);
          if got != want { continue; }
      }
      out.push(rec);
  }
  Ok(out)

(Note: this interacts with LIMIT/OFFSET — if exact paging with a mime filter is required, do the classification in SQL instead by OR-ing the content-type patterns for that MimeKind, or push the limit handling after the in-Rust filter.)

Option B (if the field is genuinely unwanted): delete `pub mime: Option<MimeKind>` from HistoryFilter (history.rs:36) and drop the now-unused `MimeKind` import on line 4, removing the misleading public contract. All current callers use ..Default::default() so this is non-breaking.

_Verified (high): Confirmed against the actual source. HistoryFilter declares a public `mime: Option<MimeKind>` (history.rs:36), but HistoryStore::list() (history.rs:156-196) builds its WHERE clause only from host/method/status/search/only_in_scope and never references filter.mime. A caller setting `mime` would silently get unfiltered rows — Rust's type system does not catch this (a Some(mime) value compiles and is just never read). The code is live/reachable, not dead. It does not misbehave today only because every caller (lancer-cli history.rs, lancer-api main.rs x2, lancer-gui commands_ipc.rs, lancer-tools engagement.rs x3) uses ..Default::default() (mime = None). Severity low/latent is accurate. The proposed fix's note that the `mime` column stores the raw Content-Type string (bound from resp.header(\"Content-Type\") at lines 95/109, read as Option<String> at line 229) — not a MimeKind — is correct. However a single LIKE prefix is incomplete: several content-types map to one MimeKind (Html ← text/html AND application/xhtml+xml; Image ← image/*; Xml ← application/xml AND text/xml), so the proposed one-pattern SQL would under-match. Filtering in Rust via the existing MimeKind::from_content_type is more robust._


---

#### [x] #86 · `crates/lancer-templates/src/lib.rs:304-309` · LOW · correctness
**Numeric DSL variable compared against non-numeric RHS falls through to a wrong string comparison**

**Problem:** When LHS is a numeric variable (`status_code`, `content_length`, or `len(...)`) but the RHS does not parse as i64 (e.g. `status_code == foo` or a quoted non-numeric), the `if let (Some(l), Ok(r))` guard fails and execution falls to the string-comparison path at line 308. There `dsl_part(lhs, ...)` is called with lhs = "status_code"/"content_length"/"len(...)", none of which are header names, so dsl_part returns the response body. The code then compares the entire body against the RHS literal, producing a meaningless/incorrect result instead of failing the term. This yields wrong matcher verdicts for malformed or unusual DSL.

**Evidence:**
````
if let (Some(l), Ok(r)) = (lhs_num, rhs_lit.parse::<i64>()) {
    return match op { ... };
}
// String comparison (body/header == "literal").
let lhs_str = dsl_part(lhs, body, headers);
return match op { "==" => lhs_str == rhs_lit, "!=" => lhs_str != rhs_lit, _ => false };
````

**Fix:** Guard against falling through to the string-comparison path when the LHS is a numeric variable. Insert before line 307 (the string-comparison block):

```rust
if let (Some(l), Ok(r)) = (lhs_num, rhs_lit.parse::<i64>()) {
    return match op { "==" => l == r, "!=" => l != r, "<=" => l <= r, ">=" => l >= r, "<" => l < r, _ => l > r };
}
// A numeric LHS variable with a non-numeric RHS is a malformed/unsatisfiable
// term; never fall through to comparing it as a string against the whole body.
if lhs_num.is_some() {
    return false;
}
// String comparison (body/header == "literal").
let lhs_str = dsl_part(lhs, body, headers);
return match op { "==" => lhs_str == rhs_lit, "!=" => lhs_str != rhs_lit, _ => false };
```

This only changes behavior in the exact buggy case (numeric LHS + non-i64 RHS), returning false instead of doing an unintended whole-body string compare. The valid numeric path and the genuine body/header string-compare path are unaffected.

_Verified (high): Code at lines 304-309 is exactly as cited. When LHS is a numeric variable (status_code/content_length/len(...)) but RHS fails to parse as i64, the `if let (Some(l), Ok(r))` guard fails and control falls to line 308. dsl_part("status_code"/"content_length"/"len(...)", ...) returns `body` (none match the header-name arm at line 271), so the entire response body is string-compared against the RHS literal. For == / != ops this yields a meaningless verdict (e.g. `status_code != foo` becomes `body != "foo"`, almost always true). The numeric variable is never a real header/body source, so the string-compare path is semantically wrong here. Rust's types don't prevent it; the path is reachable for any malformed/non-numeric RHS DSL. Severity is genuinely low since well-formed Nuclei DSL uses numeric RHS, but the wrong-verdict consequence is real._


---

#### [x] #87 · `crates/lancer-tools/src/engagement.rs:108-117` · LOW · correctness
**CSRF PoC emits invalid enctype and empty form for multipart requests**

**Problem:** The doc comment states multipart/form-data is supported, but the code only populates fields when the MIME is FormUrlEncoded (line 118). For a multipart request the form's enctype attribute is set verbatim to the request's Content-Type header, which is `multipart/form-data; boundary=...`. Including the boundary parameter in an HTML form enctype is invalid, and no <input> fields are emitted, so the generated PoC submits an empty multipart form that does not reproduce the original request.

**Evidence:**
````
html.push_str(&format!(
    "<form name=\"csrf\" action=\"{}\" method=\"{}\" enctype=\"{}\">\n",
    req.url(),
    req.method.as_str(),
    req.header("Content-Type").unwrap_or("application/x-www-form-urlencoded"),
));
````

**Fix:** Two-part fix in generate_csrf_poc:

1. Set enctype from the parsed MimeKind, not the raw header, so no boundary leaks into the attribute. Compute `mime` first, then choose a canonical enctype keyword:

```rust
let mime = req
    .header("Content-Type")
    .map(MimeKind::from_content_type)
    .unwrap_or(MimeKind::FormUrlEncoded);
let enctype = match mime {
    MimeKind::Multipart => "multipart/form-data",
    _ => "application/x-www-form-urlencoded",
};
html.push_str(&format!(
    "<form name=\"csrf\" action=\"{}\" method=\"{}\" enctype=\"{}\">\n",
    req.url(),
    req.method.as_str(),
    enctype,
));
```

2. Emit hidden inputs for multipart bodies by parsing the boundary from the Content-Type and splitting parts. Only handle text parts (Content-Disposition: form-data with a name and no filename); skip file parts since a self-submitting CSRF form cannot recreate uploaded file bytes anyway:

```rust
match mime {
    MimeKind::FormUrlEncoded => {
        if let Ok(body) = std::str::from_utf8(&req.body) {
            for pair in body.split('&') {
                if let Some((k, v)) = pair.split_once('=') {
                    html.push_str(&format!(
                        "  <input type=\"hidden\" name=\"{}\" value=\"{}\" />\n",
                        html_escape(k), html_escape(v),
                    ));
                }
            }
        }
    }
    MimeKind::Multipart => {
        if let Some(boundary) = req.header("Content-Type")
            .and_then(|ct| ct.split("boundary=").nth(1))
            .map(|b| b.trim().trim_matches('"').to_string())
        {
            if let Ok(body) = std::str::from_utf8(&req.body) {
                let delim = format!("--{}", boundary);
                for part in body.split(&delim) {
                    let part = part.trim_start_matches("\r\n");
                    // split headers / value on the first blank line
                    if let Some((headers, value)) = part.split_once("\r\n\r\n") {
                        // only simple form-data text parts (no filename)
                        let lower = headers.to_ascii_lowercase();
                        if lower.contains("filename=") { continue; }
                        if let Some(name) = headers
                            .split("name=").nth(1)
                            .and_then(|s| s.split('"').nth(1))
                        {
                            let value = value.trim_end_matches("\r\n");
                            html.push_str(&format!(
                                "  <input type=\"hidden\" name=\"{}\" value=\"{}\" />\n",
                                html_escape(name), html_escape(value),
                            ));
                        }
                    }
                }
            }
        }
    }
    _ => {}
}
```

This keeps the existing FormUrlEncoded path identical, emits a valid enctype keyword, and reproduces multipart text fields. (Minimal alternative if a multipart parser is unwanted: at least fix the enctype keyword in step 1 and narrow the doc comment to only claim x-www-form-urlencoded support.)

_Verified (high): Verified the cited code in crates/lancer-tools/src/engagement.rs lines 102-136. The doc comment (line 103) claims "Supports application/x-www-form-urlencoded and multipart/form-data bodies." But: (1) line 112 sets the HTML form's enctype attribute verbatim from the Content-Type header. For a multipart request that header is `multipart/form-data; boundary=...`. enctype is an HTML enumerated attribute whose only valid keywords are application/x-www-form-urlencoded, multipart/form-data, text/plain; a value containing the `; boundary=...` suffix is invalid and browsers fall back to the default application/x-www-form-urlencoded, so the form is not even submitted as multipart. (2) line 118 only populates <input> fields when mime is FormUrlEncoded (confirmed MimeKind::Multipart and ::FormUrlEncoded are distinct variants in lancer-core/src/http_msg.rs, and from_content_type maps multipart/* to Multipart). So a multipart request yields a form with an invalid enctype and zero hidden inputs — an empty form that does not reproduce the original request. The code is reachable (public fn used by engagement CSRF-PoC feature). Consequence as stated is genuine. Severity low is appropriate._


---

#### [x] #88 · `crates/lancer-tools/src/engagement.rs:202-204` · LOW · resource-leak
**discover_content aborts entire run if any single wordlist entry fails URL join**

**Problem:** Inside the per-word loop, base_url.join(&word)? propagates an error out of discover_content. A single malformed wordlist entry (e.g. one containing a space or other char that makes join fail) causes the whole function to return Err, discarding all already-spawned tasks and the results collected so far; the owned permits acquired for in-flight tasks are dropped without those tasks being awaited. One bad line in a large wordlist kills the entire discovery scan.

**Evidence:**
````
for word in wordlist {
    let candidate = base_url.join(&word)?;
    let permit = sem.clone().acquire_owned().await?;
````

**Fix:** Skip entries that fail to join instead of aborting the whole run:

```rust
for word in wordlist {
    let candidate = match base_url.join(&word) {
        Ok(u) => u,
        Err(_) => continue,
    };
    let permit = sem.clone().acquire_owned().await?;
    ...
}
```

This preserves all valid candidates and tolerates the occasional malformed wordlist entry. (The `acquire_owned().await?` on the next line can also only fail if the semaphore is closed, which never happens here, so it is fine to leave.)

_Verified (high): Code at crates/lancer-tools/src/engagement.rs:202-204 matches the report exactly: `let candidate = base_url.join(&word)?;` inside the per-word spawn loop. The `?` propagates any join error out of `discover_content`, aborting the whole loop. Already-spawned `JoinHandle`s (in `handles`) are then dropped without being awaited (detached, results discarded), and no further words are processed — so one malformed wordlist entry kills the entire discovery scan. The functional defect and the proposed `continue` fix are correct. Two minor inaccuracies in the report's framing, neither of which changes the verdict: (1) "results collected so far" is wrong — `out` is built only after the loop (line 221+), so nothing is collected yet; the loss is the in-flight/queued tasks, not gathered results. (2) The "resource-leak" category is a stretch: dropping a JoinHandle detaches but does not leak (the task runs to completion and its owned permit drops cleanly); there is no leaked permit or unbounded resource. Whether `Url::join` realistically fails is the only soft spot — the url crate percent-encodes spaces and is lenient, so failures are uncommon, but malformed entries (e.g. invalid IPv6 literals, bad schemes) can fail, making the abort-on-one-bad-word behavior a genuine robustness bug. Net: real low-severity correctness/robustness issue; proposed fix is safe._


---

#### [x] #89 · `crates/lancer-tools/src/intruder.rs:168-195` · LOW · logic-error
**CharFrobberIter emits the unchanged base string once per position (delta == 0 case)**

**Problem:** `delta` cycles -1, 0, 1 for each position (it is reset to -1 only after exceeding 1). When `delta == 0`, `n = b + 0 = b`, so the byte is replaced with itself and the iterator yields a string identical to `base`. For an N-character base this produces N copies of the original payload, contradicting the doc comment 'All single-character substitutions of base' and wasting one Intruder request per position re-testing the unmodified value.

**Evidence:**
````
let b = self.base[self.pos] as i16;
            let n = b + self.delta;
            if (0..=255).contains(&n) {
                out[self.pos] = n as u8;
                self.delta += 1;
                if self.delta > 1 {
                    self.delta = -1;
                    self.pos += 1;
                }
````

**Fix:** Skip the no-op delta==0 in both advance sites of CharFrobberIter::next. Replace the body so delta steps -1 -> 1 -> reset, never producing delta==0:

```rust
impl Iterator for CharFrobberIter {
    type Item = String;
    fn next(&mut self) -> Option<String> {
        while self.pos < self.base.len() {
            let mut out = self.base.clone();
            let b = self.base[self.pos] as i16;
            let n = b + self.delta;
            // advance: -1 -> 1 -> (reset to -1, next pos), skipping the no-op 0
            let emit = (0..=255).contains(&n);
            if self.delta < 1 {
                self.delta = 1;            // -1 -> 1, skip 0
            } else {
                self.delta = -1;           // 1 -> reset, advance position
                self.pos += 1;
            }
            if emit {
                out[self.pos.min(self.base.len().saturating_sub(1))] = n as u8;
                // NOTE: pos may have advanced above; recompute against the byte we mutated
            }
            // ... (see cleaner version below)
        }
        None
    }
}
```

That ordering is fragile because pos is mutated before use. A cleaner, clearly-correct version captures the target index first, then advances:

```rust
impl Iterator for CharFrobberIter {
    type Item = String;
    fn next(&mut self) -> Option<String> {
        while self.pos < self.base.len() {
            let target = self.pos;
            let b = self.base[target] as i16;
            let n = b + self.delta;

            // step delta -1 -> 1 -> reset, skipping the no-op 0
            if self.delta < 1 {
                self.delta = 1;
            } else {
                self.delta = -1;
                self.pos += 1;
            }

            if (0..=255).contains(&n) {
                let mut out = self.base.clone();
                out[target] = n as u8;
                if let Ok(s) = String::from_utf8(out) {
                    return Some(s);
                }
            }
        }
        None
    }
}
```

This emits exactly b-1 and b+1 for each position (genuine substitutions only), skips delta==0, and preserves the existing out-of-range / non-UTF8 skip behavior (it just continues the while loop). It also dedups the previously duplicated advance logic into one place.

_Verified (high): Code at crates/lancer-tools/src/intruder.rs:156-195 matches the report. CharFrobberIter starts delta=-1 and cycles -1, 0, 1 per position before resetting to -1 and advancing pos. When delta==0, n = b + 0 = b, so out[self.pos] = b (the original byte), and the yielded String equals base. For an N-byte base this emits N copies identical to the original payload. The doc comment at line 45 promises "All single-character substitutions of `base`," which the no-op delta=0 case violates. Consequence (N wasted, redundant Intruder requests re-testing the unmodified value) is real and as stated. Severity low is appropriate — wasteful, not incorrect output. Note the delta-advance logic is duplicated in TWO branches (the in-range branch at 177-181 and the out-of-range branch at 187-191), so a correct fix must skip delta==0 in both, not just one. The report's single-site proposed snippet would be incomplete; my refined fix patches both advance sites._


---

#### [x] #90 · `crates/lancer-tools/src/sequencer.rs:124-127` · LOW · correctness
**Runs-test statistic uses wrong denominator (2*sqrt(n) instead of 2*sqrt(2n))**

**Problem:** The NIST runs-test z statistic is |V - 2*n*pi*(1-pi)| / (2*sqrt(2n)*pi*(1-pi)). The code uses 2.0 * (total_bits).sqrt() in the denominator, i.e. 2*sqrt(n) instead of 2*sqrt(2n). This inflates z by a factor of sqrt(2), systematically pushing runs_p_value too low and causing tokens to be judged 'non-random' (pass=false) more often than the test warrants.

**Evidence:**
````
let z = (transitions as f64 - expected).abs()
    / (2.0 * (total_bits as f64).sqrt() * pi * (1.0 - pi));
````

**Fix:** Change the denominator to use sqrt(2n):

    let z = (transitions as f64 - expected).abs()
        / (2.0 * (2.0 * total_bits as f64).sqrt() * pi * (1.0 - pi));

This yields the correct NIST normalization 2*sqrt(2n)*pi*(1-pi). (Optionally also use `transitions as f64 + 1.0` in the numerator to match V_n exactly, but that is a negligible refinement for total_bits >= 100.)

_Verified (high): Confirmed the cited code at crates/lancer-tools/src/sequencer.rs:124-127. The NIST SP 800-22 runs-test z-statistic is |V - 2*n*pi*(1-pi)| / (2*sqrt(2n)*pi*(1-pi)). The numerator term `expected = 2.0 * total_bits * pi * (1.0 - pi)` is correct (modulo a negligible +1 since the code uses `transitions` rather than `transitions+1` runs). The denominator is `2.0 * (total_bits).sqrt() * pi * (1.0-pi)` = 2*sqrt(n)*pi*(1-pi), but should be 2*sqrt(2n)*pi*(1-pi). This makes the denominator smaller by sqrt(2), inflating z by sqrt(2). Since the p-value `erfc(z/sqrt(2))` is monotonically decreasing in z, the inflated z yields a systematically lower p-value, biasing the randomness verdict toward 'non-random'. Type system does not prevent this; the code is reachable (called from token randomness analysis). Guards at line 117 (total_bits>=100) and line 121 (pi near 0.5) keep the denominator non-zero, so the proposed fix introduces no new division-by-zero. The fix is correct and safe._


---


## Rejected after verification (NOT fixed)

- `crates/lancer-bulkprobe/src/lib.rs:90` — techs.dedup() only removes adjacent duplicates, not all duplicates — _reason:_ The cited line `techs.dedup();` (line 90) exists exactly as described, and the general statement that Vec::dedup only removes adjacent duplicates is technically true. However, the reported consequence cannot occur in this function. Every push in detect_technologies uses a distinct string value, and no technology string is pushed by more than one code path: the `server`-header block (lines 47-52) pushes Nginx/Apache/IIS/Caddy/Gunicorn/Cloudflare, the x-powered-by block pushes PHP/ASP.NET/Express, x-generator pushes a "Generator:..." string, and each body heuristic (lines 67-89) pushes its own unique tag (WordPress, Drupal, Joomla, Next.js, etc.). No value appears in two different push sites, and each `if` runs at most once, so a given tag can never be added twice. The finding's premise — e.g. that 'Cloudflare' from the server header could be duplicated by a later body-derived push — is false; no body heuristic ever pushes 'Cloudflare' (or any other repeated value). Thus dedup() is effectively a harmless no-op and no duplicated tags can ever appear, regardless of dedup's adjacency limitation. The defect's stated impact does not materialize.
- `crates/lancer-cms/src/lib.rs:94` — Joomla detection mixes && and || without parentheses, changing intended grouping — _reason:_ The code at crates/lancer-cms/src/lib.rs:94 is exactly as cited and does parse as `contains("joomla!") || (contains("/templates/") && contains("administrator"))` due to Rust binding && tighter than ||. However, this is not a defect: the existing grouping is a reasonable, behavior-correct heuristic. `/templates/` alone is a weak signal shared by many sites/CMSes, so gating it behind a joint `administrator` (the Joomla admin path) check is a sensible false-positive guard — exactly why it differs from the other arms, which OR only strong independent signatures. The reporter's claimed intent ("/templates/ alone should detect Joomla") is unsupported speculation, and their proposed alternative `(joomla! || /templates/) && administrator` would be actively WORSE: it would fail to detect a page that clearly contains "joomla!" but lacks "administrator", breaking the strongest signal. The reporter even concedes the AND may be intended. There is no clippy lint for mixed &&/|| by default, the code compiles and runs correctly, and the stated consequence (missing weak-signal pages) is arguably correct behavior, not a bug. At most this warrants explicit parentheses for readability while preserving current semantics.
- `crates/lancer-deser/src/lib.rs:129` — Class-name length prefix u16 cast can wrap (theoretical, chain-name controlled) — _reason:_ The cited code at crates/lancer-deser/src/lib.rs:129 is present exactly as reported: `buf.extend_from_slice(&(class_name.len() as u16).to_be_bytes());`. However, the u16 cast cannot wrap. `java_envelope(chain, ..)` is only ever called from `generate()` (line 171) with `info.name`, where `info` is obtained by matching `req.chain` against the static `known_chains()` catalog (lines 165-168); an unknown chain returns an Err. All catalog names (e.g. "CommonsCollections1", "TypeConfuseDelegate") are short, so `class_name` = `com.lancer.ysoserial.{chain}` is at most a few dozen bytes — nowhere near the 65535 limit. The report itself acknowledges this is purely theoretical ("this cannot wrap today", "Mentioned for completeness"). Since the chain name is bounded by the static catalog, the stated consequence (silent prefix truncation) cannot occur with current code. This is a defensive-coding suggestion, not a genuine triggerable defect. Verdict: not real under the strict standard (must both exist AND cause the stated consequence). The actually-reachable user-controlled path is the cmd at line 137, which is out of scope for this line-129 finding.
- `crates/lancer-gui/src/app.rs:212-224` — Reverse proxy forwards hop-by-hop request headers (notably Connection/Transfer-Encoding) to the upstream HTTP/1 connection — _reason:_ The cited code at crates/lancer-gui/src/app.rs:212-224 is real and accurately quoted: the request-header copy loop skips only `host` and `content-length`, forwarding hop-by-hop headers verbatim. However, the claimed CONSEQUENCE does not materialize. I read hyper 1.9.0's HTTP/1 encoder (proto/h1/role.rs, the `encode` header-drain loop at lines ~678-940). The upstream body is a `Full<Bytes>` (BodyLength::Known). Hyper writes the body's implicit Content-Length only AFTER the explicit-header loop, guarded by `if !wrote_len`. The upstream Request is built WITHOUT a content-length header (skipped in app.rs), so two outcomes are possible, neither malformed: (1) If a stray `transfer-encoding: chunked` header is forwarded, the TE branch runs while `wrote_len==false`, writes `transfer-encoding: chunked`, sets `encoder=Encoder::chunked()` and `wrote_len=true`; the post-loop `if !wrote_len` is then skipped so NO Content-Length is emitted, and the sized body is correctly chunk-encoded. Result is a valid single-framing chunked request, NOT the claimed "both framing signals present" malformed request. (2) If a `content-length` had been forwarded after the body already set length, hyper rewinds and returns Err(new_user_header) -> handler returns 502, again not a malformed wire request. So hyper's encoder structurally deduplicates framing and never emits conflicting Content-Length + Transfer-Encoding. Additionally, the actual client is the trusted local webview/SPA doing `fetch("/api/v1/...")`, which does not emit `Transfer-Encoding: chunked`; a forwarded `Connection: keep-alive` is handled by the encoder's CONNECTION branch and is harmless to the upstream hyper server. The defect described is a real RFC 7230 §6.1 hop-by-hop hygiene gap, but it does not cause the stated malformed-request / upstream-confusion consequence, so per the verification bar it is not a real bug.
- `crates/lancer-modules/src/lib.rs:171` — start() unconditionally clobbers an Auto module's persisted state to On, losing the idle-timeout config — _reason:_ The cited line (crates/lancer-modules/src/lib.rs:171) does unconditionally set the in-memory state to ModuleState::On on a successful start(), clobbering an Auto state in memory. BUT the reported consequence — "permanently lost once states_snapshot() is persisted to modules.toml" — does not hold. persist_modules() (the sole writer of modules.toml, via states_snapshot()) is called from exactly ONE site: the /v1/modules/{id}/set-state handler (lancer-api/src/main.rs:1659). The /start handler (lines 1620-1626) and /stop handler do NOT call persist_modules. And in set-state, set_state(id, st) runs immediately before persist_modules (1658-1659), so the snapshot it writes always reflects the user's explicit choice, never a value clobbered by start(). Therefore start()'s in-memory clobber can never leak to disk. The persisted Auto{idle_timeout_min} survives and is rehydrated at boot (main.rs:300-311). The only real effect is a transient, session-only cosmetic glitch: GET /v1/modules would show On instead of Auto until the next restart restores it from the intact modules.toml. The idle_timeout_min config is never destroyed. Additionally, Auto's idle-timeout has no consuming logic anywhere (nothing reads idle_timeout_min to shut a module down), so even the in-memory clobber is functionally inert. The finding overstates a minor display inconsistency as permanent data loss, and that stated consequence is contradicted by the actual persistence flow.
- `crates/lancer-gui/web/src/views/Issues.svelte:111-124, 56, 121` — Expand/collapse state is keyed by loop index, not stable issue id — _reason:_ The code pattern described is accurately present: in crates/lancer-gui/web/src/views/Issues.svelte the `{#each filtered as issue, i}` block (line 111) is unkeyed, and expand state is keyed by the loop index — `toggle(i)` (line 113), `expanded[i]` (line 121), `{#if expanded[i]}` (line 124) — while `toggle(id)`/`expanded[id]` (lines 55-58) just store under whatever key is passed. `filtered` is a reactive derivation (line 53) that recomputes on `filter`/`hideFp` change, so after a filter change the same index points to a different issue and the wrong row would render as expanded. A stable `issue.id` does exist (used in `patchIssue`, line 30). So the bug pattern is real in isolation. HOWEVER, the stated user-facing consequence cannot occur: Issues.svelte is dead/unreachable code. It is not imported by App.svelte and not present in the `tabs` array (the source of truth for rendered views). Its only referrer is Sidebar.svelte, which is itself imported by nothing. CLAUDE.md explicitly classifies Issues.svelte (and Sidebar.svelte) as legacy/unused. Since no user ever renders this component, the wrong-issue-expanded behavior never manifests. Per the bar (genuine defect AND causes the stated consequence), the consequence is blocked by the component being unreachable, so is_real=false. If the maintainer ever re-wires this view into tabs, the fix below should be applied.
- `crates/lancer-gui/web/src/views/Settings.svelte:264-286` — Upstream-rule save misaligns preserved fields when an earlier rule is filtered out — _reason:_ The cited code (Settings.svelte:264-286) is present exactly as described, and the positional-reindex-after-filter pattern is genuinely fragile: `.map((u,i)=>...)` uses `i` against the FILTERED array but indexes the UNFILTERED `origRules[i]`, so adding a blank new row or clearing an originally-loaded rule's host_pattern does misalign `i` from its true original. However, the stated consequence (config corruption via wrong fields/shape) does NOT actually occur, for two reasons grounded in the backend type (crates/lancer-proxy/src/settings.rs:38-61): (1) `UpstreamRule` is ALWAYS nested `{ host_pattern, upstream: UpstreamProxy }` — plain serde, no flat variant. So every entry in `origRules` always has `.upstream` defined and never a top-level `.host`, meaning the nested branch (`origRules[i].upstream !== undefined`) or the `else` (also nested) always fires. The flat branch (`Object.assign(base, inner)`) is unreachable for real backend data, so shape is always correct regardless of misalignment. (2) The `{ ...origRules[i] }` field-preservation can only carry over `host_pattern` and `upstream`, and BOTH are unconditionally overwritten in the map (`base.host_pattern = u.host_pattern.trim()` and `base.upstream = inner`/`Object.assign`). `UpstreamRule` has no other fields, and the struct isn't deny_unknown_fields. So even when misaligned, the produced JSON is identical to the correctly-aligned result. The misalignment is real but inert — no corruption reaches the backend. This is a latent code smell, not a defect causing the stated harm.
