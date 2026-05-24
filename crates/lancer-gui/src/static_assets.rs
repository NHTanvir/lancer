//! Svelte SPA build, embedded at compile time.
//!
//! Run `npm run build` in `crates/lancer-gui/web/` first; this points at
//! `crates/lancer-gui/dist/`, which Vite writes to (see web/vite.config.js).

use include_dir::{include_dir, Dir};

pub static FRONTEND: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/dist");

/// Fallback when the SPA hasn't been built — keeps the binary functional.
pub const FALLBACK_INDEX_HTML: &str = r##"<!doctype html>
<html><head><meta charset="utf-8"/><title>Lancer</title>
<style>body{font-family:system-ui;background:#0f111a;color:#d3d6e0;padding:40px}</style></head>
<body><h1>Lancer GUI</h1>
<p>Frontend assets not embedded. Build with:</p>
<pre>cd crates/lancer-gui/web &amp;&amp; npm install &amp;&amp; npm run build</pre>
</body></html>
"##;

pub fn lookup(path: &str) -> Option<(&'static [u8], &'static str)> {
    let trimmed = path.trim_start_matches('/');
    let key = if trimmed.is_empty() { "index.html" } else { trimmed };
    let file = FRONTEND.get_file(key)?;
    let ct = mime_for(key);
    Some((file.contents(), ct))
}

fn mime_for(path: &str) -> &'static str {
    if path.ends_with(".html") {
        "text/html; charset=utf-8"
    } else if path.ends_with(".js") || path.ends_with(".mjs") {
        "application/javascript; charset=utf-8"
    } else if path.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if path.ends_with(".json") {
        "application/json"
    } else if path.ends_with(".svg") {
        "image/svg+xml"
    } else if path.ends_with(".png") {
        "image/png"
    } else if path.ends_with(".ico") {
        "image/x-icon"
    } else if path.ends_with(".woff2") {
        "font/woff2"
    } else {
        "application/octet-stream"
    }
}
