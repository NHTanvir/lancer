//! Minimal embedded shell for the dev HTTP server.
//! Real frontend lives outside this crate (Svelte / SolidJS / React TBD).

pub const INDEX_HTML: &str = r##"<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<title>Lancer</title>
<style>
  * { box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
  body { margin: 0; background: #0f111a; color: #d3d6e0; }
  header { padding: 12px 18px; background: #1a1d2b; border-bottom: 1px solid #292d40; display: flex; justify-content: space-between; align-items: center; }
  h1 { margin: 0; font-size: 16px; font-weight: 600; }
  main { padding: 24px; }
  input { width: 100%; background: #1a1d2b; border: 1px solid #292d40; color: #d3d6e0; padding: 10px 14px; border-radius: 6px; font-size: 14px; }
  ul { list-style: none; padding: 0; margin: 12px 0 0; }
  li { padding: 8px 12px; border-radius: 4px; cursor: pointer; }
  li:hover { background: #1a1d2b; }
  .hot { color: #6a7090; font-size: 12px; float: right; }
  .empty { color: #6a7090; padding: 12px; }
</style>
</head>
<body>
<header>
  <h1>Lancer</h1>
  <span id="status" class="hot">connecting…</span>
</header>
<main>
  <input id="q" autofocus placeholder="Type a command (try: repeater, scan, theme)…" />
  <ul id="list"></ul>
</main>
<script>
const $ = (sel) => document.querySelector(sel);
const list = $("#list");
const q = $("#q");
async function refresh() {
  const resp = await fetch("/api/palette?q=" + encodeURIComponent(q.value));
  const cmds = await resp.json();
  list.innerHTML = "";
  if (!cmds.length) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = "no commands";
    list.appendChild(li);
    return;
  }
  for (const cmd of cmds) {
    const li = document.createElement("li");
    li.innerHTML = `<span>${cmd.label}</span>` +
      (cmd.hotkey ? `<span class="hot">${cmd.hotkey}</span>` : "");
    list.appendChild(li);
  }
}
q.addEventListener("input", refresh);
refresh();
fetch("/api/status").then(r => r.json()).then(s => {
  $("#status").textContent = "Lancer " + s.version;
});
</script>
</body>
</html>
"##;
