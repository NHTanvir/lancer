//! `lancer infiltrator` — §57 Burp-Infiltrator equivalent.
//!
//! Burp Infiltrator patches a target's bytecode to pingback Collaborator when
//! scanner input reaches an unsafe sink. Lancer emits a **Frida** instrumentation
//! script (consistent with §22 mobile tooling) that hooks dangerous server-side
//! sinks at runtime — no recompile — and, when it sees an injected §6 OAST
//! payload reach a sink, does a DNS pingback `<sink>.<payload-host>` that the
//! OAST correlation engine ties back to the originating request ("input reached
//! Runtime.exec server-side"). Attach with `frida -l infiltrator.js -f <target>`.

use anyhow::Result;
use clap::{Args, ValueEnum};

#[derive(Debug, Clone, ValueEnum)]
enum Lang {
    Java,
    Node,
    Native,
}

#[derive(Debug, Args)]
pub struct InfiltratorArgs {
    /// OAST/Collaborator domain that injected payloads use (e.g. oast.lancer.local).
    #[arg(long)]
    domain: String,
    /// Target runtime to instrument.
    #[arg(long, value_enum, default_value = "java")]
    lang: Lang,
    /// Write the script to this file instead of stdout.
    #[arg(long)]
    out: Option<std::path::PathBuf>,
}

fn java_script(domain: &str) -> String {
    format!(r#"// Lancer Infiltrator — Java sink taint tracking (Frida).
// Attach: frida -l this.js -f <jvm-app>  (or -n for a running PID)
// When scanner input containing *.{domain} reaches a sink, pingback
// <sink>.<payload-host> so Lancer's OAST correlation flags the server-side hit.
const OAST = "{domain}";

function pingback(sink, value) {{
  const m = (value || "").toString().match(new RegExp("([a-z0-9-]+\\." + OAST.replace(/\./g, "\\.") + ")", "i"));
  if (!m) return;
  const host = sink + "." + m[1];
  try {{
    const InetAddress = Java.use("java.net.InetAddress");
    InetAddress.getByName(host);            // DNS pingback -> Lancer OAST server
    console.log("[lancer-infiltrator] " + sink + " reached with OAST payload -> " + host);
  }} catch (e) {{}}
}}

Java.perform(function () {{
  // OS command execution
  try {{
    const Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload("java.lang.String").implementation = function (cmd) {{
      pingback("exec", cmd); return this.exec(cmd);
    }};
    Runtime.exec.overload("[Ljava.lang.String;").implementation = function (a) {{
      pingback("exec", a ? a.join(" ") : ""); return this.exec(a);
    }};
  }} catch (e) {{}}
  try {{
    const PB = Java.use("java.lang.ProcessBuilder");
    PB.start.implementation = function () {{
      try {{ pingback("proc", this.command().toString()); }} catch (e) {{}}
      return this.start();
    }};
  }} catch (e) {{}}
  // File access
  try {{
    const FIS = Java.use("java.io.FileInputStream");
    FIS.$init.overload("java.lang.String").implementation = function (p) {{
      pingback("fileread", p); return this.$init(p);
    }};
  }} catch (e) {{}}
  // SQL
  try {{
    const Stmt = Java.use("java.sql.Statement");
    Stmt.execute.overload("java.lang.String").implementation = function (q) {{
      pingback("sql", q); return this.execute(q);
    }};
  }} catch (e) {{}}
  // SSRF / URL fetch
  try {{
    const URL = Java.use("java.net.URL");
    URL.openConnection.overload().implementation = function () {{
      pingback("urlopen", this.toString()); return this.openConnection();
    }};
  }} catch (e) {{}}
  console.log("[lancer-infiltrator] Java sink hooks installed (OAST=" + OAST + ")");
}});
"#)
}

fn node_script(domain: &str) -> String {
    format!(r#"// Lancer Infiltrator — Node.js sink taint tracking (Frida).
const OAST = "{domain}";
function pingback(sink, value) {{
  const m = (value || "").toString().match(new RegExp("([a-z0-9-]+\\." + OAST.replace(/\./g, "\\.") + ")", "i"));
  if (!m) return;
  try {{ require("dns").lookup(sink + "." + m[1], () => {{}}); }} catch (e) {{}}
}}
const cp = require("child_process");
for (const fn of ["exec", "execSync", "spawn", "spawnSync"]) {{
  const orig = cp[fn];
  cp[fn] = function () {{ pingback("exec", arguments[0]); return orig.apply(this, arguments); }};
}}
const fs = require("fs");
for (const fn of ["readFile", "readFileSync", "writeFile"]) {{
  const orig = fs[fn];
  fs[fn] = function () {{ pingback("file", arguments[0]); return orig.apply(this, arguments); }};
}}
console.log("[lancer-infiltrator] Node sink hooks installed (OAST=" + OAST + ")");
"#)
}

fn native_script(domain: &str) -> String {
    format!(r#"// Lancer Infiltrator — native libc sink taint tracking (Frida).
const OAST = "{domain}";
function pingback(sink, value) {{
  const m = (value || "").match(new RegExp("([a-z0-9-]+\\." + OAST.replace(/\./g, "\\.") + ")", "i"));
  if (!m) return;
  const host = Memory.allocUtf8String(sink + "." + m[1]);
  const gethostbyname = new NativeFunction(Module.getExportByName(null, "gethostbyname"), "pointer", ["pointer"]);
  gethostbyname(host); // DNS pingback
}}
["system", "popen", "execl", "execlp", "execv"].forEach(function (sym) {{
  try {{
    Interceptor.attach(Module.getExportByName(null, sym), {{
      onEnter: function (args) {{ try {{ pingback(sym, args[0].readUtf8String()); }} catch (e) {{}} }}
    }});
  }} catch (e) {{}}
}});
console.log("[lancer-infiltrator] native sink hooks installed (OAST=" + OAST + ")");
"#)
}

pub async fn run(args: InfiltratorArgs) -> Result<()> {
    let script = match args.lang {
        Lang::Java => java_script(&args.domain),
        Lang::Node => node_script(&args.domain),
        Lang::Native => native_script(&args.domain),
    };
    match &args.out {
        Some(path) => {
            std::fs::write(path, &script)?;
            eprintln!("Wrote Infiltrator script to {}", path.display());
            eprintln!("Attach with: frida -l {} -f <target>", path.display());
        }
        None => print!("{script}"),
    }
    Ok(())
}
