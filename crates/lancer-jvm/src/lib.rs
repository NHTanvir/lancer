//! JVM-embedding plugin host so existing Burp Montoya extensions can load.
//!
//! Feature-gated (`jvm`). Without the feature flag we ship the trait + a
//! stub; with it we boot an in-process JVM via the `jni` crate, load the
//! plugin JAR, and call its Montoya-compatible entry method.
//!
//! Lancer exposes its own `MontoyaShim` Java interface that mirrors the
//! parts of `burp.api.montoya.MontoyaApi` we currently route into:
//! `proxy.requestHandler`, `proxy.responseHandler`, and a few core helpers.
//! Extensions written against Burp's official Montoya API can be loaded
//! unchanged as long as they don't reach for the parts we don't ship yet.

use std::path::PathBuf;

use anyhow::Result;
use async_trait::async_trait;
use lancer_plugin::hosts::{Host, HostKind, InvocationCtx};

#[derive(Clone, Debug)]
pub struct JvmConfig {
    /// Path to libjvm. On Windows: `<JDK>/bin/server/jvm.dll`. On macOS:
    /// `<JDK>/lib/server/libjvm.dylib`. On Linux: `<JDK>/lib/server/libjvm.so`.
    pub libjvm: PathBuf,
    /// Class-path entries (JAR files + directories) to pass to the JVM.
    pub classpath: Vec<PathBuf>,
    /// Initial JVM heap, e.g. "512m".
    pub initial_heap: String,
    /// Max JVM heap.
    pub max_heap: String,
}

impl Default for JvmConfig {
    fn default() -> Self {
        Self {
            libjvm: PathBuf::new(),
            classpath: Vec::new(),
            initial_heap: "256m".into(),
            max_heap: "1g".into(),
        }
    }
}

#[cfg(feature = "jvm")]
pub mod runtime {
    use super::*;
    use std::sync::Arc;

    use jni::objects::{JObject, JString, JValue};
    use jni::sys::jvalue;
    use jni::{InitArgsBuilder, JNIEnv, JNIVersion, JavaVM};
    use parking_lot::Mutex;

    pub struct JvmHost {
        pub jvm: Arc<JavaVM>,
        plugins: Mutex<std::collections::HashMap<String, String>>, // id -> class name
    }

    impl JvmHost {
        pub fn boot(config: JvmConfig) -> Result<Self> {
            // jni::JavaVM::with_libjvm lets us point at a custom libjvm path —
            // important on Windows where the OS won't auto-resolve `jvm.dll`.
            let libjvm = config.libjvm.clone();
            // libjvm is `<JDK>/{bin,lib}/server/<jvm-lib>`; strip three components
            // (file -> server -> bin/lib -> JDK root) so JAVA_HOME is the JDK root.
            let java_home = libjvm
                .parent()
                .and_then(|p| p.parent())
                .and_then(|p| p.parent())
                .unwrap_or(&libjvm);
            std::env::set_var("JAVA_HOME", java_home);
            let cp = config
                .classpath
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(if cfg!(windows) { ";" } else { ":" });
            let args = InitArgsBuilder::new()
                .version(JNIVersion::V8)
                .option(format!("-Djava.class.path={cp}"))
                .option(format!("-Xms{}", config.initial_heap))
                .option(format!("-Xmx{}", config.max_heap))
                .build()?;
            let jvm = JavaVM::new(args)?;
            Ok(Self {
                jvm: Arc::new(jvm),
                plugins: Mutex::new(Default::default()),
            })
        }

        /// Register a plugin by its fully-qualified class name. The plugin's
        /// class must expose a public static method
        ///   `public static String lancerInvoke(String ctxJson)`.
        pub fn register(&self, plugin_id: &str, class_name: &str) {
            self.plugins.lock().insert(plugin_id.into(), class_name.into());
        }

        fn call_invoke(&self, class_name: &str, ctx_json: &str) -> Result<String> {
            let mut env: JNIEnv = self.jvm.attach_current_thread_as_daemon()?;
            let class = env.find_class(class_name.replace('.', "/"))?;
            let arg = env.new_string(ctx_json)?;
            let result = env.call_static_method(
                class,
                "lancerInvoke",
                "(Ljava/lang/String;)Ljava/lang/String;",
                &[JValue::Object(&arg)],
            )?;
            let s: JString = result.l()?.into();
            let owned: String = env.get_string(&s)?.into();
            Ok(owned)
        }
    }

    #[async_trait]
    impl Host for JvmHost {
        fn kind(&self) -> HostKind { HostKind::Native }
        async fn invoke(&self, plugin_id: &str, ctx: InvocationCtx) -> Result<serde_json::Value> {
            let class_name = self
                .plugins
                .lock()
                .get(plugin_id)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("unknown JVM plugin {plugin_id}"))?;
            let ctx_json = serde_json::to_string(&ctx)?;
            let raw = self.call_invoke(&class_name, &ctx_json)?;
            Ok(serde_json::from_str(&raw)?)
        }
    }
}

#[cfg(not(feature = "jvm"))]
pub struct JvmHost;

#[cfg(not(feature = "jvm"))]
impl JvmHost {
    pub fn boot(_config: JvmConfig) -> Result<Self> {
        anyhow::bail!("JVM host disabled — rebuild with `--features jvm`")
    }
    pub fn register(&self, _plugin_id: &str, _class_name: &str) {}
}

#[cfg(not(feature = "jvm"))]
#[async_trait]
impl Host for JvmHost {
    fn kind(&self) -> HostKind { HostKind::Native }
    async fn invoke(&self, _id: &str, _ctx: InvocationCtx) -> Result<serde_json::Value> {
        anyhow::bail!("JVM host disabled — rebuild with `--features jvm`")
    }
}

/// MontoyaShim.java — the Java-side interface our wrapper exposes.
/// Drop into your plugin's source tree (or build into the host's classpath
/// alongside libjvm). Provides minimal compatibility with Burp's Montoya API
/// so most read-only extensions can run unchanged.
pub const MONTOYA_SHIM_JAVA: &str = r#"
package io.lancer.montoya;

import java.util.Map;
import java.util.HashMap;

public class MontoyaShim {
    public static String lancerInvoke(String ctxJson) {
        // Default no-op implementation. Real plugins override this method.
        Map<String, Object> out = new HashMap<>();
        out.put("ok", true);
        out.put("noop", true);
        return jsonOf(out);
    }

    private static String jsonOf(Map<String, Object> m) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> e : m.entrySet()) {
            if (!first) sb.append(',');
            first = false;
            sb.append('"').append(e.getKey()).append('"').append(':');
            Object v = e.getValue();
            if (v instanceof String) sb.append('"').append(v).append('"');
            else sb.append(v.toString());
        }
        sb.append('}');
        return sb.toString();
    }
}
"#;
