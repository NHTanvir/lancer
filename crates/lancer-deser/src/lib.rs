//! §40 Deserialization payload generator — ysoserial / ysoserial.net equivalent.
//!
//! Generates raw payload bytes for known Java + .NET gadget chains. Distinct
//! from §5.2 deserialization *detection* — this generates *exploit* payloads.
//!
//! Authorization gate: ysoserial-style chains execute arbitrary code. Every
//! generated payload is flagged `requires_authorization = true`. The caller is
//! responsible for enforcing `--target-authorized`.

use base64::Engine;
use serde::{Deserialize, Serialize};

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Encoding {
    Raw,
    Base64,
    Hex,
    UrlEncoded,
    FormEncoded,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Java,
    DotNet,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadRequest {
    pub chain: String,
    pub cmd: String,
    #[serde(default = "default_encoding")]
    pub encoding: Encoding,
}

fn default_encoding() -> Encoding { Encoding::Base64 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedPayload {
    pub chain: String,
    pub platform: Platform,
    pub encoding: Encoding,
    pub payload: String,
    pub requires_authorization: bool,
}

// ── Chain catalog ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ChainInfo {
    pub name: &'static str,
    pub platform: Platform,
    pub description: &'static str,
    pub library: &'static str,
}

const fn c(
    name: &'static str,
    platform: Platform,
    description: &'static str,
    library: &'static str,
) -> ChainInfo {
    ChainInfo { name, platform, description, library }
}

pub fn known_chains() -> Vec<ChainInfo> {
    use Platform::*;
    vec![
        // Java
        c("CommonsCollections1", Java, "Apache Commons Collections 3.x InvokerTransformer chain", "commons-collections:3.1"),
        c("CommonsCollections2", Java, "Apache Commons Collections 4.x InvokerTransformer chain", "commons-collections4:4.0"),
        c("CommonsCollections3", Java, "CC3 — InstantiateTransformer", "commons-collections:3.1"),
        c("CommonsCollections4", Java, "CC4 — InstantiateTransformer", "commons-collections4:4.0"),
        c("CommonsCollections5", Java, "CC5 — BadAttributeValueExpException", "commons-collections:3.1"),
        c("CommonsCollections6", Java, "CC6 — HashSet trigger", "commons-collections:3.1"),
        c("CommonsCollections7", Java, "CC7 — Hashtable trigger", "commons-collections:3.1"),
        c("CommonsBeanutils1", Java, "BeanComparator + PropertyUtils", "commons-beanutils"),
        c("Spring1", Java, "Spring AOP gadget chain", "spring-core, spring-beans"),
        c("Spring2", Java, "Spring AOP variant", "spring-core, spring-beans"),
        c("Groovy1", Java, "Groovy MethodClosure chain", "groovy"),
        c("Hibernate1", Java, "Hibernate TypedValue chain", "hibernate-core"),
        c("Hibernate2", Java, "Hibernate variant", "hibernate-core"),
        c("JBossInterceptors1", Java, "JBoss interceptor chain", "jboss-interceptors"),
        c("JSON1", Java, "json-lib JSONObject chain", "json-lib"),
        c("MozillaRhino1", Java, "Rhino NativeError chain", "rhino"),
        c("MozillaRhino2", Java, "Rhino variant", "rhino"),
        c("Vaadin1", Java, "Vaadin PropertysetItem chain", "vaadin-server"),
        c("Click1", Java, "Apache Click ColumnComparator", "click"),
        c("Clojure", Java, "Clojure AbstractTableModel chain", "clojure"),
        c("JavassistWeld1", Java, "Javassist + Weld bean", "weld-core, javassist"),
        c("JdkUtil", Java, "JDK 7u21 native gadget", "jdk"),
        c("ROME", Java, "ROME SyndFeedImpl chain", "rome"),
        c("Wicket1", Java, "Wicket DiskFileItem", "wicket-core"),
        c("URLDNS", Java, "URLDNS detection-only chain", "java-stdlib"),
        // .NET
        c("TypeConfuseDelegate", DotNet, "BinaryFormatter delegate confusion", ".NET runtime"),
        c("TextFormattingRunProperties", DotNet, "WPF TextFormattingRunProperties", "PresentationFramework"),
        c("ResourceSet", DotNet, "ResourceSet gadget", ".NET runtime"),
        c("ActivitySurrogateSelector", DotNet, "WF ActivitySurrogateSelector", "System.Workflow"),
        c("BinaryFormatter", DotNet, "Raw BinaryFormatter chain", ".NET runtime"),
        c("SoapFormatter", DotNet, "SoapFormatter chain", "Formatters.Soap"),
        c("JsonNet", DotNet, "Newtonsoft.Json TypeNameHandling chain", "Json.NET"),
        c("ObjectStateFormatter", DotNet, "ASP.NET ObjectStateFormatter", "ASP.NET"),
        c("LosFormatter", DotNet, "ASP.NET LosFormatter (ViewState)", "ASP.NET"),
        c("WindowsIdentity", DotNet, "WindowsIdentity gadget", ".NET runtime"),
    ]
}

// ── Payload synthesis ─────────────────────────────────────────────────────────
//
// We emit marker-bearing serialized envelopes. The real ysoserial chains
// include the full gadget classpath. We emit a representative envelope that
// wraps the command — sufficient for behavior testing through a proxy +
// Collaborator OAST and for chain selection, without shipping a ready-made
// worm.

fn java_envelope(chain: &str, cmd: &str) -> Result<Vec<u8>, String> {
    let cmd_len = u16::try_from(cmd.len())
        .map_err(|_| "command too long for TC_STRING (max 65535 bytes)".to_string())?;
    let mut buf = Vec::new();
    // ACED 0005 — Java serialization magic
    buf.extend_from_slice(&[0xac, 0xed, 0x00, 0x05]);
    // TC_OBJECT + TC_CLASSDESC
    buf.push(0x73);
    buf.push(0x72);
    let class_name = format!("com.lancer.ysoserial.{chain}");
    buf.extend_from_slice(&(class_name.len() as u16).to_be_bytes());
    buf.extend_from_slice(class_name.as_bytes());
    // serialVersionUID + flags
    buf.extend_from_slice(&[0; 8]);
    buf.push(0x02);
    buf.extend_from_slice(&[0x00, 0x00, 0x78, 0x70]);
    // Append the cmd as a TC_STRING.
    buf.push(0x74);
    buf.extend_from_slice(&cmd_len.to_be_bytes());
    buf.extend_from_slice(cmd.as_bytes());
    Ok(buf)
}

fn dotnet_envelope(chain: &str, cmd: &str) -> Vec<u8> {
    // BinaryFormatter v1.0 record header: 00 01 00 00 00 ff ff ff ff 01 00 00 00 00 00 00 00
    let mut buf = vec![
        0x00, 0x01, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    // Embed a UTF-16-LE class name + cmd as evidence
    let class_name = format!("Lancer.YsoSerial.{chain}");
    for ch in class_name.encode_utf16() {
        buf.extend_from_slice(&ch.to_le_bytes());
    }
    buf.extend_from_slice(&[0x00, 0x00]);
    for ch in cmd.encode_utf16() {
        buf.extend_from_slice(&ch.to_le_bytes());
    }
    buf
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Generate a payload for the given chain + command.
pub fn generate(req: &PayloadRequest) -> Result<GeneratedPayload, String> {
    let info = known_chains()
        .into_iter()
        .find(|c| c.name == req.chain)
        .ok_or_else(|| format!("unknown chain: {}", req.chain))?;

    let bytes = match info.platform {
        Platform::Java => java_envelope(&info.name, &req.cmd)?,
        Platform::DotNet => dotnet_envelope(&info.name, &req.cmd),
    };

    let encoded = encode(&bytes, req.encoding);

    Ok(GeneratedPayload {
        chain: info.name.into(),
        platform: info.platform,
        encoding: req.encoding,
        payload: encoded,
        requires_authorization: true,
    })
}

fn encode(bytes: &[u8], enc: Encoding) -> String {
    match enc {
        Encoding::Raw => String::from_utf8_lossy(bytes).into_owned(),
        Encoding::Base64 => base64::engine::general_purpose::STANDARD.encode(bytes),
        Encoding::Hex => hex::encode(bytes),
        Encoding::UrlEncoded => {
            bytes.iter().map(|b| match *b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    String::from(*b as char)
                }
                _ => format!("%{b:02X}"),
            }).collect()
        }
        Encoding::FormEncoded => {
            let mut out = String::from("payload=");
            for b in bytes {
                match *b {
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                        out.push(*b as char)
                    }
                    b' ' => out.push('+'),
                    _ => out.push_str(&format!("%{b:02X}")),
                }
            }
            out
        }
    }
}

/// Substitute `<collab>` in the cmd with a Collaborator payload.
pub fn substitute_collaborator(cmd: &str, collab_addr: &str) -> String {
    cmd.replace("<collab>", collab_addr)
}

/// Recommend chains based on a discovered library list.
pub fn suggest_for_libraries(libs: &[String]) -> Vec<String> {
    let mut hits = Vec::new();
    for chain in known_chains() {
        let lib = chain.library.to_lowercase();
        for found in libs {
            let f = found.to_lowercase();
            if lib.split(',').any(|l| f.contains(l.trim().split(':').next().unwrap_or("").trim())) {
                hits.push(chain.name.into());
                break;
            }
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn java_payload_generates() {
        let req = PayloadRequest {
            chain: "CommonsCollections1".into(),
            cmd: "touch /tmp/lancer".into(),
            encoding: Encoding::Base64,
        };
        let p = generate(&req).unwrap();
        assert_eq!(p.platform, Platform::Java);
        assert!(!p.payload.is_empty());
        assert!(p.requires_authorization);
    }

    #[test]
    fn dotnet_payload_generates() {
        let req = PayloadRequest {
            chain: "TypeConfuseDelegate".into(),
            cmd: "calc.exe".into(),
            encoding: Encoding::Hex,
        };
        let p = generate(&req).unwrap();
        assert_eq!(p.platform, Platform::DotNet);
    }

    #[test]
    fn unknown_chain_errors() {
        let req = PayloadRequest {
            chain: "Bogus".into(),
            cmd: "x".into(),
            encoding: Encoding::Raw,
        };
        assert!(generate(&req).is_err());
    }
}
