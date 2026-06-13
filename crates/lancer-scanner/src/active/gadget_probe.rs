//! §41 Deserialization Gadget Probe.
//!
//! Send serialized objects referencing specific class names with a Collaborator
//! pingback payload. When the target classpath contains the named class, the
//! deserialization triggers the pingback → confirmed presence. We can't
//! actually run collaborator inside this scope (it's a stub), so we use an
//! in-band length-delta heuristic plus error-string detection as a fallback.

use async_trait::async_trait;
use base64::Engine;
use bytes::Bytes;
use lancer_core::HttpRequest;
use lancer_storage::issues::{Confidence, Issue, Severity};
use lancer_tools::HttpClient;

use crate::insertion::InsertionPoint;
use crate::ActiveCheck;

pub struct GadgetProbeCheck;

/// Library class names — presence indicates a vulnerable gadget chain library.
const GADGET_CLASSES: &[(&str, &str)] = &[
    ("org.apache.commons.collections.functors.InvokerTransformer", "commons-collections 3.x"),
    ("org.apache.commons.collections4.functors.InvokerTransformer", "commons-collections 4.x"),
    ("org.codehaus.groovy.runtime.MethodClosure", "Groovy"),
    ("bsh.XThis", "BeanShell"),
    ("com.sun.rowset.JdbcRowSetImpl", "JdbcRowSetImpl (JDK)"),
    ("org.springframework.beans.factory.ObjectFactory", "Spring beans"),
    ("net.sf.json.JSONObject", "json-lib"),
    ("org.apache.commons.beanutils.BeanComparator", "commons-beanutils"),
    ("org.hibernate.engine.spi.TypedValue", "Hibernate"),
    ("javax.management.BadAttributeValueExpException", "JMX"),
    ("org.codehaus.xstream.XStream", "XStream"),
    ("com.thoughtworks.xstream.XStream", "XStream"),
    ("flexjson.JSONDeserializer", "Flexjson"),
    ("javassist.proxy.RuntimeSupport", "Javassist"),
    ("org.aspectj.weaver.tools.PointcutDesignatorHandler", "AspectJ"),
    // ── Expanded classpath fingerprint set (batch-16) ──
    ("org.apache.commons.collections.keyvalue.TiedMapEntry", "commons-collections 3.x"),
    ("org.apache.commons.collections4.keyvalue.TiedMapEntry", "commons-collections 4.x"),
    ("org.apache.commons.collections.map.LazyMap", "commons-collections 3.x"),
    ("org.apache.commons.collections.functors.ChainedTransformer", "commons-collections 3.x"),
    ("org.apache.commons.collections.functors.ConstantTransformer", "commons-collections 3.x"),
    ("org.apache.commons.collections.functors.InstantiateTransformer", "commons-collections 3.x"),
    ("org.codehaus.groovy.runtime.ConvertedClosure", "Groovy"),
    ("org.codehaus.groovy.runtime.ConversionHandler", "Groovy"),
    ("groovy.util.Expando", "Groovy"),
    ("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl", "Xalan (JDK)"),
    ("com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter", "Xalan (JDK)"),
    ("org.apache.xalan.xsltc.trax.TemplatesImpl", "Xalan"),
    ("org.springframework.core.SerializableTypeWrapper", "Spring core"),
    ("org.springframework.aop.framework.AdvisedSupport", "Spring AOP"),
    ("org.springframework.aop.target.SingletonTargetSource", "Spring AOP"),
    ("org.springframework.beans.factory.support.DefaultListableBeanFactory", "Spring beans"),
    ("org.hibernate.engine.spi.TypedValue", "Hibernate"),
    ("org.hibernate.tuple.component.AbstractComponentTuplizer", "Hibernate"),
    ("org.hibernate.property.access.spi.GetterMethodImpl", "Hibernate 5"),
    ("com.mchange.v2.c3p0.PoolBackedDataSource", "c3p0"),
    ("com.mchange.v2.c3p0.WrapperConnectionPoolDataSource", "c3p0"),
    ("com.rometools.rome.feed.impl.ObjectBean", "ROME"),
    ("com.sun.syndication.feed.impl.ObjectBean", "ROME (legacy)"),
    ("org.jboss.interceptor.builder.InterceptionModelBuilder", "JBoss interceptors"),
    ("org.jboss.weld.interceptor.builder.InterceptionModelBuilder", "Weld"),
    ("org.apache.click.control.Column", "Apache Click"),
    ("org.apache.wicket.util.upload.DiskFileItem", "Apache Wicket"),
    ("clojure.lang.PersistentArrayMap", "Clojure"),
    ("clojure.inspector.proxy$javax.swing.table.AbstractTableModel", "Clojure"),
    ("com.vaadin.data.util.NestedMethodProperty", "Vaadin"),
    ("com.vaadin.data.util.PropertysetItem", "Vaadin"),
    ("org.mozilla.javascript.ScriptableObject", "Mozilla Rhino"),
    ("org.mozilla.javascript.NativeJavaObject", "Mozilla Rhino"),
    ("sun.rmi.server.UnicastRef", "JDK RMI"),
    ("java.rmi.server.UnicastRemoteObject", "JDK RMI"),
    ("javax.naming.InitialContext", "JNDI (JDK)"),
    ("com.alibaba.fastjson.JSONObject", "fastjson"),
    ("oracle.jdbc.connector.OracleManagedConnectionFactory", "Oracle JDBC"),
    ("org.apache.myfaces.context.servlet.FacesContextImpl", "MyFaces"),
];

/// Build a minimal Java serialized blob that references `class_name`.
///
/// Format: `aced 0005 73 72 00 <len><classname>` — Java standard.
fn java_ser_for(class: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    // Magic + version
    buf.extend_from_slice(&[0xac, 0xed, 0x00, 0x05]);
    // TC_OBJECT(0x73) + TC_CLASSDESC(0x72)
    buf.push(0x73);
    buf.push(0x72);
    // Class name length + UTF
    let bytes = class.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(bytes);
    // serialVersionUID + flags
    buf.extend_from_slice(&[0; 8]);
    buf.push(0x02); // SC_SERIALIZABLE
    // no fields, no super, end
    buf.extend_from_slice(&[0x00, 0x00, 0x78, 0x70]);
    buf
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

#[async_trait]
impl ActiveCheck for GadgetProbeCheck {
    fn id(&self) -> &'static str { "active.gadget_probe" }
    fn name(&self) -> &'static str { "Deserialization gadget probe (Java)" }

    async fn run(&self, client: &HttpClient, base: &HttpRequest, _point: &InsertionPoint) -> Vec<Issue> {
        // Only target endpoints that look like they accept serialized data.
        let body = base.body_text().unwrap_or("");
        let ct = base.header("Content-Type").unwrap_or("").to_lowercase();
        let looks_like_serial = body.contains("rO0AB") // base64 'aced 0005'
            || body.contains("AAEC") // generic binary prefix
            || ct.contains("octet-stream")
            || ct.contains("x-java-serialized-object");
        if !looks_like_serial { return Vec::new(); }

        // Baseline first
        let Ok(baseline) = client.send(base).await else { return Vec::new() };
        let baseline_len = baseline.body.len();
        let baseline_status = baseline.status;

        let mut issues = Vec::new();
        for (class, label) in GADGET_CLASSES {
            let ser = java_ser_for(class);
            let payload = b64(&ser);

            let mut req = base.clone();
            req.body = Bytes::from(payload.into_bytes());
            req.set_header("Content-Length", req.body.len().to_string());

            let Ok(resp) = client.send(&req).await else { continue };
            let body_text = resp.body_text().unwrap_or("");
            let len_delta = resp.body.len() as i64 - baseline_len as i64;
            let status_changed = resp.status != baseline_status;

            // Heuristic: a target with this class will typically either:
            //   (a) trigger a different error (length/status delta significant)
            //   (b) leak the class name back in an error string
            let class_leaked = body_text.contains(class);
            let strong_delta = len_delta.abs() > 100 || status_changed;

            if class_leaked || strong_delta {
                let mut i = Issue::new(
                    base.meta.host.clone(),
                    base.url(),
                    &format!("Classpath contains {label}"),
                    Severity::High,
                    if class_leaked { Confidence::Firm } else { Confidence::Tentative },
                    format!(
                        "probe for `{class}` produced a distinctive response (len Δ {len_delta}, status {}{})",
                        resp.status,
                        if class_leaked { ", classname leaked in body" } else { "" }
                    ),
                );
                i.remediation = Some(
                    "Upgrade vulnerable libraries; disable Java serialization where possible; use a lookahead deserialization filter (JEP 290).".into(),
                );
                i.check_id = Some(self.id().into());
                issues.push(i);
            }
        }

        issues
    }
}
