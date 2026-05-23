//! Custom report templates via Tera (Handlebars-style syntax).
//!
//! User supplies a `.tera` file; we run it with `meta` and `issues` exposed
//! in the rendering context. Bundled defaults are also available by name.

use anyhow::Result;
use lancer_storage::issues::Issue;
use tera::{Context, Tera};

use crate::ReportMeta;

pub fn render(template_body: &str, meta: &ReportMeta, issues: &[Issue]) -> Result<String> {
    let mut t = Tera::default();
    t.add_raw_template("report.tera", template_body)?;
    let mut ctx = Context::new();
    ctx.insert("meta", meta);
    ctx.insert("issues", issues);
    Ok(t.render("report.tera", &ctx)?)
}

pub const DEFAULT_TEMPLATE: &str = r#"# {{ meta.title }}

_{{ meta.project_name }} — {{ meta.generated_at }}_

{% if meta.executive_summary %}## Executive summary

{{ meta.executive_summary }}

{% endif %}## Findings

{% for i in issues %}### [{{ i.severity }}/{{ i.confidence }}] {{ i.name }}

- **Host:** `{{ i.host }}`
- **URL:** `{{ i.url }}`

{{ i.description }}

{% if i.remediation %}**Remediation:** {{ i.remediation }}{% endif %}

{% endfor %}"#;
