//! PDF report — text-only rendering of issues into a paginated A4 PDF.
//!
//! Built on `printpdf` so we don't need a Chromium/headless engine. Layout is
//! deliberately simple: title + per-issue heading and body, with wrapping and
//! page breaks. Good enough for archival; for design-heavy reports use HTML
//! and convert externally.

use lancer_storage::issues::{Issue, Severity};
use printpdf::*;

use crate::{ReportFilter, ReportMeta};

const PAGE_WIDTH_MM: f32 = 210.0;
const PAGE_HEIGHT_MM: f32 = 297.0;
const MARGIN_MM: f32 = 18.0;
const LINE_HEIGHT_MM: f32 = 5.0;
const FONT_SIZE_TITLE: f32 = 20.0;
const FONT_SIZE_HEADING: f32 = 13.0;
const FONT_SIZE_BODY: f32 = 10.0;
const CHARS_PER_LINE: usize = 95;

pub fn render_pdf(meta: &ReportMeta, issues: &[Issue], filter: &ReportFilter) -> Vec<u8> {
    let (doc, page1, layer1) = PdfDocument::new(
        meta.title.clone(),
        Mm(PAGE_WIDTH_MM),
        Mm(PAGE_HEIGHT_MM),
        "L1",
    );
    let font = doc
        .add_builtin_font(BuiltinFont::Helvetica)
        .expect("Helvetica");
    let font_bold = doc
        .add_builtin_font(BuiltinFont::HelveticaBold)
        .expect("Helvetica-Bold");

    let mut layer = doc.get_page(page1).get_layer(layer1);
    let mut cursor_mm = PAGE_HEIGHT_MM - MARGIN_MM;

    cursor_mm = put_line(
        &layer,
        &meta.title,
        MARGIN_MM,
        cursor_mm,
        FONT_SIZE_TITLE,
        &font_bold,
    );
    cursor_mm -= 2.0;
    cursor_mm = put_line(
        &layer,
        &format!(
            "{} — generated {}",
            meta.project_name,
            meta.generated_at.format("%Y-%m-%d %H:%M UTC")
        ),
        MARGIN_MM,
        cursor_mm,
        FONT_SIZE_BODY,
        &font,
    );
    cursor_mm -= 4.0;

    let kept: Vec<&Issue> = issues.iter().filter(|i| keep(filter, i)).collect();
    let (crit, high, med, low, info) = counts(&kept);
    cursor_mm = put_line(
        &layer,
        &format!(
            "Posture: {crit} critical · {high} high · {med} medium · {low} low · {info} info"
        ),
        MARGIN_MM,
        cursor_mm,
        FONT_SIZE_BODY,
        &font,
    );
    cursor_mm -= 4.0;

    if let Some(es) = &meta.executive_summary {
        cursor_mm = put_line(
            &layer,
            "Executive summary",
            MARGIN_MM,
            cursor_mm,
            FONT_SIZE_HEADING,
            &font_bold,
        );
        cursor_mm = put_wrapped(&layer, es, MARGIN_MM, cursor_mm, FONT_SIZE_BODY, &font);
        cursor_mm -= 4.0;
    }

    for i in kept {
        if cursor_mm < MARGIN_MM + 20.0 {
            let (p, l) = doc.add_page(Mm(PAGE_WIDTH_MM), Mm(PAGE_HEIGHT_MM), "Lx");
            layer = doc.get_page(p).get_layer(l);
            cursor_mm = PAGE_HEIGHT_MM - MARGIN_MM;
        }
        let heading = format!("[{}/{}] {}", i.severity.as_str(), i.confidence.as_str(), i.name);
        cursor_mm = put_line(
            &layer,
            &heading,
            MARGIN_MM,
            cursor_mm,
            FONT_SIZE_HEADING,
            &font_bold,
        );
        cursor_mm = put_wrapped(
            &layer,
            &format!("Host: {}  URL: {}", i.host, i.url),
            MARGIN_MM,
            cursor_mm,
            FONT_SIZE_BODY,
            &font,
        );
        cursor_mm = put_wrapped(&layer, &i.description, MARGIN_MM, cursor_mm, FONT_SIZE_BODY, &font);
        if let Some(rem) = &i.remediation {
            cursor_mm = put_wrapped(
                &layer,
                &format!("Remediation: {rem}"),
                MARGIN_MM,
                cursor_mm,
                FONT_SIZE_BODY,
                &font,
            );
        }
        cursor_mm -= 3.0;
    }

    let mut buf = std::io::BufWriter::new(Vec::new());
    doc.save(&mut buf).ok();
    buf.into_inner().unwrap_or_default()
}

fn put_line(
    layer: &PdfLayerReference,
    text: &str,
    x_mm: f32,
    y_mm: f32,
    size: f32,
    font: &IndirectFontRef,
) -> f32 {
    layer.use_text(text.to_string(), size, Mm(x_mm), Mm(y_mm), font);
    y_mm - LINE_HEIGHT_MM
}

fn put_wrapped(
    layer: &PdfLayerReference,
    text: &str,
    x_mm: f32,
    mut y_mm: f32,
    size: f32,
    font: &IndirectFontRef,
) -> f32 {
    for chunk in wrap(text, CHARS_PER_LINE) {
        y_mm = put_line(layer, &chunk, x_mm, y_mm, size, font);
    }
    y_mm
}

fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    for paragraph in text.split('\n') {
        let mut line = String::new();
        for word in paragraph.split_whitespace() {
            if line.len() + word.len() + 1 > width && !line.is_empty() {
                out.push(std::mem::take(&mut line));
            }
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(word);
        }
        if !line.is_empty() {
            out.push(line);
        }
    }
    if out.is_empty() {
        out.push(String::new());
    }
    out
}

fn counts(issues: &[&Issue]) -> (usize, usize, usize, usize, usize) {
    let mut c = (0, 0, 0, 0, 0);
    for i in issues {
        match i.severity {
            Severity::Critical => c.0 += 1,
            Severity::High => c.1 += 1,
            Severity::Medium => c.2 += 1,
            Severity::Low => c.3 += 1,
            Severity::Info => c.4 += 1,
        }
    }
    c
}

fn keep(filter: &ReportFilter, i: &Issue) -> bool {
    if !filter.include_fp && i.false_positive {
        return false;
    }
    if let Some(s) = filter.min_severity {
        if rank_sev(i.severity) < rank_sev(s) {
            return false;
        }
    }
    if let Some(c) = filter.min_confidence {
        if rank_conf(i.confidence) < rank_conf(c) {
            return false;
        }
    }
    if let Some(h) = &filter.host_filter {
        if !i.host.contains(h) {
            return false;
        }
    }
    true
}

fn rank_sev(s: Severity) -> u8 {
    match s {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

fn rank_conf(c: lancer_storage::issues::Confidence) -> u8 {
    use lancer_storage::issues::Confidence;
    match c {
        Confidence::Tentative => 0,
        Confidence::Firm => 1,
        Confidence::Certain => 2,
    }
}
