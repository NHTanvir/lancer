//! §5.1.1 Deep JS-rendering crawler (also backs §13 embedded browser + §7 live
//! DOM Invader). Renders a page in headless Chromium so client-side-JS routes,
//! `fetch`/XHR endpoints, and lazily-injected links are discovered — things a
//! plain HTML crawler misses on SPAs.
//!
//! Feature-gated: build with `--features chromium` (requires a Chrome/Chromium
//! binary on PATH). Without the feature, `crawl_js` returns a clear error.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JsCrawlResult {
    pub url: String,
    pub title: String,
    /// Links discovered after JS rendered the page.
    pub links: Vec<String>,
    /// `<script src>` URLs.
    pub scripts: Vec<String>,
    /// Endpoint-looking URLs scraped from the rendered DOM + inline JS.
    pub endpoints: Vec<String>,
}

#[cfg(feature = "chromium")]
pub async fn crawl_js(url: &str, wait_ms: u64) -> anyhow::Result<JsCrawlResult> {
    use chromiumoxide::{Browser, BrowserConfig};
    use futures::StreamExt;

    let cfg = BrowserConfig::builder()
        .build()
        .map_err(|e| anyhow::anyhow!("chromium config: {e}"))?;
    let (mut browser, mut handler) = Browser::launch(cfg).await?;
    let handler_task = tokio::spawn(async move { while handler.next().await.is_some() {} });

    let result = (|| async {
        let page = browser.new_page(url).await?;
        page.wait_for_navigation().await?;
        if wait_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(wait_ms)).await;
        }
        let title = page.get_title().await?.unwrap_or_default();

        let links: Vec<String> = page
            .evaluate("Array.from(document.querySelectorAll('a[href]')).map(a => a.href)")
            .await?
            .into_value()
            .unwrap_or_default();
        let scripts: Vec<String> = page
            .evaluate("Array.from(document.querySelectorAll('script[src]')).map(s => s.src)")
            .await?
            .into_value()
            .unwrap_or_default();
        let forms: Vec<String> = page
            .evaluate("Array.from(document.querySelectorAll('form[action]')).map(f => f.action)")
            .await?
            .into_value()
            .unwrap_or_default();
        let html: String = page.content().await.unwrap_or_default();

        Ok::<_, anyhow::Error>((title, links, scripts, forms, html))
    })()
    .await;

    let _ = browser.close().await;
    handler_task.abort();
    let (title, links, scripts, forms, html) = result?;

    // Scrape endpoint-looking URLs from the rendered DOM + inline JS.
    let re = regex::Regex::new(r#"["'`](/[A-Za-z0-9_./\-]{2,}|https?://[A-Za-z0-9_./:\-]+)["'`]"#).unwrap();
    let mut endpoints: Vec<String> = forms;
    for cap in re.captures_iter(&html) {
        if let Some(m) = cap.get(1) {
            endpoints.push(m.as_str().to_string());
        }
    }
    endpoints.sort();
    endpoints.dedup();

    Ok(JsCrawlResult { url: url.to_string(), title, links, scripts, endpoints })
}

#[cfg(not(feature = "chromium"))]
pub async fn crawl_js(_url: &str, _wait_ms: u64) -> anyhow::Result<JsCrawlResult> {
    anyhow::bail!("deep JS crawler disabled — rebuild with `--features chromium` (needs a Chrome/Chromium binary)")
}
