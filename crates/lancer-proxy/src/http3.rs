//! HTTP/3 (QUIC) support — outbound client + inbound listener.
//!
//! Feature-gated: rebuild with `--features http3` to pull in `quinn` /
//! `h3-quinn`. Without the feature, the placeholders here keep the module
//! compileable while clearly signalling that HTTP/3 is off.

use anyhow::Result;
use bytes::Bytes;
use lancer_core::{HttpRequest, HttpResponse, MessageMeta};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http3Config {
    pub max_idle_timeout_ms: u64,
    pub keep_alive_ms: u64,
    pub alpn: Vec<String>,
}

impl Default for Http3Config {
    fn default() -> Self {
        Self {
            max_idle_timeout_ms: 30_000,
            keep_alive_ms: 5_000,
            alpn: vec!["h3".to_string()],
        }
    }
}

#[cfg(feature = "http3")]
pub mod runtime {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::Arc;

    use anyhow::Context;
    use bytes::Buf;
    use quinn::{ClientConfig, Endpoint};
    use rustls::pki_types::ServerName;
    use rustls::RootCertStore;

    /// Dial `host:port` over QUIC, perform the H3 handshake, send the request,
    /// collect the response. One-shot — no connection pooling.
    pub async fn dial_and_send(
        host: &str,
        port: u16,
        req: &HttpRequest,
        cfg: &Http3Config,
    ) -> Result<HttpResponse> {
        // Build a rustls client config with HTTP/3 ALPN.
        let mut roots = RootCertStore::empty();
        for anchor in webpki_roots::TLS_SERVER_ROOTS.iter().cloned() {
            roots.roots.push(anchor);
        }
        let mut tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = cfg.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
        let qcfg = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .context("converting rustls -> quinn config")?;
        let mut client_cfg = ClientConfig::new(Arc::new(qcfg));
        let mut tp = quinn::TransportConfig::default();
        tp.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(std::time::Duration::from_millis(cfg.max_idle_timeout_ms))
                .unwrap_or_default(),
        ));
        tp.keep_alive_interval(Some(std::time::Duration::from_millis(cfg.keep_alive_ms)));
        client_cfg.transport_config(Arc::new(tp));

        let bind_addr: SocketAddr = "[::]:0".parse().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
        let mut endpoint = Endpoint::client(bind_addr).context("quinn endpoint")?;
        endpoint.set_default_client_config(client_cfg);

        let remote: SocketAddr = tokio::net::lookup_host((host, port))
            .await
            .context("lookup_host")?
            .next()
            .ok_or_else(|| anyhow::anyhow!("no addr"))?;
        let conn = endpoint
            .connect(remote, host)
            .context("connect")?
            .await
            .context("handshake")?;
        let h3_conn = h3_quinn::Connection::new(conn);
        let (mut driver, mut send_request) = h3::client::new(h3_conn).await.context("h3 init")?;
        tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let mut h3_req = http::Request::builder()
            .method(req.method.as_str())
            .uri(req.url())
            .version(http::Version::HTTP_3);
        for h in &req.headers {
            if h.name.eq_ignore_ascii_case("host") {
                continue;
            }
            h3_req = h3_req.header(h.name.as_str(), h.value.as_str());
        }
        let h3_req = h3_req.body(())?;

        let mut stream = send_request.send_request(h3_req).await.context("send_request")?;
        stream.send_data(req.body.clone()).await.ok();
        stream.finish().await.ok();

        let resp = stream.recv_response().await.context("recv_response")?;
        let mut body = Vec::new();
        while let Some(chunk) = stream.recv_data().await.context("recv_data")? {
            body.extend_from_slice(chunk.chunk());
        }
        let mut headers = Vec::new();
        for (n, v) in resp.headers() {
            headers.push(lancer_core::http_msg::Header {
                name: n.as_str().to_string(),
                value: v.to_str().unwrap_or("").to_string(),
            });
        }
        let mut meta = MessageMeta::new(&req.meta.host, &req.meta.scheme, req.meta.port);
        meta.tool_generated = true;
        Ok(HttpResponse {
            meta,
            status: resp.status().as_u16(),
            reason: resp.status().canonical_reason().unwrap_or("").to_string(),
            version: lancer_core::HttpVersion::Http3,
            headers,
            body: Bytes::from(body),
            elapsed_ms: None,
        })
    }

    // ── §1.1 Inbound HTTP/3 (QUIC) listener ──────────────────────────────────
    use quinn::ServerConfig;
    use lancer_core::http_msg::Header;

    fn split_authority(authority: &str, scheme: &str) -> (String, u16) {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().unwrap_or(443)),
            None => (authority.to_string(), if scheme == "http" { 80 } else { 443 }),
        }
    }

    /// Start an inbound HTTP/3 listener on `addr`. Each request is forwarded to
    /// the origin (from the `:authority`) over HTTP/3 and the response relayed
    /// back. Uses a self-signed cert with the `h3` ALPN (per-host MITM certs are
    /// a refinement). Runs until the endpoint is dropped.
    pub async fn inbound_listen(addr: SocketAddr) -> Result<()> {
        let ck = rcgen::generate_simple_self_signed(vec!["lancer-proxy".to_string()])
            .context("rcgen self-signed")?;
        let cert = rustls::pki_types::CertificateDer::from(ck.cert.der().to_vec());
        let key = rustls::pki_types::PrivateKeyDer::try_from(ck.key_pair.serialize_der())
            .map_err(|e| anyhow::anyhow!("key der: {e}"))?;
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .context("rustls server cfg")?;
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let qsc = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
            .context("quic server cfg")?;
        let endpoint = Endpoint::server(ServerConfig::with_crypto(Arc::new(qsc)), addr)
            .context("quinn endpoint::server")?;
        tracing::info!("HTTP/3 inbound listener on {addr}");

        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                match incoming.await {
                    Ok(conn) => {
                        if let Err(e) = handle_h3_connection(conn).await {
                            tracing::debug!("h3 connection ended: {e}");
                        }
                    }
                    Err(e) => tracing::debug!("h3 accept: {e}"),
                }
            });
        }
        Ok(())
    }

    async fn handle_h3_connection(conn: quinn::Connection) -> Result<()> {
        let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(conn))
            .await
            .context("h3 server conn")?;
        loop {
            match h3_conn.accept().await {
                Ok(Some(resolver)) => {
                    tokio::spawn(async move {
                        match resolver.resolve_request().await {
                            Ok((req, stream)) => {
                                if let Err(e) = handle_h3_request(req, stream).await {
                                    tracing::debug!("h3 request: {e}");
                                }
                            }
                            Err(e) => tracing::debug!("h3 resolve_request: {e}"),
                        }
                    });
                }
                Ok(None) => break,
                Err(e) => {
                    tracing::debug!("h3 accept request: {e}");
                    break;
                }
            }
        }
        Ok(())
    }

    async fn handle_h3_request<S>(
        req: http::Request<()>,
        mut stream: h3::server::RequestStream<S, Bytes>,
    ) -> Result<()>
    where
        S: h3::quic::BidiStream<Bytes>,
    {
        let scheme = req.uri().scheme_str().unwrap_or("https").to_string();
        let authority = req
            .uri()
            .authority()
            .map(|a| a.to_string())
            .or_else(|| {
                req.headers()
                    .get("host")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
            })
            .unwrap_or_default();
        let (host, port) = split_authority(&authority, &scheme);
        let pq = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let url = format!("{scheme}://{authority}{pq}");

        // Read the request body off the stream.
        let mut body = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.context("h3 recv_data")? {
            body.extend_from_slice(chunk.chunk());
        }

        // Build the forwarded request.
        let mut lreq = HttpRequest::builder(req.method().as_str(), &url)?;
        for (k, v) in req.headers() {
            lreq.set_header(k.as_str(), v.to_str().unwrap_or(""));
        }
        lreq.body = Bytes::from(body);

        // Forward to the origin over HTTP/3 and relay the response.
        match dial_and_send(&host, port, &lreq, &Http3Config::default()).await {
            Ok(resp) => {
                let mut builder = http::Response::builder().status(resp.status);
                for h in &resp.headers {
                    let _: &Header = h;
                    builder = builder.header(h.name.as_str(), h.value.as_str());
                }
                let out = builder.body(()).context("build h3 response")?;
                stream.send_response(out).await.context("send_response")?;
                stream.send_data(resp.body).await.context("send_data")?;
            }
            Err(e) => {
                let out = http::Response::builder().status(502).body(())?;
                stream.send_response(out).await.ok();
                stream
                    .send_data(Bytes::from(format!("lancer h3 upstream error: {e}")))
                    .await
                    .ok();
            }
        }
        stream.finish().await.context("h3 finish")?;
        Ok(())
    }
}

#[cfg(not(feature = "http3"))]
pub mod runtime {
    use super::*;
    pub async fn dial_and_send(
        _host: &str,
        _port: u16,
        _req: &HttpRequest,
        _cfg: &Http3Config,
    ) -> Result<HttpResponse> {
        anyhow::bail!("HTTP/3 disabled — rebuild with `--features http3`")
    }
    pub async fn inbound_listen(_addr: std::net::SocketAddr) -> Result<()> {
        anyhow::bail!("HTTP/3 disabled — rebuild with `--features http3`")
    }
}
