//! Connecting outbound through an upstream proxy (HTTP CONNECT / SOCKS5).
//!
//! The bulk of TLS handling lives in the listener; this module's job is only to
//! get a `TcpStream` that's already in the right TCP state (CONNECT issued or
//! SOCKS handshake done) so the rest of the proxy doesn't need to care.

use std::io;

use anyhow::{anyhow, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::settings::{UpstreamKind, UpstreamProxy};

pub async fn dial(host: &str, port: u16, upstream: Option<&UpstreamProxy>) -> Result<TcpStream> {
    match upstream {
        None => {
            let stream = TcpStream::connect((host, port))
                .await
                .with_context(|| format!("direct connect {host}:{port}"))?;
            Ok(stream)
        }
        Some(up) => match up.kind {
            UpstreamKind::Http => dial_http(host, port, up).await,
            UpstreamKind::Socks5 => dial_socks5(host, port, up).await,
            UpstreamKind::Socks4 => dial_socks4(host, port, up).await,
        },
    }
}

async fn dial_http(host: &str, port: u16, up: &UpstreamProxy) -> Result<TcpStream> {
    let mut stream = TcpStream::connect((up.host.as_str(), up.port))
        .await
        .context("connect to upstream http proxy")?;
    let mut req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
    if let (Some(u), Some(p)) = (&up.username, &up.password) {
        use base64::Engine as _;
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"));
        req.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await?;

    let mut buf = [0u8; 4096];
    let mut total = 0;
    loop {
        let n = stream.read(&mut buf[total..]).await?;
        if n == 0 {
            return Err(anyhow!("upstream proxy closed during CONNECT"));
        }
        total += n;
        if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if total == buf.len() {
            return Err(anyhow!("CONNECT response too large"));
        }
    }
    let head = std::str::from_utf8(&buf[..total]).unwrap_or("");
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok());
    if !matches!(status, Some(200..=299)) {
        return Err(anyhow!("upstream CONNECT failed: {head}"));
    }
    Ok(stream)
}

async fn dial_socks5(host: &str, port: u16, up: &UpstreamProxy) -> Result<TcpStream> {
    let mut stream = TcpStream::connect((up.host.as_str(), up.port))
        .await
        .context("connect to upstream socks5 proxy")?;

    // greeting: VER + NMETHODS + METHODS
    let auth = up.username.is_some() && up.password.is_some();
    let methods: &[u8] = if auth { &[0x00, 0x02] } else { &[0x00] };
    let mut greet = vec![0x05u8, methods.len() as u8];
    greet.extend_from_slice(methods);
    stream.write_all(&greet).await?;

    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != 0x05 {
        return Err(anyhow!("not socks5"));
    }
    match resp[1] {
        0x00 => {}
        0x02 if auth => {
            let u = up.username.as_ref().unwrap();
            let p = up.password.as_ref().unwrap();
            let mut frame = vec![0x01u8, u.len() as u8];
            frame.extend_from_slice(u.as_bytes());
            frame.push(p.len() as u8);
            frame.extend_from_slice(p.as_bytes());
            stream.write_all(&frame).await?;
            let mut auth_resp = [0u8; 2];
            stream.read_exact(&mut auth_resp).await?;
            if auth_resp[1] != 0x00 {
                return Err(anyhow!("socks5 auth rejected"));
            }
        }
        m => return Err(anyhow!("socks5 chose unsupported method {m:02x}")),
    }

    // request: VER CMD RSV ATYP DST.ADDR DST.PORT
    let mut req = vec![0x05u8, 0x01, 0x00];
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        req.push(0x01);
        req.extend_from_slice(&v4.octets());
    } else if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        req.push(0x04);
        req.extend_from_slice(&v6.octets());
    } else {
        req.push(0x03);
        req.push(host.len() as u8);
        req.extend_from_slice(host.as_bytes());
    }
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).await?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[1] != 0x00 {
        return Err(anyhow!("socks5 connect failed: {}", head[1]));
    }
    // consume bound addr/port (variable length depending on ATYP)
    let skip: usize = match head[3] {
        0x01 => 4 + 2,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            (len[0] as usize) + 2
        }
        0x04 => 16 + 2,
        a => return Err(anyhow!("socks5 unknown atyp {a:02x}")),
    };
    let mut throwaway = vec![0u8; skip];
    stream.read_exact(&mut throwaway).await?;
    Ok(stream)
}

async fn dial_socks4(host: &str, port: u16, up: &UpstreamProxy) -> Result<TcpStream> {
    let mut stream = TcpStream::connect((up.host.as_str(), up.port))
        .await
        .context("connect to upstream socks4 proxy")?;
    let ip: std::net::Ipv4Addr = host.parse().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "socks4 requires ipv4 host")
    })?;
    let mut req = Vec::with_capacity(9);
    req.push(0x04);
    req.push(0x01);
    req.extend_from_slice(&port.to_be_bytes());
    req.extend_from_slice(&ip.octets());
    req.push(0x00); // empty userid
    stream.write_all(&req).await?;
    let mut resp = [0u8; 8];
    stream.read_exact(&mut resp).await?;
    if resp[1] != 0x5A {
        return Err(anyhow!("socks4 rejected: {:02x}", resp[1]));
    }
    Ok(stream)
}
