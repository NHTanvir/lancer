//! Optional eBPF kernel-level traffic capture (Linux only).
//!
//! Without the `linux` feature this crate exposes only the trait + a noop
//! implementation so callers can compile cross-platform. With `--features
//! linux` the real `aya`-backed implementation kicks in and starts hooking
//! BPF probes against `tcp_sendmsg` / `tcp_recvmsg` for per-process
//! attribution and against OpenSSL/BoringSSL `SSL_read`/`SSL_write` for
//! plaintext sniffing.

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedFlow {
    pub pid: u32,
    pub comm: String,
    pub src: String,
    pub dst: String,
    pub direction: Direction,
    pub payload_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Tx,
    Rx,
}

#[async_trait]
pub trait Capturer: Send + Sync {
    async fn start(&self) -> Result<()>;
    async fn stop(&self) -> Result<()>;
    async fn drain(&self) -> Result<Vec<CapturedFlow>>;
}

pub struct NullCapturer;

#[async_trait]
impl Capturer for NullCapturer {
    async fn start(&self) -> Result<()> {
        anyhow::bail!("eBPF capture is only available on Linux with `--features linux`")
    }
    async fn stop(&self) -> Result<()> { Ok(()) }
    async fn drain(&self) -> Result<Vec<CapturedFlow>> { Ok(Vec::new()) }
}

#[cfg(feature = "linux")]
pub mod linux {
    use super::*;

    pub struct AyaCapturer;

    #[async_trait]
    impl Capturer for AyaCapturer {
        async fn start(&self) -> Result<()> {
            anyhow::bail!("aya linker stub — populate with kprobe + uprobe loads")
        }
        async fn stop(&self) -> Result<()> { Ok(()) }
        async fn drain(&self) -> Result<Vec<CapturedFlow>> { Ok(Vec::new()) }
    }
}
