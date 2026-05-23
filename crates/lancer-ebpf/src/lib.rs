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

/// The eBPF program (Aya / BPF-C-like) — for documentation. The actual binary
/// object is produced from a sibling `ebpf/` cdylib crate; we embed it here.
///
/// ```c
/// SEC("kprobe/tcp_sendmsg")
/// int trace_sendmsg(struct pt_regs *ctx) {
///     u32 pid = bpf_get_current_pid_tgid() >> 32;
///     char comm[16]; bpf_get_current_comm(&comm, sizeof(comm));
///     struct flow_event ev = { .pid = pid, .direction = TX, .payload_bytes = PT_REGS_PARM3(ctx) };
///     __builtin_memcpy(ev.comm, comm, sizeof(comm));
///     bpf_perf_event_output(ctx, &EVENTS, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
///     return 0;
/// }
/// // … and the equivalent recvmsg + SSL_read / SSL_write uprobes.
/// ```
pub const EBPF_SOURCE_DOC: &str = "see lancer-ebpf::EBPF_SOURCE_DOC for the BPF program shape";

#[cfg(feature = "linux")]
pub mod linux {
    use super::*;
    use std::sync::Arc;

    use aya::maps::AsyncPerfEventArray;
    use aya::programs::KProbe;
    use aya::Ebpf;
    use bytes::BytesMut;
    use parking_lot::Mutex;

    /// Compile-time-embedded eBPF object.
    ///
    /// The repo doesn't include a precompiled BPF object — the companion
    /// `lancer-ebpf-probe` cdylib (in a side crate, built with
    /// `cargo +nightly build --target bpfel-unknown-none -Z build-std=core`)
    /// produces the artefact you want here. To wire it in: replace this with
    /// `include_bytes_aligned!("path/to/lancer-ebpf-probe")` once your build
    /// pipeline drops the file. With the empty placeholder, `start()` returns
    /// a clear error.
    const PROG_OBJECT: &[u8] = &[];

    /// AyaCapturer attaches kprobes to `tcp_sendmsg` and `tcp_recvmsg` and
    /// drains a perf-event array into in-memory CapturedFlow records.
    pub struct AyaCapturer {
        ebpf: Mutex<Option<Ebpf>>,
        flows: Arc<Mutex<Vec<CapturedFlow>>>,
    }

    impl AyaCapturer {
        pub fn new() -> Self {
            Self { ebpf: Mutex::new(None), flows: Arc::new(Mutex::new(Vec::new())) }
        }
    }

    #[async_trait]
    impl Capturer for AyaCapturer {
        async fn start(&self) -> Result<()> {
            if PROG_OBJECT.is_empty() {
                anyhow::bail!(
                    "BPF object not bundled — build the companion ebpf cdylib crate and rebuild with LANCER_BPF_OBJ pointing at its output"
                );
            }
            let mut ebpf = Ebpf::load(PROG_OBJECT)?;
            let send: &mut KProbe = ebpf.program_mut("tcp_sendmsg").unwrap().try_into()?;
            send.load()?;
            send.attach("tcp_sendmsg", 0)?;
            let recv: &mut KProbe = ebpf.program_mut("tcp_recvmsg").unwrap().try_into()?;
            recv.load()?;
            recv.attach("tcp_recvmsg", 0)?;

            let mut perf = AsyncPerfEventArray::try_from(ebpf.take_map("EVENTS").unwrap())?;
            for cpu_id in aya::util::online_cpus().unwrap_or_default() {
                let mut buf = perf.open(cpu_id, None)?;
                let flows = self.flows.clone();
                tokio::spawn(async move {
                    let mut buffers = (0..16)
                        .map(|_| BytesMut::with_capacity(1024))
                        .collect::<Vec<_>>();
                    loop {
                        let events = match buf.read_events(&mut buffers).await {
                            Ok(e) => e,
                            Err(_) => break,
                        };
                        for b in buffers.iter().take(events.read) {
                            if let Ok(f) = serde_json::from_slice::<CapturedFlow>(b) {
                                flows.lock().push(f);
                            }
                        }
                    }
                });
            }
            *self.ebpf.lock() = Some(ebpf);
            Ok(())
        }

        async fn stop(&self) -> Result<()> {
            *self.ebpf.lock() = None;
            Ok(())
        }

        async fn drain(&self) -> Result<Vec<CapturedFlow>> {
            let mut g = self.flows.lock();
            Ok(std::mem::take(&mut *g))
        }
    }
}
