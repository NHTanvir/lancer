// BPF program — gets built as a no_std cdylib for the bpfel-unknown-none target.

#![no_std]
#![no_main]

use aya_ebpf::bindings::pt_regs;
use aya_ebpf::helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid};
use aya_ebpf::macros::{kprobe, map};
use aya_ebpf::maps::PerfEventArray;
use aya_ebpf::programs::ProbeContext;
use aya_ebpf::EbpfContext;

#[repr(C)]
pub struct FlowEvent {
    pub pid: u32,
    pub direction: u32, // 0 = Tx, 1 = Rx
    pub payload_bytes: u32,
    pub comm: [u8; 16],
}

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<FlowEvent> = PerfEventArray::with_max_entries(1024, 0);

#[kprobe(function = "tcp_sendmsg")]
pub fn tcp_sendmsg(ctx: ProbeContext) -> u32 {
    emit(ctx, 0).unwrap_or(0)
}

#[kprobe(function = "tcp_recvmsg")]
pub fn tcp_recvmsg(ctx: ProbeContext) -> u32 {
    emit(ctx, 1).unwrap_or(0)
}

fn emit(ctx: ProbeContext, direction: u32) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let mut comm: [u8; 16] = [0; 16];
    let _ = bpf_get_current_comm()
        .map(|c| { for i in 0..16 { comm[i] = c[i]; } });
    // payload size arg is in the 3rd argument register on x86_64 (rdx).
    let payload: u32 = unsafe { (*ctx.regs as *const pt_regs).read_volatile().rdx } as u32;
    let ev = FlowEvent { pid, direction, payload_bytes: payload, comm };
    unsafe { EVENTS.output(&ctx, &ev, 0) };
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
