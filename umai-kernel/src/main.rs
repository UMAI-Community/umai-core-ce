//! UMAI Core — kernel-side XDP program.
//!
//! Iteration 0: source-IPv4 blacklist. The userspace agent pushes entries
//! into `umai_intel_map`; this program looks each ingress packet's source
//! IP up in the map and returns `XDP_DROP` on a hit, otherwise `XDP_PASS`.
//!
//! Map shapes:
//!   * `umai_intel_map` — BPF_MAP_TYPE_LRU_HASH<u32 src_ip_be, IntelEntry>.
//!     LRU bounds memory at MAX_INTEL_ENTRIES and naturally evicts cold
//!     signatures while keeping the most active threats hot.
//!   * `umai_counters`  — BPF_MAP_TYPE_PERCPU_ARRAY<u32, DropCounter>.
//!     Fixed-size; index 0 = drop count, 1 = pass count, 2 = parse errors.
//!     Per-CPU so we never contend on a hot counter at line rate.
//!
//! What this program intentionally does *not* do (deferred to later
//! iterations):
//!   * TLS ClientHello parsing for SNI/JA4 (v0.2)
//!   * IPv6 (v0.2)
//!   * Userspace mirroring via AF_XDP for L7 protocol decode (v0.4)

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{LruHashMap, PerCpuArray},
    programs::XdpContext,
};
// aya-log-ebpf removed — see umai-kernel/Cargo.toml. Per-drop signal is
// the per-CPU counter; per-event detail comes from a ringbuf in v0.2.
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};
use umai_common::{DropCounter, IntelEntry, COUNTERS_LEN, COUNTER_DROPS, COUNTER_PASSES, COUNTER_PARSE_ERRORS};

/// Cap on signatures held in the kernel map. LRU eviction handles overflow
/// from the cloud feed silently — older / less-active signatures drop out
/// rather than the agent having to GC. 65 536 entries × ~24 bytes payload
/// ≈ 1.5 MB of kernel memory, fine for an enforcement appliance.
const MAX_INTEL_ENTRIES: u32 = 65_536;

#[map(name = "umai_intel_map")]
static UMAI_INTEL_MAP: LruHashMap<u32, IntelEntry> =
    LruHashMap::<u32, IntelEntry>::with_max_entries(MAX_INTEL_ENTRIES, 0);

#[map(name = "umai_counters")]
static UMAI_COUNTERS: PerCpuArray<DropCounter> =
    PerCpuArray::<DropCounter>::with_max_entries(COUNTERS_LEN, 0);

#[xdp]
pub fn umai_monitor(ctx: XdpContext) -> u32 {
    match try_umai_monitor(&ctx) {
        Ok(action) => action,
        Err(_) => {
            // Bookkeeping for parser errors; we fail-open (PASS) rather than
            // black-hole legit traffic if a malformed packet trips our
            // bounds checks.
            bump_counter(COUNTER_PARSE_ERRORS);
            xdp_action::XDP_PASS
        }
    }
}

#[inline(always)]
fn try_umai_monitor(ctx: &XdpContext) -> Result<u32, ()> {
    // Bounds-check the ethernet header.
    let ethhdr: *const EthHdr = ptr_at(ctx, 0)?;
    // SAFETY: ptr_at verified `mem::size_of::<EthHdr>()` bytes are within
    // the packet. `EthHdr` is a `#[repr(C)]` POD struct.
    let ether_type = unsafe { (*ethhdr).ether_type };

    // Iteration 0 only handles IPv4. Anything else passes — UDP/TCP/whatever
    // routing decisions stay where they are. v0.2 will add IPv6.
    if ether_type != EtherType::Ipv4 {
        bump_counter(COUNTER_PASSES);
        return Ok(xdp_action::XDP_PASS);
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(ctx, EthHdr::LEN)?;
    // SAFETY: same as above. `src_addr` is a u32 in network byte order.
    let src_ip_be = unsafe { (*ipv4hdr).src_addr };

    // Map lookup. `LruHashMap::get` returns `Option<&V>` semantically; we
    // only need to know whether the entry exists for drop, so a discard is
    // fine.
    if let Some(_entry) = unsafe { UMAI_INTEL_MAP.get(&src_ip_be) } {
        // Drop signal lives in the per-CPU counter map. v0.2 will swap to
        // a BPF_MAP_TYPE_RINGBUF for per-event detail (src/dst/proto)
        // streamed back to userspace. aya-log-ebpf intentionally omitted
        // — see umai-kernel/Cargo.toml for the dep-chain rationale.
        bump_counter(COUNTER_DROPS);
        return Ok(xdp_action::XDP_DROP);
    }

    bump_counter(COUNTER_PASSES);
    Ok(xdp_action::XDP_PASS)
}

/// Bounds-checked pointer into the packet at `offset`. Returns `Err(())` if
/// the desired struct would extend past `data_end`. The eBPF verifier
/// requires this check explicitly — it has no way to infer safety from
/// types alone.
#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

/// Per-CPU counter increment. Wraps the PerCpuArray pointer dance into a
/// single inline so the call site reads cleanly.
#[inline(always)]
fn bump_counter(index: u32) {
    if let Some(counter) = UMAI_COUNTERS.get_ptr_mut(index) {
        // SAFETY: pointer comes from PerCpuArray::get_ptr_mut which the
        // verifier only hands out when `index < max_entries`. The struct
        // behind it is initialised to zero by the kernel.
        unsafe {
            (*counter).drops = (*counter).drops.wrapping_add(1);
        }
    }
}

/// Mandatory panic handler for the BPF target — without an allocator and
/// without `std`, we just trap. Reaching this means we lost type-system
/// invariants somewhere; the verifier will probably reject the program
/// before it loads.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
