//! Shared wire/map types used by both the eBPF kernel program (umai-kernel)
//! and the userspace agent (umai-agent). Anything in this crate must remain
//! `no_std`-friendly so the kernel side can pull it in unchanged.
//!
//! Layout matters: these structs are written by one side and read by the
//! other through a BPF map. We use `#[repr(C)]` everywhere and derive
//! `Pod`/`Zeroable` from `bytemuck` so callers can safely transmute.

#![cfg_attr(not(feature = "user"), no_std)]

use bytemuck::{Pod, Zeroable};

/// A single entry in the kernel-side LRU intel map. v0 only encodes IPv4
/// signatures, but the struct is sized to give us headroom for v0.2 (JA4
/// fingerprint hash) and v0.3 (X.509 SPKI hash) without changing the map
/// shape and forcing operators to flush state on upgrade.
///
/// `tag` indicates which signature variant this entry represents; the rest
/// of the bytes are interpreted accordingly. Anything we don't yet support
/// stays zero.
#[repr(C)]
#[derive(Copy, Clone, Pod, Zeroable, Debug)]
pub struct IntelEntry {
    /// SignatureTag value. See constants below.
    pub tag: u8,
    /// Threat severity 0..=255. Reserved for future use; ignored by v0.
    pub severity: u8,
    /// Padding so the discriminant + ipv4 land aligned on a 4-byte boundary.
    pub _pad: [u8; 2],
    /// IPv4 address in **network byte order** (matches what XDP sees when
    /// reading from packet memory). 0 when tag != SIG_IPV4.
    pub ipv4_be: u32,
    /// Reserved for v0.2 JA4 hash (16 bytes) — currently always zero.
    pub ja4: [u8; 16],
}

/// `IntelEntry::tag` constants. Kept as plain `u8`s rather than an enum so
/// the eBPF verifier doesn't have to reason about enum representation.
pub const SIG_NONE: u8 = 0;
pub const SIG_IPV4: u8 = 1;
pub const SIG_JA4: u8 = 2; // reserved for v0.2

/// Per-CPU drop counter slot. Single field, but wrapped so the agent's
/// aggregation code stays type-safe rather than reading raw u64s out of
/// a map.
#[repr(C)]
#[derive(Copy, Clone, Pod, Zeroable, Debug, Default)]
pub struct DropCounter {
    pub drops: u64,
}

/// Stable indices for fixed-size map slots. Iteration 0 only uses
/// `COUNTER_DROPS`; reserved entries left for future stats so the kernel
/// program doesn't need to grow its map.
pub const COUNTER_DROPS: u32 = 0;
pub const COUNTER_PASSES: u32 = 1;
pub const COUNTER_PARSE_ERRORS: u32 = 2;
pub const COUNTERS_LEN: u32 = 8;

impl IntelEntry {
    /// Construct an entry from a host-byte-order IPv4. Convenience used by
    /// the agent — the kernel only ever reads these.
    #[cfg(feature = "user")]
    pub fn from_ipv4(addr: core::net::Ipv4Addr) -> Self {
        Self {
            tag: SIG_IPV4,
            severity: 0,
            _pad: [0; 2],
            ipv4_be: u32::from_be_bytes(addr.octets()),
            ja4: [0; 16],
        }
    }
}
