//! UMAI Core — Terminal UI (placeholder).
//!
//! The iter-0 TUI talked to umai-agent's gRPC server, which is not
//! shipped in the open-source Community Edition. The v0.2 replacement
//! will be a standalone ratatui reader of the in-kernel BPF maps via
//! aya (no gRPC dep). For now this binary prints a status message and
//! exits cleanly so the workspace builds end-to-end.
//!
//! Track progress: https://github.com/UMAI-Community/umai-core-ce/issues

use anyhow::Result;

fn main() -> Result<()> {
    println!("UMAI Core — Terminal UI (placeholder)");
    println!();
    println!("The interactive ratatui dashboard is scheduled for v0.2.");
    println!("Until then, inspect kernel state directly with bpftool:");
    println!();
    println!("  sudo bpftool prog show name umai_monitor");
    println!("  sudo bpftool map  show name umai_intel_map");
    println!("  sudo bpftool map  show name umai_counters");
    println!();
    println!("Track progress at:");
    println!("  https://github.com/UMAI-Community/umai-core-ce/issues");
    Ok(())
}
