//! UMAI Loader — load + attach the kernel ELF, optionally poll the UMAI
//! Threat Intel feed and write IPv4 indicators into the in-kernel
//! umai_intel_map so the XDP program can XDP_DROP them at line rate.
//!
//! Default build = `cloud` (Premium + Enterprise) — includes the poll
//! task. CE build (`--no-default-features --features ce`) compiles the
//! HTTP client out entirely; the binary just attaches and parks.

use std::path::PathBuf;
use std::sync::Arc;
#[cfg(feature = "cloud")]
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
#[cfg(feature = "cloud")]
use aya::maps::HashMap as AyaHashMap;
use aya::{
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use clap::Parser;
use tokio::sync::Mutex;
use tracing::{info, warn};

#[cfg(feature = "cloud")]
use umai_common::IntelEntry;

/// Newtype around `IntelEntry` so we can implement aya's marker `Pod`
/// trait on it without dragging an aya dep into the shared umai-common
/// crate (which is also used by the no_std kernel side). Only needed
/// when the cloud feature is on — CE builds never write into the map.
///
/// SAFETY: `IntelEntry` is already a #[repr(C)] POD with no padding
/// other than its explicit `_pad` field, validated by bytemuck::Pod on
/// the userspace build of umai-common.
#[cfg(feature = "cloud")]
#[repr(transparent)]
#[derive(Copy, Clone)]
struct IntelEntryAya(IntelEntry);
#[cfg(feature = "cloud")]
unsafe impl aya::Pod for IntelEntryAya {}

#[derive(Debug, Parser)]
#[command(name = "umai-loader", version)]
struct Cli {
    /// Network interface to attach the XDP program to (e.g. veth-router, eth0).
    #[arg(long)]
    iface: String,

    /// Path to the prebuilt umai-kernel ELF (Dockerfile.ebpf output).
    #[arg(long, env = "UMAI_KERNEL_OBJECT")]
    kernel_object: PathBuf,

    /// Force generic (skb-mode) XDP attach. Required for veth + netns
    /// (driver-mode XDP isn't supported on virtual devices). Default true.
    #[arg(long, default_value_t = true)]
    xdpgeneric: bool,

    /// UMAI Threat Intel sync URL (e.g. https://umai.entelijan.com/api/v1/intel/sync).
    /// Omit to disable the poll loop. (cloud feature only)
    #[arg(long, env = "UMAI_INTEL_SYNC_URL")]
    #[cfg(feature = "cloud")]
    intel_sync_url: Option<String>,

    /// Bearer token shipped as Authorization: Bearer <…>. Either an IntelKey
    /// (umm_key_…) for Premium consumers or a MonitorInstance token for
    /// Enterprise agents. (cloud feature only)
    #[arg(long, env = "UMAI_INTEL_BEARER")]
    #[cfg(feature = "cloud")]
    intel_bearer: Option<String>,

    /// How often to poll the intel feed, in seconds. (cloud feature only)
    #[arg(long, env = "UMAI_INTEL_INTERVAL_SECS", default_value_t = 300)]
    #[cfg(feature = "cloud")]
    intel_interval_secs: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();

    info!(
        iface = %cli.iface,
        kernel = %cli.kernel_object.display(),
        xdpgeneric = cli.xdpgeneric,
        "umai-loader starting"
    );

    let bytes = std::fs::read(&cli.kernel_object)
        .with_context(|| format!("reading kernel ELF at {}", cli.kernel_object.display()))?;
    info!(bytes = bytes.len(), "loaded ELF into memory");

    let mut ebpf = Ebpf::load(&bytes).context("aya::Ebpf::load")?;

    // Find the XDP entry and load it into the kernel.
    let program: &mut Xdp = ebpf
        .program_mut("umai_monitor")
        .ok_or_else(|| anyhow!("umai_monitor program not present in ELF"))?
        .try_into()?;
    program.load().context("Xdp::load")?;
    info!("XDP program loaded into kernel");

    let flags = if cli.xdpgeneric { XdpFlags::SKB_MODE } else { XdpFlags::default() };
    program
        .attach(&cli.iface, flags)
        .with_context(|| format!("attach to {}", cli.iface))?;
    info!(iface = %cli.iface, ?flags, "XDP attached — kernel-resident");

    // Wrap Ebpf in Arc<Mutex<>> so the poll task can mutate the intel
    // map while the main task waits on Ctrl-C. Lock is held only for
    // the duration of each map.insert() call — micro-second scale.
    let ebpf = Arc::new(Mutex::new(ebpf));

    #[cfg(feature = "cloud")]
    let _poll_handle = {
        if let (Some(url), Some(bearer)) = (cli.intel_sync_url.as_deref(), cli.intel_bearer.as_deref()) {
            let url = url.to_string();
            let bearer = bearer.to_string();
            let interval = Duration::from_secs(cli.intel_interval_secs);
            let ebpf = ebpf.clone();
            info!(url = %url, interval_secs = cli.intel_interval_secs, "starting intel-sync poll task");
            Some(tokio::spawn(intel_poll_task(ebpf, url, bearer, interval)))
        } else {
            warn!("intel sync disabled — pass --intel-sync-url + --intel-bearer to enable");
            None
        }
    };

    println!();
    println!("══════════════════════════════════════════════════════════");
    println!("  umai-loader is parked. Verify from another shell:");
    println!("    sudo bpftool prog list | grep umai_monitor");
    println!("    sudo bpftool map  dump name umai_intel_map | head");
    println!();
    println!("  Ctrl-C to detach.");
    println!("══════════════════════════════════════════════════════════");
    println!();

    tokio::signal::ctrl_c().await.context("waiting for SIGINT")?;
    warn!("Ctrl-C — detaching XDP and exiting");
    Ok(())
}

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let _ = fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_target(false)
        .try_init();
}

// ─── Cloud-only: intel-sync poll loop ────────────────────────────────────

#[cfg(feature = "cloud")]
async fn intel_poll_task(
    ebpf: Arc<Mutex<Ebpf>>,
    url: String,
    bearer: String,
    interval: Duration,
) {
    let mut cursor: Option<String> = None;
    let client = match reqwest::Client::builder().timeout(Duration::from_secs(20)).build() {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "could not build reqwest client; aborting poll task");
            return;
        }
    };

    loop {
        match pull_and_write(&client, &url, &bearer, &cursor, &ebpf).await {
            Ok(stats) => {
                info!(
                    inserted = stats.inserted,
                    skipped_non_ipv4 = stats.skipped_non_ipv4,
                    bundle_size = stats.bundle_size,
                    cursor_next = ?stats.cursor_next,
                    "intel-sync pull"
                );
                if let Some(next) = stats.cursor_next {
                    cursor = Some(next);
                }
            }
            Err(e) => {
                warn!(error = %e, "intel-sync pull failed; retrying after interval");
            }
        }
        tokio::time::sleep(interval).await;
    }
}

#[cfg(feature = "cloud")]
struct PullStats {
    inserted: usize,
    skipped_non_ipv4: usize,
    bundle_size: usize,
    cursor_next: Option<String>,
}

#[cfg(feature = "cloud")]
async fn pull_and_write(
    client: &reqwest::Client,
    url: &str,
    bearer: &str,
    cursor: &Option<String>,
    ebpf: &Arc<Mutex<Ebpf>>,
) -> Result<PullStats> {
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Bundle {
        objects: Vec<serde_json::Value>,
        x_umai: Option<XUmai>,
    }
    #[derive(Deserialize)]
    struct XUmai {
        cursor_next: Option<String>,
    }

    let mut req = client.get(url).bearer_auth(bearer);
    if let Some(c) = cursor {
        req = req.query(&[("cursor", c.as_str())]);
    }
    let res = req.send().await.context("intel-sync GET")?;
    let status = res.status();
    if !status.is_success() {
        let body = res.text().await.unwrap_or_default();
        anyhow::bail!("intel-sync HTTP {}: {}", status, body.chars().take(200).collect::<String>());
    }
    let bundle: Bundle = res.json().await.context("intel-sync JSON decode")?;
    let bundle_size = bundle.objects.len();

    let mut inserted = 0usize;
    let mut skipped_non_ipv4 = 0usize;

    // Lock the Ebpf so we can borrow its map_mut. Acquired ONCE for the
    // whole batch — we don't want to thrash if the bundle is large.
    let mut guard = ebpf.lock().await;
    let map_ref = guard
        .map_mut("umai_intel_map")
        .ok_or_else(|| anyhow!("umai_intel_map not present on Ebpf instance"))?;
    let mut intel_map: AyaHashMap<_, u32, IntelEntryAya> = AyaHashMap::try_from(map_ref)
        .context("AyaHashMap::try_from(umai_intel_map)")?;

    for obj in bundle.objects.iter() {
        let kind = obj.get("x_umai_kind").and_then(|v| v.as_str()).unwrap_or("");
        if kind != "IPV4" {
            skipped_non_ipv4 += 1;
            continue;
        }
        let value_str = obj.get("x_umai_value").and_then(|v| v.as_str()).unwrap_or("");
        let addr: std::net::Ipv4Addr = match value_str.parse() {
            Ok(a) => a,
            Err(_) => continue,
        };
        let entry = IntelEntryAya(IntelEntry::from_ipv4(addr));
        let key_be: u32 = u32::from_be_bytes(addr.octets());
        // BPF_ANY = 0; overwrites on conflict, which is what we want for
        // refresh-on-every-pull semantics.
        if let Err(e) = intel_map.insert(&key_be, &entry, 0) {
            warn!(error = %e, addr = %addr, "intel_map.insert failed");
            continue;
        }
        inserted += 1;
    }

    Ok(PullStats {
        inserted,
        skipped_non_ipv4,
        bundle_size,
        cursor_next: bundle.x_umai.and_then(|x| x.cursor_next),
    })
}

#[cfg(not(target_os = "linux"))]
compile_error!("umai-loader only builds on Linux — XDP/eBPF is Linux-only");
