#!/usr/bin/env bash
#
# umai-sync.sh — feed IPv4 signatures into UMAI Core's in-kernel intel map.
#
# Lets log parsers, IDS hooks, fail2ban actions, and CI scripts inject or
# remove block rules at runtime without recompiling the loader. Speaks
# directly to the kernel via `bpftool` — no userspace agent indirection.
#
# Usage:
#   ./umai-sync.sh <ipv4> block      # add an IP to umai_intel_map
#   ./umai-sync.sh <ipv4> unblock    # remove an IP from umai_intel_map
#   ./umai-sync.sh list              # dump all current intel-map entries
#   ./umai-sync.sh stats             # show per-CPU drop / pass counters
#   ./umai-sync.sh help              # print this help
#
# Requirements:
#   - root / CAP_BPF + CAP_NET_ADMIN
#   - bpftool installed (Ubuntu: `sudo apt install linux-tools-generic
#     linux-tools-common`)
#   - umai-loader running in another shell (v0.1.0 holds the map alive
#     via its process fd; v0.2 will pin the map under /sys/fs/bpf/umai/
#     so this script becomes loader-independent)
#
# Map layout reference (matches umai-common::IntelEntry):
#   key   — u32, source IPv4 in network byte order (4 bytes)
#   value — 24 bytes:
#             tag        u8       0x01 = SIG_IPV4
#             severity   u8       reserved, 0x00 for now
#             _pad       u8[2]    alignment padding, 0x00 0x00
#             ipv4_be    u32      host-LE bytes of the network-order IP
#             ja4        u8[16]   reserved for v0.2 JA4 hash, zeros today
#
# Endianness note:
#   The IntelEntry struct's `ipv4_be` field stores the network-order IPv4
#   as a u32 — on x86_64 / aarch64 (little-endian hosts) that lays out in
#   memory as the reversed byte order. This script assumes LE; for big-
#   endian hosts the value encoding below needs to flip the four IP bytes.

set -euo pipefail

MAP_NAME="umai_intel_map"
COUNTER_MAP="umai_counters"
PIN_PATH="/sys/fs/bpf/${MAP_NAME}"

# ─── Map handle resolver ────────────────────────────────────────────────
# Prefer the pinned-path form (v0.2 forward-compat) — falls back to
# bpftool's by-name lookup which works against a live loader today.
map_handle() {
  if [ -e "$PIN_PATH" ]; then
    echo "pinned $PIN_PATH"
  else
    echo "name $MAP_NAME"
  fi
}

# ─── Preconditions ──────────────────────────────────────────────────────

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "error: must run as root (CAP_BPF required for map writes)" >&2
    exit 1
  fi
}

need_bpftool() {
  if ! command -v bpftool >/dev/null 2>&1; then
    echo "error: bpftool not on PATH" >&2
    echo "       install: sudo apt install -y linux-tools-generic linux-tools-common" >&2
    exit 1
  fi
}

need_le_host() {
  case "$(uname -m)" in
    x86_64|aarch64|x86|i386|i686|armv7l|armv6l|riscv64) : ;;
    *)
      echo "warning: host arch $(uname -m) — IntelEntry encoding assumes LE." >&2
      echo "         If this is a big-endian box, edit ipv4_to_value_hex() before use." >&2
      ;;
  esac
}

# ─── IPv4 validation + encoding ─────────────────────────────────────────

is_ipv4() {
  [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  IFS='.' read -r o1 o2 o3 o4 <<< "$1"
  for o in "$o1" "$o2" "$o3" "$o4"; do
    [ "$o" -ge 0 ] && [ "$o" -le 255 ] || return 1
  done
  return 0
}

# IP a.b.c.d -> "aa bb cc dd" (network byte order, matches packet src_addr)
ipv4_to_key_hex() {
  IFS='.' read -r o1 o2 o3 o4 <<< "$1"
  printf '%02x %02x %02x %02x' "$o1" "$o2" "$o3" "$o4"
}

# IntelEntry value for IP a.b.c.d on a little-endian host:
#   01 00 00 00         tag=SIG_IPV4, severity=0, _pad
#   dd cc bb aa         ipv4_be as u32 (LE bytes of network-order IP)
#   00 x16              ja4 placeholder
ipv4_to_value_hex() {
  IFS='.' read -r o1 o2 o3 o4 <<< "$1"
  printf '01 00 00 00 %02x %02x %02x %02x 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00' \
    "$o4" "$o3" "$o2" "$o1"
}

# ─── Actions ────────────────────────────────────────────────────────────

cmd_block() {
  local ip="$1"
  is_ipv4 "$ip" || { echo "error: '$ip' is not a valid IPv4" >&2; exit 1; }
  local key val
  key="$(ipv4_to_key_hex "$ip")"
  val="$(ipv4_to_value_hex "$ip")"
  echo ">> block $ip"
  echo "   key:   $key"
  echo "   value: $val"
  # shellcheck disable=SC2086
  bpftool map update $(map_handle) key hex $key value hex $val
  echo ">> ok"
}

cmd_unblock() {
  local ip="$1"
  is_ipv4 "$ip" || { echo "error: '$ip' is not a valid IPv4" >&2; exit 1; }
  local key
  key="$(ipv4_to_key_hex "$ip")"
  echo ">> unblock $ip (key: $key)"
  # shellcheck disable=SC2086
  bpftool map delete $(map_handle) key hex $key
  echo ">> ok"
}

cmd_list() {
  # shellcheck disable=SC2086
  bpftool map dump $(map_handle)
}

cmd_stats() {
  bpftool map dump name "$COUNTER_MAP"
}

usage() {
  cat <<'EOF'
Usage:
  umai-sync.sh <ipv4> block      Add IP to umai_intel_map (XDP_DROP on next ingress)
  umai-sync.sh <ipv4> unblock    Remove IP from umai_intel_map
  umai-sync.sh list              Dump current intel-map entries
  umai-sync.sh stats             Show per-CPU drop / pass / parse-error counters
  umai-sync.sh help              Print this help

Examples:
  sudo ./umai-sync.sh 198.51.100.42 block
  sudo ./umai-sync.sh 198.51.100.42 unblock
  sudo ./umai-sync.sh list
  sudo ./umai-sync.sh stats
EOF
}

# ─── Dispatch ───────────────────────────────────────────────────────────

arg1="${1:-help}"
arg2="${2:-}"

case "$arg1" in
  -h|--help|help)
    usage
    exit 0
    ;;
  list)
    need_root
    need_bpftool
    cmd_list
    ;;
  stats)
    need_root
    need_bpftool
    cmd_stats
    ;;
  *)
    # First arg is an IP, second arg is the action.
    if ! is_ipv4 "$arg1"; then
      echo "error: first argument must be an IPv4 address or one of: list, stats, help" >&2
      usage
      exit 1
    fi
    if [ -z "$arg2" ]; then
      echo "error: missing action (block | unblock)" >&2
      usage
      exit 1
    fi
    need_root
    need_bpftool
    need_le_host
    case "$arg2" in
      block)   cmd_block "$arg1" ;;
      unblock) cmd_unblock "$arg1" ;;
      *)
        echo "error: unknown action '$arg2' — expected block or unblock" >&2
        usage
        exit 1
        ;;
    esac
    ;;
esac
