# Playground

Three-stage live demo: stand up a deliberately-vulnerable mock MCP server in a container, prove an unauthenticated attacker can exploit it, then arm UMAI Core's kernel-resident XDP program and watch the same exploit get dropped at the bridge before the mock server ever sees the packet.

## Layout

| File | Role |
|---|---|
| `docker-compose.yml` | Two containers on a `172.30.0.0/24` bridge: `mock-mcp` (vulnerable target on :8080) + `attacker` (Alpine with curl) |
| `mock-mcp/Dockerfile` | Builds the mock MCP image from `python:3.12-alpine` |
| `mock-mcp/server.py` | Deliberately-vulnerable HTTP responder exposing `/mcp/exec` with `shell.exec`, `fs.read`, `model.invoke` tools — no auth |
| `demo-exploit.sh` | Orchestrator: preflight → playground up → Stage 1 → Stage 2 → Stage 3 → cleanup |

## Run it

```bash
cd playground
sudo ./demo-exploit.sh
```

That's the whole interface. The script handles everything else.

## What you'll see

1. **Stage 1 (Defenseless)** — attacker container fires `curl POST /mcp/exec` and receives a fake `uid=0(root)` + `/etc/secrets/openai_key` leak. That's the "this is what's wrong with the unauthenticated agentic web" moment.
2. **Stage 2 (Kernel armed)** — `umai-loader` attaches XDP to the Docker bridge for the playground network. `examples/umai-sync.sh` injects the attacker container's IP into `umai_intel_map`. `bpftool map dump` confirms the entry landed.
3. **Stage 3 (The drop)** — same attacker, same target, same curl. This time it times out. `bpftool map dump name umai_counters` shows the drop counter rose by one. The mock server's stdout shows it never received the second request.

## Prerequisites

- **Linux 5.10+** (required for `XDP_GENERIC` support on a Docker bridge)
- **Docker** + the `compose` plugin
- **bpftool** (Ubuntu: `sudo apt install -y linux-tools-generic linux-tools-common`)
- **sudo / `CAP_BPF` + `CAP_NET_ADMIN`** (XDP attach is privileged)

### Won't run on

- macOS / Windows with Docker Desktop — the Linux VM Docker Desktop ships doesn't expose XDP attach to user containers. Stage 1 works (containers run fine), Stages 2–3 don't.
- Rootless Docker — no `CAP_NET_ADMIN`.
- Kernels older than 5.10 — XDP attach API surface is too thin.

## Timing

| Run | Wall clock |
|---|---|
| First run on a fresh clone (Docker image pulls + Alpine `apk add curl` + umai-loader cold cargo build + kernel ELF download from GitHub release) | ~3–5 minutes |
| Re-runs (everything cached) | ~30 seconds |

## How the auto-setup works

The script is self-healing on first run:

1. If `target/release/umai-loader` is missing → runs `cargo build --release -p umai-loader --no-default-features --features ce` automatically
2. If `dist/umai-kernel` is missing → downloads it from the v0.1.0 GitHub release (1,872 bytes)
3. If the Docker images aren't built → `docker compose up --build` builds them
4. If the playground network exists from a prior run → `docker compose down --remove-orphans` cleans up on exit

## Cleanup

The script registers a `trap` on `EXIT`, `INT`, `TERM` that:
- Kills the parked `umai-loader` (kernel auto-detaches XDP when the loader's fds close)
- Tears down all playground containers + the bridge network

So even if you Ctrl-C mid-demo, the host is left clean.

## What this proves about UMAI Core

- **The kernel program is real.** `bpftool prog show name umai_monitor` reports a JIT-compiled XDP program after Stage 2. Same `tag` hash as our published release.
- **Map writes work from any userspace tool.** `examples/umai-sync.sh` is just 175 lines of bash wrapping `bpftool map update`. Your fail2ban / Suricata / honeypot hook can do the same thing.
- **The drop is at the bridge driver, not application-layer.** The mock-mcp Python process never accepts a TCP connection for the Stage-3 attempt — `tcpdump -i <bridge>` would show the SYN entering the bridge and never reaching the container's `veth`.
