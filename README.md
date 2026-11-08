# OhmZ

High-performance network scanner written in Zig.

![CI](https://github.com/effront/OhmZ/actions/workflows/ci.yml/badge.svg)
![Release](https://img.shields.io/github/v/release/effront/OhmZ)
![License](https://img.shields.io/github/license/effront/OhmZ)
![Zig](https://img.shields.io/badge/zig-0.14.1-F7A41D?logo=zig)

## Features

- **SYN scan** with SipHash-2-4 SYN cookies (fully stateless)
- **TCP Connect, FIN, XMAS, NULL** scan types
- **Banner grabbing** (`-sV`) for service version detection (SSH, HTTP, FTP, SMTP)
- **BlackRock cipher** for O(1) target randomization (Feistel network permutation)
- **Adaptive rate throttle** with 256-bucket sliding window
- **VPN-aware** source IP detection (tun0/wg0 support)
- **nmap-compatible CLI** flags (`-sS`, `-sV`, `-sC`, `-O`, `-A`, `-Pn`, `-T0`-`-T5`)
- **Output formats** - JSON (`-oJ`), XML (`-oX`), Grepable (`-oG`), Normal text (`-oN`)
- **ANSI progress bar** with EWMA-smoothed PPS and ETA
- **Static binary**, no dependencies, ~200KB

## Quick Start

```bash
# Install via script
curl -sSL https://raw.githubusercontent.com/effront/OhmZ/main/install.sh | sh

# Or via Homebrew
brew tap effront/tap && brew install ohmz

# Or via Docker
docker run --cap-add=NET_RAW ghcr.io/effront/ohmz -sS 192.168.1.0/24

# Or download the .deb
sudo dpkg -i ohmz_0.2.0_amd64.deb
```

## Usage

```bash
# SYN scan top 1000 ports (default, needs root)
sudo ohmz -sS -p 1-1000 192.168.1.0/24

# TCP Connect scan (no root needed)
ohmz -sT -p 80,443 target.com

# Full port scan with banner grabbing
sudo ohmz -sS -sV -p 1-65535 10.10.10.1

# Fast scan (top 100 ports)
sudo ohmz -F 10.10.10.1

# Output to all formats at once
sudo ohmz -sS -oA scan_results 192.168.1.0/24

# Distributed scanning (machine 1 of 4)
sudo ohmz -sS -p 1-65535 --shard 1/4 10.0.0.0/8
```

## Scan Types

| Flag | Type | Root | Description |
|------|------|------|-------------|
| `-sS` | SYN | Yes | Half-open scan, fast and stealthy (default) |
| `-sT` | Connect | No | Full TCP handshake via kernel |
| `-sF` | FIN | Yes | FIN flag only, evades stateless firewalls |
| `-sX` | XMAS | Yes | FIN+PSH+URG flags |
| `-sN` | NULL | Yes | No flags set |

## Output Formats

| Flag | Format | Description |
|------|--------|-------------|
| `-oN` | Normal | Human-readable text file |
| `-oJ` | JSON | Structured JSON array |
| `-oX` | XML | nmap-compatible XML (works with Metasploit, OpenVAS) |
| `-oG` | Grepable | One line per host, parseable with grep/awk |
| `-oA` | All | Generates all formats with a shared prefix |

## Performance

```
65,535 ports scanned in 15.8 seconds
4,200 packets/sec at 168 KB/s bandwidth
40 bytes per SYN probe (20B IP + 20B TCP)
0 bytes of per-connection state (SYN cookies)
3 threads, 0 locks (atomic counters only)
~200 KB static binary
```

## CLI Reference

```
ohmz [scan_type] [options] <target(s)>

SCAN TYPES:
  -sS              TCP SYN (default)
  -sT              TCP Connect
  -sF / -sX / -sN  FIN / XMAS / NULL

PORTS:
  -p <range>       Port range (e.g. -p 22,80,443 or -p 1-65535)
  -F               Fast scan (top 100 ports)
  --top-ports <n>  Most common N ports

SERVICE DETECTION:
  -sV              Banner grabbing / version detection
  -A               Aggressive (enables -sV, -sC, -O)

OUTPUT:
  -oN / -oJ        Normal text / JSON
  -oX / -oG        XML (nmap-compat) / Grepable
  -oA <prefix>     All formats at once

PERFORMANCE:
  --rate <pps>     Packets per second
  -T0 to -T5      Timing template (Paranoid to Insane)

OPTIONS:
  -Pn              Skip host discovery
  -iL <file>       Target list file
  --exclude <t>    Exclude target
  --shard <N/M>    Distributed sharding
  --stats          Show real-time stats
  -v / -vv / -vvv  Verbosity levels
```

## Building from Source

Requires [Zig 0.14.1](https://ziglang.org/download/).

```bash
# Debug build
zig build

# Release build
zig build -Doptimize=ReleaseSafe

# Cross-compile for ARM
zig build -Doptimize=ReleaseSafe -Dtarget=aarch64-linux

# Run tests
zig build test
```

## How It Works

OhmZ uses a stateless scanning architecture inspired by masscan:

1. **BlackRock cipher** (Feistel network) permutes the target space in O(1) memory, visiting every IP:port pair exactly once in pseudorandom order
2. **SYN cookies** via SipHash-2-4 encode probe identity into the TCP sequence number, eliminating per-connection state
3. **Raw AF_PACKET sockets** with IP_HDRINCL bypass the kernel TCP stack entirely
4. **Lock-free atomics** (monotonic ordering) connect the TX, RX, and progress threads with zero mutex overhead
5. **Adaptive rate throttle** with a 256-bucket sliding window maintains target PPS within 5% accuracy

## Ethical Use

OhmZ is designed for **authorized security testing** and network administration only.

- Always obtain written authorization before scanning
- Respect rate limits and scope boundaries
- Never scan targets without explicit permission
- Comply with all applicable local, national, and international laws

See [SECURITY.md](SECURITY.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for details.

## Contributing

Contributions are welcome. Please read the [Code of Conduct](CODE_OF_CONDUCT.md) before contributing.

```bash
# Before submitting
zig fmt src/ build.zig
zig build test
zig build -Doptimize=ReleaseSafe
```

## License

[AGPL-3.0](LICENSE)

Built by [@effront](https://github.com/effront)
