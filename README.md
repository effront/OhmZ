```
 ██████╗ ██╗  ██╗███╗   ███╗███████╗
██╔═══██╗██║  ██║████╗ ████║╚══███╔╝
██║   ██║███████║██╔████╔██║  ███╔╝
██║   ██║██╔══██║██║╚██╔╝██║ ███╔╝
╚██████╔╝██║  ██║██║ ╚═╝ ██║███████╗
 ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝
      High-Performance Network Scanner
```

**powered by [@effront](https://github.com/effront)**

<div align="center">

[![CI](https://github.com/effront/OhmZ/actions/workflows/ci.yml/badge.svg)](https://github.com/effront/OhmZ/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/effront/OhmZ)](https://github.com/effront/OhmZ/releases)
[![Zig](https://img.shields.io/badge/zig-0.14.1-F7A41D?logo=zig)](https://ziglang.org/)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-lightgrey)]()
[![Binary](https://img.shields.io/badge/binary-static%20%7C%20zero%20deps-success)]()

</div>

---

```
+===========================================================================+
|  OHMZ -- Zig Network Scanner                                             |
+===========================================================================+
|  Asynchronous stateless network scanner written in pure Zig.             |
|  Raw socket TX/RX on dedicated threads, SYN cookie validation,           |
|  BlackRock target randomization, sub-microsecond packet templating.      |
|  Single static binary, zero dependencies, cross-compiled from one host.  |
+===========================================================================+
```

```
+---------------------------------------------------------------------------+
|  Speed: 100K+ pps (AF_PACKET), 500K+ pps (io_uring)                      |
|  Memory: < 50MB RSS for /16 full-port scan                               |
|  Binary: < 5MB static, no libc, no libpcap                               |
|  Stateless: SYN cookies via SipHash-2-4, no per-connection table         |
|  Randomization: BlackRock cipher (Feistel network) over IP x port space  |
|  Progress: Native ANSI progress bar on dedicated UI thread               |
|  Resume: Pause with Ctrl+C, resume from exact index                      |
|  Sharding: --shard N/M for distributed scanning, zero overlap            |
|  IPv6: Dual-stack native from day one                                    |
+---------------------------------------------------------------------------+
```

---

<details>
<summary><kbd>Scan Types (click to expand)</kbd></summary>

```
+---------------------------------------------------------------------------+
|  TCP                                                                      |
|  [x] SYN (-sS)       -- half-open scan, fast and stealthy (default)       |
|  [x] Connect (-sT)   -- full handshake, no root required                  |
|  [x] FIN (-sF)       -- FIN flag only, evades stateless firewalls         |
|  [x] XMAS (-sX)      -- FIN+PSH+URG, evades stateless firewalls           |
|  [x] NULL (-sN)      -- no flags set, evades stateless firewalls          |
|  [x] ACK (-sA)       -- maps firewall rules (filtered vs unfiltered)      |
|  [x] Window (-sW)    -- ACK variant, detects open via window size         |
|                                                                           |
|  UDP                                                                      |
|  [x] UDP (-sU)       -- protocol-specific payloads (DNS, SNMP, NTP)       |
|                                                                           |
|  SCTP                                                                     |
|  [ ] INIT (-sY)      -- SCTP equivalent of SYN scan                       |
|  [ ] COOKIE-ECHO     -- evades INIT-only firewalls                        |
|                                                                           |
|  OTHER                                                                    |
|  [ ] IP Protocol      -- enumerate supported IP protocols per host        |
+---------------------------------------------------------------------------+
```

</details>

<details>
<summary><kbd>Service Detection (click to expand)</kbd></summary>

```
+---------------------------------------------------------------------------+
|  BANNER GRABBING (-sV)                                                    |
|  [x] HTTP            -- Server header, status, redirect chain             |
|  [x] SSH             -- version string, key exchange algorithms           |
|  [x] TLS/SSL         -- version, ciphers, certificate (CN, SAN, expiry)   |
|  [x] FTP             -- server banner, AUTH TLS support                   |
|  [x] SMTP            -- MTA version, EHLO capabilities                    |
|  [x] SMB             -- version, hostname, domain, shares                 |
|  [x] DNS             -- version.bind, recursion, zone transfer            |
|  [x] MySQL           -- version, auth plugin, capabilities                |
|  [x] Redis           -- version, memory, auth status                      |
|  [x] RDP             -- NLA support, protocol version                     |
+---------------------------------------------------------------------------+
```

</details>

<details>
<summary><kbd>Detection Features (click to expand)</kbd></summary>

```
+---------------------------------------------------------------------------+
|  SCRIPT SCANNING (-sC)                                                    |
|  [x] http-title       -- extract page title from HTTP response            |
|  [x] http-robots      -- parse robots.txt disallow entries                |
|  [x] ssh-hostkey      -- SSH version string and host key                  |
|  [x] smtp-commands    -- EHLO extension enumeration                       |
|  [x] mysql-info       -- version, auth plugin, capabilities               |
|                                                                           |
|  OS FINGERPRINTING (-O)                                                   |
|  [x] TCP SYN probe    -- sends SYN, analyzes SYN-ACK response             |
|  [x] TTL analysis     -- base TTL detection (64/128/255)                  |
|  [x] Window size      -- range matching per OS version                    |
|  [x] TCP options      -- MSS, WScale, SACK, Timestamps                    |
|  [x] Signature DB     -- Linux, Windows, macOS, FreeBSD, OpenBSD,         |
|                          Cisco IOS, Solaris                               |
|                                                                           |
|  TRACEROUTE (--traceroute)                                                |
|  [x] UDP probes       -- incrementing TTL (1-30)                          |
|  [x] ICMP listener    -- Time Exceeded / Destination Unreachable          |
|  [x] Auto-stop        -- after 5 consecutive timeouts                     |
|  [x] Concurrent       -- multi-threaded for multiple targets              |
+---------------------------------------------------------------------------+
```

</details>

<details>
<summary><kbd>Evasion Techniques (click to expand)</kbd></summary>

```
+---------------------------------------------------------------------------+
|  FIREWALL / IDS EVASION                                                   |
|  [x] Decoy IPs       -- mix real packets with decoy source addresses      |
|  [x] Fragmentation   -- split packets at custom MTU boundaries            |
|  [x] Source Port Pin  -- fix source port (e.g. 53 to mimic DNS)           |
|  [x] TTL Control      -- custom TTL to evade traceroute-based IDS         |
|  [x] Scan Delay       -- per-host delay between probes                    |
|  [ ] Idle/Zombie      -- bounce scan off idle host (no IP exposure)       |
|  [ ] Spoofed Source   -- fake source IP (decoy/idle scan modes)           |
+---------------------------------------------------------------------------+
```

</details>

---

## Table of Contents

```
+------------------------------------------------------+
|  01 - Quick Start                                    |
|  02 - Technology Stack                               |
|  03 - Architecture                                   |
|  04 - Progress Bar                                   |
|  05 - Usage                                          |
|  06 - Output Formats                                 |
|  07 - Performance                                    |
|  08 - Development                                    |
|  09 - Roadmap                                        |
|  10 - Ethical Use                                    |
+------------------------------------------------------+
```

---

## 01 - Quick Start

### Install

```bash
# Install via script
curl -sSL https://raw.githubusercontent.com/effront/OhmZ/main/install.sh | sh

# Or via Homebrew
brew tap effront/tap && brew install ohmz

# Or via Docker
docker run --cap-add=NET_RAW ghcr.io/effront/ohmz -sS 192.168.1.0/24

# Or download the .deb
sudo dpkg -i ohmz_0.4.0_amd64.deb
```

### Prerequisites

```
+---------------------------------------------------------------------------+
|  Linux    |  Kernel 5.0+ with CAP_NET_RAW (or root)                       |
|  Windows  |  Npcap or WinPcap (fallback raw sockets)                      |
|  macOS    |  BPF access (/dev/bpf*)                                       |
+---------------------------------------------------------------------------+
```

### Build from source

```bash
git clone https://github.com/effront/ohmz.git
cd ohmz
zig build -Doptimize=ReleaseSafe
```

### Run

```bash
# SYN scan a /24 subnet, top 1000 ports
sudo ./zig-out/bin/ohmz -sS -p 1-1000 192.168.1.0/24

# TCP Connect scan (no root needed)
ohmz -sT -p 80,443 target.com

# Fast scan (top 100 ports)
sudo ohmz -F 10.10.10.1

# Full port scan with banner grabbing and all output formats
sudo ohmz -sS -sV -p 1-65535 -oA results 10.0.0.0/24

# UDP scan with banner grabbing
sudo ohmz -sU -sV -p 53,161,123 10.0.0.0/24
```

### Cross-compile

```bash
# Static binary for ARM (Raspberry Pi, routers)
zig build -Dtarget=aarch64-linux -Doptimize=ReleaseSmall

# Windows binary from Linux
zig build -Dtarget=x86_64-windows -Doptimize=ReleaseSafe

# Result: single static binary, zero runtime dependencies
```

---

## 02 - Technology Stack

```
+======================+====================================================+
|  LAYER               |  TECHNOLOGY                                        |
+======================+====================================================+
|  Language            |  Zig 0.14.1 (stable)                               |
|  Packet Engine       |  Raw AF_PACKET / io_uring / fallback raw sockets   |
|  Concurrency         |  Zig std.Thread + atomic counters (lock-free)      |
|  Memory              |  Explicit allocators(GPA dev, FixedBuffer hot path)|
|  Hashing             |  SipHash-2-4 (SYN cookies + BlackRock)             |
|  Randomization       |  BlackRock cipher (Feistel network permutation)    |
|  Rate Control        |  256-bucket sliding window with adaptive batching  |
|  Output              |  JSON, XML (nmap-compat), Grepable, Normal, NDJSON |
|  Build               |  zig build (native, no cmake/make/autotools)       |
|  Binary              |  100% static, no libc, no external deps            |
+======================+====================================================+
```

```
+======================+============+=============+============+
|  METRIC              |  OHMZ      |  NMAP       |  MASSCAN   |
+======================+============+=============+============+
|  Language            |  Zig       |  C/C++      |  C         |
|  Memory model        |  Explicit  |  malloc     |  malloc    |
|  Binary size         |  < 5 MB    |  ~4 MB+deps |  ~200 KB   |
|  Dependencies        |  0         |  pcap+lua+  |  pcap      |
|  IPv6                |  Native    |  Partial    |  Partial   |
|  Scan model          |  Stateless |  Stateful   |  Stateless |
|  Extensibility       |  comptime  |  Lua/NSE    |  None      |
|  io_uring            |  Yes       |  No         |  No        |
+======================+============+=============+============+
```

---

## 03 - Architecture

```
+------------------------------------------------------------------+
|                         CLI Parser                               |
|  (std.process.args, config file, --resume)                       |
+------------------------------------------------------------------+
         |                    |                    |
         v                    v                    v
+----------------+  +------------------+  +------------------+
| Target Engine  |  |  Rate Engine     |  | Output Engine    |
| - CIDR parser  |  |  - Throttle      |  | - JSON/XML/Grep  |
| - BlackRock    |  |  - Timing (-T)   |  | - Normal/NDJSON  |
| - Exclude list |  |  - Batch sizing  |  | - File rotation  |
| - Sharding     |  |  - Stats         |  | - Merge tool     |
| - Top ports    |  |  - Drain scaling |  |                  |
+----------------+  +------------------+  +------------------+
         |                    |
         v                    v
+------------------------------------------------------------------+
|                     Scan Orchestrator                            |
|  (host discovery -> port scan -> banner grab -> output)          |
+------------------------------------------------------------------+
         |                    |                    |
         v                    v                    v
+----------------+  +------------------+  +------------------+
| TX Thread(s)   |  | RX Thread(s)     |  | UI Thread        |
| - TcpTemplate  |  | - SYN cookie val |  | - Progress bar   |
|   patch        |  | - Deduplication  |  | - PPS / ETA      |
| - Evasion      |  | - Banner capture |  | - ANSI rendering |
| - AF_PACKET /  |  | - Protocol parse |  | - Atomic reads   |
|   io_uring     |  | - Per-scan-type  |  |                  |
|                |  |   response logic |  |                  |
+----------------+  +------------------+  +------------------+
| ConnectEngine  |           |
| - Kernel TCP   |           v
| - No root req  |  +------------------+
| - Non-blocking |  | Drain Timer      |
|   poll()       |  | - Proportional   |
+----------------+  | - Rate-aware     |
                    +------------------+
         |                    |
         v                    v
+------------------------------------------------------------------+
|                 Network Adapter Abstraction                      |
|  AF_PACKET | io_uring | Raw Socket | PF_RING                     |
+------------------------------------------------------------------+
```

### Thread Model

```
+---------------------------------------------------------------------------+
|  THREAD              |  ROLE                 |  COMMUNICATION             |
+---------------------------------------------------------------------------+
|  TX (1 per NIC)      |  Packet transmission  |  Writes: packets_sent      |
|  RX (1 per NIC)      |  Response capture     |  Writes: packets_recv,     |
|                      |                       |   ports_open, ports_closed |
|  UI (1 global)       |  Progress rendering   |  Reads: all atomic counters|
|  Main                |  Orchestration        |  Sets: is_done flag        |
+---------------------------------------------------------------------------+
|  Sync: std.atomic.Value (lock-free, monotonic ordering)                   |
|  Zero mutexes on hot path. UI reads stale-by-250ms, which is fine.        |
+---------------------------------------------------------------------------+
|  Connect mode: batch 512 concurrent sockets, poll() loop with deadline.   |
|  No raw sockets needed - uses kernel TCP connect().                       |
+---------------------------------------------------------------------------+
```

### Project Structure

```
OhmZ/
  src/
    main.zig              Entry point, thread orchestration, output wiring
    cli.zig               Argument parser, ScanConfig, nmap-compatible flags
    packet.zig            TcpTemplate: IP+TCP header construction, checksums
    tx.zig                TX engine: raw socket packet transmission
    rx.zig                RX engine: response capture, per-scan-type logic
    connect.zig           ConnectEngine: batch concurrent connect() for -sT
    cookie.zig            SipHash-2-4 SYN cookie generation/validation
    os.zig                OS fingerprinting: TCP stack analysis (TTL, window, options)
    scripts.zig           Default script engine (http-title, ssh-hostkey, etc.)
    traceroute.zig        UDP traceroute with ICMP listener
    blackrock.zig         BlackRock cipher: O(1) target space permutation
    throttle.zig          Rate limiter: 256-bucket sliding window
    stats.zig             ScanStats: atomic counters + snapshot
    progress.zig          ProgressBar: ANSI UI thread
    target.zig            CIDR parser, target space builder, top ports wiring
    ports.zig             Top 1000 ports frequency table (nmap ranking)
    output.zig            Writers: Normal, JSON, XML, Grepable, NDJSON
    banner.zig            Banner grabbing: HTTP, SSH, FTP, SMTP, TLS
  build.zig               Build system (static, cross-compile)
  Dockerfile              Multi-stage Alpine build, non-root runtime
  install.sh              Auto-detect arch/OS installer script
  dist/
    aur/PKGBUILD          AUR binary package
```

---

## 04 - Progress Bar

Native terminal progress bar running on a dedicated UI thread, no key press required (: ).

```
 67% ██████████████████████░░░░░░░░ 42.1K pps ETA: 1m23s | sent:168750 recv:165420 open:847
```

### Design

```
+---------------------------------------------------------------------------+
|  COMPONENT           |  IMPLEMENTATION                                    |
+---------------------------------------------------------------------------+
|  Percentage          |  packets_sent / total_targets (atomic read)        |
|  Visual bar          |  Unicode blocks: filled + light shade              |
|  PPS                 |  packets_sent / elapsed_seconds (auto-scaled K/M)  |
|  ETA                 |  remaining_targets / current_pps                   |
|  Verbose counters    |  sent, recv, open (--stats or -vv flag)            |
|  Refresh rate        |  250ms (4 Hz), non-blocking sleep                  |
|  Rendering           |  \r + ANSI clear-to-EOL, cursor hidden during scan |
|  Completion          |  Summary line with total time, hosts, open ports   |
+---------------------------------------------------------------------------+
```

### How it works

- TX thread increments `packets_sent` via `fetchAdd` (atomic, no lock)
- RX thread increments `packets_recv`, `ports_open` via `fetchAdd`
- UI thread calls `snapshot()` every 250ms - reads all atomics, computes PPS and ETA
- Main thread sets `is_done` flag (release ordering) when TX finishes
- UI thread sees `is_done` (acquire ordering), prints final summary, exits

Zero mutexes. Zero contention on the hot path. UI reads are allowed to be 250ms stale.

---

## 05 - Usage

```
ohmz [scan_type] [options] <target(s)>

TARGETS:
  <ip>                    Single host (192.168.1.1 or 2001:db8::1)
  <cidr>                  CIDR range (10.0.0.0/8)
  -iL <file>              Target list (one per line)
  --exclude <ip/cidr>     Exclude hosts
  --excludefile <file>    Exclusion list file

SCAN TYPES:
  -sS                     TCP SYN (default with root)
  -sT                     TCP Connect (default without root)
  -sU                     UDP
  -sF / -sX / -sN         FIN / XMAS / NULL
  -sA / -sW               ACK / Window
  -sY / -sZ               SCTP INIT / COOKIE-ECHO

DISCOVERY:
  -Pn                     Skip discovery (assume all hosts up)
  -PS / -PA / -PU         TCP SYN / ACK / UDP ping
  -PE / -PP               ICMP Echo / Timestamp
  -PR                     ARP ping (local network)

PORTS:
  -p <range>              Port range (e.g. -p 22,80,443 or -p 1-65535)
  -F                      Fast scan (top 100 ports)
  --top-ports <n>         Most common N ports

DETECTION:
  -sV                     Banner grabbing / version detection
  -sC                     Default script scanning
  -O                      OS fingerprinting (requires root)
  --traceroute            Trace hop path to each target (requires root)
  -A                      Aggressive (-sV -sC -O --traceroute)

OUTPUT:
  -oN / -oJ               Normal text / JSON
  -oX / -oG               XML (nmap-compat) / Grepable
  -oA <prefix>            All formats at once

PERFORMANCE:
  --rate <pps>            Packets per second
  -T0 to -T5             Timing template (Paranoid to Insane)
  --max-retries <n>       Retransmissions (default: 2)

EVASION:
  --decoys <ips>          Decoy source IPs
  --mtu <bytes>           IP fragmentation
  --source-port <p>       Fixed source port
  --scan-delay <ms>       Per-host probe delay
  --ttl <n>               Custom TTL

DISTRIBUTED:
  --shard <N>/<total>     Deterministic sharding
  --resume <file>         Resume interrupted scan

RUNTIME:
  --stats                 Real-time metrics on stderr
  -v / -vv / -vvv         Verbosity levels
  -6                      Force IPv6 mode
```

### Examples

```bash
# Quick LAN scan
sudo ohmz 192.168.1.0/24

# TCP Connect scan (no root needed)
ohmz -sT -p 80,443,8080 target.com

# Fast scan - top 100 ports
sudo ohmz -F 10.10.10.1

# Aggressive scan (banner + scripts + OS + traceroute)
sudo ohmz -A -sT -p 1-65535 target.com

# Stealth scan with evasion
sudo ohmz -sF --scan-delay 500 --decoys 10.0.0.5,10.0.0.9 -T1 target.com

# Distributed: machine 1 of 4
sudo ohmz -sS -p 1-65535 --shard 1/4 --rate 50000 10.0.0.0/8

# Resume interrupted scan
sudo ohmz --resume ohmz-resume.json

# Firewall rule mapping
sudo ohmz -sA -p 1-1024 target.com
```

---

## 06 - Output Formats

| Flag | Format | Use Case |
|---|---|---|
| `-oN` | Normal text | Human-readable, nmap-style report |
| `-oJ` | JSON | Native format, full metadata |
| `-oX` | XML | Nmap-compatible (Metasploit, OpenVAS, Nessus) |
| `-oG` | Grepable | One line per host, parseable with grep/awk |
| `-oA` | All | Generates all formats with shared prefix |

All formats include: IP, port, protocol, status (open/closed/filtered), service (if `-sV`), timestamp, RTT latency.

```bash
# Output to all formats at once
sudo ohmz -sS -sV -oA scan_results 192.168.1.0/24
# Creates: scan_results.nmap, scan_results.xml, scan_results.gnmap, scan_results.json

# Merge results from distributed scan
ohmz merge shard1.json shard2.json shard3.json shard4.json -o full_scan.json
```

---

## 07 - Performance

```
+---------------------------------------------------------------------------+
|  PERFORMANCE TARGETS                                                      |
+---------------------------------------------------------------------------+
|  SYN scan throughput   |  >= 100K pps (AF_PACKET)                         |
|                        |  >= 500K pps (io_uring on 5.6+)                  |
|  Hot path latency      |  < 1 microsecond per packet                      |
|  Memory (RSS)          |  < 50 MB for /16 full-port scan                  |
|  Binary size           |  < 5 MB (ReleaseSmall)                           |
|  Rate accuracy         |  +/- 5% of target rate                           |
|  /24 top-1000          |  < 5 seconds on local gigabit                    |
+---------------------------------------------------------------------------+
```

```
+---------------------------------------------------------------------------+
|  WHY IT'S FAST                                                            |
+---------------------------------------------------------------------------+
|  Packet templates    |  Base packet built once, only IP/port/seq patched  |
|  Zero alloc hot path |  FixedBufferAllocator, pre-allocated buffers       |
|  Atomic counters     |  No mutex on TX/RX/UI communication                |
|  Batch throttle      |  Rate measured per-batch, not per-packet           |
|  BlackRock shuffle   |  O(1) per-target, no stored permutation            |
|  SYN cookies         |  No connection state table, O(1) validation        |
|  io_uring            |  Kernel-side batched I/O, zero syscall per packet  |
|  Drain scaling       |  Proportional post-TX wait based on scan size      |
+---------------------------------------------------------------------------+
```

---

## 08 - Development

### Build

```bash
zig build                              # debug
zig build -Doptimize=ReleaseSafe       # release with safety checks
zig build -Doptimize=ReleaseSmall      # smallest binary
zig build -Doptimize=ReleaseFast       # maximum speed
```

### Test

```bash
zig build test                         # unit tests
```

### Format

```bash
zig fmt src/ build.zig                 # before submitting
```

### Cross-compile targets

```bash
zig build -Dtarget=x86_64-linux        # Linux x86_64 (Tier 1)
zig build -Dtarget=aarch64-linux       # Linux ARM64 (Tier 1)
zig build -Dtarget=x86_64-windows      # Windows (Tier 2)
zig build -Dtarget=aarch64-macos       # macOS Apple Silicon (Tier 2)
zig build -Dtarget=arm-linux-gnueabihf # ARM 32-bit (Tier 3)
```

---

## 09 - Roadmap

```
+=======+==========================================+==========+
| PHASE |  SCOPE                                   |  STATUS  |
+=======+==========================================+==========+
|   1   |  Core: SYN scan, raw sockets, SYN        |  DONE    |
|       |  cookies, BlackRock, rate engine,        |  v0.1.0  |
|       |  JSON output, progress bar, static build |          |
+-------+------------------------------------------+----------+
|   2   |  Parity: FIN/XMAS/NULL/ACK/Connect/UDP,  |  DONE    |
|       |  host discovery, XML/grepable/normal,    |  v0.2.0  |
|       |  top ports, timing templates, excludes,  |          |
|       |  proportional drain, ConnectEngine       |          |
+-------+------------------------------------------+----------+
|   3   |  Intelligence: banner grabbing (-sV),    |  DONE    |
|       |  protocol parsers (10+), TLS cert        |  v0.3.0  |
|       |  extraction                              |          |
+-------+------------------------------------------+----------+
|   4   |  Detection: OS fingerprinting (-O),      |  DONE    |
|       |  script scanning (-sC), traceroute,      |  v0.4.0  |
|       |  aggressive mode (-A), batch connect     |          |
|       |  engine (512 concurrent, poll loop)      |          |
+-------+------------------------------------------+----------+
|   5   |  Advanced: IPv6, SCTP, io_uring backend, |  PLAN    |
|       |  evasion techniques, multi-NIC, sharding,|          |
|       |  plugin system (comptime + WASM)         |          |
+=======+==========================================+==========+
```

---

## 10 - Ethical Use

```
+---------------------------------------------------------------------------+
|  OhmZ is designed for authorized security testing and network             |
|  administration only.                                                     |
|                                                                           |
|  - Always obtain written authorization before scanning                    |
|  - Respect scope boundaries and rate limits                               |
|  - Never scan targets without explicit permission                         |
|  - Use --exclude to avoid hitting out-of-scope networks                   |
|  - Comply with local laws regarding network scanning                      |
|                                                                           |
|  Intended use cases:                                                      |
|  - Authorized penetration testing engagements                             |
|  - Network inventory and asset discovery                                  |
|  - Vulnerability assessment of your own infrastructure                    |
|  - Red team operations with proper authorization                          |
|  - CTF competitions and security research                                 |
+---------------------------------------------------------------------------+
```

---

## License

AGPL-3.0 License - see [LICENSE](LICENSE) for details.

---

<div align="center">

Built by [@effront](https://github.com/effront)

</div>
