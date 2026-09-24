<div align="center">

```
  ██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗ ██████╗  █████╗ ████████╗███████╗
  ██║  ██║██╔══██╗██║    ██║██║ ██╔╝██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝
  ███████║███████║██║ █╗ ██║█████╔╝ ██║  ███╗███████║   ██║   █████╗  
  ██╔══██║██╔══██║██║███╗██║██╔═██╗ ██║   ██║██╔══██║   ██║   ██╔══╝  
  ██║  ██║██║  ██║╚███╔███╔╝██║  ██╗╚██████╔╝██║  ██║   ██║   ███████╗
  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝
```

**eBPF-based captive portal and network access control**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Kernel: 6.0+](https://img.shields.io/badge/Kernel-6.0%2B-orange.svg)]()
[![Language: C/C++](https://img.shields.io/badge/Language-C%2FC%2B%2B-green.svg)]()

</div>

---

## What is HawkGate?

HawkGate is a captive portal system built on Linux eBPF TC hooks. It replaces iptables-based solutions (OpenNDS, NoDogSplash, CoovaChilli) with a modern kernel datapath that enforces per-client authentication, bandwidth shaping, and session management entirely in O(1) BPF hash map lookups.

The core idea: instead of maintaining per-client iptables rules that must be evaluated linearly for every packet, HawkGate uses BPF hash maps. Whether you have 10 clients or 10,000, each packet takes exactly one map lookup to determine its fate.

---

## How it works

```
 Client packet arrives on br0
         │
         ▼
 ┌─────────────────────────────────────────┐
 │         hg_tc_ingress (eBPF)            │
 │                                         │
 │  1. L2 EtherType check                  │
 │  2. Static bypass (trusted IPs)         │
 │  3. MAC↔IP binding update              │
 │  4. Portal traffic bypass               │
 │  5. Auth lookup → hg_clients (by MAC)  │
 │     ├─ authenticated → rate shape + fwd │
 │     └─ unauthenticated ──────────────┐  │
 │  6. Pre-auth allow (DNS, DHCP, ARP)  │  │
 │  7. Walled garden check              │  │
 │  8. DNAT → captive portal ◄──────────┘  │
 └─────────────────────────────────────────┘
```

**Authenticated clients** are rate-shaped using Linux EDT (Earliest Departure Time) — the same mechanism used by Google and Cloudflare for traffic shaping at scale. Packets are stamped with a future departure time; the FQ qdisc holds them until that time arrives. No drops, no artificial burstiness, smooth accurate shaping.

**Unauthenticated clients** have their HTTP traffic DNAT'd to the captive portal. The portal responds with `307 Temporary Redirect` + HTML body — the exact pattern used by production captive portal deployments and verified against real device traffic from Android 16, iOS 18, and Windows 11.

---

## Features

- **O(1) per-client enforcement** via BPF hash maps — no performance degradation at scale
- **MAC-based session identity** — sessions survive IP changes (DHCP lease renewal, roaming)
- **Self-maintaining MAC↔IP bindings** built from live traffic — no DHCP snooping required
- **EDT bandwidth shaping** — separate upload and download rate limits per client
- **Walled garden** — allow unauthenticated access to specific IPs/subnets (LPM_TRIE)
- **Pre-auth protocol allow-list** — ARP, DNS, DHCP, NTP auto-loaded from config
- **Static IP bypass** — trusted devices skip portal enforcement entirely
- **CAPPORT API** (RFC 8908) — modern OS captive portal detection support
- **Captive portal detection** — Android 16, iOS 18, Windows 11, Firefox confirmed working
- **DNS-independent** — no DNS hijacking required. BPF intercepts all unauthenticated HTTP at the kernel level
- **Click-through portal** — pluggable `AuthProvider` interface for custom auth (vouchers, RADIUS, etc.)
- **Single-threaded epoll ET server** — hawkgated handles thousands of connections with zero threads

---

## Architecture

HawkGate has two halves that communicate only through the BPF map filesystem at `/sys/fs/bpf/hg/`:

**`kernel/`** — eBPF TC programs + `hgctl` CLI
- BPF programs attach to any network interface (bridge, NIC, VLAN)
- `hgctl` is the sole writer of all BPF maps — clean privilege boundary
- `hg_reader.c` links directly into hawkgated for zero-overhead stats reads

**`hawkgated/`** — C++20 captive portal daemon
- Single-threaded epoll ET HTTP/1.1 server
- Shells out to `hgctl` for all kernel state changes (no direct map writes)
- Pluggable `AuthProvider` interface — swap auth backends without touching the daemon

---

## Requirements

- Linux kernel **6.0 or later**
- x86\_64
- clang, gcc, g++ (C++), bpftool, make
- libbpf-dev, libelf-dev, zlib1g-dev

---

## Quick Start

```bash
# clone
git clone https://github.com/<your-username>/hawkgate.git
cd hawkgate

# probe toolchain and generate Makefiles
./configure.sh

# build
make

# install
sudo make install

# configure — edit /etc/hawkgate/hawkgate.conf
sudo nano /etc/hawkgate/hawkgate.conf

# start
sudo systemctl enable --now hawkgated

# check status
sudo hgctl show -i br0
```

---

## Configuration

`/etc/hawkgate/hawkgate.conf`:

```ini
iface_name      = br0
http_port       = 2050
portal_ip       = 192.168.99.1
gateway_fqdn    = portal.hawkgate.local
session_timeout = 3600
max_clients     = 4096
u_rate          = 5120        # kbps upload per client
d_rate          = 10240       # kbps download per client
log_level       = info        # debug | info | warning | error

[preauth-protocol]
l2 = arp
l3 = icmp
l4 = dns, dhcp, ntp

[walled_garden]
# ip = 93.184.216.34
# ip = 192.168.1.0/24
```

---

## Managing Clients

```bash
# view active sessions
sudo hgctl show -i br0

# authenticate a client by MAC
sudo hgctl add -i br0 -m aa:bb:cc:dd:ee:ff -e 3600 -D 10240 -U 5120

# authenticate by IP (client must have sent traffic first)
sudo hgctl add -i br0 -c 192.168.99.82 -e 3600 -D 10240 -U 5120

# deauthenticate
sudo hgctl del -i br0 -m aa:bb:cc:dd:ee:ff

# trust a static IP device permanently
sudo hgctl bypass-add --ip 192.168.99.50

# walled garden
sudo hgctl wg-add --ip 93.184.216.34
sudo hgctl wg-add --ip 192.168.1.0/24

# add preauth protocol at runtime
sudo hgctl proto -a add -i br0 --l4 17:any:53
```

---

## Why not iptables?

| | iptables | HawkGate |
|---|---|---|
| Per-packet policy evaluation | O(n) rules | O(1) map lookup |
| 10K clients | ~10K rules evaluated per packet | 1 hash lookup |
| Session identity | IP address | MAC address |
| IP change handling | session lost | session survives |
| Bandwidth shaping | HTB/TBF (drop-based) | EDT (delay-based, smooth) |
| Architecture | hooks + chains | single BPF program |

---

## Known Limitations

- **IPv4 only** — IPv6 support planned for v2
- **HTTP interception only** — HTTPS is not intercepted (standard for all captive portal implementations)
- **Bypass IPs not persistent** — `hgctl bypass-add` entries are lost on restart (v2 will add `[bypass]` config section)
- **`ifb0`/`ifb1` interfaces** — persist after `hgctl stop` (harmless, `sudo rmmod ifb` to remove)

---

## Documentation

- [User Guide](docs/user-guide.md) — installation, configuration, operation
- [Developer Guide](docs/developer-guide.md) — architecture, extending HawkGate, coding conventions
- [Changelog](CHANGELOG.md) — version history
- [Roadmap](ROADMAP.md) — planned features and future releases

---

## Project Structure

```
hawkgate/
├── kernel/          eBPF TC programs + hgctl CLI (C)
├── hawkgated/       captive portal daemon (C++20)
│   ├── src/         daemon source
│   └── etc/         default config + portal pages
├── docs/            user and developer documentation
├── testlab/         test scripts and setup
└── configure.sh     toolchain probe + Makefile generation
```

---

## License

MIT — see [LICENSE](LICENSE)

---

<div align="center">
<sub>belong to infinity</sub>
</div>
