# HawkGate User Guide

HawkGate is an eBPF-based captive portal and network access control system. It replaces iptables-based solutions with a modern kernel datapath that enforces per-client authentication, bandwidth shaping, and session management entirely in O(1) BPF hash map lookups — with no performance degradation as client count grows.

This guide covers installation, configuration, and day-to-day operation.

---

## Requirements

**Kernel:** Linux 6.0 or later. Kernels below 6.0 may have TC redirect issues that affect upload EDT shaping reliability.

**Architecture:** x86\_64 with a Linux bridge interface (`br0` or similar). HawkGate attaches eBPF TC hooks to the bridge — all client traffic must flow through it.

**Tools:** clang, gcc, g++ (C++20), bpftool, make, libbpf-dev, libelf-dev, zlib1g-dev.


---

## Typical Setup

HawkGate attaches eBPF TC hooks to any network interface where client traffic flows — a Linux bridge, a physical NIC, a VLAN interface, or a bonded interface. All client traffic must pass through the chosen interface for enforcement to work.

The gateway machine needs an IPv4 address on that interface. HawkGate intercepts all unauthenticated HTTP traffic on it, redirects to the captive portal, and enforces rate limits after authentication.

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/UNKOWN-MK/hawkgate.git
cd hawkgate

# 2. Run the configure script — probes your toolchain and generates Makefiles
./configure.sh

# 3. Build everything
make

# 4. Install to system
sudo make install
```

`make install` copies:
- `hgctl` → `/usr/local/bin/hgctl`
- `hawkgated` → `/usr/local/bin/hawkgated`
- Portal pages → `/etc/hawkgate/static/`
- Default config → `/etc/hawkgate/hawkgate.conf` (only if not already present)
- Systemd unit → `/etc/systemd/system/hawkgated.service`

---

## Configuration

Edit `/etc/hawkgate/hawkgate.conf`:

```ini
# Logging — debug, info, warning, error (default: info)
# Use debug only for troubleshooting — it is very verbose
log_level       = info

# Network
iface_name      = br0               # interface name
http_port       = 2050              # hawkgated HTTP port
portal_ip       = 192.168.99.1      # gateway IP on the interface
gateway_fqdn    = portal.hawkgate.local

# Session
session_timeout = 3600              # seconds; 0 = no expiry
max_clients     = 4096

# Bandwidth — per client defaults (kbps)
u_rate          = 5120              # upload limit
d_rate          = 10240             # download limit
quota           = 0                 # bytes per session; 0 = unlimited

portal_mode     = builtin

# Pre-authentication protocols
# These are allowed for ALL clients before they authenticate.
# Supported l2: arp, ipv4, ipv6, vlan, pppoe
# Supported l3: icmp, igmp, tcp, udp, gre, esp, ah, icmpv6, ospf, sctp
# Supported l4: dns, dhcp, ntp, http, https, mdns, llmnr, syslog, snmp
# L4 rules are applied in both directions automatically.
[preauth-protocol]
l2 = arp
l3 = icmp
l4 = dns, dhcp, ntp

# Walled garden — IPs/subnets unauthenticated clients can reach
# [walled_garden]
# ip = 93.184.216.34
# ip = 192.168.1.0/24
```

---

---

## Starting HawkGate

**Manual start:**
```bash
sudo hawkgated -c /etc/hawkgate/hawkgate.conf
```

**With debug logging** — set `log_level = debug` in `hawkgate.conf` first:
```bash
sudo hawkgated -c /etc/hawkgate/hawkgate.conf
```

**Systemd:**
```bash
sudo systemctl enable --now hawkgated
sudo systemctl status hawkgated
```

On startup, hawkgated:
1. Attempts `hgctl stop` to clean any stale BPF state from a previous crash
2. Runs `hgctl start` to attach TC hooks and create BPF maps
3. Loads preauth protocol rules from config
4. Loads walled garden entries from config
5. Starts the HTTP server on the configured port

---

## Managing Clients

**View active sessions:**
```bash
sudo hgctl show -i br0
```

**View detailed stats for one client:**
```bash
sudo hgctl details -i br0 --ip 192.168.99.82
```

**Manually authenticate a client (by MAC):**
```bash
sudo hgctl add -i br0 -m aa:bb:cc:dd:ee:ff -e 3600 -D 10240 -U 5120
```

**Manually authenticate by IP (client must have sent traffic first):**
```bash
sudo hgctl add -i br0 -c 192.168.99.82 -e 3600 -D 10240 -U 5120
```

**Deauthenticate a client:**
```bash
sudo hgctl del -i br0 -m aa:bb:cc:dd:ee:ff
```

**Pre-authorise a static IP device (bypass auth entirely):**
```bash
sudo hgctl bypass-add --ip 192.168.99.50
sudo hgctl bypass-del --ip 192.168.99.50
```

**Add a walled garden entry at runtime:**
```bash
sudo hgctl wg-add --ip 93.184.216.34        # exact host
sudo hgctl wg-add --ip 192.168.1.0/24       # subnet
sudo hgctl wg-del --ip 93.184.216.34
```

**Add a preauth protocol rule at runtime:**
```bash
sudo hgctl proto -a add -i br0 --l2 0x0806       # ARP
sudo hgctl proto -a add -i br0 --l4 17:any:53    # DNS outbound
```

**Stop HawkGate (detaches BPF hooks, removes maps):**
```bash
sudo hgctl stop -i br0
```

---

## Captive Portal Flow

1. Client connects to WiFi and gets an IP from DHCP
2. Client's OS sends an HTTP probe to a known endpoint (e.g. `connectivitycheck.gstatic.com`)
3. BPF TC ingress on `br0` intercepts the probe — any unauthenticated HTTP (port 80) traffic is caught regardless of destination IP
4. BPF DNAT rewrites destination to `portal_ip:portal_port` and forwards to hawkgated
5. hawkgated returns `307 Temporary Redirect` with an HTML body fallback to `/portal`
6. Client's OS detects the non-204 response and shows the captive portal popup
7. User opens the portal page and clicks "Connect"
8. Client is authenticated — traffic passes freely at configured rate limits
9. After session expires, client is deauthenticated automatically

No DNS hijacking is required. The BPF hook intercepts all unauthenticated HTTP traffic at the bridge level, before any routing decision.

---

## Portal Pages

Portal pages are served from `/etc/hawkgate/static/`:

| File | Purpose |
|---|---|
| `login.html` | Click-through login page shown before auth |
| `success.html` | Shown after successful authentication |

Edit these files directly to customise the portal appearance. Changes take effect immediately — no restart required.

---

## Known Limitations

**HTTPS interception** — HawkGate only intercepts HTTP (port 80). HTTPS traffic from unauthenticated clients is dropped. OS captive portal detection uses HTTP probes, so this does not affect the popup flow. Users who manually type an HTTPS URL before authenticating will see a connection error — this is expected and consistent with all captive portal implementations.

**IPv6** — Not supported in v1. IPv6 traffic from unauthenticated clients is dropped.

**ifb0 / ifb1 interfaces** — The `ifb` kernel module creates two default interfaces that persist after `hgctl stop`. They are `state DOWN` and harmless. Remove manually with `sudo rmmod ifb` if needed (only if nothing else uses IFB on the system).

**MAC randomisation** — Devices using MAC randomisation (Android, iOS, Windows default) create a new session on each reconnect. This is correct behaviour — a randomised MAC is treated as a new device identity.

---

## Troubleshooting

**Portal page not appearing:**
```bash
# Check BPF hooks are attached
sudo tc filter show dev br0 ingress
sudo tc filter show dev br0 egress

# Check hawkgated is running
sudo systemctl status hawkgated

# Verify port 80 traffic is being intercepted
sudo tcpdump -i br0 -n 'tcp and dst port 80' 2>/dev/null
# Should see SYN packets from clients — BPF will DNAT these to port 2050
```

**Client authenticated but no internet:**
```bash
# Check client appears in map
sudo hgctl show -i br0

# Check IFB is up for rate shaping
ip link show ifb_hg

# Check masquerade rule exists for WAN
sudo iptables -t nat -L POSTROUTING -n
```

**High CPU on hawkgated:**
This should not happen under normal load. hawkgated is single-threaded epoll — if CPU is high, run with `-v` and check for error loops in the log.

**`hgctl start` fails with map pin conflicts:**
Stale BPF state from a previous crash. hawkgated handles this automatically on startup via `hgctl stop` before `hgctl start`. If running `hgctl start` manually:
```bash
sudo hgctl stop -i br0
sudo hgctl start -i br0 -P 192.168.99.1 -p 2050
```

