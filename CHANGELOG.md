# Changelog

All notable changes to HawkGate are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
HawkGate uses [Semantic Versioning](https://semver.org/).

---

## [1.0.0] — 2026-07-14

First public release.

### Added

**Kernel datapath**
- eBPF TC ingress/egress hooks on any network interface
- Per-client authentication via `hg_clients` map keyed by MAC address
- Self-maintaining MAC↔IP binding maps (`hg_mac_ip`, `hg_ip_mac`) populated from live traffic — no DHCP snooping or external dependency
- EDT (Earliest Departure Time) bandwidth shaping with separate upload and download rate limits per client
- Upload shaping via IFB redirect — FQ qdisc on IFB enforces upload EDT timestamps
- Download shaping via FQ qdisc on bridge interface
- Per-CPU byte/packet accounting via `hg_counters` (zero lock contention)
- In-kernel DNAT to captive portal with full conntrack DNAT/SNAT (LRU map, 512 entries, 120s timeout)
- Runtime portal IP/port configuration via `hg_portal_cfg` map
- Pre-auth protocol allow-list via `hg_proto` map with wildcard matching (exact, sport, dport, proto)
- L2 EtherType allow-list via `hg_l2_allow` map
- Walled garden via `hg_walled_garden` (LPM_TRIE — subnet matching)
- Static IP bypass via `hg_bypass` map (trusted devices skip portal entirely)
- Conditional MAC↔IP binding writes — only written when IP changes (~90% write reduction in steady state)
- `BPF_F_PSEUDO_HDR` flag on TCP checksum updates in DNAT/SNAT — fixes TCP handshake for redirected connections

**hgctl CLI**
- `hgctl start` — attach TC hooks, create and pin BPF maps, configure IFB and FQ qdiscs
- `hgctl stop` — detach hooks, remove maps, tear down IFB
- `hgctl add` — authenticate a client (three modes: MAC only, IP only, MAC+IP)
- `hgctl del` — deauthenticate a client by MAC
- `hgctl show` — per-client traffic counters and session state
- `hgctl details` — full session info for a single client
- `hgctl proto` — manage pre-auth protocol allow rules at runtime
- `hgctl bypass-add/del` — manage static trusted IP entries
- `hgctl wg-add/del` — manage walled garden IP/subnet entries
- `hgctl map-del` — delete arbitrary BPF map entries by key
- `posix_spawn` for all subprocess calls — no `system()`, no shell injection surface
- `inet_pton` validation before any IP enters an argv array

**hawkgated daemon**
- Single-threaded epoll ET HTTP/1.1 server on configurable port
- Incremental HTTP/1.1 state-machine parser (REQUEST_LINE → HEADERS → BODY → COMPLETE)
- Per-connection RAII state machine with non-blocking I/O
- `AuthProvider` pure virtual interface — pluggable auth backends
- `LocalAuth` click-through implementation (v1 — always succeeds, applies config defaults)
- CAPPORT API at `GET /api/v1/capport` (RFC 8908) — `application/captive+json` responses
- Portal pages served from disk (`/etc/hawkgate/static/`) — live editable without restart
- `307 Temporary Redirect` + HTML body fallback for all unauthenticated HTTP requests — verified working on Android 16, iOS 18, Windows 11 Firefox
- OS probe table — correct responses for authenticated clients (Android, iOS, Windows, Firefox)
- `HgBpfCtrl` — sole kernel interface, shells out to `hgctl` for all map writes
- `hg_reader.c` linked directly into hawkgated for zero-overhead read-only stats access
- Stale BPF state cleanup on startup — attempts `hgctl stop` before `hgctl start`
- `cleanup_on_failure()` in `start_action` — no leaked BPF state on partial startup failure
- Log level control via config (`debug`, `info`, `warning`, `error`) — default `info`
- C++20 `source_location` logger with timestamp and file/line annotation
- Graceful shutdown on SIGTERM/SIGINT — detaches BPF hooks cleanly

**Configuration**
- INI-style config parser for `/etc/hawkgate/hawkgate.conf`
- `[preauth-protocol]` section — named protocol auto-translation (e.g. `dns` → `17:any:53` + `17:53:any`)
- `[walled_garden]` section — CIDR entries auto-loaded on startup
- Per-client upload/download rate defaults
- Session timeout, max clients, portal IP/port, gateway FQDN all configurable

**Build system**
- `configure.sh` — probes toolchain, generates `kernel/Makefile`, `hawkgated/Makefile`, root `Makefile`
- Interactive `vmlinux.h` handler — generate from running kernel or provide path
- `make install` — installs binaries, portal pages, config, and systemd unit
- Systemd service unit (`hawkgated.service`) — starts after `network-online.target`, restarts on failure

### Known Limitations

- IPv4 only
- HTTPS not intercepted (standard for captive portal implementations)
- Bypass IPs not persistent across restart — re-add via `hgctl bypass-add` or startup script
- `ifb0`/`ifb1` interfaces persist after `hgctl stop` (harmless — `sudo rmmod ifb` to remove)
- MAC randomisation creates a new session per reconnect (by design — randomised MAC = new identity)

---

*See [ROADMAP.md](ROADMAP.md) for planned features.*
