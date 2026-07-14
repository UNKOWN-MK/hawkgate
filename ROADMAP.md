# HawkGate Roadmap

This document outlines planned features and improvements for future releases.
Items are grouped by release target but are subject to change.

Community contributions are welcome — see the [Developer Guide](docs/developer-guide.md)
for architecture details and coding conventions.

---

## v1.x — Patch releases

Small improvements and bug fixes on top of v1.0.0.

- **Persistent bypass IPs** — `[bypass]` section in `hawkgate.conf` so static trusted devices survive restart
- **Conntrack cleanup on auth** — iterate conntrack map by client IP on authentication to remove stale entries immediately rather than waiting for LRU eviction
- **Session persistence across restart** — serialize authenticated sessions to disk, restore on startup so clients do not need to re-authenticate after a daemon restart
- **Log rotation** — integrate with logrotate or add built-in log file rotation
- **Health check endpoint** — `GET /api/v1/health` returning daemon status and uptime

---

## v2.0 — Major release

### Performance — 10Gbps target

v1 is designed for 1Gbps / 10K clients with 7-8x headroom at realistic packet sizes. v2 targets 10Gbps line rate with real traffic.

- **RSS multi-queue** — multiple TC hook instances across CPU cores via Receive Side Scaling. Each core processes its own queue independently — effective throughput scales linearly with cores
- **`hg_clients` map split** — separate auth metadata (PERCPU_HASH, no lock) from EDT timestamps (locked HASH). Auth lookup on the hot path becomes lock-free across all cores
- **Per-CPU rate profiles** — eliminate spin lock contention on `hg_rate_cfg` lookups at high PPS

### Security

- **HTTPS interception** — TLS termination in hawkgated with self-signed CA for managed deployments. Let's Encrypt integration for public-facing portals
- **Rate limiting per IP** — protect the portal HTTP server from unauthenticated clients flooding connections
- **Session token validation** — replace click-through with a signed session token to prevent auth bypass

### Authentication

- **Voucher auth** — time-limited voucher codes via `AuthProvider` plugin. Operator generates codes, clients enter them on the portal page
- **RADIUS integration** — `AuthProvider` implementation for RADIUS authentication. Supports existing AAA infrastructure
- **External auth URL** — redirect to an external authentication service instead of the built-in portal. Useful for integration with existing user management systems
- **Concurrent session limit** — maximum number of simultaneous sessions per MAC address
- **Idle timeout enforcement** — deauthenticate clients after a configurable period of inactivity, measured from `last_seen` counter

### Management

- **Admin REST API** — authenticated JSON API for client management, stats export, and config changes without shell access
- **Admin dashboard** — web UI for real-time monitoring: active clients, bandwidth usage, session list, top talkers
- **Config hot-reload** — apply config changes without restarting the daemon or dropping existing sessions
- **Bandwidth accounting export** — push per-client byte counters to external systems (syslog, InfluxDB, Prometheus)
- **Multi-profile rate limits** — named rate profiles (e.g. `guest`, `staff`, `premium`) assigned per client at auth time

### Platform

- **IPv6 support** — dual-stack enforcement. MAC identity already handles IPv6 correctly at L2; requires IPv6 DNAT/SNAT in the BPF egress hook
- **ARM64 support** — tested and documented for ARM64 gateways (OpenWrt, Raspberry Pi, NanoPi)
- **Multi-interface** — enforce across multiple interfaces simultaneously with a shared client map

---

## Ideas under consideration

These are not committed to any release but have been discussed:

- **WPA Enterprise integration** — use 802.1X EAP authentication result to auto-authenticate clients without a portal page
- **OpenRoaming / Passpoint** — automatic authentication for devices with Passpoint credentials
- **QoS priority queues** — multiple FQ bands per client for traffic prioritisation (VoIP, video, bulk)
- **Kernel module packaging** — DKMS package for easier installation on standard distributions

---

*Have a feature request? Open an issue on GitHub.*