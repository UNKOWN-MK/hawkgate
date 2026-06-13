# Changelog

All notable changes to HawkGate will be documented here.

## [Unreleased]

### Added
- Initial project structure under HawkGate name
- eBPF TC ingress/egress hooks for captive portal enforcement
- EDT-based bandwidth shaping (upload via IFB + download via FQ)
- In-kernel DNAT portal redirect (`hg_tc_ingress`)
- Per-client byte/packet accounting via `hg_counters` PERCPU_HASH map
- Pre-auth protocol allow-list (`hg_proto`, `hg_l2_allow`)
- `hgctl` CLI: start / stop / add / del / show / details / proto
- `hawkgated` C++ daemon foundation: logger + config parser
