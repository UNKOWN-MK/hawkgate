# HawkGate Developer Guide

This guide is for developers who want to understand the HawkGate codebase, extend it, or contribute to it. It assumes familiarity with C, C++, and basic Linux networking concepts. BPF knowledge is helpful but not required to understand the architecture.

---

## Project Structure

```
hawkgate/
├── kernel/                    eBPF TC programs + hgctl CLI
│   ├── hg_common.h            shared structs, map macros, constants
│   ├── hg_tc.bpf.h/c          BPF TC ingress/egress programs
│   ├── hg_control.c           hgctl action implementations
│   ├── hg_cli.c               hgctl CLI argument parsing
│   ├── hg_user.h              shared userspace declarations
│   └── hg_reader.h/c          BPF map reader (linked into hawkgated)
├── hawkgated/src/
│   ├── main.cpp               daemon lifecycle, signal handlers
│   ├── util/
│   │   ├── hg_log.h/cpp       C++20 source_location logger
│   │   └── hg_config.h/cpp    INI parser → HgConfig struct
│   ├── bpf/
│   │   └── hg_bpf_ctrl.h/cpp  kernel interface (shells out to hgctl)
│   ├── http/
│   │   ├── hg_parser.h/cpp    incremental HTTP/1.1 state-machine parser
│   │   ├── hg_connection.h/cpp per-connection RAII state machine
│   │   └── hg_server.h/cpp    single-threaded epoll ET server
│   └── portal/
│       ├── hg_router.h/cpp    URL → handler dispatch
│       ├── hg_auth_provider.h AuthProvider pure virtual interface
│       ├── local_auth.h/cpp   click-through auth (v1)
│       ├── hg_auth.h/cpp      POST /login handler
│       └── hg_portal.h/cpp    captive detection, probe table, portal pages
└── configure.sh               toolchain probe, generates Makefiles
```

---

## Architecture

HawkGate has two halves that communicate only through the BPF map filesystem at `/sys/fs/bpf/hg/`.

### Kernel half — the datapath

eBPF TC programs attach to the bridge interface (`br0`) as classifier-actions on both ingress and egress. Every packet from every client passes through these hooks in microseconds.

**Ingress policy (upload path):**
```
1. L2 EtherType check     → hg_l2_allow map
2. Static bypass          → hg_bypass map (trusted IPs)
3. MAC↔IP binding update  → hg_mac_ip / hg_ip_mac maps (conditional)
4. Portal traffic bypass  → pass portal-IP:portal-port through
5. Auth lookup            → hg_clients map (keyed by MAC)
   authenticated          → EDT rate shaping + accounting + IFB redirect
6. Pre-auth protocol      → hg_proto map (DNS, DHCP, ARP, etc.)
6a. Walled garden         → hg_walled_garden map (LPM_TRIE)
7. Everything else        → redirect_to_portal() DNAT
```

**Egress policy (download path):**
```
1. L2 check
2. Portal response        → SNAT via conntrack map
3. Static bypass
4. Auth lookup            → hg_ip_mac → hg_clients
   authenticated          → EDT shaping + accounting
5. Pre-auth protocol
5a. Walled garden return traffic
6. Drop
```

### Userspace half — hawkgated

A single-threaded epoll ET HTTP/1.1 server. No threads. No blocking I/O. All operations complete in O(1) or are dispatched asynchronously.

**The architectural rule:** hawkgated never calls `bpf_map_update_elem` directly. All BPF map writes go through `hgctl` via `posix_spawn`. This keeps a clean separation — `hgctl` owns all map write paths, hawkgated owns the HTTP/portal layer.

The exception is read-only map access: hawkgated links `hg_reader.c` directly and calls `hg_read_one()` for per-client stats — no subprocess needed for reads.

---

## BPF Maps Reference

| Map | Type | Key | Value | Purpose |
|---|---|---|---|---|
| `hg_clients` | HASH | `hg_mac_key` | `hg_client` | Auth state + EDT timestamps |
| `hg_rates` | HASH | `__u32` rate_id | `hg_rate_cfg` | Rate profiles (d/u kbps + horizon) |
| `hg_counters` | PERCPU_HASH | `__u32` IP | `hg_counter` | Per-client byte/packet accounting |
| `hg_mac_ip` | HASH | `hg_mac_key` | `__u32` IP | MAC → current IP binding |
| `hg_ip_mac` | HASH | `__u32` IP | `hg_mac_key` | IP → MAC reverse lookup |
| `hg_bypass` | HASH | `__u32` IP | `__u8` | Static IP trust bypass |
| `hg_proto` | HASH | `hg_allow_key` | `__u8` | Pre-auth protocol allow-list |
| `hg_walled_garden` | LPM_TRIE | `hg_wg_key` | `__u8` | Unauthenticated IP/subnet access |
| `hg_l2_allow` | HASH | `__u16` ethertype | `__u8` | L2 EtherType allow-list |
| `hg_portal_cfg` | ARRAY | `__u32` 0 | `hg_portal_cfg` | Portal IP + port (runtime) |
| `hg_ifb_idx` | ARRAY | `__u32` 0 | `__u32` | IFB interface index for upload EDT |
| `hg_conntrack` | LRU_HASH | `hg_ct_key` | `hg_ct_val` | DNAT/SNAT conntrack (512 entries) |

All maps are pinned under `/sys/fs/bpf/hg/` on `hgctl start` and removed on `hgctl stop`.

---

## EDT Bandwidth Shaping

HawkGate uses Linux's Earliest Departure Time (EDT) model for rate limiting — the same approach used by Google and Cloudflare at scale.

Instead of dropping packets when a rate is exceeded, HawkGate stamps each packet with a future departure time in `skb->tstamp`. The FQ (Fair Queuing) qdisc holds the packet until that time arrives, then releases it. This produces smooth, accurate shaping without TCP retransmits.

**Upload path:** client → `br0` ingress → EDT stamp → IFB redirect → FQ on IFB holds packet → WAN
**Download path:** WAN → `br0` egress → EDT stamp → FQ on `br0` holds packet → client

Upload uses an explicit drop when the burst horizon is exceeded (TCP needs the drop signal — there's no backpressure from IFB to the LAN client). Download uses FQ backpressure to the sender socket — no drops needed.

Separate `rate_Bps_d` (download) and `rate_Bps_u` (upload) fields in `hg_rate_cfg` allow asymmetric rate limits per client.

---

## How to Add a New hgctl Command

Example: adding `hgctl quota-set --ip <ip> --bytes <n>`.

**Step 1 — `hg_common.h`:** Add a new map or extend an existing struct if needed.

**Step 2 — `hg_user.h`:** Add the opcode to `action_opcode` enum and declare the action + parse functions:
```c
QUOTA_SET = 13,
// ...
int quota_set_action(const char *ip, __u64 bytes);
int parse_quota_set(int argc, char **argv, const char *prog);
void print_quota_help(const char *prog);
```

**Step 3 — `hg_control.c`:** Implement `quota_set_action()`. Open the map, update the entry, close the fd. Follow the existing pattern — always `close(fd)` on every path.

**Step 4 — `hg_cli.c`:** Implement `parse_quota_set()`. Parse the argv array, validate inputs with `inet_pton` for IPs, call the action. Add `{"quota-set", QUOTA_SET}` to the action table and a case in the main dispatch switch.

**Step 5 — `hg_tc.bpf.c`:** If a new map is needed, define it here and add `bpf_map__set_pin_path()` in `start_action()` and `_clean_map()` in `hg_clean_maps()`.

---

## How to Add a New HTTP Route

Example: adding `GET /api/v1/stats` to return JSON stats.

**Step 1 — `hg_portal.h`:** Declare the handler:
```cpp
std::string handle_stats(const HttpRequest& req, const std::string& client_ip);
```

**Step 2 — `hg_portal.cpp`:** Implement the handler. Call `g_bpf->poll_one()` for per-client data or read from config. Return a complete HTTP response string.

**Step 3 — `hg_router.cpp`:** Add the route before the `/api/v1/` catch-all:
```cpp
else if (req.path == "/api/v1/stats")
{
    return handle_stats(req, client_ip);
}
```

That's it. No registration, no framework — just a function and a route.

---

## How to Add a Custom Auth Provider

The `AuthProvider` interface in `hg_auth_provider.h` is the extension point for custom authentication — vouchers, RADIUS, database lookup, etc.

```cpp
class MyAuth : public AuthProvider {
public:
    AuthResult authenticate(const Credentials& creds) override
    {
        AuthResult result;
        // your logic here
        // query a DB, call a REST API, check a voucher code
        result.success    = true;           // or false
        result.message    = "Connected";
        result.expire_sec = 3600;           // 0 = use config default
        result.down_kbps  = 10240;          // 0 = use config default
        result.up_kbps    = 5120;           // 0 = use config default
        return result;
    }
};
```

In `main.cpp`, replace `LocalAuth` with your implementation:
```cpp
// was:
auto auth = std::make_unique<LocalAuth>();
// becomes:
auto auth = std::make_unique<MyAuth>();
```

The rest of the auth flow — calling `hgctl add`, building the BPF map entry, rate limiting — is handled automatically by `hg_auth.cpp`. Your provider only decides success/failure and the rate/timeout parameters.

---

## Coding Conventions

| Element | Style | Example |
|---|---|---|
| functions / variables | `snake_case` | `load_config()`, `iface_name` |
| class / struct / enum types | `PascalCase` | `HgConfig`, `HttpRequest` |
| constants / enum values | `UPPER_CASE` | `AUTH_OK`, `HG_CT_TIMEOUT_NS` |
| filenames | `hg_` prefix | `hg_server.cpp` |

**Logger — always use the project logger, never `printf` or `cout`:**
```cpp
log_info("server started");
log_error("failed to bind socket");
log_debug("route: GET /portal from 192.168.99.82");
log_warning("conntrack delete missed — expected");
```

**No temporary `.c_str()` calls:**
```cpp
// WRONG — temporary destroyed at end of expression
const char *p = (std::to_string(port)).c_str();

// CORRECT — named variable keeps the string alive
std::string port_str = std::to_string(port);
const char *p = port_str.c_str();
```

**No blocking calls in the epoll loop.** Everything in `handle_readable` and `handle_writable` must be non-blocking. File reads (`read_html_file`) are the one accepted exception — portal pages are small and read once per request.

**RAII over manual cleanup.** Use `std::unique_ptr`, `std::string`, and RAII wrappers. No manually-managed `new`/`delete`.

**Zero warnings with `-Wall -Wextra`.** Every PR must compile clean.

---

## Build System

```bash
./configure.sh        # probe toolchain, generate Makefiles
make                  # build kernel + hawkgated
make kernel           # kernel only (hgctl + BPF object)
make hawkgated        # daemon only
make rebuild          # clean + full rebuild
sudo make install     # install to system
```

The configure script generates three Makefiles — `kernel/Makefile`, `hawkgated/Makefile`, and the root `Makefile`. Never edit generated Makefiles directly — re-run `./configure.sh` instead.

**Debug kernel BPF logs** (disabled by default — `bpf_printk` has measurable overhead):
```bash
EXTRA_CFLAGS="-DHG_DEBUG=1" make kernel
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

---

## Commit Conventions

```
<type>(<scope>): <summary ≤50 chars>

<body — the why, ~72 col, only when non-obvious>
```

Types: `feat`, `fix`, `refactor`, `chore`, `docs`, `test`, `perf`

Scopes: `kernel`, `hawkgated`, `hgctl`, `portal`, `config`, `build`, `docs`

One commit = one logical change. If the summary needs "and" it is two commits. Present tense. No back-story.

---

## Key Design Decisions

**Why BPF over iptables?**
iptables rule evaluation is O(n) per packet where n is the number of rules. At 10K clients that means 10K rules — microseconds of evaluation per packet. BPF hash map lookup is O(1) regardless of client count. At 1K+ clients, HawkGate is measurably faster. At 10K clients it is not close.

**Why MAC as the auth key?**
IP addresses change — DHCP leases expire, clients reconnect on new IPs. A MAC-keyed session survives IP changes. The self-maintaining `hg_mac_ip` / `hg_ip_mac` binding maps update from live traffic on every packet — no DHCP snooping or external dependency needed.

**Why shell out to hgctl for map writes?**
Single writer. One process owns all map mutations. hawkgated never calls `bpf_map_update_elem` directly — it uses `posix_spawn` to call `hgctl`. This keeps the privilege boundary clean and makes the write path auditable from a single binary.

**Why 307 and not 302 for portal redirect?**
From pcap analysis of real captive portal implementations (OpenNDS) and real device traffic (Android 16, iOS 18, Windows 11 Firefox): all modern OS captive portal detection requires `307 Temporary Redirect` with an HTML body fallback. `302` is ignored or treated differently by Android 16. The HTML body is required as a fallback for devices where the WebView doesn't follow the redirect automatically.

**Why EDT over token bucket / HTB?**
EDT produces smoother traffic and lower latency than token bucket approaches. It eliminates artificial burstiness and integrates naturally with TCP's congestion control — the FQ qdisc and TCP CC cooperate on pacing rather than fighting each other.
