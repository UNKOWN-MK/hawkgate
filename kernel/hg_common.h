#ifndef HG_COMMON_H
#define HG_COMMON_H

#ifdef __bpf__
/* BPF side: vmlinux.h (included by hg_tc.bpf.h before this file) already
 * provides all kernel types. We only need the BPF helper macros.           */
#include <bpf/bpf_helpers.h>
#else
/* Userspace side: pull in just the types we need. linux/types.h gives us
 * __u8/__u16/__u32/__u64. linux/bpf.h gives us struct bpf_spin_lock.
 * Never include linux/bpf.h on the BPF side — vmlinux.h already has it
 * and the double inclusion produces hundreds of redefinition errors.
 *
 * Guard: if vmlinux.h was already included (e.g. via hg_tc.bpf.h leaking
 * into a userspace TU), skip linux/bpf.h entirely to avoid conflicts.     */
#ifndef __VMLINUX_H__ /* skip if vmlinux.h already pulled in  */
#include <linux/types.h>
#include <linux/bpf.h>
#endif
#endif

/* ─── BPF map names ────────────────────────────────────────────────────────────
 * Defined as bare tokens (no quotes) so MAP_PATH() can stringify them via XSTR.
 * ALL map references in kernel and userspace must use these macros — never the
 * raw name — so a rename here propagates everywhere automatically.
 * --------------------------------------------------------------------------- */
#define HG_CLIENT_MAP hg_clients
#define HG_RATE_MAP hg_rates
#define HG_PROTO_MAP hg_proto
#define HG_L2_ALLOW_MAP hg_l2_allow
#define HG_COUNTER_MAP hg_counters
#define HG_IFB_IDX_MAP hg_ifb_idx
#define HG_PORTAL_CFG_MAP hg_portal_cfg
#define HG_CONNTRACK_MAP hg_conntrack
#define HG_MAC_IP_MAP      hg_mac_ip    /* MAC → current IP binding   */
#define HG_IP_MAC_MAP      hg_ip_mac    /* IP  → MAC reverse lookup   */
#define HG_BYPASS_MAP      hg_bypass    /* static IP trust bypass      */


/* ─── BPF pin directory ────────────────────────────────────────────────────────
 * All maps live under /sys/fs/bpf/hg/ — one subdir, easy to list and wipe.
 * --------------------------------------------------------------------------- */
#define HG_PIN_DIR "/sys/fs/bpf/hg"

#define STR(x) #x
#define XSTR(x) STR(x)
#define MAP_PATH(m) HG_PIN_DIR "/" XSTR(m)

/* ─── EDT shaping constants ────────────────────────────────────────────────── */
#define NSEC_PER_SEC 1000000000ULL
#define HG_HORIZON_NS 100000000ULL /* 100 ms default burst depth      */

/* ─── Unit conversion macros ───────────────────────────────────────────────── */
#define KB_TO_BYTE(kb) ((kb) * 1024ULL)
#define BYTE_TO_KB(b) ((b) / 1024ULL)
#define KBIT_TO_BPS(kb) ((kb) * 1000ULL / 8ULL) /* kbit/s → bytes/s   */
#define BPS_TO_KBIT(b) ((b) * 8ULL / 1000ULL)   /* bytes/s → kbit/s   */

/* ─── Conntrack session timeout ────────────────────────────────────────────────── */
#define HG_CT_TIMEOUT_NS  (120ULL * 1000000000ULL)   /* 120 seconds */

/* ─── Client session status ────────────────────────────────────────────────── */
#ifndef HG_CLIENT_STATUS_DEFINED
#define HG_CLIENT_STATUS_DEFINED
enum client_status
{
  AUTH_OK = 0, /* session active                  */
  EXPIRE = 1,  /* session timer reached zero      */
  BLOCK = 2,   /* client explicitly blocked       */
  IDLE = 3,    /* idle timeout reached (future)   */
};
#endif

/* ─── Per-CPU accounting counters (hg_counters map) ───────────────────────── */
struct hg_counter
{
  __u64 U_packets; /* upload packet count  (this CPU) */
  __u64 U_bytes;   /* upload byte count    (this CPU) */
  __u64 D_packets; /* download packet count           */
  __u64 D_bytes;   /* download byte count             */
  __u64 last_seen; /* last packet timestamp (CLOCK_MONOTONIC ns) */
  __u32 state;     /* enum client_status              */
};

/* ─── Rate profile (hg_rates map) ─────────────────────────────────────────── */
struct hg_rate_cfg
{
  __u64 rate_Bps_d;   /* allowed rate in bytes/second download    */
  __u64 rate_Bps_u;   /* allowed rate in bytes/second upload      */
  __u64 horizon_ns; /* max burst depth in nanoseconds  */
};

/* ─── MAC address key (hg_clients map, hg_mac_ip map) ─────────────────────── */
struct hg_mac_key
{
  __u8  mac[6];
  __u16 pad;   /* MUST be zero — BPF map key comparison is byte-exact */
};


/* ─── Per-client auth + EDT state (hg_clients map) ────────────────────────── *
 * Key: struct hg_mac_key (MAC address). Changed from __u32 (IPv4).            */
struct hg_client
{
  struct bpf_spin_lock lock; /* MUST be first — BPF verifier requirement  */

  /* session metadata */
  __u64 expiry_ns; /* absolute expiry (CLOCK_MONOTONIC ns); 0 = never  */
  __u64 idle_ns;   /* idle timeout tracking (not yet enforced in BPF)  */
  __u64 auth_ns;   /* time of authentication                            */

  /* bandwidth management */
  __u32 rate_limit_id; /* key into hg_rates map                             */
  __u32 pad;           /* explicit 64-bit alignment padding                 */

  /* EDT departure timestamps — initialised to now_ns at add time */
  __u64 last_u_tstamp; /* next allowed upload   departure (ns)              */
  __u64 last_d_tstamp; /* next allowed download departure (ns)              */

  /* legacy phase-1 accounting (superseded by hg_counters PERCPU_HASH) */
  __u64 tx_bytes;
  __u64 tx_packets;
  __u64 rx_bytes;
  __u64 rx_packets;
};

/* ─── Pre-auth protocol allow-list key (hg_proto map) ─────────────────────── */
struct hg_allow_key
{
  __u8 proto;   /* IP protocol number (IPPROTO_UDP=17, TCP=6); 0=wildcard */
  __u16 s_port; /* source port; 0 = wildcard                              */
  __u16 d_port; /* destination port; 0 = wildcard                         */
  __u32 pad;    /* MUST be zeroed — BPF map key includes padding bytes     */
};

/* ─── Portal redirect config (hg_portal_cfg_map) ──────────────────────────── */
struct hg_portal_cfg
{
  __u32 portal_ip;   /* network byte order — from g_config.portal_ip  */
  __u16 portal_port; /* network byte order — from g_config.http_port  */
  __u16 pad;         /* explicit alignment padding — must be zero      */
};

/* Conntrack map key.
 * Identifies a redirected TCP flow by the client's source address.
 * pad MUST be zeroed — BPF map key comparison is byte-exact.
 * Unzeroed padding = lookup misses on the same logical key.          */
struct hg_ct_key
{
  __u32 client_ip;   /* client source IP   (network order)         */
  __u16 client_port; /* client source port (network order)         */
  __u16 pad;         /* MUST be zero — zero the whole struct first  */
};

/* Conntrack map value.
 * Stores original destination before DNAT + creation timestamp.      */
struct hg_ct_val
{
  __u32 orig_dst_ip;   /* original dst IP   (network order)         */
  __u16 orig_dst_port; /* original dst port (network order)         */
  __u16 pad;           /* MUST be zero — zero the whole struct first  */
  __u64 created_ns; /* bpf_ktime_get_boot_ns() at DNAT time
                     * used for stale-entry check in egress SNAT
                     * also useful for bpftool inspection         */
};
#endif /* HG_COMMON_H */
