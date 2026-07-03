#include "hg_tc.bpf.h"
#include "hg_common.h"

char LICENSE[] SEC("license") = "GPL";

/* ─── BPF map definitions ──────────────────────────────────────────────────── *
 * All maps use the macro names from hg_common.h so a rename there propagates  *
 * here automatically. Maps are pinned under /sys/fs/bpf/hg/ via               *
 * ---------------------------------------------------------------------------- */

/* Rate profiles: rate_id → hg_rate_cfg */
struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 256);
  __type(key, __u32);
  __type(value, struct hg_rate_cfg);
} HG_RATE_MAP SEC(".maps");

/* L2 EtherType allow-list: ethertype → __u8 (1 = allow) */
struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 16);
  __type(key, __u16);
  __type(value, __u8);
} HG_L2_ALLOW_MAP SEC(".maps");

/* L3/L4 protocol allow-list: hg_allow_key → __u8 (1 = allow) */
struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 64);
  __type(key, struct hg_allow_key);
  __type(value, __u8);
} HG_PROTO_MAP SEC(".maps");

/* Per-client auth + EDT state: mac → hg_client
 * Must be BPF_MAP_TYPE_HASH (not LRU) — only HASH supports bpf_spin_lock. */
struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, struct hg_mac_key);
  __type(value, struct hg_client);
} HG_CLIENT_MAP SEC(".maps");

/* MAC → current IP binding — written conditionally (only on IP change) */
struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, struct hg_mac_key);
  __type(value, __u32);
} HG_MAC_IP_MAP SEC(".maps");

/* IP → MAC reverse lookup — used by egress and hgctl add -c <ip> */
struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, __u32);
  __type(value, struct hg_mac_key);
} HG_IP_MAC_MAP SEC(".maps");

/* Static IP bypass — traffic from/to these IPs passes regardless of auth */
struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 256);
  __type(key, __u32);
  __type(value, __u8);
} HG_BYPASS_MAP SEC(".maps");

/* Walled garden — unauthenticated clients can reach these IPs/subnets */
struct
{
  __uint(type,        BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, 64);
  __type(key,         struct hg_wg_key);
  __type(value,       __u8);
  __uint(map_flags,   BPF_F_NO_PREALLOC);   /* required for LPM_TRIE */
} HG_WALLED_GARDEN_MAP SEC(".maps");

/* Per-CPU byte/packet counters: src_ip → hg_counter (per CPU) */
struct
{
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(max_entries, 4096);
  __type(key, __u32);
  __type(value, struct hg_counter);
} HG_COUNTER_MAP SEC(".maps");

/* IFB interface index for upload EDT shaping (0 = IFB not configured) */
struct
{
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u32);
} HG_IFB_IDX_MAP SEC(".maps");

/* Portal IP/port config — single entry, written by hawkgated at startup */
struct
{
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct hg_portal_cfg);
} HG_PORTAL_CFG_MAP SEC(".maps");

/* Conntrack map — for tracking redirected TCP flows */
struct
{
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 512);
  __type(key, struct hg_ct_key);
  __type(value, struct hg_ct_val);
} HG_CONNTRACK_MAP SEC(".maps");

/* ─── apply_edt_shaping ────────────────────────────────────────────────────── *
 * Computes the next EDT departure timestamp for this packet and stamps it into *
 * skb->tstamp. The FQ qdisc holds the packet until that time arrives.         *
 *                                                                              *
 * Upload (is_upload=true):  explicit drop when burst depth > horizon_ns       *
 *   — LAN client has no backpressure from IFB; TCP CC needs the drop signal.  *
 * Download (is_upload=false): no drop — FQ backpressures the sender socket.   *
 * ---------------------------------------------------------------------------- */
static __always_inline int apply_edt_shaping(struct __sk_buff *skb,
                                             struct hg_client *cs,
                                             bool is_upload)
{
  __u32 r_id = cs->rate_limit_id;

  struct hg_rate_cfg *cfg = bpf_map_lookup_elem(&HG_RATE_MAP, &r_id);
  if (!cfg)
    return TC_ACT_OK;

  __u64 rate = is_upload ? cfg->rate_Bps_u : cfg->rate_Bps_d;
  if (rate == 0)
    return TC_ACT_OK;

  __u64 now = bpf_ktime_get_ns();
  __u64 delay = ((__u64)skb->len * NSEC_PER_SEC) / rate;

  bpf_spin_lock(&cs->lock);

  __u64 last_ts = is_upload ? cs->last_u_tstamp : cs->last_d_tstamp;
  __u64 next_tstamp = (now > last_ts) ? now + delay : last_ts + delay;

  if (is_upload && (next_tstamp - now) > cfg->horizon_ns)
  {
    bpf_spin_unlock(&cs->lock);
    return TC_ACT_SHOT;
  }

  if (is_upload)
    cs->last_u_tstamp = next_tstamp;
  else
    cs->last_d_tstamp = next_tstamp;

  bpf_spin_unlock(&cs->lock);

  bpf_skb_set_tstamp(skb, next_tstamp, BPF_SKB_TSTAMP_DELIVERY_MONO);
  return TC_ACT_OK;
}

/* ─── hg_tc_ingress ────────────────────────────────────────────────────────── *
 * TC INGRESS hook — upload path.                                                *
 *                                                                              *
 * Policy order:                                                                *
 *  1. L2 EtherType check    → HG_L2_ALLOW_MAP  (always enforced)             *
 *  2. Static bypass check   → HG_BYPASS_MAP    (trusted IPs pass always)     *
 *  3. Conditional MAC↔IP binding update                                       *
 *  4. Bypass portal-bound traffic               (skip auth + shaping)         *
 *  5. Auth lookup           → HG_CLIENT_MAP     (keyed by MAC)                *
 *       expired?            → delete + TC_ACT_SHOT                            *
 *       authenticated?      → EDT shaping + accounting + redirect to IFB      *
 *  6. Pre-auth protocol?    → HG_PROTO_MAP      (DNS, DHCP, ARP, etc.)       *
 *  6a. Walled garden?        → HG_WALLED_GARDEN_MAP (allowed dst IP/subnet) *
 *  7. Everything else       → redirect_to_portal() (in-kernel DNAT)          *
 * ---------------------------------------------------------------------------- */
SEC("tc")
int hg_tc_ingress(struct __sk_buff *skb)
{
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  struct iphdr *iph;
  struct hg_client *auth = NULL;
  struct hg_allow_key p_allow = {0};
  __u16 eth_proto;

  int res_filter_p = filter_proto(data, data_end, &iph, &p_allow, &eth_proto);

  /* 1 — L2 allow check */
  if (res_filter_p == PROTO_L2_ONLY)
  {
    __u8 *l2_ok = bpf_map_lookup_elem(&HG_L2_ALLOW_MAP, &eth_proto);
    if (!l2_ok)
    {
      bpf_printk("hg ingress: l2 drop ethertype=0x%04X\n", eth_proto);
      return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
  }
  if (res_filter_p == PROTO_INVALID)
  {
    bpf_printk("hg ingress: drop malformed packet\n");
    return TC_ACT_SHOT;
  }

  /* past L2/INVALID early returns — eth and iph both valid */
  __u32 src_ip = iph->saddr;

  /* 2 — static bypass: trusted IPs pass unconditionally */
  if (bpf_map_lookup_elem(&HG_BYPASS_MAP, &src_ip))
    return TC_ACT_OK;

  /* 3 — conditional MAC↔IP binding update
   * eth header already validated by filter_proto — safe to re-cast data.
   * Only write when IP changes — reduces map writes ~90% in steady state. */
  struct ethhdr *eth = data;
  struct hg_mac_key mac_key = {0};
  __builtin_memcpy(mac_key.mac, eth->h_source, 6);

  __u32 *existing_ip = bpf_map_lookup_elem(&HG_MAC_IP_MAP, &mac_key);
  if (!existing_ip || *existing_ip != src_ip)
  {
    bpf_map_update_elem(&HG_MAC_IP_MAP, &mac_key, &src_ip, BPF_ANY);
    bpf_map_update_elem(&HG_IP_MAC_MAP, &src_ip, &mac_key, BPF_ANY);
  }

  /* 4 — bypass traffic already addressed to the portal */
  __u32 cfg_key = 0;
  struct hg_portal_cfg *cfg = bpf_map_lookup_elem(&HG_PORTAL_CFG_MAP, &cfg_key);
  if (cfg)
  {
    if (iph->daddr == cfg->portal_ip)
    {
      if (iph->protocol == IPPROTO_TCP)
      {
        struct tcphdr *tcph = (void *)(iph + 1);
        if ((void *)(tcph + 1) <= data_end && tcph->dest == cfg->portal_port)
          return TC_ACT_OK;
      }
      bpf_printk("hg ingress: drop portal ip but not portal port\n");
      return TC_ACT_SHOT;
    }
  }

  /* 5 — authenticated client path (keyed by MAC) */
  auth = bpf_map_lookup_elem(&HG_CLIENT_MAP, &mac_key);
  if (auth)
  {
    __u64 now_ns = bpf_ktime_get_ns();

    /* session expiry check */
    if (auth->expiry_ns && now_ns > auth->expiry_ns)
    {
      bpf_map_delete_elem(&HG_CLIENT_MAP, &mac_key);
      struct hg_counter *cnt = bpf_map_lookup_elem(&HG_COUNTER_MAP, &src_ip);
      if (cnt)
        cnt->state = EXPIRE;
      bpf_printk("hg ingress: session expired src=0x%X\n", src_ip);
      return TC_ACT_SHOT;
    }

    /* EDT rate shaping */
    if (apply_edt_shaping(skb, auth, true) == TC_ACT_SHOT)
      return TC_ACT_SHOT;

    /* accounting */
    struct hg_counter *cnt = bpf_map_lookup_elem(&HG_COUNTER_MAP, &src_ip);
    if (!cnt)
    {
      bpf_printk("hg ingress: counter missing src=0x%X\n", src_ip);
      return TC_ACT_SHOT;
    }
    cnt->U_packets++;
    cnt->U_bytes += skb->len;
    cnt->last_seen = now_ns;

    /* redirect to IFB so FQ can honour skb->tstamp on the upload path.
     * IFB re-injects with tc_skip_classify=1 — no infinite loop.
     * Falls through to TC_ACT_OK if IFB is not configured.             */
    __u32 ifb_key = 0;
    __u32 *ifb_idx = bpf_map_lookup_elem(&HG_IFB_IDX_MAP, &ifb_key);
    if (ifb_idx && *ifb_idx)
      return bpf_redirect(*ifb_idx, 0);

    return TC_ACT_OK;
  }

  /* 6 — pre-auth protocol allow-list */
  if (proto_allowed(&p_allow))
    return TC_ACT_OK;

  /* 6a — walled garden: allow unauthenticated access to specific IPs/subnets */
  struct hg_wg_key wg_key = {
      .prefixlen = 32,
      .ip        = iph->daddr,
  };
  if (bpf_map_lookup_elem(&HG_WALLED_GARDEN_MAP, &wg_key))
    return TC_ACT_OK;

  if (p_allow.proto != IPPROTO_TCP || p_allow.d_port != 80)
  {
    bpf_printk("hg ingress: drop not http pkts\n");
    return TC_ACT_SHOT;
  }

  /* 7 — redirect everything else to captive portal */
  if (!cfg)
    return TC_ACT_OK;

  bpf_printk("hg ingress: redirecting to portal\n");
  return redirect_to_portal(skb, cfg);
}

/* ─── hg_tc_egress ─────────────────────────────────────────────────────────── *
 * TC EGRESS hook — download path.                                              *
 *                                                                              *
 * Policy order:                                                                *
 *  1. L2 EtherType check    → HG_L2_ALLOW_MAP  (always enforced)             *
 *  2. Bypass portal response traffic            (src == PORTAL_IP)            *
 *  3. Static bypass check   → HG_BYPASS_MAP    (trusted IPs pass always)     *
 *  4. Auth lookup           → HG_IP_MAC_MAP → HG_CLIENT_MAP (keyed by MAC)   *
 *       authenticated?      → EDT shaping + accounting                        *
 *  5. Pre-auth protocol?    → HG_PROTO_MAP                                    *
 *  6. Everything else       → TC_ACT_SHOT (drop)                              *
 * ---------------------------------------------------------------------------- */
SEC("tc")
int hg_tc_egress(struct __sk_buff *skb)
{
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  struct iphdr *iph;
  struct hg_client *auth = NULL;
  struct hg_allow_key p_allow = {0};
  __u16 eth_proto;

  int res_filter_p = filter_proto(data, data_end, &iph, &p_allow, &eth_proto);

  /* 1 — L2 allow check */
  if (res_filter_p == PROTO_L2_ONLY)
  {
    __u8 *l2_ok = bpf_map_lookup_elem(&HG_L2_ALLOW_MAP, &eth_proto);
    if (!l2_ok)
    {
      bpf_printk("hg egress: l2 drop\n");
      return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
  }
  if (res_filter_p == PROTO_INVALID)
  {
    bpf_printk("hg egress: drop malformed packet\n");
    return TC_ACT_SHOT;
  }

  /* 2 — pass portal response traffic unconditionally */
  __u32 cfg_key = 0;
  struct hg_portal_cfg *cfg = bpf_map_lookup_elem(&HG_PORTAL_CFG_MAP, &cfg_key);
  if (cfg)
  {
    if (iph->saddr == cfg->portal_ip)
      return snat_from_conntrack(skb);
  }

  /* 3 — static bypass: traffic destined to trusted IPs passes unconditionally */
  __u32 dst_ip = iph->daddr;
  if (bpf_map_lookup_elem(&HG_BYPASS_MAP, &dst_ip))
    return TC_ACT_OK;

  /* 4 — authenticated client path (MAC-based lookup via reverse binding) */
  struct hg_mac_key *dst_mac = bpf_map_lookup_elem(&HG_IP_MAC_MAP, &dst_ip);
  if (!dst_mac)
    goto check_preauth;

  auth = bpf_map_lookup_elem(&HG_CLIENT_MAP, dst_mac);
  if (auth)
  {
    /* EDT rate shaping */
    if (apply_edt_shaping(skb, auth, false) == TC_ACT_SHOT)
      return TC_ACT_SHOT;

    /* accounting */
    struct hg_counter *cnt = bpf_map_lookup_elem(&HG_COUNTER_MAP, &dst_ip);
    if (!cnt)
    {
      bpf_printk("hg egress: counter missing dst=0x%X\n", dst_ip);
      return TC_ACT_SHOT;
    }
    cnt->D_packets++;
    cnt->D_bytes += skb->len;
    return TC_ACT_OK;
  }

check_preauth:
  /* 5 — pre-auth protocol allow-list */
  if (proto_allowed(&p_allow))
    return TC_ACT_OK;

  /* 5a — walled garden: allow return traffic from whitelisted IPs/subnets
   * so unauthenticated clients get replies (e.g. TCP SYN-ACK) back.       */
  struct hg_wg_key wg_key = {
      .prefixlen = 32,
      .ip        = iph->saddr,
  };
  if (bpf_map_lookup_elem(&HG_WALLED_GARDEN_MAP, &wg_key))
    return TC_ACT_OK;

  /* 6 — drop everything else */
  bpf_printk("hg egress: drop unauthenticated dst=0x%X\n", dst_ip);
  return TC_ACT_SHOT;
}

/* ─── proto_allowed ────────────────────────────────────────────────────────── *
 * Checks HG_PROTO_MAP with five progressively wider wildcard lookups:         *
 *  1. exact match  (proto + sport + dport)                                    *
 *  2. wildcard proto                                                           *
 *  3. wildcard sport                                                           *
 *  4. wildcard dport                                                           *
 *  5. wildcard sport + dport                                                   *
 * ---------------------------------------------------------------------------- */
static __always_inline bool proto_allowed(struct hg_allow_key *k)
{
  struct hg_allow_key tmp = *k;

  /* level 1 — exact */
  if (bpf_map_lookup_elem(&HG_PROTO_MAP, &tmp))
    return true;

  /* level 2 — wildcard proto */
  tmp.proto = 0;
  if (bpf_map_lookup_elem(&HG_PROTO_MAP, &tmp))
    return true;

  /* level 3 — wildcard sport */
  tmp = *k;
  tmp.s_port = 0;
  if (bpf_map_lookup_elem(&HG_PROTO_MAP, &tmp))
    return true;

  /* level 4 — wildcard dport */
  tmp = *k;
  tmp.d_port = 0;
  if (bpf_map_lookup_elem(&HG_PROTO_MAP, &tmp))
    return true;

  /* level 5 — wildcard sport + dport */
  tmp.s_port = 0;
  tmp.d_port = 0;
  if (bpf_map_lookup_elem(&HG_PROTO_MAP, &tmp))
    return true;

  return false;
}

/* ─── redirect_to_portal ───────────────────────────────────────────────────── *
 * In-kernel DNAT: reads portal IP/port from hg_portal_cfg_map at runtime,   *
 * rewrites IP dst + TCP/UDP dst port, fixes checksums with BPF helpers.      *
 * After bpf_skb_store_bytes() the data/data_end pointers are invalidated;     *
 * the helper re-fetches them from skb before each L4 access.                *
 * ---------------------------------------------------------------------------- */
static __always_inline int redirect_to_portal(struct __sk_buff *skb, struct hg_portal_cfg *cfg)
{
  if (bpf_skb_pull_data(skb, 0) < 0)
    return TC_ACT_OK;

  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_SHOT;

  if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
    return TC_ACT_OK;

  /* ── IPv4 ── */
  int ip_off = sizeof(struct ethhdr);
  struct iphdr *iph = data + ip_off;
  if ((void *)(iph + 1) > data_end)
    return TC_ACT_SHOT;
  if (iph->ihl < 5)
    return TC_ACT_SHOT;

  int ip_hdr_len = iph->ihl * 4;
  if (data + ip_off + ip_hdr_len > data_end)
    return TC_ACT_SHOT;

  struct hg_ct_key ct_key = {0};
  struct hg_ct_val ct_val = {0};

  __be32 new_daddr = cfg->portal_ip;
  __be16 new_dport = cfg->portal_port;

  // read the original header details before we overwrite them
  // And store them in the conntrack map for later use
  ct_val.orig_dst_ip = iph->daddr;
  ct_key.client_ip = iph->saddr;
  ct_val.created_ns = bpf_ktime_get_boot_ns();

  __u8 iph_protocol = iph->protocol;

  /* fix IP checksum, then write new dst IP */
  bpf_l3_csum_replace(skb, ip_off + offsetof(struct iphdr, check),
                      ct_val.orig_dst_ip, new_daddr, sizeof(new_daddr));
  bpf_skb_store_bytes(skb, ip_off + offsetof(struct iphdr, daddr),
                      &new_daddr, sizeof(new_daddr), 0);

  /* ── L4 ── */
  int l4_off = ip_off + ip_hdr_len;

  if (iph_protocol == IPPROTO_TCP)
  {
    /* re-fetch after store_bytes invalidated pointers */
    void *data1 = (void *)(long)skb->data;
    void *data_end1 = (void *)(long)skb->data_end;

    struct tcphdr *tcph = data1 + l4_off;
    if ((void *)(tcph + 1) > data_end1)
      return TC_ACT_SHOT;

    // read the original header tcp ports before we overwrite them
    ct_val.orig_dst_port = tcph->dest;
    ct_key.client_port = tcph->source;

    // Let's track the connection ,update to the conntrack map
    bpf_map_update_elem(&HG_CONNTRACK_MAP, &ct_key, &ct_val, BPF_ANY);

    // DNAT the packet to the portal IP and port
    bpf_l4_csum_replace(skb, l4_off + offsetof(struct tcphdr, check),
                        ct_val.orig_dst_ip, new_daddr, sizeof(new_daddr));
    bpf_l4_csum_replace(skb, l4_off + offsetof(struct tcphdr, check),
                        ct_val.orig_dst_port, new_dport, sizeof(new_dport));
    bpf_skb_store_bytes(skb, l4_off + offsetof(struct tcphdr, dest),
                        &new_dport, sizeof(new_dport), 0);
  }

  bpf_printk("hg ingress: portal redirect done\n");
  return TC_ACT_OK;
}

static __always_inline int snat_from_conntrack(struct __sk_buff *skb)
{
  if (bpf_skb_pull_data(skb, 0) < 0)
    return TC_ACT_OK;

  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_SHOT;

  if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
    return TC_ACT_OK;

  /* ── IPv4 ── */
  int ip_off = sizeof(struct ethhdr);
  struct iphdr *iph = data + ip_off;
  if ((void *)(iph + 1) > data_end)
    return TC_ACT_SHOT;
  if (iph->ihl < 5)
    return TC_ACT_SHOT;

  int ip_hdr_len = iph->ihl * 4;
  if (data + ip_off + ip_hdr_len > data_end)
    return TC_ACT_SHOT;

  __u8 iph_protocol = iph->protocol;

  struct hg_ct_key ct_key = {0};
  struct hg_ct_val *ct_val;

  ct_key.client_ip = iph->daddr;
  if (iph_protocol == IPPROTO_TCP)
  {
    struct tcphdr *tcph = data + ip_off + ip_hdr_len;
    if ((void *)(tcph + 1) > data_end)
      return TC_ACT_SHOT;

    ct_key.client_port = tcph->dest;
    ct_val = bpf_map_lookup_elem(&HG_CONNTRACK_MAP, &ct_key);
    if (!ct_val)
    {
      bpf_printk("hg egress: no conntrack entry\n");
      return TC_ACT_OK;
    }
    // SNAT the packet back to the original destination IP and port
    __u64 now = bpf_ktime_get_boot_ns();
    if (now - ct_val->created_ns > HG_CT_TIMEOUT_NS)
    {
      bpf_printk("hg egress: conntrack entry expired\n");
      return TC_ACT_OK;
    }
    __be32 new_saddr = ct_val->orig_dst_ip;
    __be16 new_sport = ct_val->orig_dst_port;
    __be32 old_saddr = iph->saddr;
    __be16 old_sport = tcph->source;
    bpf_l3_csum_replace(skb, ip_off + offsetof(struct iphdr, check),
                        old_saddr, new_saddr, sizeof(new_saddr));
    bpf_skb_store_bytes(skb, ip_off + offsetof(struct iphdr, saddr),
                        &new_saddr, sizeof(new_saddr), 0);
    // port

    bpf_l4_csum_replace(skb, ip_off + ip_hdr_len + offsetof(struct tcphdr, check),
                        old_saddr, new_saddr, sizeof(new_saddr));
    bpf_l4_csum_replace(skb, ip_off + ip_hdr_len + offsetof(struct tcphdr, check),
                        old_sport, new_sport, sizeof(new_sport));
    bpf_skb_store_bytes(skb, ip_off + ip_hdr_len + offsetof(struct tcphdr, source),
                        &new_sport, sizeof(new_sport), 0);
    return TC_ACT_OK;
  }
  else
  {
    return TC_ACT_OK;
  }
}