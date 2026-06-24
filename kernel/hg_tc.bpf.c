#include "hg_tc.bpf.h"
#include "hg_common.h"

char LICENSE[] SEC("license") = "GPL";

/* ─── BPF map definitions ──────────────────────────────────────────────────── *
 * All maps use the macro names from hg_common.h so a rename there propagates  *
 * here automatically. Maps are pinned under /sys/fs/bpf/hg/ via               *
 * LIBBPF_PIN_BY_NAME, which uses the C identifier as the filename.            *
 * ---------------------------------------------------------------------------- */

/* Rate profiles: rate_id → hg_rate_cfg */
struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 256);
  __type(key, __u32);
  __type(value, struct hg_rate_cfg);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} HG_RATE_MAP SEC(".maps");

/* L2 EtherType allow-list: ethertype → __u8 (1 = allow) */
struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 16);
  __type(key, __u16);
  __type(value, __u8);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} HG_L2_ALLOW_MAP SEC(".maps");

/* L3/L4 protocol allow-list: hg_allow_key → __u8 (1 = allow) */
struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 64);
  __type(key, struct hg_allow_key);
  __type(value, __u8);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} HG_PROTO_MAP SEC(".maps");

/* Per-client auth + EDT state: src_ip → hg_client
 * Must be BPF_MAP_TYPE_HASH (not LRU) — only HASH supports bpf_spin_lock. */
struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, __u32);
  __type(value, struct hg_client);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} HG_CLIENT_MAP SEC(".maps");

/* Per-CPU byte/packet counters: src_ip → hg_counter (per CPU) */
struct
{
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(max_entries, 4096);
  __type(key, __u32);
  __type(value, struct hg_counter);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} HG_COUNTER_MAP SEC(".maps");

/* IFB interface index for upload EDT shaping (0 = IFB not configured) */
struct
{
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u32);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} HG_IFB_IDX_MAP SEC(".maps");

/* Portal IP/port config — single entry, written by hawkgated at startup */
struct
{
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct hg_portal_cfg);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} HG_PORTAL_CFG_MAP SEC(".maps");

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
  if (!cfg || cfg->rate_Bps == 0)
    return TC_ACT_OK;

  __u64 now = bpf_ktime_get_ns();
  __u64 delay = ((__u64)skb->len * NSEC_PER_SEC) / cfg->rate_Bps;
  __u64 next_tstamp;

  bpf_spin_lock(&cs->lock);

  __u64 last_ts = is_upload ? cs->last_u_tstamp : cs->last_d_tstamp;
  next_tstamp = (now > last_ts) ? now + delay : last_ts + delay;

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
 * TC INGRESS hook — upload path (replaces ndsULR nftables chain).             *
 *                                                                              *
 * Policy order:                                                                *
 *  1. L2 EtherType check  → HG_L2_ALLOW_MAP  (always enforced)               *
 *  2. Bypass portal-bound traffic             (skip auth + shaping)           *
 *  3. Auth lookup         → HG_CLIENT_MAP                                     *
 *       expired?          → delete + TC_ACT_SHOT                              *
 *       authenticated?    → EDT shaping + accounting + redirect to IFB        *
 *  4. Pre-auth protocol?  → HG_PROTO_MAP      (DNS, DHCP, ARP, etc.)         *
 *  5. Everything else     → redirect_to_portal() (in-kernel DNAT)            *
 * ---------------------------------------------------------------------------- */
SEC("tc")
int hg_tc_ingress(struct __sk_buff *skb)
{
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  struct iphdr *iph;
  struct hg_client *auth;
  struct hg_allow_key p_allow = {0};
  __u16 eth_proto;

  int res = filter_proto(data, data_end, &iph, &p_allow, &eth_proto);

  /* 1 — L2 allow check */
  if (res == PROTO_L2_ONLY)
  {
    __u8 *l2_ok = bpf_map_lookup_elem(&HG_L2_ALLOW_MAP, &eth_proto);
    if (!l2_ok)
    {
      bpf_printk("hg ingress: l2 drop ethertype=0x%04X\n", eth_proto);
      return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
  }
  if (res == PROTO_INVALID)
  {
    bpf_printk("hg ingress: drop malformed packet\n");
    return TC_ACT_SHOT;
  }

  /* 2 — bypass traffic already addressed to the portal */
  __u32 cfg_key = 0;
  struct hg_portal_cfg *cfg = bpf_map_lookup_elem(&HG_PORTAL_CFG_MAP, &cfg_key);
  if (cfg)
  {
    if (iph->daddr == cfg->portal_ip)
    {
       if (iph->protocol == IPPROTO_TCP)
      {
        struct tcphdr *tcph = (void *)(iph + 1);
        if ((void *)(tcph + 1) <= data_end &&
            tcph->dest == cfg->portal_port)
          return TC_ACT_OK;
      }
    }
   
  }

  /* 3 — authenticated client path */
  __u32 src_ip = iph->saddr;
  auth = bpf_map_lookup_elem(&HG_CLIENT_MAP, &src_ip);
  if (auth)
  {
    __u64 now_ns = bpf_ktime_get_ns();

    /* session expiry check */
    if (auth->expiry_ns && now_ns > auth->expiry_ns)
    {
      bpf_map_delete_elem(&HG_CLIENT_MAP, &src_ip);
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

  /* 4 — pre-auth protocol allow-list */
  if (proto_allowed(&p_allow))
    return TC_ACT_OK;

  /* 5 — redirect everything else to captive portal */
  if (!cfg)
    return TC_ACT_OK;
  bpf_printk("hg ingress: redirecting to portal\n");
  return redirect_to_portal(skb,cfg);
}

/* ─── hg_tc_egress ─────────────────────────────────────────────────────────── *
 * TC EGRESS hook — download path (replaces ndsDLR nftables chain).            *
 *                                                                              *
 * Policy order:                                                                *
 *  1. L2 EtherType check  → HG_L2_ALLOW_MAP  (always enforced)               *
 *  2. Bypass portal response traffic          (src == PORTAL_IP)              *
 *  3. Auth lookup         → HG_CLIENT_MAP                                     *
 *       authenticated?    → EDT shaping + accounting                          *
 *  4. Pre-auth protocol?  → HG_PROTO_MAP                                      *
 *  5. Everything else     → TC_ACT_SHOT (drop)                                *
 * ---------------------------------------------------------------------------- */
SEC("tc")
int hg_tc_egress(struct __sk_buff *skb)
{
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  struct iphdr *iph;
  struct hg_client *auth;
  struct hg_allow_key p_allow = {0};
  __u16 eth_proto;

  int res = filter_proto(data, data_end, &iph, &p_allow, &eth_proto);

  /* 1 — L2 allow check */
  if (res == PROTO_L2_ONLY)
  {
    __u8 *l2_ok = bpf_map_lookup_elem(&HG_L2_ALLOW_MAP, &eth_proto);
    if (!l2_ok)
    {
      bpf_printk("hg egress: l2 drop\n");
      return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
  }
  if (res == PROTO_INVALID)
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
      return TC_ACT_OK;
  }

  /* 3 — authenticated client path */
  __u32 dst_ip = iph->daddr;
  auth = bpf_map_lookup_elem(&HG_CLIENT_MAP, &dst_ip);
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

  /* 4 — pre-auth protocol allow-list */
  if (proto_allowed(&p_allow))
    return TC_ACT_OK;

  /* 5 — drop everything else */
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

  __be32 new_daddr = cfg->portal_ip;
  __be16 new_dport = cfg->portal_port;

  __be32 old_daddr = iph->daddr;
  __be16 iph_protocol = iph->protocol;

  /* fix IP checksum, then write new dst IP */
  bpf_l3_csum_replace(skb, ip_off + offsetof(struct iphdr, check),
                      old_daddr, new_daddr, sizeof(new_daddr));
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

    __be16 old_dport = tcph->dest;

    bpf_l4_csum_replace(skb, l4_off + offsetof(struct tcphdr, check),
                        old_daddr, new_daddr, sizeof(new_daddr));
    bpf_l4_csum_replace(skb, l4_off + offsetof(struct tcphdr, check),
                        old_dport, new_dport, sizeof(new_dport));
    bpf_skb_store_bytes(skb, l4_off + offsetof(struct tcphdr, dest),
                        &new_dport, sizeof(new_dport), 0);
  }
  else if (iph_protocol == IPPROTO_UDP)
  {
    /* re-fetch after store_bytes invalidated pointers */
    void *data1 = (void *)(long)skb->data;
    void *data_end1 = (void *)(long)skb->data_end;

    struct udphdr *udph = data1 + l4_off;
    if ((void *)(udph + 1) > data_end1)
      return TC_ACT_SHOT;

    __be16 old_dport = udph->dest;

    if (udph->check)
    {
      bpf_l4_csum_replace(skb, l4_off + offsetof(struct udphdr, check),
                          old_daddr, new_daddr, sizeof(new_daddr));
      bpf_l4_csum_replace(skb, l4_off + offsetof(struct udphdr, check),
                          old_dport, new_dport, sizeof(new_dport));
    }
    bpf_skb_store_bytes(skb, l4_off + offsetof(struct udphdr, dest),
                        &new_dport, sizeof(new_dport), 0);
  }

  bpf_printk("hg ingress: portal redirect done\n");
  return TC_ACT_OK;
}
