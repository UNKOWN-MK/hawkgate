#ifndef HG_TC_BPF_H
#define HG_TC_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "hg_common.h"

/* ─── TC return codes ──────────────────────────────────────────────────────── */
#define TC_ACT_OK    0
#define TC_ACT_SHOT  2

/* ─── EtherType constants ──────────────────────────────────────────────────── */
#define ETH_P_IP     0x0800
#define ETH_P_ARP    0x0806

/* ─── Packet classification result ────────────────────────────────────────── */
enum proto_result {
    PROTO_L2_ONLY,   /* non-IP EtherType — check hg_l2_allow only            */
    PROTO_L3_ONLY,   /* IP but key ptr was NULL — L3 proto extracted          */
    PROTO_L3_OK,     /* IP + L4 ports extracted into allow_key                */
    PROTO_INVALID,   /* malformed / truncated packet                          */
};

/* forward declarations */
static __always_inline bool proto_allowed(struct hg_allow_key *k);
static __always_inline int redirect_to_portal(struct __sk_buff *skb, struct hg_portal_cfg *cfg);
static __always_inline int snat_from_conntrack(struct __sk_buff *skb);

/* ─── parse_udp_tcp ────────────────────────────────────────────────────────── *
 * Extracts source and destination ports from a UDP or TCP header into key.    *
 * Returns 0 on success, -1 if the header is truncated.                        *
 * ---------------------------------------------------------------------------- */
static __always_inline int parse_udp_tcp(struct iphdr *iph, void *data_end,
                                          struct hg_allow_key *proto_key)
{
    if (iph->protocol == IPPROTO_UDP)
    {
        struct udphdr *udph = (void *)iph + (iph->ihl * 4);
        if ((void *)(udph + 1) > data_end)
            return -1;

        proto_key->s_port = bpf_ntohs(udph->source);
        proto_key->d_port = bpf_ntohs(udph->dest);
        return 0;
    }

    if (iph->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
        if ((void *)(tcph + 1) > data_end)
            return -1;

        proto_key->s_port = bpf_ntohs(tcph->source);
        proto_key->d_port = bpf_ntohs(tcph->dest);
        return 0;
    }

    return 0;
}

/* ─── filter_proto ─────────────────────────────────────────────────────────── *
 * Parses Ethernet + IP headers and fills *key with the L3/L4 allow_key.       *
 * Returns one of enum proto_result.                                            *
 * ---------------------------------------------------------------------------- */
static __always_inline int filter_proto(void *data, void *data_end,
                                         struct iphdr **iph,
                                         struct hg_allow_key *key,
                                         __u16 *eth_proto)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return PROTO_INVALID;

    *eth_proto = bpf_ntohs(eth->h_proto);

    if (*eth_proto != ETH_P_IP)
        return PROTO_L2_ONLY;

    *iph = (void *)(eth + 1);
    if ((void *)(*iph + 1) > data_end)
        return PROTO_INVALID;

    if (!key)
        return PROTO_L3_ONLY;

    key->proto = (*iph)->protocol;

    if (parse_udp_tcp(*iph, data_end, key) < 0)
        return PROTO_INVALID;

    return PROTO_L3_OK;
}

#endif /* HG_TC_BPF_H */
