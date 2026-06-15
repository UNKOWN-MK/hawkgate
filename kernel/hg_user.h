#ifndef HG_USER_H
#define HG_USER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <time.h>
#include <inttypes.h>
#include <stdbool.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "hg_common.h"

/* ─── Return codes ─────────────────────────────────────────────────────────── */
#define SUCCESS 0
#define FAILED  1

/* ─── Misc ─────────────────────────────────────────────────────────────────── */
#define IS_EMPTY(str)       ((str) == NULL || *(str) == '\0')
#define RATE_ID_NO_LIMIT    0

/* ─── CLI action opcodes ───────────────────────────────────────────────────── */
typedef enum {
    BAD_OP   = 0,
    START    = 1,
    STOP     = 2,
    ADD      = 3,
    DEL      = 4,
    SHOW     = 5,
    DETAILS  = 6,
    PROTOCOL = 7
} action_opcode;

/* ─── Pre-auth protocol rule (userspace only) ──────────────────────────────── */
enum proto_level {
    PROTO_L2 = 1,
    PROTO_L3 = 2,
    PROTO_L4 = 3
};

struct proto_rule {
    __u8  level;
    __u16 proto;
    __u16 sport;
    __u16 dport;
};

/* ─── Action opcode parser ─────────────────────────────────────────────────── */
action_opcode hg_parse_opcode(const char *cmd);

/* ─── CLI parse functions (hg_cli.c) ──────────────────────────────────────── */
int parse_start(int argc, char **argv, const char *prog);
int parse_stop(int argc, char **argv, const char *prog);
int parse_add(int argc, char **argv, const char *prog);
int parse_del(int argc, char **argv, const char *prog);
int parse_proto(int argc, char **argv, const char *prog);
int parse_show(int argc, char **argv, const char *prog);
int parse_details(int argc, char **argv, const char *prog);

/* ─── Help print functions (hg_cli.c) ─────────────────────────────────────── */
void print_help(const char *prog);
void print_start_help(const char *prog);
void print_stop_help(const char *prog);
void print_add_help(const char *prog);
void print_del_help(const char *prog);
void print_show_help(const char *prog);
void print_details_help(const char *prog);
void print_proto_help(const char *prog);

/* ─── Action functions (hg_control.c) ─────────────────────────────────────── */
int  start_action(const char *iface);
int  stop_action(const char *iface);
int  add_action(const char *iface, const char *ip,
                time_t expire, time_t idle,
                __u64 d_limit, __u64 u_limit, __u32 rate_id);
int  del_action(const char *iface, const char *ip);
int  show_action(const char *iface);
int  details_action(const char *iface);
int  protocol_allow_add_action(struct proto_rule *rule);
int  protocol_allow_del_action(struct proto_rule *rule);
bool hg_get_rate_cfg(__u32 rate_id, struct hg_rate_cfg *out);
void show_protocols(void);

#endif /* HG_USER_H */
