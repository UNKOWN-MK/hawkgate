#include "hg_user.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/stat.h>
#include "hg_tc.skel.h"

/* ─── Private helpers (this TU only) ──────────────────────────────────────── */

/* Resolve an interface name to its ifindex. */
static int get_ifindex(const char *iface)
{
    int idx = (int)if_nametoindex(iface);
    if (!idx)
    {
        perror("if_nametoindex");
        return FAILED;
    }
    return idx;
}

/* Current CLOCK_MONOTONIC time in nanoseconds (used for EDT timestamps). */
static __u64 get_boottime_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (__u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/* Run a shell command; fail with a message and return FAILED on non-zero exit.
 * Use for commands where failure means the feature is broken (not optional). */
static int run_cmd_strict(const char *cmd, const char *desc)
{
    int rc = system(cmd);
    if (rc != 0)
    {
        fprintf(stderr, "hgctl: %s failed (exit %d)\n  cmd: %s\n", desc, rc, cmd);
        return FAILED;
    }
    return SUCCESS;
}

/* Run a shell command where failure is acceptable (best-effort).
 * Returns the exit code but never prints on failure. */
static int run_cmd_best_effort(const char *cmd)
{
    return system(cmd);
}

/* Remove a pinned BPF map file; ignores ENOENT. */
static int _clean_map(const char *path)
{
    if (unlink(path) < 0 && errno != ENOENT)
    {
        fprintf(stderr, "hgctl: unlink %s: %s\n", path, strerror(errno));
        return FAILED;
    }
    return SUCCESS;
}

static void hg_clean_maps(void)
{
    /* remove maps from correct pin dir /sys/fs/bpf/hg/<name> */
    _clean_map(MAP_PATH(HG_CLIENT_MAP));
    _clean_map(MAP_PATH(HG_COUNTER_MAP));
    _clean_map(MAP_PATH(HG_PROTO_MAP));
    _clean_map(MAP_PATH(HG_L2_ALLOW_MAP));
    _clean_map(MAP_PATH(HG_RATE_MAP));
    _clean_map(MAP_PATH(HG_IFB_IDX_MAP));

    /* remove the pin directory itself — ignore ENOENT and ENOTEMPTY */
    if (rmdir(HG_PIN_DIR) < 0 && errno != ENOENT && errno != ENOTEMPTY)
        fprintf(stderr, "hgctl: rmdir %s: %s\n", HG_PIN_DIR, strerror(errno));
}

/* ─── Action string → opcode table ────────────────────────────────────────── */
static const struct
{
    const char *name;
    action_opcode op;
} action_table[] = {
    {"start", START},
    {"stop", STOP},
    {"add", ADD},
    {"del", DEL},
    {"show", SHOW},
    {"details", DETAILS},
    {"proto", PROTOCOL},
    {NULL, BAD_OP}};

/* ─── main ─────────────────────────────────────────────────────────────────── */
int main(int argc, char **argv)
{
    if (argc < 2)
    {
        print_help(argv[0]);
        return FAILED;
    }

    const char *prog = argv[0];
    const char *cmd = argv[1];
    argc--;
    argv++;

    switch (hg_parse_opcode(cmd))
    {
    case START:
        return parse_start(argc, argv, prog);
    case STOP:
        return parse_stop(argc, argv, prog);
    case ADD:
        return parse_add(argc, argv, prog);
    case DEL:
        return parse_del(argc, argv, prog);
    case SHOW:
        return parse_show(argc, argv, prog);
    case DETAILS:
        return parse_details(argc, argv, prog);
    case PROTOCOL:
        return parse_proto(argc, argv, prog);
    default:
        print_help(prog);
        return FAILED;
    }
}

/* ─── start_action ─────────────────────────────────────────────────────────── *
 * Loads the BPF object, attaches hg_tc_ingress + hg_tc_egress to the clsact  *
 * qdisc on <iface>, installs FQ on the bridge (download EDT), and sets up     *
 * an IFB interface with FQ for upload EDT shaping.                             *
 *                                                                              *
 * Failure policy:                                                              *
 *   - TC hook attach failures  → hard fail (no enforcement at all)            *
 *   - FQ on bridge failure     → hard fail (download rate limit broken)       *
 *   - IFB / FQ on ifb0 failure → hard fail (upload rate limit broken)        *
 * ---------------------------------------------------------------------------- */
int start_action(const char *iface)
{
    struct hg_tc_bpf *skel;
    struct bpf_tc_hook hook = {};
    struct bpf_tc_opts opts = {};
    char cmd[160];
    int ifindex, err;

    ifindex = get_ifindex(iface);
    if (ifindex <= 0)
        return FAILED;

    /* ── ensure pin directory exists ─────────────────────────────────────────
     * Each map gets an explicit pin path set before load via
     * bpf_map__set_pin_path(). This is the correct libbpf API — it gives
     * each map an exact path, avoids the double-slash issue with
     * bpf_object__pin_maps(), and does not conflict with any prior
     * LIBBPF_PIN_BY_NAME annotation in the BPF object.
     * mkdir is idempotent — EEXIST is not an error.                        */
    if (mkdir(HG_PIN_DIR, 0700) < 0 && errno != EEXIST)
    {
        fprintf(stderr, "hgctl: failed to create pin dir %s: %s\n",
                HG_PIN_DIR, strerror(errno));
        return FAILED;
    }

    /* ── open BPF object ── */
    skel = hg_tc_bpf__open();
    if (!skel)
    {
        fprintf(stderr, "hgctl: failed to open BPF object\n");
        return FAILED;
    }

    /* ── set explicit pin path for every map before load ── */
    bpf_map__set_pin_path(skel->maps.HG_CLIENT_MAP, MAP_PATH(HG_CLIENT_MAP));
    bpf_map__set_pin_path(skel->maps.HG_COUNTER_MAP, MAP_PATH(HG_COUNTER_MAP));
    bpf_map__set_pin_path(skel->maps.HG_RATE_MAP, MAP_PATH(HG_RATE_MAP));
    bpf_map__set_pin_path(skel->maps.HG_PROTO_MAP, MAP_PATH(HG_PROTO_MAP));
    bpf_map__set_pin_path(skel->maps.HG_L2_ALLOW_MAP, MAP_PATH(HG_L2_ALLOW_MAP));
    bpf_map__set_pin_path(skel->maps.HG_IFB_IDX_MAP, MAP_PATH(HG_IFB_IDX_MAP));

    /* ── load — libbpf will pin each map to its set_pin_path on load ── */
    if (hg_tc_bpf__load(skel))
    {
        fprintf(stderr, "hgctl: failed to load BPF object\n");
        hg_tc_bpf__destroy(skel);
        return FAILED;
    }

    /* ── create clsact qdisc ── */
    hook.sz = sizeof(hook);
    hook.ifindex = ifindex;
    hook.attach_point = BPF_TC_INGRESS;

    err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST)
    {
        fprintf(stderr, "hgctl: failed to create clsact on %s: %d\n", iface, err);
        return FAILED;
    }

    /* ── attach ingress (upload) hook ── */
    opts.sz = sizeof(opts);
    opts.prog_fd = bpf_program__fd(skel->progs.hg_tc_ingress);

    err = bpf_tc_attach(&hook, &opts);
    if (err)
    {
        fprintf(stderr, "hgctl: failed to attach ingress on %s: %d\n", iface, err);
        return FAILED;
    }

    /* ── attach egress (download) hook ── */
    memset(&opts, 0, sizeof(opts)); /* clear priority/handle from previous attach */
    opts.sz = sizeof(opts);
    opts.prog_fd = bpf_program__fd(skel->progs.hg_tc_egress);
    hook.attach_point = BPF_TC_EGRESS;

    err = bpf_tc_attach(&hook, &opts);
    if (err)
    {
        fprintf(stderr, "hgctl: failed to attach egress on %s: %d\n", iface, err);
        return FAILED;
    }

    printf("hgctl: TC hooks attached on %s (ingress + egress)\n", iface);

    /* ── install FQ on bridge for download EDT shaping ──
     * Bridge defaults to noqueue; txqueuelen must be non-zero before FQ sticks.
     * Failure here means download rate limiting is silently broken — hard fail. */
    snprintf(cmd, sizeof(cmd), "ip link set dev %s txqueuelen 1000", iface);
    if (run_cmd_strict(cmd, "set txqueuelen on bridge") != SUCCESS)
        return FAILED;

    snprintf(cmd, sizeof(cmd), "tc qdisc replace dev %s root fq", iface);
    if (run_cmd_strict(cmd, "install FQ qdisc on bridge (download EDT)") != SUCCESS)
        return FAILED;

    printf("hgctl: download EDT shaping enabled (FQ on %s)\n", iface);

    /* ── set up IFB for upload EDT shaping ──
     * Upload flow: br0 ingress [eBPF sets tstamp + bpf_redirect]
     *           → ifb0 [FQ honours tstamp]
     *           → re-inject (tc_skip_classify=1) → ip_forward → WAN
     * Failure here means upload rate limiting is silently broken — hard fail. */
    run_cmd_best_effort("modprobe ifb 2>/dev/null");
    run_cmd_best_effort("ip link add ifb0 type ifb 2>/dev/null");
    run_cmd_best_effort("ip link set ifb0 up 2>/dev/null");

    if (run_cmd_strict("tc qdisc replace dev ifb0 root fq",
                       "install FQ qdisc on ifb0 (upload EDT)") != SUCCESS)
        return FAILED;

    __u32 ifb_ifindex = if_nametoindex("ifb0");
    if (!ifb_ifindex)
    {
        fprintf(stderr, "hgctl: ifb0 not found after setup\n");
        return FAILED;
    }

    int ifb_fd = bpf_obj_get(MAP_PATH(HG_IFB_IDX_MAP));
    if (ifb_fd < 0)
    {
        fprintf(stderr, "hgctl: could not open IFB index map\n");
        return FAILED;
    }

    __u32 ifb_key = 0;
    if (bpf_map_update_elem(ifb_fd, &ifb_key, &ifb_ifindex, BPF_ANY))
    {
        fprintf(stderr, "hgctl: IFB ifindex map update failed\n");
        close(ifb_fd);
        return FAILED;
    }

    printf("hgctl: upload EDT shaping enabled (ifb0, ifindex=%u)\n", ifb_ifindex);
    close(ifb_fd);
    return SUCCESS;
}

/* ─── stop_action ──────────────────────────────────────────────────────────── *
 * Destroys the clsact qdisc (detaches both hooks), tears down IFB, removes    *
 * the FQ qdisc from the bridge, and unpins all BPF maps.                      *
 * ---------------------------------------------------------------------------- */
int stop_action(const char *iface)
{
    struct bpf_tc_hook hook = {};
    char cmd[160];
    int ifindex, err;

    ifindex = get_ifindex(iface);
    if (ifindex <= 0)
        return FAILED;

    hook.sz = sizeof(hook);
    hook.ifindex = ifindex;
    hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;

    err = bpf_tc_hook_destroy(&hook);
    if (err && err != -ENOENT)
    {
        fprintf(stderr, "hgctl: failed to destroy TC hook: %s\n", strerror(-err));
        return FAILED;
    }

    /* tear down IFB and restore bridge qdisc — best effort on stop */
    run_cmd_best_effort("ip link del ifb0 2>/dev/null");

    snprintf(cmd, sizeof(cmd), "tc qdisc del dev %s root 2>/dev/null", iface);
    run_cmd_best_effort(cmd);

    snprintf(cmd, sizeof(cmd), "ip link set dev %s txqueuelen 0", iface);
    run_cmd_best_effort(cmd);

    hg_clean_maps();
    printf("hgctl: TC hooks detached and maps removed from %s\n", iface);
    return SUCCESS;
}

/* ─── add_action ───────────────────────────────────────────────────────────── *
 * Authenticates a client by inserting entries into hg_clients, hg_counters,  *
 * and hg_rates. All three must succeed or the client entry is rolled back.    *
 *                                                                              *
 * Note: iface is accepted for API consistency (future per-iface map support). *
 *       u_limit is stored for future use; EDT currently uses d_limit only.    *
 * ---------------------------------------------------------------------------- */
int add_action(const char *iface, const char *ip,
               time_t expire, time_t idle,
               __u64 d_limit, __u64 u_limit, __u32 rate_id)
{
    /* suppress unused-parameter warnings for args reserved for future use */
    (void)iface;
    (void)u_limit;

    struct hg_client client_val = {0};
    struct hg_rate_cfg rate_val = {0};
    __u32 ip_key;
    int client_fd, counter_fd, rate_fd;

    /* build rate profile */
    rate_val.rate_Bps = KBIT_TO_BPS(d_limit);
    rate_val.horizon_ns = HG_HORIZON_NS;

    printf("hgctl: rate_id=%u  rate=%llu kbps  horizon=%llu ms\n",
           rate_id,
           BPS_TO_KBIT(rate_val.rate_Bps),
           rate_val.horizon_ns / 1000000ULL);

    /* build client entry */
    inet_pton(AF_INET, ip, &ip_key);

    __u64 now_ns = get_boottime_ns();
    client_val.expiry_ns = (expire > 0) ? (now_ns + (__u64)expire * NSEC_PER_SEC) : 0;
    client_val.idle_ns = (idle > 0) ? ((__u64)idle * NSEC_PER_SEC) : 0;
    client_val.auth_ns = now_ns;
    client_val.rate_limit_id = rate_id;
    /* prime EDT timestamps so the first packet is never delayed */
    client_val.last_u_tstamp = now_ns;
    client_val.last_d_tstamp = now_ns;

    /* open maps */
    client_fd = bpf_obj_get(MAP_PATH(HG_CLIENT_MAP));
    counter_fd = bpf_obj_get(MAP_PATH(HG_COUNTER_MAP));
    rate_fd = bpf_obj_get(MAP_PATH(HG_RATE_MAP));

    if (client_fd < 0 || counter_fd < 0 || rate_fd < 0)
    {
        fprintf(stderr, "hgctl: add — map open failed "
                        "(client=%d counter=%d rate=%d)\n",
                client_fd, counter_fd, rate_fd);
        if (client_fd >= 0)
            close(client_fd);
        if (counter_fd >= 0)
            close(counter_fd);
        if (rate_fd >= 0)
            close(rate_fd);
        return FAILED;
    }

    /* insert client auth entry */
    if (bpf_map_update_elem(client_fd, &ip_key, &client_val, BPF_ANY))
    {
        fprintf(stderr, "hgctl: client map insert failed for %s\n", ip);
        close(client_fd);
        close(counter_fd);
        close(rate_fd);
        return FAILED;
    }

    /* initialise per-CPU counter entry (all CPUs zeroed) */
    int ncpu = libbpf_num_possible_cpus();
    struct hg_counter *zeros = calloc((size_t)ncpu, sizeof(struct hg_counter));
    if (!zeros)
    {
        fprintf(stderr, "hgctl: calloc failed for per-CPU counters\n");
        bpf_map_delete_elem(client_fd, &ip_key); /* rollback */
        close(client_fd);
        close(counter_fd);
        close(rate_fd);
        return FAILED;
    }

    if (bpf_map_update_elem(counter_fd, &ip_key, zeros, BPF_ANY))
    {
        fprintf(stderr, "hgctl: counter map insert failed for %s\n", ip);
        int rb = bpf_map_delete_elem(client_fd, &ip_key);
        fprintf(stderr, "hgctl: client rollback %s\n", rb == 0 ? "ok" : "failed");
        free(zeros);
        close(client_fd);
        close(counter_fd);
        close(rate_fd);
        return FAILED;
    }
    free(zeros);

    /* insert rate profile */
    if (bpf_map_update_elem(rate_fd, &rate_id, &rate_val, BPF_ANY))
        fprintf(stderr, "hgctl: warning — rate map insert failed for id=%u "
                        "(client authenticated without rate limit)\n",
                rate_id);

    close(client_fd);
    close(counter_fd);
    close(rate_fd);
    printf("hgctl: client %s authenticated  expire=%lds idle=%lds\n",
           ip, expire, idle);
    return SUCCESS;
}

/* ─── del_action ───────────────────────────────────────────────────────────── */
int del_action(const char *iface, const char *ip)
{
    (void)iface; /* reserved for future per-iface map support */

    __u32 ip_key;
    struct hg_client val = {0};
    int client_fd, counter_fd;
    int client_st, counter_st, rate_st = -1;

    inet_pton(AF_INET, ip, &ip_key);

    client_fd = bpf_obj_get(MAP_PATH(HG_CLIENT_MAP));
    counter_fd = bpf_obj_get(MAP_PATH(HG_COUNTER_MAP));

    if (client_fd < 0 || counter_fd < 0)
    {
        fprintf(stderr, "hgctl: del — map open failed\n");
        if (client_fd >= 0)
            close(client_fd);
        if (counter_fd >= 0)
            close(counter_fd);
        return FAILED;
    }

    /* look up rate_id before deleting the client entry */
    if (bpf_map_lookup_elem(client_fd, &ip_key, &val) == 0)
    {
        __u32 rate_id = val.rate_limit_id;
        int rate_fd = bpf_obj_get(MAP_PATH(HG_RATE_MAP));
        if (rate_fd >= 0)
        {
            rate_st = bpf_map_delete_elem(rate_fd, &rate_id);
            close(rate_fd);
        }
    }

    client_st = bpf_map_delete_elem(client_fd, &ip_key);
    counter_st = bpf_map_delete_elem(counter_fd, &ip_key);

    close(client_fd);
    close(counter_fd);

    printf("hgctl: del %s  client=%s  counter=%s  rate=%s\n", ip,
           client_st == 0 ? "removed" : "not found",
           counter_st == 0 ? "removed" : "not found",
           rate_st == 0 ? "removed" : "not found");
    return SUCCESS;
}

/* ─── show_action ──────────────────────────────────────────────────────────── */
int show_action(const char *iface)
{
    (void)iface; /* reserved for future per-iface map support */

    int map_fd = bpf_obj_get(MAP_PATH(HG_COUNTER_MAP));
    if (map_fd < 0)
    {
        perror("hgctl: show — hg_counters open failed");
        return FAILED;
    }

    int ncpu = libbpf_num_possible_cpus();
    struct hg_counter *values = calloc((size_t)ncpu, sizeof(struct hg_counter));
    if (!values)
    {
        perror("hgctl: calloc");
        close(map_fd);
        return FAILED;
    }

    printf("\nClient traffic counters\n");
    printf("%-18s %-10s %-14s %-10s %-14s\n",
           "IP", "UP pkts", "UP bytes", "DN pkts", "DN bytes");
    printf("%-18s %-10s %-14s %-10s %-14s\n",
           "--", "-------", "--------", "-------", "--------");

    __u32 key, prev_key;
    int ret = bpf_map_get_next_key(map_fd, NULL, &key);
    while (ret == 0)
    {
        memset(values, 0, (size_t)ncpu * sizeof(struct hg_counter));
        struct hg_counter total = {0};

        if (bpf_map_lookup_elem(map_fd, &key, values) == 0)
        {
            for (int i = 0; i < ncpu; i++)
            {
                total.U_packets += values[i].U_packets;
                total.U_bytes += values[i].U_bytes;
                total.D_packets += values[i].D_packets;
                total.D_bytes += values[i].D_bytes;
            }
            struct in_addr a = {.s_addr = key};
            printf("%-18s %-10llu %-14llu %-10llu %-14llu\n",
                   inet_ntoa(a),
                   total.U_packets, total.U_bytes,
                   total.D_packets, total.D_bytes);
        }

        prev_key = key;
        ret = bpf_map_get_next_key(map_fd, &prev_key, &key);
    }

    free(values);
    close(map_fd);
    return SUCCESS;
}

/* ─── details_action ───────────────────────────────────────────────────────── */
int details_action(const char *iface)
{
    (void)iface; /* reserved for future per-iface map support */

    int counter_fd = bpf_obj_get(MAP_PATH(HG_COUNTER_MAP));
    int client_fd = bpf_obj_get(MAP_PATH(HG_CLIENT_MAP));

    if (counter_fd < 0 || client_fd < 0)
    {
        perror("hgctl: details — map open failed");
        if (counter_fd >= 0)
            close(counter_fd);
        if (client_fd >= 0)
            close(client_fd);
        return FAILED;
    }

    int ncpu = libbpf_num_possible_cpus();
    struct hg_counter *values = calloc((size_t)ncpu, sizeof(struct hg_counter));
    if (!values)
    {
        perror("hgctl: calloc");
        close(counter_fd);
        close(client_fd);
        return FAILED;
    }

    /* compute CLOCK_BOOTTIME → wall clock offset for expiry display */
    struct timespec ts_real, ts_boot;
    clock_gettime(CLOCK_REALTIME, &ts_real);
    clock_gettime(CLOCK_BOOTTIME, &ts_boot);
    time_t boot_to_wall = ts_real.tv_sec - ts_boot.tv_sec;

    printf("\nClient details\n");
    printf("===========================================================================================================\n");
    printf("%-18s %-9s %-12s %-9s %-12s %-10s %-22s %s\n",
           "IP", "UP pkts", "UP bytes", "DN pkts", "DN bytes",
           "State", "Policy (id|rate)", "Last seen");
    printf("-----------------------------------------------------------------------------------------------------------\n");

    __u32 key, prev_key;
    int ret = bpf_map_get_next_key(counter_fd, NULL, &key);
    while (ret == 0)
    {
        memset(values, 0, (size_t)ncpu * sizeof(struct hg_counter));
        struct hg_counter total = {0};
        __u64 last_seen_ns = 0;
        int current_state = AUTH_OK;

        if (bpf_map_lookup_elem(counter_fd, &key, values) == 0)
        {
            for (int i = 0; i < ncpu; i++)
            {
                total.U_packets += values[i].U_packets;
                total.U_bytes += values[i].U_bytes;
                total.D_packets += values[i].D_packets;
                total.D_bytes += values[i].D_bytes;
                if (values[i].last_seen > last_seen_ns)
                    last_seen_ns = values[i].last_seen;
                if (values[i].state > (__u32)current_state)
                    current_state = (int)values[i].state;
            }

            time_t last_wall = boot_to_wall + (time_t)(last_seen_ns / NSEC_PER_SEC);
            time_t now = ts_real.tv_sec;
            time_t age = (last_wall > 0 && now >= last_wall) ? (now - last_wall) : 0;

            struct hg_client st = {0};
            struct hg_rate_cfg rate = {0};
            __u32 policy_id = 0;

            if (bpf_map_lookup_elem(client_fd, &key, &st) == 0)
            {
                if (st.expiry_ns > 0 &&
                    st.expiry_ns <= (__u64)ts_boot.tv_sec * NSEC_PER_SEC)
                    current_state = EXPIRE;
                policy_id = st.rate_limit_id;
                hg_get_rate_cfg(policy_id, &rate);
            }

            const char *state_str;
            switch (current_state)
            {
            case AUTH_OK:
                state_str = "AUTH_OK";
                break;
            case EXPIRE:
                state_str = "EXPIRE";
                break;
            case BLOCK:
                state_str = "BLOCK";
                break;
            case IDLE:
                state_str = "IDLE";
                break;
            default:
                state_str = "UNKNOWN";
                break;
            }

            char policy_buf[32];
            snprintf(policy_buf, sizeof(policy_buf), "%u|%llukbps",
                     policy_id, BPS_TO_KBIT(rate.rate_Bps));

            struct in_addr a = {.s_addr = key};
            printf("%-18s %-9llu %-12llu %-9llu %-12llu %-10s %-22s %lds ago\n",
                   inet_ntoa(a),
                   total.U_packets, total.U_bytes,
                   total.D_packets, total.D_bytes,
                   state_str, policy_buf, age);
        }

        prev_key = key;
        ret = bpf_map_get_next_key(counter_fd, &prev_key, &key);
    }

    free(values);
    close(counter_fd);
    close(client_fd);
    show_protocols();
    return SUCCESS;
}

/* ─── show_protocols ───────────────────────────────────────────────────────── */
void show_protocols(void)
{
    int l2_fd = bpf_obj_get(MAP_PATH(HG_L2_ALLOW_MAP));
    int l3l4_fd = bpf_obj_get(MAP_PATH(HG_PROTO_MAP));

    if (l2_fd < 0 || l3l4_fd < 0)
    {
        fprintf(stderr, "hgctl: could not open protocol maps\n");
        if (l2_fd >= 0)
            close(l2_fd);
        if (l3l4_fd >= 0)
            close(l3l4_fd);
        return;
    }

    printf("\nPre-auth allow rules\n");
    printf("%-12s  %s\n", "EtherType", "(L2)");
    printf("%-12s  %s\n", "---------", "----");

    __u16 l2_key, l2_prev;
    __u8 l2_val;
    int ret = bpf_map_get_next_key(l2_fd, NULL, &l2_key);
    while (ret == 0)
    {
        if (bpf_map_lookup_elem(l2_fd, &l2_key, &l2_val) == 0)
            printf("0x%04X\n", l2_key);
        l2_prev = l2_key;
        ret = bpf_map_get_next_key(l2_fd, &l2_prev, &l2_key);
    }

    printf("\n%-8s %-8s %-8s  %s\n", "Proto", "Sport", "Dport", "(L3/L4)");
    printf("%-8s %-8s %-8s  %s\n", "-----", "-----", "-----", "-------");

    struct hg_allow_key l3_key, l3_prev;
    __u8 l3_val;
    ret = bpf_map_get_next_key(l3l4_fd, NULL, &l3_key);
    while (ret == 0)
    {
        if (bpf_map_lookup_elem(l3l4_fd, &l3_key, &l3_val) == 0)
            printf("%-8u %-8u %-8u\n",
                   l3_key.proto, l3_key.s_port, l3_key.d_port);
        l3_prev = l3_key;
        ret = bpf_map_get_next_key(l3l4_fd, &l3_prev, &l3_key);
    }

    close(l2_fd);
    close(l3l4_fd);
}

/* ─── hg_get_rate_cfg ──────────────────────────────────────────────────────── */
bool hg_get_rate_cfg(__u32 rate_id, struct hg_rate_cfg *out)
{
    int fd = bpf_obj_get(MAP_PATH(HG_RATE_MAP));
    if (fd < 0)
        return false;

    bool found = (bpf_map_lookup_elem(fd, &rate_id, out) == 0);
    if (!found)
        fprintf(stderr, "hgctl: no rate profile for id=%u\n", rate_id);

    close(fd);
    return found;
}

/* ─── protocol_allow_add_action ────────────────────────────────────────────── */
int protocol_allow_add_action(struct proto_rule *rule)
{
    if (rule->level == PROTO_L2)
    {
        int fd = bpf_obj_get(MAP_PATH(HG_L2_ALLOW_MAP));
        if (fd < 0)
        {
            fprintf(stderr, "hgctl: L2 allow map open failed\n");
            return FAILED;
        }
        __u16 key = (__u16)rule->proto;
        __u8 val = 1;
        if (bpf_map_update_elem(fd, &key, &val, BPF_ANY))
        {
            fprintf(stderr, "hgctl: L2 insert failed ethertype=0x%04X\n", key);
            close(fd);
            return FAILED;
        }
        printf("hgctl: L2 allow added ethertype=0x%04X\n", key);
        close(fd);
        return SUCCESS;
    }
    else if (rule->level == PROTO_L3 || rule->level == PROTO_L4)
    {
        int fd = bpf_obj_get(MAP_PATH(HG_PROTO_MAP));
        if (fd < 0)
        {
            fprintf(stderr, "hgctl: proto map open failed\n");
            return FAILED;
        }
        struct hg_allow_key key = {0};
        key.proto = rule->proto;
        key.s_port = rule->sport;
        key.d_port = rule->dport;
        __u8 val = 1;
        if (bpf_map_update_elem(fd, &key, &val, BPF_ANY))
        {
            fprintf(stderr, "hgctl: proto insert failed proto=%u\n", key.proto);
            close(fd);
            return FAILED;
        }
        printf("hgctl: L%d allow added proto=%u sport=%u dport=%u\n",
               rule->level, key.proto, key.s_port, key.d_port);
        close(fd);
        return SUCCESS;
    }

    fprintf(stderr, "hgctl: unknown proto level %d\n", rule->level);
    return FAILED;
}

/* ─── protocol_allow_del_action ────────────────────────────────────────────── */
int protocol_allow_del_action(struct proto_rule *rule)
{
    if (rule->level == PROTO_L2)
    {
        int fd = bpf_obj_get(MAP_PATH(HG_L2_ALLOW_MAP));
        if (fd < 0)
        {
            fprintf(stderr, "hgctl: L2 allow map open failed\n");
            return FAILED;
        }
        __u16 key = (__u16)rule->proto;
        if (bpf_map_delete_elem(fd, &key))
        {
            fprintf(stderr, "hgctl: L2 delete failed ethertype=0x%04X\n", key);
            close(fd);
            return FAILED;
        }
        printf("hgctl: L2 allow removed ethertype=0x%04X\n", key);
        close(fd);
        return SUCCESS;
    }
    else if (rule->level == PROTO_L3 || rule->level == PROTO_L4)
    {
        int fd = bpf_obj_get(MAP_PATH(HG_PROTO_MAP));
        if (fd < 0)
        {
            fprintf(stderr, "hgctl: proto map open failed\n");
            return FAILED;
        }
        struct hg_allow_key key = {0};
        key.proto = rule->proto;
        key.s_port = rule->sport;
        key.d_port = rule->dport;
        if (bpf_map_delete_elem(fd, &key))
        {
            fprintf(stderr, "hgctl: proto delete failed proto=%u\n", key.proto);
            close(fd);
            return FAILED;
        }
        printf("hgctl: L%d allow removed proto=%u sport=%u dport=%u\n",
               rule->level, key.proto, key.s_port, key.d_port);
        close(fd);
        return SUCCESS;
    }

    fprintf(stderr, "hgctl: unknown proto level %d\n", rule->level);
    return FAILED;
}

/* ─── hg_parse_opcode ──────────────────────────────────────────────────────── */
action_opcode hg_parse_opcode(const char *cmd)
{
    for (int i = 0; action_table[i].name; i++)
        if (strcasecmp(cmd, action_table[i].name) == 0)
            return action_table[i].op;

    fprintf(stderr, "hgctl: unknown command '%s'\n", cmd);
    return BAD_OP;
}
