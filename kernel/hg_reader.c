#include "hg_reader.h"
#include "hg_user.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <arpa/inet.h>

/* ─── internal helpers ─────────────────────────────────────────────────────── */

/* open all three maps needed for a full read; returns 0 on success.
 * All fds are set to -1 on failure; caller closes any that are >= 0. */
static int open_read_maps(int *counter_fd, int *client_fd, int *rate_fd)
{
    *counter_fd = bpf_obj_get(MAP_PATH(HG_COUNTER_MAP));
    *client_fd = bpf_obj_get(MAP_PATH(HG_CLIENT_MAP));
    *rate_fd = bpf_obj_get(MAP_PATH(HG_RATE_MAP));

    if (*counter_fd < 0 || *client_fd < 0 || *rate_fd < 0)
    {
        fprintf(stderr, "hg_reader: map open failed "
                        "(counter=%d client=%d rate=%d) — is hawkgate running?\n",
                *counter_fd, *client_fd, *rate_fd);
        if (*counter_fd >= 0)
        {
            close(*counter_fd);
            *counter_fd = -1;
        }
        if (*client_fd >= 0)
        {
            close(*client_fd);
            *client_fd = -1;
        }
        if (*rate_fd >= 0)
        {
            close(*rate_fd);
            *rate_fd = -1;
        }
        return -1;
    }
    return 0;
}

/* aggregate a PERCPU_HASH value across all CPUs into a single hg_counter */
static void aggregate_percpu(const struct hg_counter *percpu, int ncpu,
                             struct hg_counter *out)
{
    memset(out, 0, sizeof(*out));
    for (int i = 0; i < ncpu; i++)
    {
        out->U_packets += percpu[i].U_packets;
        out->U_bytes += percpu[i].U_bytes;
        out->D_packets += percpu[i].D_packets;
        out->D_bytes += percpu[i].D_bytes;
        if (percpu[i].last_seen > out->last_seen)
            out->last_seen = percpu[i].last_seen;
        if (percpu[i].state > out->state)
            out->state = percpu[i].state;
    }
}

/* resolve timestamps into wall-clock time_t values */
static void resolve_times(const struct hg_client *cs,
                          uint64_t last_seen_ns,
                          struct hg_client_stats *s)
{
    struct timespec ts_real, ts_boot;
    clock_gettime(CLOCK_REALTIME, &ts_real);
    clock_gettime(CLOCK_BOOTTIME, &ts_boot);

    /* CLOCK_BOOTTIME offset — convert boottime ns to wall clock */
    time_t boot_offset = ts_real.tv_sec - ts_boot.tv_sec;
    time_t now = ts_real.tv_sec;

    s->auth_time = (cs->auth_ns > 0)
                       ? (boot_offset + (time_t)(cs->auth_ns / NSEC_PER_SEC))
                       : 0;

    s->expiry_time = (cs->expiry_ns > 0)
                         ? (boot_offset + (time_t)(cs->expiry_ns / NSEC_PER_SEC))
                         : 0;

    s->last_seen = (last_seen_ns > 0)
                       ? (boot_offset + (time_t)(last_seen_ns / NSEC_PER_SEC))
                       : 0;

    s->age_sec = (s->last_seen > 0 && now >= s->last_seen)
                     ? (now - s->last_seen)
                     : 0;

    s->session_sec = (s->auth_time > 0 && now >= s->auth_time)
                         ? (now - s->auth_time)
                         : 0;

    s->ttl_sec = (s->expiry_time > 0)
                     ? (long)(s->expiry_time - now)
                     : -1;
}

/* check whether a session has expired by comparing expiry_ns to boot time */
static bool is_expired(const struct hg_client *cs)
{
    if (cs->expiry_ns == 0)
        return false;

    struct timespec ts;
    clock_gettime(CLOCK_BOOTTIME, &ts);
    uint64_t now_ns = (uint64_t)ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
    return (cs->expiry_ns <= now_ns);
}

/* fill one hg_client_stats from raw map values */
static void fill_stats(uint32_t ip_key,
                       const struct hg_counter *agg,
                       const struct hg_client *cs,
                       const struct hg_rate_cfg *rate,
                       struct hg_client_stats *s)
{
    memset(s, 0, sizeof(*s));

    s->ip_key = ip_key;
    struct in_addr a = {.s_addr = ip_key};
    snprintf(s->ip, sizeof(s->ip), "%s", inet_ntoa(a));

    s->up_bytes = agg->U_bytes;
    s->up_packets = agg->U_packets;
    s->dn_bytes = agg->D_bytes;
    s->dn_packets = agg->D_packets;

    /* state — expiry check takes priority over counter state */
    s->state = (int)agg->state;
    if (is_expired(cs))
        s->state = EXPIRE;

    s->rate_id = cs->rate_limit_id;
    s->rate_kbps = rate ? BPS_TO_KBIT(rate->rate_Bps) : 0;
    s->horizon_ms = rate ? (rate->horizon_ns / 1000000ULL) : 0;

    resolve_times(cs, agg->last_seen, s);
}

/* sort comparators */
static int cmp_dn_bytes(const void *a, const void *b)
{
    const struct hg_client_stats *x = a, *y = b;
    if (y->dn_bytes > x->dn_bytes)
        return 1;
    if (y->dn_bytes < x->dn_bytes)
        return -1;
    return 0;
}
static int cmp_up_bytes(const void *a, const void *b)
{
    const struct hg_client_stats *x = a, *y = b;
    if (y->up_bytes > x->up_bytes)
        return 1;
    if (y->up_bytes < x->up_bytes)
        return -1;
    return 0;
}
static int cmp_last_seen(const void *a, const void *b)
{
    const struct hg_client_stats *x = a, *y = b;
    return (int)(y->last_seen - x->last_seen);
}
static int cmp_age(const void *a, const void *b)
{
    const struct hg_client_stats *x = a, *y = b;
    return (int)(x->auth_time - y->auth_time); /* oldest first */
}

/* ─── hg_read_all ──────────────────────────────────────────────────────────── */
int hg_read_all(struct hg_client_stats **out, int *count,
                hg_sort_key sort, hg_state_filter filter, int limit,
                struct hg_gateway_stats *summary)
{
    int counter_fd, client_fd, rate_fd;
    if (open_read_maps(&counter_fd, &client_fd, &rate_fd) < 0)
        return -1;

    int ncpu = libbpf_num_possible_cpus();
    struct hg_counter *percpu = calloc((size_t)ncpu, sizeof(struct hg_counter));
    if (!percpu)
    {
        close(counter_fd);
        close(client_fd);
        close(rate_fd);
        return -1;
    }

    /* first pass — count entries so we can allocate exactly */
    int total = 0;
    uint32_t key, prev_key;
    int ret = bpf_map_get_next_key(counter_fd, NULL, &key);
    while (ret == 0)
    {
        total++;
        prev_key = key;
        ret = bpf_map_get_next_key(counter_fd, &prev_key, &key);
    }

    if (total == 0)
    {
        *out = NULL;
        *count = 0;
        if (summary)
            memset(summary, 0, sizeof(*summary));
        free(percpu);
        close(counter_fd);
        close(client_fd);
        close(rate_fd);
        return 0;
    }

    struct hg_client_stats *buf = calloc((size_t)total,
                                         sizeof(struct hg_client_stats));
    if (!buf)
    {
        free(percpu);
        close(counter_fd);
        close(client_fd);
        close(rate_fd);
        return -1;
    }

    /* second pass — fill buf */
    if (summary)
        memset(summary, 0, sizeof(*summary));

    int idx = 0;
    ret = bpf_map_get_next_key(counter_fd, NULL, &key);
    while (ret == 0 && idx < total)
    {
        struct hg_counter agg;
        struct hg_client cs = {0};
        struct hg_rate_cfg rate = {0};

        memset(percpu, 0, (size_t)ncpu * sizeof(struct hg_counter));

        if (bpf_map_lookup_elem(counter_fd, &key, percpu) == 0)
        {
            aggregate_percpu(percpu, ncpu, &agg);
            bpf_map_lookup_elem(client_fd, &key, &cs); /* best-effort */

            if (cs.rate_limit_id != RATE_ID_NO_LIMIT)
            {
                uint32_t rid = cs.rate_limit_id;
                bpf_map_lookup_elem(rate_fd, &rid, &rate);
            }

            fill_stats(key, &agg, &cs, &rate, &buf[idx]);

            /* accumulate summary */
            if (summary)
            {
                summary->total_clients++;
                summary->total_up_bytes += agg.U_bytes;
                summary->total_dn_bytes += agg.D_bytes;
                summary->total_up_packets += agg.U_packets;
                summary->total_dn_packets += agg.D_packets;
                switch (buf[idx].state)
                {
                case AUTH_OK:
                    summary->active_clients++;
                    break;
                case EXPIRE:
                    summary->expired_clients++;
                    break;
                case BLOCK:
                    summary->blocked_clients++;
                    break;
                default:
                    break;
                }
            }
            idx++;
        }

        prev_key = key;
        ret = bpf_map_get_next_key(counter_fd, &prev_key, &key);
    }

    free(percpu);
    close(counter_fd);
    close(client_fd);
    close(rate_fd);

    /* sort */
    switch (sort)
    {
    case HG_SORT_DN_BYTES:
        qsort(buf, idx, sizeof(*buf), cmp_dn_bytes);
        break;
    case HG_SORT_UP_BYTES:
        qsort(buf, idx, sizeof(*buf), cmp_up_bytes);
        break;
    case HG_SORT_LAST_SEEN:
        qsort(buf, idx, sizeof(*buf), cmp_last_seen);
        break;
    case HG_SORT_AGE:
        qsort(buf, idx, sizeof(*buf), cmp_age);
        break;
    }

    /* filter */
    if (filter != HG_FILTER_ALL)
    {
        int keep = 0;
        for (int i = 0; i < idx; i++)
        {
            int match = 0;
            switch (filter)
            {
            case HG_FILTER_ACTIVE:
                match = (buf[i].state == AUTH_OK);
                break;
            case HG_FILTER_EXPIRED:
                match = (buf[i].state == EXPIRE);
                break;
            case HG_FILTER_BLOCKED:
                match = (buf[i].state == BLOCK);
                break;
            default:
                match = 1;
                break;
            }
            if (match)
                buf[keep++] = buf[i];
        }
        idx = keep;
    }

    /* limit */
    if (limit > 0 && idx > limit)
        idx = limit;

    *out = buf;
    *count = idx;
    return 0;
}

/* ─── hg_read_one ──────────────────────────────────────────────────────────── */
int hg_read_one(const char *ip, struct hg_client_stats *out)
{
    uint32_t ip_key;
    if (inet_pton(AF_INET, ip, &ip_key) != 1)
    {
        fprintf(stderr, "hg_reader: invalid IP address '%s'\n", ip);
        return -1;
    }

    int counter_fd, client_fd, rate_fd;
    if (open_read_maps(&counter_fd, &client_fd, &rate_fd) < 0)
        return -1;

    int ncpu = libbpf_num_possible_cpus();
    struct hg_counter *percpu = calloc((size_t)ncpu, sizeof(struct hg_counter));
    if (!percpu)
    {
        close(counter_fd);
        close(client_fd);
        close(rate_fd);
        return -1;
    }

    int found = -1;

    if (bpf_map_lookup_elem(counter_fd, &ip_key, percpu) == 0)
    {
        struct hg_counter agg = {0};
        struct hg_client cs = {0};
        struct hg_rate_cfg rate = {0};

        aggregate_percpu(percpu, ncpu, &agg);
        bpf_map_lookup_elem(client_fd, &ip_key, &cs);

        if (cs.rate_limit_id != RATE_ID_NO_LIMIT)
        {
            uint32_t rid = cs.rate_limit_id;
            bpf_map_lookup_elem(rate_fd, &rid, &rate);
        }

        fill_stats(ip_key, &agg, &cs, &rate, out);
        found = 0;
    }
    else
    {
        fprintf(stderr, "hg_reader: client %s not found\n", ip);
    }

    free(percpu);
    close(counter_fd);
    close(client_fd);
    close(rate_fd);
    return found;
}

/* ─── hg_stats_free ────────────────────────────────────────────────────────── */
void hg_stats_free(struct hg_client_stats *stats)
{
    free(stats);
}

/* ─── hg_state_str ─────────────────────────────────────────────────────────── */
const char *hg_state_str(int state)
{
    switch (state)
    {
    case AUTH_OK:
        return "AUTH_OK";
    case EXPIRE:
        return "EXPIRE";
    case BLOCK:
        return "BLOCK";
    case IDLE:
        return "IDLE";
    default:
        return "UNKNOWN";
    }
}

/* ─── hg_format_bytes ──────────────────────────────────────────────────────── */
void hg_format_bytes(uint64_t bytes, char *buf, size_t buf_size)
{
    if (bytes >= 1099511627776ULL)
        snprintf(buf, buf_size, "%.1f TB", (double)bytes / 1099511627776.0);
    else if (bytes >= 1073741824ULL)
        snprintf(buf, buf_size, "%.1f GB", (double)bytes / 1073741824.0);
    else if (bytes >= 1048576ULL)
        snprintf(buf, buf_size, "%.1f MB", (double)bytes / 1048576.0);
    else if (bytes >= 1024ULL)
        snprintf(buf, buf_size, "%.1f KB", (double)bytes / 1024.0);
    else
        snprintf(buf, buf_size, "%llu B", (unsigned long long)bytes);
}
