#ifndef HG_READER_H
#define HG_READER_H

/* ─────────────────────────────────────────────────────────────────────────────
 * hg_reader — shared BPF map reader for hgctl and hawkgated
 *
 * This module is the single place that reads hg_clients, hg_counters, and
 * hg_rates and aggregates them into hg_client_stats structs.
 *
 * Both consumers use it differently:
 *   hgctl       — calls hg_read_all() or hg_read_one() on demand, prints result
 *   hawkgated   — calls hg_read_all() on a poll timer, caches result in memory,
 *                 serves cached data to the HTTP API (maps never hit per-request)
 *
 * Caller is responsible for freeing the array returned by hg_read_all()
 * using hg_stats_free().
 * ───────────────────────────────────────────────────────────────────────────── */

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "hg_common.h"

/* ─── aggregated per-client stats — shaped for JSON serialisation ──────────── */
struct hg_client_stats
{
    /* identity */
    char ip[16];     /* dotted-decimal string e.g. "192.168.100.10"  */
    uint32_t ip_key; /* raw network-order IPv4 key from the map       */

    /* traffic counters (aggregated across all CPUs) */
    uint64_t up_bytes;
    uint64_t up_packets;
    uint64_t dn_bytes;
    uint64_t dn_packets;

    /* session metadata */
    int state;           /* enum client_status value                      */
    uint32_t rate_id;    /* key into hg_rates map                         */
    uint64_t rate_kbps;  /* resolved download rate in kbit/s (0=unlimited)*/
    uint64_t horizon_ms; /* EDT burst depth in ms                         */

    /* timestamps — all as wall-clock time_t for easy formatting */
    time_t auth_time;   /* when session was created                      */
    time_t expiry_time; /* when session expires (0 = never)              */
    time_t last_seen;   /* last packet timestamp                         */
    time_t age_sec;     /* seconds since last packet                     */
    time_t session_sec; /* seconds since auth                            */
    long ttl_sec;       /* seconds until expiry (-1 = never)             */
};

/* ─── gateway-wide summary ─────────────────────────────────────────────────── */
struct hg_gateway_stats
{
    int total_clients;
    int active_clients;  /* state == AUTH_OK                              */
    int expired_clients; /* state == EXPIRE                               */
    int blocked_clients; /* state == BLOCK                                */
    uint64_t total_up_bytes;
    uint64_t total_dn_bytes;
    uint64_t total_up_packets;
    uint64_t total_dn_packets;
};

/* ─── sort keys for hg_read_all() ─────────────────────────────────────────── */
typedef enum
{
    HG_SORT_DN_BYTES = 0, /* default — heaviest downloaders first          */
    HG_SORT_UP_BYTES = 1,
    HG_SORT_LAST_SEEN = 2, /* most recently active first                    */
    HG_SORT_AGE = 3,       /* oldest session first                          */
} hg_sort_key;

/* ─── state filter for hg_read_all() ──────────────────────────────────────── */
typedef enum
{
    HG_FILTER_ALL = -1,    /* no filter — return all clients                */
    HG_FILTER_ACTIVE = 0,  /* AUTH_OK only                                  */
    HG_FILTER_EXPIRED = 1, /* EXPIRE only                                   */
    HG_FILTER_BLOCKED = 2, /* BLOCK only                                    */
} hg_state_filter;

/* ─── public API ───────────────────────────────────────────────────────────── *
 *
 * hg_read_all()
 *   Reads all clients from the BPF maps, aggregates per-CPU counters, resolves
 *   rate profiles, and returns a sorted, filtered array of hg_client_stats.
 *
 *   out      — set to a malloc'd array of hg_client_stats on success
 *   count    — set to the number of entries in the array
 *   sort     — sort order for the returned array
 *   filter   — state filter (HG_FILTER_ALL returns all clients)
 *   limit    — max entries to return (0 = no limit)
 *   summary  — if non-NULL, filled with gateway-wide totals
 *
 *   Returns 0 on success, -1 on error (errno set).
 *   Caller must call hg_stats_free(out, count) when done.
 *
 * hg_read_one()
 *   Reads a single client by IP string. Returns 0 on success, -1 if not found.
 *
 * hg_stats_free()
 *   Frees the array returned by hg_read_all().
 *
 * hg_state_str()
 *   Returns a human-readable string for a client_status enum value.
 *
 * hg_format_bytes()
 *   Formats a byte count as a human-readable string (e.g. "8.4 GB").
 *   buf must be at least 16 bytes.
 * ---------------------------------------------------------------------------- */
int hg_read_all(struct hg_client_stats **out, int *count,
                hg_sort_key sort, hg_state_filter filter, int limit,
                struct hg_gateway_stats *summary);

int hg_read_one(const char *ip, struct hg_client_stats *out);

void hg_stats_free(struct hg_client_stats *stats);

const char *hg_state_str(int state);

void hg_format_bytes(uint64_t bytes, char *buf, size_t buf_size);

#endif /* HG_READER_H */
