#include "hg_user.h"
#include "hg_reader.h"
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
  _clean_map(MAP_PATH(HG_PORTAL_CFG_MAP));
  _clean_map(MAP_PATH(HG_CONNTRACK_MAP));
  _clean_map(MAP_PATH(HG_MAC_IP_MAP));
  _clean_map(MAP_PATH(HG_IP_MAC_MAP));
  _clean_map(MAP_PATH(HG_BYPASS_MAP));
  _clean_map(MAP_PATH(HG_WALLED_GARDEN_MAP));

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
    {"map-del", MAP_DEL},
    {"bypass-add", BYPASS_ADD},
    {"bypass-del", BYPASS_DEL},
    {"wg-add", WG_ADD},
    {"wg-del", WG_DEL},

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
  case MAP_DEL:
    return parse_map_del(argc, argv, prog);
  case BYPASS_ADD:
    return parse_bypass_add(argc, argv, prog);
  case BYPASS_DEL:
    return parse_bypass_del(argc, argv, prog);
  case WG_ADD:
    return parse_wg_add(argc, argv, prog);
  case WG_DEL:
    return parse_wg_del(argc, argv, prog);

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
 *   - IFB / FQ on ifb_hg failure → hard fail (upload rate limit broken)        *
 * ---------------------------------------------------------------------------- */
int start_action(const char *iface, const char *portal_ip, __u16 portal_port)
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
  bpf_map__set_pin_path(skel->maps.HG_PORTAL_CFG_MAP, MAP_PATH(HG_PORTAL_CFG_MAP));
  bpf_map__set_pin_path(skel->maps.HG_CONNTRACK_MAP, MAP_PATH(HG_CONNTRACK_MAP));
  bpf_map__set_pin_path(skel->maps.HG_MAC_IP_MAP, MAP_PATH(HG_MAC_IP_MAP));
  bpf_map__set_pin_path(skel->maps.HG_IP_MAC_MAP, MAP_PATH(HG_IP_MAC_MAP));
  bpf_map__set_pin_path(skel->maps.HG_BYPASS_MAP, MAP_PATH(HG_BYPASS_MAP));
  bpf_map__set_pin_path(skel->maps.HG_WALLED_GARDEN_MAP, MAP_PATH(HG_WALLED_GARDEN_MAP));

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
   *           → ifb_hg [FQ honours tstamp]
   *           → re-inject (tc_skip_classify=1) → ip_forward → WAN
   * Failure here means upload rate limiting is silently broken — hard fail. */
  run_cmd_best_effort("modprobe ifb 2>/dev/null");
  run_cmd_best_effort("ip link add ifb_hg type ifb 2>/dev/null");
  run_cmd_best_effort("ip link set ifb_hg up 2>/dev/null");

  if (run_cmd_strict("tc qdisc replace dev ifb_hg root fq",
                     "install FQ qdisc on ifb_hg (upload EDT)") != SUCCESS)
    return FAILED;

  __u32 ifb_ifindex = if_nametoindex("ifb_hg");
  if (!ifb_ifindex)
  {
    fprintf(stderr, "hgctl: ifb_hg not found after setup\n");
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

  printf("hgctl: upload EDT shaping enabled (ifb_hg, ifindex=%u)\n", ifb_ifindex);
  close(ifb_fd);

  int portal_fd = bpf_obj_get(MAP_PATH(HG_PORTAL_CFG_MAP));
  if (portal_fd < 0)
  {
    fprintf(stderr, "hgctl: could not open portal config map\n");
    return FAILED;
  }

  __u32 portal_key = 0;
  struct hg_portal_cfg portal_info = {0};
  struct in_addr bin_addr = {0};
  if (inet_pton(AF_INET, portal_ip, &bin_addr) != 1)
  {
    fprintf(stderr, "hgctl: invalid portal IP '%s'\n", portal_ip);
    close(portal_fd);
    return FAILED;
  }
  portal_info.portal_ip = bin_addr.s_addr;
  portal_info.portal_port = htons(portal_port);
  if (bpf_map_update_elem(portal_fd, &portal_key, &portal_info, BPF_ANY))
  {
    fprintf(stderr, "hgctl: portal config map update failed\n");
    close(portal_fd);
    return FAILED;
  }
  printf("hgctl: portal cfg written (ip=%s port=%u)\n", portal_ip, portal_port);
  close(portal_fd);
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
  run_cmd_best_effort("ip link del ifb_hg 2>/dev/null");

  snprintf(cmd, sizeof(cmd), "tc qdisc del dev %s root 2>/dev/null", iface);
  run_cmd_best_effort(cmd);

  snprintf(cmd, sizeof(cmd), "ip link set dev %s txqueuelen 0", iface);
  run_cmd_best_effort(cmd);

  hg_clean_maps();
  printf("hgctl: TC hooks detached and maps removed from %s\n", iface);
  return SUCCESS;
}

/* ─── add_action ───────────────────────────────────────────────────────────── *
 * Three valid input combinations:                                               *
 *   -m <mac> -c <ip>  both given — use directly                                *
 *   -m <mac>          look up current IP from hg_mac_ip                        *
 *   -c <ip>           look up MAC from hg_ip_mac                               *
 * ---------------------------------------------------------------------------- */
int add_action(const char *iface, const char *mac, const char *ip,
               time_t expire, time_t idle,
               __u64 d_limit, __u64 u_limit, __u32 rate_id)
{
  (void)iface;

  struct hg_mac_key mac_key = {0};
  __u32 ip_key = 0;

  if (mac && ip)
  {
    if (sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &mac_key.mac[0], &mac_key.mac[1], &mac_key.mac[2],
               &mac_key.mac[3], &mac_key.mac[4], &mac_key.mac[5]) != 6)
    {
      fprintf(stderr, "hgctl: invalid MAC address '%s'\n", mac);
      return FAILED;
    }
    if (inet_pton(AF_INET, ip, &ip_key) != 1)
    {
      fprintf(stderr, "hgctl: invalid IP address '%s'\n", ip);
      return FAILED;
    }
  }
  else if (mac)
  {
    if (sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &mac_key.mac[0], &mac_key.mac[1], &mac_key.mac[2],
               &mac_key.mac[3], &mac_key.mac[4], &mac_key.mac[5]) != 6)
    {
      fprintf(stderr, "hgctl: invalid MAC address '%s'\n", mac);
      return FAILED;
    }
    int fd = bpf_obj_get(MAP_PATH(HG_MAC_IP_MAP));
    if (fd < 0)
    {
      fprintf(stderr, "hgctl: cannot open MAC→IP binding map\n");
      return FAILED;
    }
    if (bpf_map_lookup_elem(fd, &mac_key, &ip_key) != 0)
    {
      close(fd);
      fprintf(stderr, "hgctl: no binding found for MAC %s\n"
                      "       client must have sent at least one packet first\n",
              mac);
      return FAILED;
    }
    close(fd);
  }
  else if (ip)
  {
    if (inet_pton(AF_INET, ip, &ip_key) != 1)
    {
      fprintf(stderr, "hgctl: invalid IP address '%s'\n", ip);
      return FAILED;
    }
    int fd = bpf_obj_get(MAP_PATH(HG_IP_MAC_MAP));
    if (fd < 0)
    {
      fprintf(stderr, "hgctl: cannot open IP→MAC binding map\n");
      return FAILED;
    }
    if (bpf_map_lookup_elem(fd, &ip_key, &mac_key) != 0)
    {
      close(fd);
      fprintf(stderr, "hgctl: no binding found for IP %s\n"
                      "       client must have sent at least one packet first\n",
              ip);
      return FAILED;
    }
    close(fd);
  }
  else
  {
    fprintf(stderr, "hgctl: add requires -m <mac> or -c <ip> or both\n");
    return FAILED;
  }

  struct hg_client client_val = {0};
  struct hg_rate_cfg rate_val = {0};
  int client_fd, counter_fd, rate_fd;

  rate_val.rate_Bps_d = KBIT_TO_BPS(d_limit);
  rate_val.rate_Bps_u = KBIT_TO_BPS(u_limit);
  rate_val.horizon_ns = HG_HORIZON_NS;

  printf("hgctl: rate_id=%u  rate=%llu kbps  horizon=%llu ms\n",
         rate_id,
         BPS_TO_KBIT(rate_val.rate_Bps_d),
         rate_val.horizon_ns / 1000000ULL);

  __u64 now_ns = get_boottime_ns();
  client_val.expiry_ns = (expire > 0) ? (now_ns + (__u64)expire * NSEC_PER_SEC) : 0;
  client_val.idle_ns = (idle > 0) ? ((__u64)idle * NSEC_PER_SEC) : 0;
  client_val.auth_ns = now_ns;
  client_val.rate_limit_id = rate_id;
  client_val.last_u_tstamp = now_ns;
  client_val.last_d_tstamp = now_ns;

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

  /* insert client entry — keyed by MAC */
  if (bpf_map_update_elem(client_fd, &mac_key, &client_val, BPF_ANY))
  {
    fprintf(stderr, "hgctl: client map insert failed\n");
    close(client_fd);
    close(counter_fd);
    close(rate_fd);
    return FAILED;
  }

  /* initialise per-CPU counter entry — keyed by IP */
  int ncpu = libbpf_num_possible_cpus();
  struct hg_counter *zeros = calloc((size_t)ncpu, sizeof(struct hg_counter));
  if (!zeros)
  {
    fprintf(stderr, "hgctl: calloc failed for per-CPU counters\n");
    bpf_map_delete_elem(client_fd, &mac_key);
    close(client_fd);
    close(counter_fd);
    close(rate_fd);
    return FAILED;
  }

  if (bpf_map_update_elem(counter_fd, &ip_key, zeros, BPF_ANY))
  {
    fprintf(stderr, "hgctl: counter map insert failed\n");
    int rb = bpf_map_delete_elem(client_fd, &mac_key);
    fprintf(stderr, "hgctl: client rollback %s\n", rb == 0 ? "ok" : "failed");
    free(zeros);
    close(client_fd);
    close(counter_fd);
    close(rate_fd);
    return FAILED;
  }
  free(zeros);

  if (bpf_map_update_elem(rate_fd, &rate_id, &rate_val, BPF_ANY))
    fprintf(stderr, "hgctl: warning — rate map insert failed for id=%u "
                    "(client authenticated without rate limit)\n",
            rate_id);

  close(client_fd);
  close(counter_fd);
  close(rate_fd);

  char ip_str[16] = {0};
  struct in_addr a = {.s_addr = ip_key};
  snprintf(ip_str, sizeof(ip_str), "%s", inet_ntoa(a));
  printf("hgctl: client mac=%s ip=%s authenticated  expire=%lds idle=%lds\n",
         mac ? mac : "(resolved)", ip_str, expire, idle);
  return SUCCESS;
}

/* ─── del_action ───────────────────────────────────────────────────────────── */
int del_action(const char *iface, const char *mac)
{
  (void)iface;

  struct hg_mac_key mac_key = {0};
  if (sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
             &mac_key.mac[0], &mac_key.mac[1], &mac_key.mac[2],
             &mac_key.mac[3], &mac_key.mac[4], &mac_key.mac[5]) != 6)
  {
    fprintf(stderr, "hgctl: invalid MAC address '%s'\n", mac);
    return FAILED;
  }

  struct hg_client val = {0};
  int client_fd, counter_fd;
  int client_st, counter_st = -1, rate_st = -1;

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

  /* look up rate_id before deleting client entry */
  if (bpf_map_lookup_elem(client_fd, &mac_key, &val) == 0)
  {
    __u32 rate_id = val.rate_limit_id;
    int rate_fd = bpf_obj_get(MAP_PATH(HG_RATE_MAP));
    if (rate_fd >= 0)
    {
      rate_st = bpf_map_delete_elem(rate_fd, &rate_id);
      close(rate_fd);
    }
  }

  client_st = bpf_map_delete_elem(client_fd, &mac_key);

  /* resolve current IP for counter deletion */
  int mac_ip_fd = bpf_obj_get(MAP_PATH(HG_MAC_IP_MAP));
  if (mac_ip_fd >= 0)
  {
    __u32 ip_key = 0;
    if (bpf_map_lookup_elem(mac_ip_fd, &mac_key, &ip_key) == 0)
      counter_st = bpf_map_delete_elem(counter_fd, &ip_key);
    close(mac_ip_fd);
  }

  close(client_fd);
  close(counter_fd);

  printf("hgctl: del %s  client=%s  counter=%s  rate=%s\n", mac,
         client_st == 0 ? "removed" : "not found",
         counter_st == 0 ? "removed" : "not found",
         rate_st == 0 ? "removed" : "not found");
  return SUCCESS;
}

/* ─── resolve_ip_to_mac ─────────────────────────────────────────────────────── */
int resolve_ip_to_mac(const char *ip, char *mac_out, size_t mac_len)
{
  __u32 ip_key;
  if (inet_pton(AF_INET, ip, &ip_key) != 1)
    return FAILED;

  int fd = bpf_obj_get(MAP_PATH(HG_IP_MAC_MAP));
  if (fd < 0)
    return FAILED;

  struct hg_mac_key key = {0};
  bool found = (bpf_map_lookup_elem(fd, &ip_key, &key) == 0);
  close(fd);

  if (!found)
    return FAILED;

  snprintf(mac_out, mac_len, "%02x:%02x:%02x:%02x:%02x:%02x",
           key.mac[0], key.mac[1], key.mac[2],
           key.mac[3], key.mac[4], key.mac[5]);
  return SUCCESS;
}

/* ─── show_action ──────────────────────────────────────────────────────────── *
 * Prints a summary header + top-N client table sorted by download bytes.      *
 * Options (future CLI flags, currently using defaults):                        *
 *   --top N        show only top N clients  (default: 20)                     *
 *   --sort <key>   sort by dn_bytes|up_bytes|last_seen|age (default: dn_bytes) *
 *   --state <s>    filter by auth_ok|expire|block (default: all)              *
 * ---------------------------------------------------------------------------- */
int show_action(const char *iface)
{
  (void)iface;

  struct hg_client_stats *clients = NULL;
  struct hg_gateway_stats summary = {0};
  int count = 0;

  if (hg_read_all(&clients, &count,
                  HG_SORT_DN_BYTES, HG_FILTER_ALL, 20, &summary) < 0)
    return FAILED;

  /* ── summary header ── */
  char up_buf[16], dn_buf[16];
  hg_format_bytes(summary.total_up_bytes, up_buf, sizeof(up_buf));
  hg_format_bytes(summary.total_dn_bytes, dn_buf, sizeof(dn_buf));

  printf("\nHawkGate · %s   active: %d   expired: %d   "
         "total: ↑ %s  ↓ %s\n\n",
         iface,
         summary.active_clients,
         summary.expired_clients,
         up_buf, dn_buf);

  if (count == 0)
  {
    printf("  no clients\n\n");
    return SUCCESS;
  }

  /* ── table ── */
  printf("%-18s %-10s %-12s %-10s %-12s  %s\n",
         "IP", "State", "UP", "DN pkts", "DN", "Last seen");
  printf("%-18s %-10s %-12s %-10s %-12s  %s\n",
         "--", "-----", "--", "-------", "--", "---------");

  for (int i = 0; i < count; i++)
  {
    struct hg_client_stats *c = &clients[i];
    char up_b[16], dn_b[16];
    hg_format_bytes(c->up_bytes, up_b, sizeof(up_b));
    hg_format_bytes(c->dn_bytes, dn_b, sizeof(dn_b));

    printf("%-18s %-10s %-12s %-10lu %-12s  %lds ago\n",
           c->ip,
           hg_state_str(c->state),
           up_b,
           c->dn_packets,
           dn_b,
           c->age_sec);
  }

  printf("\n  showing top %d by download · use --top N or --state to filter\n\n",
         count);

  hg_stats_free(clients);
  show_protocols();
  return SUCCESS;
}

/* ─── details_action ───────────────────────────────────────────────────────── *
 * Deep-dive for a single client. Requires -c <ip>.                            *
 * Shows full session state, rate policy, EDT timestamps, and traffic counters. *
 * ---------------------------------------------------------------------------- */
int details_action(const char *iface)
{
  (void)iface;

  /* details without -c <ip> is not useful at scale — print guidance */
  fprintf(stderr,
          "hgctl: 'details' requires a client IP\n"
          "  usage: hgctl details -i <iface> -c <ip>\n"
          "  example: hgctl details -i br0 -c 192.168.100.10\n\n"
          "  for all clients use: hgctl show -i <iface>\n");
  return FAILED;
}

/* ─── details_one_action ────────────────────────────────────────────────────── *
 * Called by parse_details when -c <ip> is provided.                            *
 * ---------------------------------------------------------------------------- */
int details_one_action(const char *iface, const char *ip)
{
  (void)iface;

  struct hg_client_stats s = {0};
  if (hg_read_one(ip, &s) < 0)
    return FAILED;

  char up_b[16], dn_b[16];
  hg_format_bytes(s.up_bytes, up_b, sizeof(up_b));
  hg_format_bytes(s.dn_bytes, dn_b, sizeof(dn_b));

  /* format timestamps */
  char auth_buf[32] = "n/a";
  char expiry_buf[32] = "never";
  char seen_buf[32] = "n/a";

  if (s.auth_time > 0)
  {
    struct tm *t = localtime(&s.auth_time);
    strftime(auth_buf, sizeof(auth_buf), "%H:%M:%S", t);
  }
  if (s.expiry_time > 0)
  {
    struct tm *t = localtime(&s.expiry_time);
    strftime(expiry_buf, sizeof(expiry_buf), "%H:%M:%S", t);
  }
  if (s.last_seen > 0)
  {
    struct tm *t = localtime(&s.last_seen);
    strftime(seen_buf, sizeof(seen_buf), "%H:%M:%S", t);
  }

  /* TTL string */
  char ttl_buf[32];
  if (s.ttl_sec < 0)
    snprintf(ttl_buf, sizeof(ttl_buf), "never");
  else if (s.ttl_sec > 3600)
    snprintf(ttl_buf, sizeof(ttl_buf), "in %ldh %ldm",
             s.ttl_sec / 3600, (s.ttl_sec % 3600) / 60);
  else
    snprintf(ttl_buf, sizeof(ttl_buf), "in %ldm %lds",
             s.ttl_sec / 60, s.ttl_sec % 60);

  printf("\nClient  %s    %s\n\n", s.ip, hg_state_str(s.state));

  printf("  %-16s %s  (%lds ago)\n", "Auth time", auth_buf, s.session_sec);
  printf("  %-16s %s  (%s)\n", "Expires", expiry_buf, ttl_buf);
  printf("  %-16s id=%-4u  %lu kbps  horizon=%lums\n",
         "Rate policy", s.rate_id, s.rate_kbps_dw, s.horizon_ms);
  printf("\n");
  printf("  %-16s %s   in %lu packets\n", "Upload", up_b, s.up_packets);
  printf("  %-16s %s   in %lu packets\n", "Download", dn_b, s.dn_packets);
  printf("  %-16s %s  (%lds ago)\n", "Last seen", seen_buf, s.age_sec);
  printf("\n");

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

int map_del_action(const char *map_name, const char *key_spec)
{
  char path[128];
  snprintf(path, sizeof(path), "%s/%s", HG_PIN_DIR, map_name);

  int fd = bpf_obj_get(path);
  if (fd < 0)
  {
    fprintf(stderr, "hgctl: map-del — cannot open map '%s': %s\n",
            map_name, strerror(errno));
    return FAILED;
  }

  int ret = FAILED;

  /* ── hg_conntrack: key format "ip:port" ── */
  if (strcmp(map_name, XSTR(HG_CONNTRACK_MAP)) == 0)
  {
    char ip_buf[16] = {0};
    char *colon = strchr(key_spec, ':');
    if (!colon)
    {
      fprintf(stderr, "hgctl: map-del hg_conntrack: key must be <ip>:<port>\n");
      goto done;
    }
    size_t ip_len = (size_t)(colon - key_spec);
    if (ip_len >= sizeof(ip_buf))
    {
      fprintf(stderr, "hgctl: map-del: IP too long\n");
      goto done;
    }
    strncpy(ip_buf, key_spec, ip_len);

    struct hg_ct_key key = {0}; /* zero entire struct — pad must be zero */
    if (inet_pton(AF_INET, ip_buf, &key.client_ip) != 1)
    {
      fprintf(stderr, "hgctl: map-del: invalid IP '%s'\n", ip_buf);
      goto done;
    }
    key.client_port = (__u16)atoi(colon + 1);

    if (bpf_map_delete_elem(fd, &key) == 0)
    {
      printf("hgctl: map-del hg_conntrack %s — removed\n", key_spec);
      ret = SUCCESS;
    }
    else
    {
      fprintf(stderr, "hgctl: map-del hg_conntrack %s — not found\n", key_spec);
    }
  }

  /* ── hg_clients: key format "aa:bb:cc:dd:ee:ff" ── */
  else if (strcmp(map_name, XSTR(HG_CLIENT_MAP)) == 0)
  {
    struct hg_mac_key key = {0};
    if (sscanf(key_spec, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &key.mac[0], &key.mac[1], &key.mac[2],
               &key.mac[3], &key.mac[4], &key.mac[5]) != 6)
    {
      fprintf(stderr, "hgctl: map-del: invalid MAC '%s'\n", key_spec);
      goto done;
    }
    if (bpf_map_delete_elem(fd, &key) == 0)
    {
      printf("hgctl: map-del hg_clients %s — removed\n", key_spec);
      ret = SUCCESS;
    }
    else
    {
      fprintf(stderr, "hgctl: map-del hg_clients %s — not found\n", key_spec);
    }
  }

  /* ── hg_proto: key format "proto:sport:dport" ── */
  else if (strcmp(map_name, XSTR(HG_PROTO_MAP)) == 0)
  {
    char tmp[32];
    strncpy(tmp, key_spec, sizeof(tmp) - 1);
    char *p = strtok(tmp, ":");
    char *s = strtok(NULL, ":");
    char *d = strtok(NULL, ":");

    if (!p || !s || !d)
    {
      fprintf(stderr, "hgctl: map-del hg_proto: key must be <proto>:<sport>:<dport>\n");
      goto done;
    }

    struct hg_allow_key key = {0};
    key.proto = (__u8)atoi(p);
    key.s_port = (__u16)atoi(s);
    key.d_port = (__u16)atoi(d);

    if (bpf_map_delete_elem(fd, &key) == 0)
    {
      printf("hgctl: map-del hg_proto %s — removed\n", key_spec);
      ret = SUCCESS;
    }
    else
    {
      fprintf(stderr, "hgctl: map-del hg_proto %s — not found\n", key_spec);
    }
  }

  else
  {
    fprintf(stderr, "hgctl: map-del: unknown map '%s'\n", map_name);
    fprintf(stderr, "  supported: %s  %s  %s\n",
            XSTR(HG_CONNTRACK_MAP),
            XSTR(HG_CLIENT_MAP),
            XSTR(HG_PROTO_MAP));
  }

done:
  close(fd);
  return ret;
}

/* ─── bypass_add_action ────────────────────────────────────────────────────── */
int bypass_add_action(const char *ip)
{
  __u32 ip_key;
  if (inet_pton(AF_INET, ip, &ip_key) != 1)
  {
    fprintf(stderr, "hgctl: invalid IP address '%s'\n", ip);
    return FAILED;
  }
  int fd = bpf_obj_get(MAP_PATH(HG_BYPASS_MAP));
  if (fd < 0)
  {
    fprintf(stderr, "hgctl: cannot open bypass map\n");
    return FAILED;
  }
  __u8 val = 1;
  int ret = bpf_map_update_elem(fd, &ip_key, &val, BPF_ANY);
  close(fd);
  if (ret)
  {
    fprintf(stderr, "hgctl: bypass-add failed for %s\n", ip);
    return FAILED;
  }
  printf("hgctl: bypass added for %s\n", ip);
  return SUCCESS;
}

/* ─── bypass_del_action ────────────────────────────────────────────────────── */
int bypass_del_action(const char *ip)
{
  __u32 ip_key;
  if (inet_pton(AF_INET, ip, &ip_key) != 1)
  {
    fprintf(stderr, "hgctl: invalid IP address '%s'\n", ip);
    return FAILED;
  }
  int fd = bpf_obj_get(MAP_PATH(HG_BYPASS_MAP));
  if (fd < 0)
  {
    fprintf(stderr, "hgctl: cannot open bypass map\n");
    return FAILED;
  }
  int ret = bpf_map_delete_elem(fd, &ip_key);
  close(fd);
  if (ret)
  {
    fprintf(stderr, "hgctl: bypass-del: %s not found\n", ip);
    return FAILED;
  }
  printf("hgctl: bypass removed for %s\n", ip);
  return SUCCESS;
}

/* ─── wg_parse_cidr ────────────────────────────────────────────────────────── *
 * Parses "192.168.1.0/24" or "93.184.216.34" into an hg_wg_key, masking host  *
 * bits so the LPM_TRIE key is a valid prefix.                                 *
 * ---------------------------------------------------------------------------- */
static int wg_parse_cidr(const char *cidr, struct hg_wg_key *key)
{
  char ip_str[32] = {0};
  int prefix = 32; /* default: host route */

  const char *slash = strchr(cidr, '/');
  if (slash)
  {
    size_t ip_len = (size_t)(slash - cidr);
    if (ip_len >= sizeof(ip_str))
    {
      fprintf(stderr, "hgctl: invalid CIDR '%s'\n", cidr);
      return FAILED;
    }
    strncpy(ip_str, cidr, ip_len);
    ip_str[ip_len] = '\0';
    prefix = atoi(slash + 1);
  }
  else
  {
    strncpy(ip_str, cidr, sizeof(ip_str) - 1);
  }

  if (prefix < 0 || prefix > 32)
  {
    fprintf(stderr, "hgctl: invalid prefix length in '%s'\n", cidr);
    return FAILED;
  }

  memset(key, 0, sizeof(*key));
  if (inet_pton(AF_INET, ip_str, &key->ip) != 1)
  {
    fprintf(stderr, "hgctl: invalid IP '%s'\n", ip_str);
    return FAILED;
  }

  /* mask host bits so the stored prefix is exact */
  if (prefix == 0)
    key->ip = 0;
  else if (prefix < 32)
    key->ip &= htonl(0xFFFFFFFFu << (32 - prefix));
  key->prefixlen = (__u32)prefix;

  return SUCCESS;
}

/* ─── wg_add_action ────────────────────────────────────────────────────────── */
int wg_add_action(const char *cidr)
{
  struct hg_wg_key key;
  if (wg_parse_cidr(cidr, &key) != SUCCESS)
    return FAILED;

  int fd = bpf_obj_get(MAP_PATH(HG_WALLED_GARDEN_MAP));
  if (fd < 0)
  {
    fprintf(stderr, "hgctl: cannot open walled garden map\n");
    return FAILED;
  }

  __u8 val = 1;
  int ret = bpf_map_update_elem(fd, &key, &val, BPF_ANY);
  close(fd);
  if (ret)
  {
    fprintf(stderr, "hgctl: wg-add failed for %s\n", cidr);
    return FAILED;
  }

  struct in_addr a = {.s_addr = key.ip};
  printf("hgctl: walled garden added %s/%u\n", inet_ntoa(a), key.prefixlen);
  return SUCCESS;
}

/* ─── wg_del_action ────────────────────────────────────────────────────────── */
int wg_del_action(const char *cidr)
{
  struct hg_wg_key key;
  if (wg_parse_cidr(cidr, &key) != SUCCESS)
    return FAILED;

  int fd = bpf_obj_get(MAP_PATH(HG_WALLED_GARDEN_MAP));
  if (fd < 0)
  {
    fprintf(stderr, "hgctl: cannot open walled garden map\n");
    return FAILED;
  }

  int ret = bpf_map_delete_elem(fd, &key);
  close(fd);
  if (ret)
  {
    struct in_addr a = {.s_addr = key.ip};
    fprintf(stderr, "hgctl: wg-del: %s/%u not found\n", inet_ntoa(a), key.prefixlen);
    return FAILED;
  }

  struct in_addr a = {.s_addr = key.ip};
  printf("hgctl: walled garden removed %s/%u\n", inet_ntoa(a), key.prefixlen);
  return SUCCESS;
}
