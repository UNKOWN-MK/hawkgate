#ifndef HG_BPF_CTRL_H
#define HG_BPF_CTRL_H
#include <string>
#include <vector>
#include <cstdint>
#include <ctime>

typedef struct HgClientStats
{
  /* identity */
  std::string ip; /*e.g. "192.168.100.10"  */
  /* traffic counters (aggregated across all CPUs) */
  uint64_t up_bytes;
  uint64_t up_packets;
  uint64_t dn_bytes;
  uint64_t dn_packets;
  /* session metadata */
  int state; /* enum client_status value*/
  /* timestamps — all as wall-clock time_t for easy formatting */
  time_t auth_time;   /* when session was created*/
  time_t expiry_time; /* when session expires (0 = never)*/
  time_t last_seen;   /* last packet timestamp*/
  time_t age_sec;     /* seconds since last packet*/
  time_t session_sec; /* seconds since auth*/
  long ttl_sec;       /* seconds until expiry (-1 = never)*/
} HgClientStats;

typedef struct client_auth
{
  std::string ip;
  uint32_t expiry_sec;
  uint32_t idle_sec;
  uint32_t dn_rate;
  uint32_t up_rate;
} client_auth;

class HgBpfCtrl
{
public:
  bool poll_all(std::vector<HgClientStats> &res);
  bool poll_one(const std::string &ip, HgClientStats &out);
  bool start_hgctl ();
  bool stop_hgctl();
  bool authenticate(const client_auth &);
  bool deauthenticate(const std::string &ip);
};

#endif // end of the fil