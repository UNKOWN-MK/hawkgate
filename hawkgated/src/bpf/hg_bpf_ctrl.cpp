#include "hg_bpf_ctrl.h"
#include "../util/hg_config.h"
#include "../util/hg_log.h"
extern "C"
{
#include "../../kernel/hg_reader.h"
}
#include <unistd.h>
#include <sys/wait.h>
#include <arpa/inet.h>

static bool exec_cmd(const char *const argv[])
{
  pid_t pid = fork();
  if (pid == -1)
    return false;
  if (pid == 0)
  {
    execvp(argv[0], const_cast<char *const *>(argv));
    _exit(1);
  }
  int status;
  if (waitpid(pid, &status, 0) == -1)
    return false;
  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

bool HgBpfCtrl::poll_all(std::vector<HgClientStats> &res)
{
  struct hg_client_stats *out = NULL;
  int count = 0;
  if (hg_read_all(&out, &count, HG_SORT_DN_BYTES, HG_FILTER_ALL, 0, NULL) == -1)
    return false;
  struct StatsGuard
  {
    hg_client_stats *ptr;
    ~StatsGuard() { hg_stats_free(ptr); }
  };
  StatsGuard guard{out};
  for (int i = 0; i < count; i++)
  {
    HgClientStats entry;
    entry.ip = out[i].ip;
    entry.up_bytes = out[i].up_bytes;
    entry.up_packets = out[i].up_packets;
    entry.dn_bytes = out[i].dn_bytes;
    entry.dn_packets = out[i].dn_packets;
    entry.state = out[i].state;
    entry.auth_time = out[i].auth_time;
    entry.expiry_time = out[i].expiry_time;
    entry.last_seen = out[i].last_seen;
    entry.age_sec = out[i].age_sec;
    entry.session_sec = out[i].session_sec;
    entry.ttl_sec = out[i].ttl_sec;
    res.push_back(entry);
  }
  return true;
}

bool HgBpfCtrl::poll_one(const std::string &ip, HgClientStats &out)
{
  struct hg_client_stats raw;
  if (hg_read_one(ip.c_str(), &raw) == -1)
    return false;
  out.ip = raw.ip;
  out.up_bytes = raw.up_bytes;
  out.up_packets = raw.up_packets;
  out.dn_bytes = raw.dn_bytes;
  out.dn_packets = raw.dn_packets;
  out.state = raw.state;
  out.auth_time = raw.auth_time;
  out.expiry_time = raw.expiry_time;
  out.last_seen = raw.last_seen;
  out.age_sec = raw.age_sec;
  out.session_sec = raw.session_sec;
  out.ttl_sec = raw.ttl_sec;
  return true;
}

bool HgBpfCtrl::start_hgctl()
{
  std::string port_str = std::to_string(g_config.http_port);
  const char *argv[] = {
      "hgctl", "start",
      "-i", g_config.iface_name.c_str(),
      "-P", g_config.portal_ip.c_str(),
      "-p", port_str.c_str(),
      nullptr};
  return exec_cmd(argv);
}

bool HgBpfCtrl::stop_hgctl()
{
  const char *argv[] = {
      "hgctl", "stop",
      "-i", g_config.iface_name.c_str(),
      nullptr};
  return exec_cmd(argv);
}

bool HgBpfCtrl::authenticate(const client_auth &auth)
{
  struct in_addr dummy;
  if (inet_pton(AF_INET, auth.ip.c_str(), &dummy) != 1)
  {
    log_error("authenticate: invalid IP address");
    return false;
  }
  std::string expire = std::to_string(auth.expiry_sec);
  std::string idle = std::to_string(auth.idle_sec);
  std::string dn = std::to_string(auth.dn_rate);
  std::string up = std::to_string(auth.up_rate);
  const char *argv[] = {
      "hgctl", "add",
      "-i", g_config.iface_name.c_str(),
      "-c", auth.ip.c_str(),
      "-e", expire.c_str(),
      "-w", idle.c_str(),
      "-D", dn.c_str(),
      "-U", up.c_str(),
      nullptr};
  return exec_cmd(argv);
}

bool HgBpfCtrl::deauthenticate(const std::string &ip)
{
  struct in_addr dummy;
  if (inet_pton(AF_INET, ip.c_str(), &dummy) != 1)
  {
    log_error("deauthenticate: invalid IP address");
    return false;
  }
  const char *argv[] = {
      "hgctl", "del",
      "-i", g_config.iface_name.c_str(),
      "-c", ip.c_str(),
      nullptr};
  return exec_cmd(argv);
}
