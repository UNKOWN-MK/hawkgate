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

static std::string translate_l2(const std::string &name)
{
  if (name == "arp")
    return "0x0806";
  if (name == "ipv4")
    return "0x0800";
  if (name == "ipv6")
    return "0x86DD";
  if (name == "vlan")
    return "0x8100";
  if (name == "pppoe")
    return "0x8864";
  log_warning(("hg_bpf_ctrl: unknown preauth l2 protocol '" + name + "' — supported: arp,ipv4,ipv6,vlan,pppoe").c_str());
  return "";
}

static std::string translate_l3(const std::string &name)
{
  if (name == "icmp")
    return "1";
  if (name == "igmp")
    return "2";
  if (name == "tcp")
    return "6";
  if (name == "udp")
    return "17";
  if (name == "gre")
    return "47";
  if (name == "esp")
    return "50";
  if (name == "ah")
    return "51";
  if (name == "icmpv6")
    return "58";
  if (name == "ospf")
    return "89";
  if (name == "sctp")
    return "132";
  log_warning(("hg_bpf_ctrl: unknown preauth l3 protocol '" + name + "' — supported: icmp,igmp,tcp,udp,gre,esp,ah,icmpv6,ospf,sctp").c_str());
  return "";
}

static std::vector<std::string> translate_l4(const std::string &name)
{
  if (name == "dns")
    return {"17:any:53", "17:53:any"};
  if (name == "dhcp")
    return {"17:68:67", "17:67:68"};
  if (name == "ntp")
    return {"17:any:123", "17:123:any"};
  if (name == "http")
    return {"6:any:80", "6:80:any"};
  if (name == "https")
    return {"6:any:443", "6:443:any"};
  if (name == "mdns")
    return {"17:any:5353", "17:5353:any"};
  if (name == "llmnr")
    return {"17:any:5355", "17:5355:any"};
  if (name == "syslog")
    return {"17:any:514", "17:514:any"};
  if (name == "snmp")
    return {"17:any:161", "17:161:any"};
  log_warning(("hg_bpf_ctrl: unknown preauth l4 protocol '" + name + "' — supported: dns,dhcp,ntp,http,https,mdns,llmnr,syslog,snmp").c_str());
  return {};
}

static void apply_preauth_l2()
{
  for (const auto &name : g_config.preauth_l2)
  {
    std::string val = translate_l2(name);
    if (val.empty())
      continue;
    std::string flag = "--l2";
    const char *av[] = {
        "hgctl", "proto", "-a", "add",
        "-i", g_config.iface_name.c_str(),
        flag.c_str(), val.c_str(),
        nullptr};
    if (!exec_cmd(av))
      log_warning(("hg_bpf_ctrl: failed to add preauth l2: " + name).c_str());
    else
      log_info(("hg_bpf_ctrl: preauth l2 added: " + name).c_str());
  }
}

static void apply_preauth_l3()
{
  for (const auto &name : g_config.preauth_l3)
  {
    std::string val = translate_l3(name);
    if (val.empty())
      continue;
    std::string flag = "--l3";
    const char *av[] = {
        "hgctl", "proto", "-a", "add",
        "-i", g_config.iface_name.c_str(),
        flag.c_str(), val.c_str(),
        nullptr};
    if (!exec_cmd(av))
      log_warning(("hg_bpf_ctrl: failed to add preauth l3: " + name).c_str());
    else
      log_info(("hg_bpf_ctrl: preauth l3 added: " + name).c_str());
  }
}

static void apply_preauth_l4()
{
  std::string flag = "--l4";
  for (const auto &name : g_config.preauth_l4)
  {
    auto rules = translate_l4(name);
    if (rules.empty())
      continue;
    for (const auto &rule : rules)
    {
      std::string r = rule;
      const char *av[] = {
          "hgctl", "proto", "-a", "add",
          "-i", g_config.iface_name.c_str(),
          flag.c_str(), r.c_str(),
          nullptr};
      if (!exec_cmd(av))
        log_warning(("hg_bpf_ctrl: failed to add preauth l4: " + name).c_str());
    }
    log_info(("hg_bpf_ctrl: preauth l4 added: " + name + " (both directions)").c_str());
  }
}

static void apply_walled_garden()
{
  for (const auto &ip : g_config.walled_garden_ips)
  {
    std::string val = ip;
    const char *av[] = {
        "hgctl", "wg-add",
        "--ip", val.c_str(),
        nullptr};
    if (!exec_cmd(av))
      log_warning(("hg_bpf_ctrl: failed to add walled garden entry: " + val).c_str());
    else
      log_info(("hg_bpf_ctrl: walled garden added " + val).c_str());
  }
}

bool HgBpfCtrl::start_hgctl()
{
  /* attempt cleanup of any stale BPF state from a previous crash */
  const char *stop_argv[] = {
      "hgctl", "stop",
      "-i", g_config.iface_name.c_str(),
      nullptr};
  exec_cmd(stop_argv); /* return value intentionally ignored */
  log_info("hg_bpf_ctrl: cleaned up any stale BPF state");

  std::string port_str = std::to_string(g_config.http_port);
  const char *argv[] = {
      "hgctl", "start",
      "-i", g_config.iface_name.c_str(),
      "-P", g_config.portal_ip.c_str(),
      "-p", port_str.c_str(),
      nullptr};
  if (!exec_cmd(argv))
  {
    log_error("Failed to start hgctl");
    return false;
  }
  apply_preauth_l2();
  apply_preauth_l3();
  apply_preauth_l4();
  apply_walled_garden();
  return true;
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

  if (!auth.mac.empty())
  {
    const char *argv[] = {
        "hgctl", "add",
        "-i", g_config.iface_name.c_str(),
        "-m", auth.mac.c_str(),
        "-c", auth.ip.c_str(),
        "-e", expire.c_str(),
        "-w", idle.c_str(),
        "-D", dn.c_str(),
        "-U", up.c_str(),
        nullptr};
    return exec_cmd(argv);
  }
  /* mac not provided — hgctl resolves from hg_ip_mac (binding guaranteed by prior traffic) */
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

bool HgBpfCtrl::map_ele_del(const std::string &map_name, const std::string &key)
{
  const char *argv[] = {
      "hgctl", "map-del",
      "--map", map_name.c_str(),
      "--key", key.c_str(),
      nullptr};
  return exec_cmd(argv);
}
