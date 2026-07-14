#ifndef HG_CONFIG_H
#define HG_CONFIG_H

#include "hg_log.h"
#include <string>
#include <cstdint>
#include <vector>

enum class PortalMode { BUILTIN, EXTERNAL_URL };

typedef struct config
{
    LogLevel log_level = LogLevel::INFO;
    std::string iface_name;
    uint16_t http_port;
    std::string portal_ip;
    uint64_t session_timeout;
    uint32_t max_clients;
    std::string gateway_fqdn;
    uint32_t u_rate;
    uint32_t d_rate;
    uint64_t quota;
    PortalMode portal_mode = PortalMode::BUILTIN;
    std::vector<std::string> preauth_l2;
    std::vector<std::string> preauth_l3;
    std::vector<std::string> preauth_l4;
    std::vector<std::string> walled_garden_ips;
}HgConfig;

extern HgConfig g_config;
bool load_config(const char* path);
#endif // HG_CONFIG_H