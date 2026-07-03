#include "hg_config.h"
#include "hg_log.h"
#include <fstream>
#include <arpa/inet.h>
#include <cctype>

HgConfig g_config;

static inline std::string trim(const std::string &str)
{
  size_t start = str.find_first_not_of(" \t\n\r");
  size_t end = str.find_last_not_of(" \t\n\r");
  if (start == std::string::npos || end == std::string::npos)
    return "";
  return str.substr(start, end - start + 1);
}

static std::vector<std::string> split_csv(const std::string &s)
{
  std::vector<std::string> result;
  size_t start = 0;
  while (true)
  {
    size_t pos = s.find(',', start);
    std::string token = trim(s.substr(start, pos == std::string::npos ? std::string::npos : pos - start));
    if (!token.empty())
    {
      for (auto &c : token)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      result.push_back(token);
    }
    if (pos == std::string::npos)
      break;
    start = pos + 1;
  }
  return result;
}

static bool is_config_valid()
{
  if (g_config.iface_name.empty())
    return false;
  if (g_config.http_port == 0)
    return false;
  if (g_config.portal_ip.empty())
    return false;
  if (g_config.session_timeout == 0)
    return false;
  if (g_config.max_clients == 0)
    return false;
  if (g_config.gateway_fqdn.empty())
    return false;

  return true;
}

bool load_config(const char *path)
{
  std::ifstream config_file(path);
  if (!config_file.is_open())
    return false;

  std::string line;
  std::string current_section;

  while (std::getline(config_file, line))
  {
    if (line.empty())
      continue;
    if (line[0] == '#')
      continue;

    if (line[0] == '[')
    {
      size_t close = line.find(']');
      if (close != std::string::npos)
        current_section = trim(line.substr(1, close - 1));
      continue;
    }

    std::string key, value;
    size_t pos = line.find('=');
    if (pos == std::string::npos)
      continue;

    key = trim(line.substr(0, pos));
    value = trim(line.substr(pos + 1));

    if (current_section == "preauth-protocol")
    {
      if (key == "l2")
      {
        auto tokens = split_csv(value);
        g_config.preauth_l2.insert(g_config.preauth_l2.end(), tokens.begin(), tokens.end());
      }
      else if (key == "l3")
      {
        auto tokens = split_csv(value);
        g_config.preauth_l3.insert(g_config.preauth_l3.end(), tokens.begin(), tokens.end());
      }
      else if (key == "l4")
      {
        auto tokens = split_csv(value);
        g_config.preauth_l4.insert(g_config.preauth_l4.end(), tokens.begin(), tokens.end());
      }
      continue;
    }

    if (current_section == "walled_garden")
    {
      if (key == "ip" && !value.empty())
        g_config.walled_garden_ips.push_back(value);
      continue;
    }

    if (key == "iface_name")
      g_config.iface_name = value;
    else if (key == "http_port")
    {
      try
      {
        unsigned long tmp = stoul(value);
        if (tmp == 0 || tmp > 65535)
        {
          log_error("Invalid http_port value");
          return false;
        }
        g_config.http_port = static_cast<uint16_t>(tmp);
      }
      catch (const std::exception &e)
      {
        log_error("Invalid http_port value");
        return false;
      }
    }
    else if (key == "portal_ip")
    {
      in_addr dst;
      if (inet_pton(AF_INET, value.c_str(), &dst) == 1)
        g_config.portal_ip = value;
      else
        return false;
    }
    else if (key == "session_timeout")
    {
      try
      {
        g_config.session_timeout = std::stoull(value);
      }
      catch (const std::exception &e)
      {
        log_error("Invalid session_timeout value");
        return false;
      }
    }
    else if (key == "max_clients")
    {
      try
      {
        g_config.max_clients = std::stoul(value);
      }
      catch (const std::exception &e)
      {
        log_error("Invalid max_clients value");
        return false;
      }
    }
    else if (key == "gateway_fqdn")
      g_config.gateway_fqdn = value;
    else if (key == "u_rate")
    {
      try
      {
        g_config.u_rate = std::stoul(value);
      }
      catch (const std::exception &e)
      {
        log_error("Invalid u_rate value");
        return false;
      }
    }
    else if (key == "d_rate")
    {
      try
      {
        g_config.d_rate = std::stoul(value);
      }
      catch (const std::exception &e)
      {
        log_error("Invalid d_rate value");
        return false;
      }
    }
    else if (key == "quota")
    {
      try
      {
        g_config.quota = std::stoull(value);
      }
      catch (const std::exception &e)
      {
        log_error("Invalid quota value");
        return false;
      }
    }
    else if (key == "portal_mode")
    {
      if (value == "builtin")
        g_config.portal_mode = PortalMode::BUILTIN;
      else if (value == "external_url")
        g_config.portal_mode = PortalMode::EXTERNAL_URL;
      else
      {
        log_warning("defaulting portal_mode to BUILTIN");
        g_config.portal_mode = PortalMode::BUILTIN;
      }
    }
  }

  return is_config_valid();
}
