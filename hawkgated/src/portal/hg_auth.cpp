#include "hg_auth.h"
#include "../util/hg_config.h"
#include "../util/hg_log.h"

static AuthProvider *g_provider = nullptr;
static HgBpfCtrl *g_bpf = nullptr;

static inline std::string parse_form_field(const std::string &body, const std::string &field_name)
{
  std::string search_str = field_name + "=";
  size_t start_pos = body.find(search_str);
  if (start_pos == std::string::npos)
  {
    return "";
  }
  start_pos += search_str.length();
  size_t end_pos = body.find("&", start_pos);
  if (end_pos == std::string::npos)
  {
    end_pos = body.length();
  }
  return body.substr(start_pos, end_pos - start_pos);
}

void init_auth(AuthProvider *p, HgBpfCtrl *b)
{
  g_provider = p;
  g_bpf = b;
}

std::string handle_auth(const HttpRequest &req, const std::string &client_ip, uint16_t client_port)
{
  std::string username = parse_form_field(req.body, "username");
  std::string password = parse_form_field(req.body, "password");
  AuthProvider::Credentials creds;
  creds.username = username;
  creds.password = password;
  creds.client_ip = client_ip;
  AuthProvider::AuthResult result = g_provider->authenticate(creds);
  if (result.success)
  {
    client_auth auth;
    auth.ip = client_ip;
    auth.client_port = client_port;
    auth.expiry_sec = result.expire_sec ? result.expire_sec : g_config.session_timeout;
    auth.dn_rate = result.down_kbps ? result.down_kbps : g_config.d_rate;
    auth.up_rate = result.up_kbps ? result.up_kbps : g_config.u_rate;
    auth.idle_sec = 0; // not used for now, can be extended to support idle timeout in the future
    if (!g_bpf->authenticate(auth))
    {
      log_error("Failed to authenticate client in kernel");
      std::string response_body = "{\"message\": \"Authentication succeeded but failed to apply in kernel\"}";
      return "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(response_body.length()) + "\r\n\r\n" + response_body;
    }
    if (!g_bpf->map_ele_del("hg_conntrack", client_ip + ":" + std::to_string(client_port)))
    {
      log_warning("Failed to delete portal config from kernel");
    }
    std::string loc = "http://" + g_config.gateway_fqdn + ":" + std::to_string(g_config.http_port) + "/portal/success";
    return "HTTP/1.1 302 Found\r\n"
           "Location: " +
           loc + "\r\n"
                 "Content-Length: 0\r\n\r\n";
  }
  else
  {
    std::string response_body = "{\"message\": \"" + result.message + "\"}";
    return "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: " + 
      std::to_string(response_body.length()) + "\r\n\r\n" + response_body;
  }
}
