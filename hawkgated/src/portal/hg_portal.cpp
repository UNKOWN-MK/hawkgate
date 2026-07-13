#include "hg_portal.h"
#include "../util/hg_config.h"
#include "../util/hg_log.h"
#include <fstream>

static HgBpfCtrl *g_bpf = nullptr;

/* ── embedded portal pages ─────────────────────────────────────────────────── */
static const char *LOGIN_PAGE = "/etc/hawkgate/static/login.html";

static const char *SUCCESS_PAGE = "/etc/hawkgate/static/success.html";

static const OsProbe g_probes[] = {
    {"connectivitycheck.gstatic.com", "/generate_204",
     204, nullptr, nullptr},
    {"www.google.com", "/generate_204",
     204, nullptr, nullptr},
    {"captive.apple.com", "/hotspot-detect.html",
     200, "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>",
     "text/html"},
    {"www.msftconnecttest.com", "/connecttest.txt",
     200, "Microsoft Connect Test", "text/plain"},
    {"www.msftncsi.com", "/ncsi.txt",
     200, "Microsoft NCSI", "text/plain"},
    {"detectportal.firefox.com", "/success.txt",
     200, "success\n", "text/plain"},
    {nullptr, nullptr, 0, nullptr, nullptr}};

void init_portal(HgBpfCtrl *b)
{
  g_bpf = b;
}

static std::string read_html_file(const char *path)
{
  std::ifstream f(path);
  if (!f.is_open())
  {
    log_warning("portal: cannot open HTML file");
    return "<html><body><h2>Portal unavailable</h2></body></html>";
  }
  return std::string(std::istreambuf_iterator<char>(f),
                     std::istreambuf_iterator<char>());
}

std::string handle_portal(const HttpRequest &req, const std::string &client_ip)
{
  auto it = req.headers.find("Host");
  std::string host = (it != req.headers.end()) ? it->second : "";
  std::string host_name = host.find(':') != std::string::npos
                        ? host.substr(0, host.find(':')) : host;

  HgClientStats stats;
  if (g_bpf->poll_one(client_ip, stats))
  {
    if (stats.state == AUTH_OK)
    {
      /* authenticated — serve exact OS probe response */
      for (auto &probe : g_probes)
      {
        if (probe.host && probe.path && probe.status)
        {
          if (host == probe.host && req.path == probe.path)
          {
            std::string response = "HTTP/1.1 " + std::to_string(probe.status) + " ";
            response += (probe.status == 200) ? "OK" : "No Content";
            response += "\r\n";
            if (probe.content_type)
              response += "Content-Type: " + std::string(probe.content_type) + "\r\n";
            if (probe.body)
            {
              std::string body_str = probe.body;
              response += "Content-Length: " + std::to_string(body_str.length())
                        + "\r\n\r\n" + body_str;
            }
            else
              response += "Content-Length: 0\r\n\r\n";
            return response;
          }
        }
      }
      return "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
    }
  }

 /* unauthenticated — serve login page for /portal directly,
 * redirect everything else to /portal with 307               */
if (host_name == g_config.gateway_fqdn || req.path == "/portal")
{
    std::string body = read_html_file(LOGIN_PAGE);
    return "HTTP/1.1 200 OK\r\n"
           "Content-Type: text/html\r\n"
           "Content-Length: " + std::to_string(body.size())
         + "\r\n\r\n" + body;
}

/* everything else — 307 redirect to portal with HTML fallback */
std::string loc = "http://" + g_config.portal_ip + ":"
                + std::to_string(g_config.http_port) + "/portal";
std::string fallback = "<html><head></head><body>"
                       "<a href='" + loc + "'>Click here to sign in</a>"
                       "</body></html>";
return "HTTP/1.1 307 Temporary Redirect\r\n"
       "Location: " + loc + "\r\n"
       "Content-Type: text/html\r\n"
       "Content-Length: " + std::to_string(fallback.size()) + "\r\n\r\n"
       + fallback;
}

std::string handle_capport(const HttpRequest &req, const std::string &client_ip)
{
  (void)req;
  std::string body;
  HgClientStats stats;

  if (g_bpf->poll_one(client_ip, stats) && stats.state == AUTH_OK)
  {
    /* authenticated — tell device it has internet */
    long ttl = stats.ttl_sec > 0 ? stats.ttl_sec : 0;
    body = "{\"captive\":false,\"seconds-remaining\":"
         + std::to_string(ttl) + "}";
  }
  else
  {
    /* unauthenticated — tell device there is a portal */
    std::string portal_url = "http://" + g_config.gateway_fqdn
                           + ":" + std::to_string(g_config.http_port)
                           + "/portal";
    body = "{\"captive\":true,"
           "\"user-portal-url\":\"" + portal_url + "\","
           "\"venue-info-url\":\"" + portal_url + "\"}";
  }

  return "HTTP/1.1 200 OK\r\n"
         "Content-Type: application/captive+json\r\n"
         "Cache-Control: no-cache\r\n"
         "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n"
         + body;
}

std::string handle_success(const HttpRequest &req, const std::string &client_ip)
{
  (void)req;
  (void)client_ip;
  std::string body = read_html_file(SUCCESS_PAGE);
  /* inject redirect URL */
  std::string placeholder = "http://example.com";
  size_t pos = body.find(placeholder);
  while (pos != std::string::npos)
  {
    body.replace(pos, placeholder.size(), "https://www.google.com");
    pos = body.find(placeholder, pos);
  }
  return "HTTP/1.1 200 OK\r\n"
         "Content-Type: text/html\r\n"
         "Content-Length: " +
         std::to_string(body.size()) + "\r\n\r\n" + body;
}
