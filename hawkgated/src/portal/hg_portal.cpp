#include "hg_portal.h"
#include "../util/hg_config.h"

static HgBpfCtrl *g_bpf = nullptr;

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

std::string handle_portal(const HttpRequest &req, const std::string &client_ip)
{
  auto it = req.headers.find("Host");
  std::string host = (it != req.headers.end()) ? it->second : "";
  HgClientStats stats;
  if (g_bpf->poll_one(client_ip, stats))
  {
    if (stats.state == AUTH_OK) // authenticated
    {
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
              response += "Content-Length: " + std::to_string(body_str.length()) + "\r\n\r\n" + body_str;
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
  std::string host_name = host.find(':') != std::string::npos ? host.substr(0, host.find(':')) : host;

  if (host_name == g_config.gateway_fqdn)
  {
    std::string form_body = "<html><body><h1>HawkGate Login</h1>"
                            "<form method=\"POST\" action=\"/login\">"
                            "Username: <input type=\"text\" name=\"username\"><br>"
                            "Password: <input type=\"password\" name=\"password\"><br>"
                            "<input type=\"submit\" value=\"Login\">"
                            "</form></body></html>";
    return "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: "
           + std::to_string(form_body.size()) + "\r\n\r\n" + form_body;
  }
  std::string loc = "http://" + g_config.gateway_fqdn + ":"
                + std::to_string(g_config.http_port) + "/portal";
  return "HTTP/1.1 302 Found\r\nLocation: " + loc + "\r\nContent-Length: 0\r\n\r\n";
}
