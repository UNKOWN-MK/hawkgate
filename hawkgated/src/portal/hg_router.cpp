#include "hg_router.h"
#include "../util/hg_log.h"
#include "hg_auth.h"
#include "hg_portal.h"

std::string route(const HttpRequest &req, const std::string &client_ip, uint16_t client_port)
{
  std::string msg = "route: " + req.method + " " + req.path +
   " from " + client_ip + ":" + std::to_string(client_port);
  
  log_debug(msg.c_str());
  if (req.path == "/login")
  {
    return handle_auth(req, client_ip, client_port);
  }
  else if (req.path == "/portal")
  {
    return handle_portal(req, client_ip);
  }
  else if (req.path.find("/api/v1/") == 0)
  {
    return "HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n";
  }
  else
  {
    return handle_portal(req, client_ip);
  }
}