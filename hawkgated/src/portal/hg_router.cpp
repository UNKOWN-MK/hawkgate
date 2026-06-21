#include "hg_router.h"
#include "../util/hg_log.h"
#include "hg_auth.h"
#include "hg_portal.h"

std::string route(const HttpRequest &req, const std::string &client_ip)
{
  log_debug("Routing request from ");
  if (req.path == "/login")
  {
    return handle_auth(req, client_ip);
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