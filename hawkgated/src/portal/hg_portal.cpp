#include "hg_portal.h"

std::string handle_portal(const HttpRequest& req, const std::string& client_ip)
{
  return "HTTP/1.1 302 Found\r\nLocation: http://portal.hawkgate.local/portal\r\nContent-Length: 0\r\n\r\n";
}
