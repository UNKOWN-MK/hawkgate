#include "hg_auth.h"

std::string handle_auth(const HttpRequest& req, const std::string& client_ip)
{
  return "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
}
