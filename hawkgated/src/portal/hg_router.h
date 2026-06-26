#ifndef HG_ROUTER_H
#define HG_ROUTER_H

#include <string>
#include <functional>
#include "../http/hg_parser.h"

using Handler = std::function<std::string(const HttpRequest&, const std::string&)>;
std::string route(const HttpRequest& req, const std::string& client_ip, uint16_t client_port);


#endif // HG_ROUTER_H