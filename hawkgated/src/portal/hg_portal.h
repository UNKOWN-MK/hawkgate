#ifndef HG_PORTAL_H
#define HG_PORTAL_H

#include <string>
#include "../http/hg_parser.h"
std::string handle_portal(const HttpRequest& req, const std::string& client_ip);

#endif // HG_PORTAL_H