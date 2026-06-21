#ifndef HG_AUTH_H
#define HG_AUTH_H
#include "../http/hg_parser.h"
#include <string>

std::string handle_auth(const HttpRequest& req, const std::string& client_ip);
#endif // HG_AUTH_H