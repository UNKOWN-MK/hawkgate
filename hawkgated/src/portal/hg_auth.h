#ifndef HG_AUTH_H
#define HG_AUTH_H
#include "../http/hg_parser.h"
#include "hg_auth_provider.h"
#include "../bpf/hg_bpf_ctrl.h"
#include <string>

void init_auth(AuthProvider *p, HgBpfCtrl *b);
std::string handle_auth(const HttpRequest& req, const std::string& client_ip, uint16_t client_port);

#endif // HG_AUTH_H