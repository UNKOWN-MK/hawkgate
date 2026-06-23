#ifndef HG_PORTAL_H
#define HG_PORTAL_H

#include <string>
#include "../http/hg_parser.h"
#include "../bpf/hg_bpf_ctrl.h"

typedef struct OsProbe 
{
  const char *host;
  const char *path;
  int         status;        // 200 or 204
  const char *body;          // nullptr for 204
  const char *content_type;  // "text/plain" or "text/html"
}OsProbe;


void init_portal(HgBpfCtrl *b);
std::string handle_portal(const HttpRequest& req, const std::string& client_ip);

#endif // HG_PORTAL_H