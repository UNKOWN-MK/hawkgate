#include "http/hg_server.h"
#include "util/hg_log.h"
#include "util/hg_config.h"
#include "bpf/hg_bpf_ctrl.h"
#include "portal/hg_auth.h"
#include "portal/local_auth.h"
#include "portal/hg_portal.h"

#include <filesystem>
#include <string>
#include <signal.h>

static HgServer  *g_server = nullptr;
static HgBpfCtrl *g_bpf_ctrl = nullptr;

void signal_handler(int sig)
{
  if (g_server)
    g_server->stop();
  if (g_bpf_ctrl)
    g_bpf_ctrl->stop_hgctl();
}

int main(int argc, char *argv[])
{
  std::string config_path = "/etc/hawkgate/hawkgate.conf";
  if(argc == 3)
  {
    if(argv[1] && std::string(argv[1]) == "-c")
    {
      config_path = argv[2];
      if (!std::filesystem::exists(config_path))
      {
        std::string err_msg = "Failed to load config from " + config_path + "\n";
        log_error(err_msg.c_str());
        return EXIT_FAILURE;
      }
    }
    else
    {
      log_warning("Config file not specified, using default config path: /etc/hawkgate/hawkgate.conf");
    }
  }
  else if(argc == 1)
  {
    log_warning("Config file not specified, using default config path: /etc/hawkgate/hawkgate.conf");
  }
  else //help or invalid args
  {
    std::string usage = "Usage: " + std::string(argv[0]) + " -c <config_file>\n";
    log_error(usage.c_str());
    return EXIT_FAILURE;
  }
  //Load the config file
  if(!load_config(config_path.c_str()))
  {
    log_error("Failed to load config, check the config file for errors");
    return EXIT_FAILURE;
  }
  set_log_level(g_config.log_level);
  //Initialize and run of kernel module
  HgBpfCtrl bpf;
  g_bpf_ctrl = &bpf;
  if (!bpf.start_hgctl())
  { 
    log_error("Failed to start hgctl"); 
    return EXIT_FAILURE; 
  }
  LocalAuth g_auth_provider;
  init_auth(&g_auth_provider, &bpf);
  init_portal(&bpf);
  HgServer server;
  g_server = &server;
  if (!g_server->init())
  {
    log_error("Failed to initialize server");
    return EXIT_FAILURE;
  }
  // Set up signal handlers for graceful shutdown
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  server.run();
  bpf.stop_hgctl();

  return EXIT_SUCCESS;
}