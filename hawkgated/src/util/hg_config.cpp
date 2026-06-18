#include "hg_config.h"
#include "hg_log.h"
#include <fstream>

HgConfig g_config;

static inline std::string trim(const std::string& str)
{
    size_t start = str.find_first_not_of(" \t\n\r");
    size_t end = str.find_last_not_of(" \t\n\r");
    if(start == std::string::npos || end == std::string::npos)
        return "";
    return str.substr(start,end-start+1);
}

static bool is_config_valid()
{
    if(g_config.iface_name.empty())
        return false;
    if(g_config.http_port == 0)
        return false;
    if(g_config.portal_ip.empty())
        return false;
    if(g_config.session_timeout == 0)
        return false;
    if(g_config.max_clients == 0)
        return false;
    if(g_config.gateway_fqdn.empty())
        return false;
   
    return true;
}

bool load_config(const char* path)
{
    std::ifstream config_file(path);
    if(!config_file.is_open())
    {
        return false;
    }
    //line by line parsing
    std::string line;
    while(std::getline(config_file,line))
    {
        if(line.empty()) continue;
        else if(line[0] == '#') continue;
        else
        {
            std::string key,value;
            size_t pos = line.find('=');
            if(pos != std::string::npos)
            {
                key = line.substr(0,pos);
                key = trim(key);
                value = line.substr(pos+1);
                value = trim(value);
                if(key == "iface_name")
                    g_config.iface_name = value;
                else if(key == "http_port")
                {
                    try
                    {
                        unsigned long tmp = stoul(value);
                        if(tmp == 0 || tmp > 65535)
                        {
                            log_error("Invalid http_port value");
                            return false;
                        }
                        g_config.http_port = static_cast<uint16_t>(tmp);
                    }
                    catch(const std::exception& e)
                    {
                        log_error("Invalid http_port value");
                        return false;
                    }
                }
                else if(key == "portal_ip")
                    g_config.portal_ip = value;
                else if(key == "session_timeout")
                {
                    try
                    {
                        g_config.session_timeout = std::stoull(value);
                    }
                    catch(const std::exception& e)
                    {
                        log_error("Invalid session_timeout value");
                        return false;
                    }
                }
                else if(key == "max_clients")
                {
                    try
                    {
                        g_config.max_clients = std::stoul(value);
                    }
                    catch(const std::exception& e)
                    {
                        log_error("Invalid max_clients value");
                        return false;
                    }
                    
                }
                else if(key == "gateway_fqdn")
                    g_config.gateway_fqdn = value;
                else if(key == "u_rate")
                {
                    try
                    {
                        g_config.u_rate = std::stoul(value);
                    }
                    catch(const std::exception& e)
                    {
                        log_error("Invalid u_rate value");
                        return false;
                    }
                }
                else if(key == "d_rate")
                {
                    try
                    {
                        g_config.d_rate = std::stoul(value);
                    }
                    catch(const std::exception& e)
                    {
                        log_error("Invalid d_rate value");
                        return false;
                    }
                }
                else if(key == "quota")
                {
                    try
                    {
                        g_config.quota = std::stoull(value);
                    }
                    catch(const std::exception& e)
                    {
                        log_error("Invalid quota value");
                        return false;
                    }
                }
                else
                    continue;
            }
            else 
                continue;

        }
    }

    return is_config_valid();   
}
