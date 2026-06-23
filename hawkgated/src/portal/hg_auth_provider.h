#ifndef HG_AUTH_PROVIDER_H
#define HG_AUTH_PROVIDER_H

#include <string>
#include <cstdint>

// hg_auth_provider.h — the seam
class AuthProvider {
public:
    struct Credentials {
        std::string username;
        std::string password;
        std::string client_ip;
    };
    struct AuthResult {
        bool         success = false;
        std::string  message;
        uint32_t     expire_sec = 0;   // 0 = use config default
        uint32_t     down_kbps  = 0;    // 0 = use config default
        uint32_t     up_kbps = 0;      // 0 = use config default
    };
    virtual AuthResult authenticate(const Credentials& creds) = 0;
    virtual ~AuthProvider() = default;
};

#endif // HG_AUTH_PROVIDER_H