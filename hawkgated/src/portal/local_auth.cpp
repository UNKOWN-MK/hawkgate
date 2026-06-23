#include "local_auth.h"

auto LocalAuth::authenticate(const Credentials& creds) -> AuthResult
{
    AuthResult result;
    // For demonstration, we will just check if the username and password are "admin"
    if (creds.username == "admin" && creds.password == "admin")
    {
        result.success = true;
        result.message = "Authentication successful.";
        result.expire_sec = 0; // take default from config
        result.down_kbps = 0; // take default from config
        result.up_kbps = 0;    // take default from config
    } 
    else
    {
        result.success = false;
        result.message = "Invalid username or password.";
    }
    return result;
}