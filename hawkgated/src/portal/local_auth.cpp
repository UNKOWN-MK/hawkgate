#include "local_auth.h"

auto LocalAuth::authenticate(const Credentials &creds) -> AuthResult
{

  (void)creds; /* click-through — no credentials needed */
  AuthResult result;
  result.success = true;
  result.message = "Connected.";
  result.expire_sec = 0;
  result.down_kbps = 0;
  result.up_kbps = 0;
  return result;
}