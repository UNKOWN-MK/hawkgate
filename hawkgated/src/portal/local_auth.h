#ifndef LOCAL_AUTH_H
#define LOCAL_AUTH_H

#include "hg_auth_provider.h"

class LocalAuth  : public AuthProvider {
public:
  AuthResult authenticate(const Credentials& creds) override;
};

#endif // LOCAL_AUTH_H