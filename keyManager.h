#ifndef KEY_MANAGER_H
#define KEY_MANAGER_H

#include <cmath>
#include "fdr.h"
#include "settings.h"

class KeyManager
{
    public:
        KeyManager();
        int getDiffieHellmanKey();
        int getDiffieHellmanKey(int base);
        int getServerPublicKey();
        int getServerPrivateKey();
        PublicRSAKey getClientPublicKey();
        void setClientPublicKey(PublicRSAKey PublicRSAKeyStruct);
        void setSessionKey(int _sessionKey);
        int getSessionKey();
        void setBase(int base);
        void setModulus(int modulus);

        int getIV();
        FDR* getFDR();
        void setIV(int _iv);
        void setFDR(FDR* _fdr);

    private:
        int exponent = 3;
        int base = 0;
        int modulus = 0;

        int sessionKey;
        int serverPublicKey = 8736;
        int serverPrivateKey = 3782;

        PublicRSAKey PublicRSAKeyStruct;

        int iv;
        FDR* fdr;
};

#endif
