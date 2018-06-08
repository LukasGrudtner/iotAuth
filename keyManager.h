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
        RSAKey getMyPublicKey();
        RSAKey getMyPrivateKey();
        void setRSAKeyPair(RSAKeyPair keys);
        RSAKey getPartnerPublicKey();
        void setPartnerPublicKey(RSAKey publicKey);
        void setSessionKey(int _sessionKey);
        int getSessionKey();
        void setBase(int base);
        void setModulus(int modulus);
        void setExponent(int exponent);
        void setMyIV(int _myIV);

        int getBase();
        int getModulus();
        int getMyIV();
        int getExponent();
        FDR* getMyFDR();
        void setMyFDR(FDR* _fdr);

    private:
        int exponent = 0; // a
        int base = 0; // g
        int modulus = 0; // p

        int sessionKey;
        RSAKeyPair rsaKeys;

        RSAKey partnerPublicKey;

        int myIV = 0;
        FDR* myFdr;
};

#endif
