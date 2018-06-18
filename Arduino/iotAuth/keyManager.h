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
        
        long int getClientPublicKeyD();
        long int getClientPublicKeyN();
        
        long int getClientPrivateKeyE();
        long int getClientPrivateKeyN();

        long int getServerPublicKeyD();
        long int getServerPublicKeyN();
        
        void setRSAKeyPair(RSAKeyPair keys);
        
        void setServerPublicKey(PublicRSAKey publicKey);
        
        void setSessionKey(int _sessionKey);
        int getSessionKey();
        void setBase(int base);
        void setModulus(int modulus);

        int getBase();
        int getModulus();
        int getIV();
        FDR* getFDR();
        void setIV(int _iv);
        void setFDR(FDR* _fdr);

    private:
        int exponent = 3; // a
        int base = 0; // g
        int modulus = 0; // p

        int sessionKey;
        RSAKeyPair rsaKeys;

        PublicRSAKey serverPublicKey;
        
        long int iv;
        FDR* fdr;
};

#endif
