#ifndef RSA_STORAGE_H
#define RSA_STORAGE_H

#include "../settings.h"

class RSAStorage
{
    public:
        RSAKey* getMyPublicKey();
        RSAKey* getMyPrivateKey();
        RSAKey* getPartnerPublicKey();

        int getMyIV();
        FDR* getMyFDR();

        int getPartnerIV();
        FDR* getPartnerFDR();

        void setKeyPair(RSAKeyPair keys);
        void setPartnerPublicKey(RSAKey key);

        void setMyIV(int iv);
        void setMyFDR(FDR fdr);

        void setPartnerIV(int iv);
        void setPartnerFDR(FDR fdr);

    private:
        RSAKey myPublicKey;
        RSAKey myPrivateKey;
        RSAKey partnerPublicKey;

        int myIV;
        int partnerIV;

        FDR myFDR;
        FDR partnerFDR;

};

#endif