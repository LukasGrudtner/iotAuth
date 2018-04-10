#include <cmath>
#include "fdr.h"

class KeyManager
{
    public:
        KeyManager();
        int getKey();
        int getKey(int base);
        int getServerPublicKey();
        int getServerPrivateKey();
        int getClientPublicKey();
        void setClientPublicKey(int _clientPublicKey);
        void setSimpleKey(int simpleKey);
        int getSimpleKey();
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

        int simpleKey;
        int serverPublicKey = 8736;
        int serverPrivateKey = 3782;

        int clientPublicKey;

        int iv;
        FDR* fdr;
};
