#include <cmath>

class KeyManager
{
    public:
        // KeyManager(int argc, char** argv);
        int getKey();
        int getKey(int base);
        int getPublicKey();
        int getPrivateKey();
        void setSimpleKey(int simpleKey);
        int getSimpleKey();
        void setBase(int base);
        void setModulus(int modulus);

    private:
        int exponent = 3;
        int base = 0;
        int modulus = 0;
        int simpleKey;
        int publicKey = 8736;
        int privateKey = 3782;

};
