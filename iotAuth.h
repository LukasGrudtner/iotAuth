#include "AES.h"

using namespace std;

class iotAuth
{
    protected:

    public:

        void encryptAES(int bits, int cipher_size, byte *key, byte plain[], unsigned long long int iv, byte cipher[]);
        void decryptAES(int bits, int cipher_size, byte *key, byte plain[], unsigned long long int iv, byte cipher[]);

    private:

        AES aes;
};
