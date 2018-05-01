#ifndef IOT_AUTH_H
#define IOT_AUTH_H

#include "utils.h"
#include <iostream>

using namespace std;

class iotAuth
{
    protected:

    public:

        void encryptHEX(byte plain[], int plain_size, char cipherHex[], int cipherHex_size);
        void decryptHEX(byte plain[], int plain_size, char cipherHex[], int cipherHex_size);

    private:

        Utils utils;
        AES aes;

        void encryptAES(int bits, int cipher_size, byte *key, byte plain[], unsigned long long int iv, byte cipher[]);
        void decryptAES(int bits, int cipher_size, byte *key, byte plain[], unsigned long long int iv, byte cipher[]);
};

#endif
