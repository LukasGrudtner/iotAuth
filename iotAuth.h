#ifndef IOT_AUTH_H
#define IOT_AUTH_H

#include "settings.h"
#include "utils.h"
#include "RSA.h"
#include "sha512.h"
#include <iostream>

using namespace std;

class iotAuth
{
    protected:

    public:

        void encryptHEX(byte plain[], int plain_size, char cipherHex[], int cipherHex_size);
        void decryptHEX(byte plain[], int plain_size, char cipherHex[], int cipherHex_size);
        RSAKeyPair generateRSAKeyPair();
        string hash(string message);
        string hashDHPackage(DHPackage DHPackageStruct);

    private:

        Utils utils;
        AES aes;
        RSA rsa;

        void encryptAES(int bits, int cipher_size, byte *key, byte plain[], unsigned long long int iv, byte cipher[]);
        void decryptAES(int bits, int cipher_size, byte *key, byte plain[], unsigned long long int iv, byte cipher[]);
};

#endif
