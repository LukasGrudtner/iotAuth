#ifndef IOT_AUTH_H
#define IOT_AUTH_H

#include "settings.h"
#include "utils.h"
#include "RSA.h"
#include "sha512.h"
#include <string>
#include <iostream>
#include <sstream>
#include "aes.h"

using namespace std;

class IotAuth
{
    protected:

    public:

        uint8_t* encryptAES(uint8_t plaintext[], uint8_t key[], uint8_t iv[], int size);
        uint8_t* decryptAES(uint8_t ciphertext[], uint8_t key[], uint8_t iv[], int size);

        // void encryptHEX(byte plain[], int plain_size, char cipherHex[], int cipherHex_size);
        // void decryptHEX(byte plain[], int plain_size, char cipherHex[], int cipherHex_size);

        RSAKeyPair generateRSAKeyPair();

        string hash(char message[]);

        string encryptRSAPublicKey(string plain, PublicRSAKey publicKey, int size);
        string encryptRSAPrivateKey(string plain, PrivateRSAKey privateKey, int size);
        string decryptRSAPublicKey(int cipher[], PublicRSAKey publicKey, int size);
        string decryptRSAPrivateKey(int cipher[], PrivateRSAKey privateKey, int size);

    private:

        Utils utils;
        AES aes;
        RSA rsa;
};
#endif
