#ifndef IOT_AUTH_H
#define IOT_AUTH_H

#include "settings.h"
#include "utils.h"
#include "RSA.h"
#include "sha512.h"
#include "fdr.h"
#include <string>
#include <iostream>
#include <sstream>
#include "aes.h"
#include <unistd.h>

using namespace std;

class IotAuth
{
    protected:

    public:

        uint8_t* encryptAES(uint8_t plaintext[], uint8_t key[], uint8_t iv[], int size);
        uint8_t* decryptAES(uint8_t ciphertext[], uint8_t key[], uint8_t iv[], int size);

        RSAKeyPair generateRSAKeyPair();
        int generateIV();
        FDR* generateFDR();

        string hash(char message[]);
        bool isHashValid(string message, string hash);

        string encryptRSA(string plain, RSAKey rsaKey, int size);
        string decryptRSA(int cipher[], RSAKey rsaKey, int size);

    private:

        int randomNumber(int upperBound);

        Utils utils;
        AES aes;
        RSA rsa;
};
#endif
