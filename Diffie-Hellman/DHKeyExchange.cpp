#include "DHKeyExchange.h"

DHKeyExchange::DHKeyExchange()
{
    memset(encryptedHash, 0, sizeof(encryptedHash));
    memset(diffieHellmanPackage, 0, sizeof(diffieHellmanPackage));
}

int* DHKeyExchange::getEncryptedHash()
{
    return encryptedHash;
}

byte* DHKeyExchange::getDiffieHellmanPackage()
{
    return diffieHellmanPackage;
}

void DHKeyExchange::setEncryptedHash(int encHash[])
{
    for (int i = 0; i < 128; i++) {
        encryptedHash[i] = encHash[i];
    }
}

void DHKeyExchange::setDiffieHellmanPackage(byte dhPackage[])
{
    for (int i = 0; i < sizeof(diffieHellmanPackage); i++) {
        diffieHellmanPackage[i] = dhPackage[i];
    }
}
