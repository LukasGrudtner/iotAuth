#include "keyManager.h"

int KeyManager::getKey()
{
    int r = pow(base, exponent);
    return r % modulus;
}

int KeyManager::getKey(int base)
{
    int r = pow(base, exponent);
    return r % modulus;
}

int KeyManager::getPublicKey()
{
    return publicKey;
}

int KeyManager::getPrivateKey()
{
    return privateKey;
}

void KeyManager::setSimpleKey(int _simpleKey)
{
    simpleKey = _simpleKey;
}

int KeyManager::getSimpleKey()
{
    return simpleKey;
}

void KeyManager::setBase(int _base)
{
    base = _base;
}

void KeyManager::setModulus(int _modulus)
{
    modulus = _modulus;
}
