#include "keyManager.h"

KeyManager::KeyManager()
{

}

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

int KeyManager::getServerPublicKey()
{
    return serverPublicKey;
}

int KeyManager::getServerPrivateKey()
{
    return serverPrivateKey;
}

int KeyManager::getClientPublicKey()
{
    return clientPublicKey;
}

void KeyManager::setClientPublicKey(int _clientPublicKey)
{
    clientPublicKey = _clientPublicKey;
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

int KeyManager::getIV()
{
    return iv;
}

FDR* KeyManager::getFDR()
{
    return fdr;
}

void KeyManager::setIV(int _iv)
{
    iv = _iv;
}

void KeyManager::setFDR(FDR* _fdr)
{
    fdr = _fdr;
}
