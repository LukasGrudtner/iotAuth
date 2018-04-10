#include "keyManager.h"

KeyManager::KeyManager()
{
    fdr = new FDR();
}

int KeyManager::getDiffieHellmanKey()
{
    int r = pow(base, exponent);
    return r % modulus;
}

int KeyManager::getDiffieHellmanKey(int base)
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

void KeyManager::setSessionKey(int _sessionKey)
{
    sessionKey = _sessionKey;
}

int KeyManager::getSessionKey()
{
    return sessionKey;
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

void KeyManager::setIV(int _iv)
{
    iv = _iv;
}

FDR* KeyManager::getFDR()
{
    return fdr;
}

void KeyManager::setFDR(FDR* _fdr)
{
    fdr = _fdr;
}
