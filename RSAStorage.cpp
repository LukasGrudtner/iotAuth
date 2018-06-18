#include "RSAStorage.h"

RSAKey* RSAStorage::getMyPublicKey()
{
    return &myPublicKey;
}

RSAKey* RSAStorage::getMyPrivateKey()
{
    return &myPrivateKey;
}

RSAKey* RSAStorage::getPartnerPublicKey()
{
    return &partnerPublicKey;
}

int RSAStorage::getMyIV()
{
    return myIV;
}

FDR* RSAStorage::getMyFDR()
{
    return &myFDR;
}

int RSAStorage::getPartnerIV()
{
    return partnerIV;
}

FDR* RSAStorage::getPartnerFDR()
{
    return &partnerFDR;
}

void RSAStorage::setKeyPair(RSAKeyPair keys)
{
    myPublicKey = keys.publicKey;
    myPrivateKey = keys.privateKey;
}

void RSAStorage::setPartnerPublicKey(RSAKey key)
{
    partnerPublicKey = key;
}

void RSAStorage::setMyIV(int iv)
{
    myIV = iv;
}

void RSAStorage::setMyFDR(FDR fdr)
{
    myFDR = fdr;
}

void RSAStorage::setPartnerIV(int iv)
{
    partnerIV = iv;
}

void RSAStorage::setPartnerFDR(FDR fdr)
{
    partnerFDR = fdr;
}