#include "DHStorage.h"

int DHStorage::getBase()
{
    return base;
}

int DHStorage::getModulus()
{
    return modulus;
}

int DHStorage::getSessionKey()
{
    return sessionKey;
}

int DHStorage::getMyIV()
{
    return myIV;
}

FDR* DHStorage::getMyFDR()
{
    return &myFDR;
}

int DHStorage::getPartnerIV()
{
    return partnerIV;
}

FDR* DHStorage::getPartnerFDR()
{
    return &partnerFDR;
}

int DHStorage::getAnswerFDR()
{
    return answerFDR;
}

int DHStorage::calculateResult()
{
    int aux = pow(base, exponent);
    return aux % modulus;
}

int DHStorage::calculateSessionKey(int result)
{
    int aux = pow(result, exponent);
    return aux % modulus;
}

void DHStorage::setSessionKey(int _sessionKey)
{
    sessionKey = _sessionKey;
}

void DHStorage::setBase(int _base)
{
    base = _base;
}

void DHStorage::setModulus(int _modulus)
{
    modulus = _modulus;
}

void DHStorage::setExponent(int _exponent)
{
    exponent = _exponent;
}

void DHStorage::setMyIV(int iv)
{
    myIV = iv;
}

void DHStorage::setMyFDR(FDR fdr)
{
    myFDR = fdr;
}

void DHStorage::setPartnerIV(int iv)
{
    partnerIV = iv;
}

void DHStorage::setPartnerFDR(FDR fdr)
{
    partnerFDR = fdr;
}

void DHStorage::setAnswerFDR(int _answerFDR)
{
    answerFDR = _answerFDR;
}