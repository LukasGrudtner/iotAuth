#include "DiffieHellmanPackage.h"
#include <iostream>

int DiffieHellmanPackage::getResult()
{
    return result;
}

int DiffieHellmanPackage::getBase()
{
    return g;
}

int DiffieHellmanPackage::getModulus()
{
    return p;
}

int DiffieHellmanPackage::getIV()
{
    return iv;
}

int DiffieHellmanPackage::getAnswerFDR()
{
    return answerFdr;
}

void DiffieHellmanPackage::setResult(int r)
{
    result = r;
}

void DiffieHellmanPackage::setBase(int base)
{
    g = base;
}

void DiffieHellmanPackage::setModulus(int modulus)
{
    p = modulus;
}

void DiffieHellmanPackage::setIV(int _iv)
{
    iv = _iv;
}

void DiffieHellmanPackage::setAnswerFDR(int aFdr)
{
    answerFdr = aFdr;
}

std::string DiffieHellmanPackage::toString()
{
    std::string result =    std::to_string(getResult())     + ":" +
                            std::to_string(getBase())       + ":" +
                            std::to_string(getModulus())    + ":" + 
                            std::to_string(getIV())         + ":" + 
                            std::to_string(getAnswerFDR());

    return result;
}
