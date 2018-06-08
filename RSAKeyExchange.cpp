#include "RSAKeyExchange.h"

RSAKeyExchange::RSAKeyExchange() {
    publicKey = {0,0};
}

RSAKey RSAKeyExchange::getPublicKey() {
    return publicKey;
}

int RSAKeyExchange::getAnswerFDR() {
    return answerFdr;
}

int RSAKeyExchange::getIV() {
    return iv;
}

FDR RSAKeyExchange::getFDR() {
    return fdr;
}

void RSAKeyExchange::setPublicKey(RSAKey pKey) {
    publicKey = pKey;
}

void RSAKeyExchange::setAnswerFDR(int aFdr) {
    answerFdr = aFdr;
}

void RSAKeyExchange::setIV(int _iv) {
    iv = _iv;
}

void RSAKeyExchange::setFDR(FDR _fdr) {
    fdr = _fdr;
}

std::string RSAKeyExchange::toString() {
    std::string result =    std::to_string(getPublicKey().d)    + " | " +
                            std::to_string(getPublicKey().n)    + " | " +
                            std::to_string(getAnswerFDR())      + " | " +
                            std::to_string(getIV())             + " | " +
                            getFDR().getOperator() +
                            std::to_string(getFDR().getOperand());

    return result;
}
