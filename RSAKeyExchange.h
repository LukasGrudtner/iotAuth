#ifndef RSA_KEY_EXCHANGE_H
#define RSA_KEY_EXCHANGE_H

#include "settings.h"
#include "fdr.h"
#include <stdio.h>
#include <string>

class RSAKeyExchange {

    public:
        RSAKeyExchange();
        /* Getters */
        RSAKey getPublicKey();
        int getAnswerFDR();
        int getIV();
        FDR getFDR();

        /* Setters */
        void setPublicKey(RSAKey pKey);
        void setAnswerFDR(int aFdr);
        void setIV(int _iv);
        void setFDR(FDR _fdr);

        std::string toString();

    private:
        RSAKey publicKey;
        int answerFdr = 0;
        int iv = 0;
        FDR fdr;

};

#endif
