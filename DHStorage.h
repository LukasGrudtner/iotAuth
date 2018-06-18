#ifndef DH_STORAGE_H
#define DH_STORAGE_H

#include <cmath>
#include "settings.h"

class DHStorage
{
    public:
        int getBase();
        int getModulus();
        int getSessionKey();

        int getMyIV();
        FDR* getMyFDR();

        int getPartnerIV();
        FDR* getPartnerFDR();

        int getAnswerFDR();

        int calculateResult();
        int calculateSessionKey(int result);

        void setSessionKey(int _sessionKey);
        void setBase(int _base);
        void setModulus(int _modulus);
        void setExponent(int _exponent);

        void setMyIV(int iv);
        void setMyFDR(FDR fdr);

        void setPartnerIV(int iv);
        void setPartnerFDR(FDR fdr);

        void setAnswerFDR(int _answerFDR);

    private:
        int exponent;   /* a */
        int base;       /* g */
        int modulus;    /* p */
        int sessionKey;

        int myIV;
        FDR myFDR;

        int partnerIV;
        FDR partnerFDR;

        int answerFDR;
};

#endif