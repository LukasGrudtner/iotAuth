#ifndef DH_PACKAGE_H
#define DH_PACKAGE_H

#include <string>

class DiffieHellmanPackage
{
    public:

        /* Getters */
        int getResult();
        int getBase();
        int getModulus();
        int getIV();
        int getAnswerFDR();

        /* Setters */
        void setResult(int r);
        void setBase(int base);
        void setModulus(int modulus);
        void setIV(int _iv);
        void setAnswerFDR(int aFdr);

        std::string toString();

    private:
        int result      = 0;
        int g           = 0;    // Base
        int p           = 0;    // Modulus
        int iv          = 0;
        int answerFdr   = 0;
};

#endif
