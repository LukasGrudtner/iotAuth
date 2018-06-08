#ifndef DH_KEY_EXCHANGE_H
#define DH_KEY_EXCHANGE_H

#include <stdio.h>
#include <string.h>
#include "DiffieHellmanPackage.h"
#include "settings.h"

class DHKeyExchange
{
    public:
        DHKeyExchange();

        /* Getters */
        int* getEncryptedHash();
        byte* getDiffieHellmanPackage();

        /* Setters */
        void setEncryptedHash(int encHash[]);
        void setDiffieHellmanPackage(byte dhPackage[]);

    private:
        int encryptedHash[128];
        byte diffieHellmanPackage[sizeof(DiffieHellmanPackage)];

};

#endif
