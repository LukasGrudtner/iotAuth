#ifndef STRING_HANDLER_H
#define STRING_HANDLER_H

#include <string>
#include <string.h>
#include <iostream>
#include <sstream>
#include "settings.h"
#include "fdr.h"

class StringHandler
{
    public:

        int getDHClientKey(char buffer[]);
        int getClientBase(char buffer[]);
        int getClientModulus(char buffer[]);
        int getDHIvClient(char buffer[]);
        int getClientPublicKey(char buffer[]);
        int getRSAExchangeIv(char buffer[]);
        FDR* getRSAClientFdr(char buffer[]);
        // std::string byteToHex(char data[], int len);
    private:
        std::string getData(char buffer[], int position);
};

#endif
