#include <string>
#include <string.h>
#include <iostream>
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
        FDR getRSAClientFdr(char buffer[]);
    private:
        std::string getData(char buffer[], int position);
};
