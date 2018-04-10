#include "stringHandler.h"

int StringHandler::getDHClientKey(char buffer[])
{
    return std::stoi(getData(buffer, 0));
}

int StringHandler::getClientBase(char buffer[])
{
    return std::stoi(getData(buffer, 1));
}

int StringHandler::getClientModulus(char buffer[])
{
    return std::stoi(getData(buffer, 2));
}

int StringHandler::getDHIvClient(char buffer[])
{
    return std::stoi(getData(buffer, 3));
}

int StringHandler::getClientPublicKey(char buffer[])
{
    return std::stoi(getData(buffer, 0));
}

int StringHandler::getRSAExchangeIv(char buffer[])
{
    return std::stoi(getData(buffer, 1));
}

/*********************************************
TERMINAR O GET FDR RSA CLIENT !!!!!
**********************************************/

/* Pega todos os caracteres entre o separador (#) da posição indicada por parâmetro
e o separador da posição + 1. */
std::string StringHandler::getData(char buffer[], int position)
{
    char buffer_aux[strlen(buffer)];
    int cont = 0;
    int current_spacer = 0;

    if (position > 0) {

        int i;
        for (i = 0; i < strlen(buffer); i++) {
            if (buffer[i] == SPACER) {
                current_spacer++;

                if (current_spacer == position)
                    break;
            }
        }
        i++;

        for (int j = i; j < strlen(buffer); j++) {
            if (buffer[j] == SPACER)
                break;
            buffer_aux[cont] = buffer[j];
            cont++;
        }
    } else {
        for (int i = 0; i < strlen(buffer); i++) {
            if (buffer[i] == SPACER)
                break;
            buffer_aux[cont] = buffer[i];
            cont++;
        }
    }

    std::string data (buffer_aux);
    return data;
}

FDR* StringHandler::getRSAClientFdr(char buffer[])
{
    char op;
    int operand;

    std::string fdr = getData(buffer, 2);
    op = fdr[0];

    char buffer_aux[fdr.length()];
    int cont = 0;
    for (int i = 1; i < fdr.length(); i++) {
        buffer_aux[cont] = fdr[i];
        cont++;
    }

    std::string data (buffer_aux);
    FDR* f = new FDR(op, std::stoi(data));

    return (f);
}
