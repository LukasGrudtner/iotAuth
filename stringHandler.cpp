#include "stringHandler.h"

/*  getDHClientKey()
    Retorna a chave Diffie-Hellman contida no buffer recebido por parâmetro.
*/
int StringHandler::getDHClientKey(char buffer[])
{
    return std::stoi(getData(buffer, 0));
}

/*  getClientBase()
    Retorna o atributo 'base', utilizado no cálculo da chave Diffie-Hellman,
    e que está contido no buffer recebido por parâmetro.
*/
int StringHandler::getClientBase(char buffer[])
{
    return std::stoi(getData(buffer, 1));
}

/*  getClientModulus()
    Retorna o atributo 'módulo', utilizado no cálculo da chave Diffie-Hellman,
    e que está contido no buffer recebido por parâmetro.
*/
int StringHandler::getClientModulus(char buffer[])
{
    return std::stoi(getData(buffer, 2));
}

/*  getDHIvClient()
    Retorna o atributo 'IV', utilizado no cálculo da chave Diffie-Hellman,
    e que está contida no buffer recebido por parâmetro.
*/
int StringHandler::getDHIvClient(char buffer[])
{
    return std::stoi(getData(buffer, 3));
}

/*  getClientPublicKey()
    Retorna a chave pública do cliente contida no buffer recebido por parâmetro.
*/
PublicRSAKey StringHandler::getPartnerPublicKey(char buffer[])
{
    PublicRSAKey publicKey = {std::stol(getData(buffer, 0)), std::stol(getData(buffer, 1))};
    return publicKey;
}

/*  getRSAExchangeIv()
    Retorna o atributo 'IV' utilizado na troca de chaves RSA, e que está
    contida no buffer recebido por parâmetro.
*/
int StringHandler::getRSAExchangeAnswerFdr(char buffer[])
{
    return std::stoi(getData(buffer, 2));
}

int StringHandler::getRSAExchangeIv(char buffer[])
{
    return std::stoi(getData(buffer, 3));
}

/*  getData()
    Parâmetros: buffer, position
    Pega todos os caracteres entre o separador (#) da posição indicada por
    parâmetro e o separador da posição seguinte.
*/
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

/*  getRSAClientFdr()
    Recebe um buffer de chars como parâmetro, e extrai dele o objeto FDR,
    retornado-o.
*/
FDR* StringHandler::getRSAExchangeFdr(char buffer[])
{
    char op;
    int operand;

    std::string fdr = getData(buffer, 4);
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
