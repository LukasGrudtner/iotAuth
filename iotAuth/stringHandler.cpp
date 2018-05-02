#include "stringHandler.h"

/*  getDHClientKey()
    Retorna a chave Diffie-Hellman contida no buffer recebido por parâmetro.
*/
int StringHandler::getDHClientKey(char buffer[])
{
    char buf[sizeof(buffer)];
    memset(buf, 0, sizeof(buf));
    strncpy(buf, getData(buffer, 0).c_str(), sizeof(buf));
    return atol(buf);
}

/*  getClientBase()
    Retorna o atributo 'base', utilizado no cálculo da chave Diffie-Hellman,
    e que está contido no buffer recebido por parâmetro.
*/
int StringHandler::getClientBase(char buffer[])
{
    char buf[sizeof(buffer)];
    memset(buf, 0, sizeof(buf));
    strncpy(buf, getData(buffer, 1).c_str(), sizeof(buf));
    return atol(buf);
}

/*  getClientModulus()
    Retorna o atributo 'módulo', utilizado no cálculo da chave Diffie-Hellman,
    e que está contido no buffer recebido por parâmetro.
*/
int StringHandler::getClientModulus(char buffer[])
{
    char buf[sizeof(buffer)];
    memset(buf, 0, sizeof(buf));
    strncpy(buf, getData(buffer, 2).c_str(), sizeof(buf));
    return atol(buf);
}

/*  getDHIvClient()
    Retorna o atributo 'IV', utilizado no cálculo da chave Diffie-Hellman,
    e que está contida no buffer recebido por parâmetro.
*/
int StringHandler::getDHIvClient(char buffer[])
{
    char buf[sizeof(buffer)];
    memset(buf, 0, sizeof(buf));
    strncpy(buf, getData(buffer, 3).c_str(), sizeof(buf));
    return atol(buf);
}

/*  getClientPublicKey()
    Retorna a chave pública do cliente contida no buffer recebido por parâmetro.
*/
long int StringHandler::getServerPublicKeyD(char buffer[])
{
    char buf[20];
    memset(buf, 0, sizeof(buf));
    strncpy(buf, getData(buffer, 0).c_str(), sizeof(buf));

    return atol(buf);
}

long int StringHandler::getServerPublicKeyN(char buffer[])
{
    char buf[20];
    memset(buf, 0, sizeof(buf));
    strncpy(buf, getData(buffer, 1).c_str(), sizeof(buf));

    return atol(buf);
}

/*  getRSAExchangeIv()
    Retorna o atributo 'IV' utilizado na troca de chaves RSA, e que está
    contida no buffer recebido por parâmetro.
*/
int StringHandler::getRSAExchangeAnswerFdr(char buffer[])
{
    char buf[sizeof(buffer)];
    memset(buf, 0, sizeof(buf));
    strncpy(buf, getData(buffer, 2).c_str(), sizeof(buf));
    return atol(buf);
}

int StringHandler::getRSAExchangeIv(char buffer[])
{
    char buf[sizeof(buffer)];
    memset(buf, 0, sizeof(buf));
    strncpy(buf, getData(buffer, 3).c_str(), sizeof(buf));
    return atol(buf);
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
            if (buffer[i] == SEPARATOR) {
                current_spacer++;

                if (current_spacer == position)
                    break;
            }
        }
        i++;

        for (int j = i; j < strlen(buffer); j++) {
            if (buffer[j] == SEPARATOR)
                break;
            buffer_aux[cont] = buffer[j];
            cont++;
        }
    } else {
        for (int i = 0; i < strlen(buffer); i++) {
            if (buffer[i] == SEPARATOR)
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
FDR* StringHandler::getRSAClientFdr(char buffer[])
{
    char op;
    int operand;

    std::string fdr = getData(buffer, 3);
    op = fdr[0];

    char buffer_aux[fdr.length()];
    int cont = 0;
    for (int i = 1; i < fdr.length(); i++) {
        buffer_aux[cont] = fdr[i];
        cont++;
    }

    std::string data (buffer_aux);
    char buf[data.length()];
    memset(buf, 0, sizeof(buf));
    strncpy(buf, data.c_str(), sizeof(buf));
    FDR* f = new FDR(op, atol(buf));

    return (f);
}
