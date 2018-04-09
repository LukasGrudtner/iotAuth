#include "stringHandler.h"

int StringHandler::getDHClientKey(char buffer[])
{
    char buffer_aux[strlen(buffer)];
    int cont = 0;

    for (int i = 0; i < strlen(buffer); i++) {
        if (buffer[i] == SPACER)
            break;
        buffer_aux[cont] = buffer[i];
        cont++;
    }

    std::string dhClientKey (buffer_aux);
    return std::stoi(dhClientKey);
}

int StringHandler::getClientBase(char buffer[])
{
    char buffer_aux[strlen(buffer)];
    int cont = 0;

    /* Avança até o primeiro dividor (#) da cadeia. */
    int i;
    for (i = 0; i < strlen(buffer); i++) {
        if (buffer[i] == SPACER)
            break;
    }
    i++;

    /* Recupera tudo o que está entre o primeiro e o segundo divisor (#). */
    for (int j = 0; j < strlen(buffer) - i; j++) {
        if (buffer[i] == SPACER)
            break;
        buffer_aux[cont] = buffer[i];
        cont++;
        i++;
    }

    std::string clientBase (buffer_aux);
    return std::stoi(clientBase);
}
