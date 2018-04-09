#include "stringHandler.h"

int StringHandler::getDHClientKey(char buffer[])
{

    char buffer_aux[2048];
    int cont = 0;

    for (int i = 0; i < strlen(buffer); i++) {
        if (buffer[i] == SPACER)
            break;
        buffer_aux[cont] = buffer[i];
        cont += 1;
    }

    std::string dhClientKey (buffer_aux);

    return std::stoi(dhClientKey);
}
