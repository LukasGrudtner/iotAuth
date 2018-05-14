#ifndef ARDUINO_H
#define ARDUINO_H

#include "iotAuth.h"
#include "keyManager.h"
#include "stringHandler.h"
#include "settings.h"
#include "utils.h"

using namespace std;

/* Simulação das funções executadas pelo Arduino. */

class Arduino
{
    public:

        int a = 2;
        int g = 23;
        int p = 86;
        long int iv = 7;
        string fdr = "+1";

        bool clientHello = false;
        bool clientDone = false;
        bool receivedRSAKey = false;
        bool receivedDHKey = false;

        /* Envia Client Hello para o Server. */
        char* sendClientHello();
        /* Envia Client Done para o Server. */
        char* sendClientDone();

        /* Recebe o Server Hello. */
        bool receiveServerHello(char buffer[]);
        /* Recebe o Server Done. */
        bool receiveServerDone(char buffer[]);

        /* Realiza o envio da chave RSA para o Server. */
        char* sendRSAKey();
        /* Recebe a chave RSA do Server. */
        void receiveRSAKey(char message[]);

        /* Realiza o envio da chave Diffie-Hellman para o Server. */
        char* sendDiffieHellmanKey();
        /* Recebe a chave Diffie-Hellman do Server. */
        void receiveDiffieHellmanKey(char message[]);

    private:

        IotAuth iotAuth;
        KeyManager keyManager;
        StringHandler stringHandler;
        Utils utils;

        /*  Retorna toda a string anterior ao símbolo "*".
            Essa string representa o Hash encriptado. */
        string getHashEncrypted(string package);

        /*  Retorna toda a string logo após o símbolo "*".
            Essa string representa o pacote com os dados DH recebidos
            do Server. */
        string getPackage(string package);

        /* Realiza o envio do Done para o Server. */
        void done();
};

#endif
