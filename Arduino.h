#ifndef ARDUINO_H
#define ARDUINO_H

#include "iotAuth.h"
#include "keyManager.h"
#include "settings.h"
#include "utils.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include "RSAKeyExchange.h"
#include "DHKeyExchange.h"
#include "DiffieHellmanPackage.h"

using namespace std;

/* Simulação das funções executadas pelo Arduino. */

class Arduino
{
    public:

        int a = 2;
        int g = 23;
        int p = 86;

        /* Resposta do FDR do servidor recebido no passo RSA Key Exchange e
        enviado no passo DH Key Exchange. */
        int answerFDR = 0;;

        bool clientHello    = false;
        bool clientDone     = false;
        bool receivedRSAKey = false;
        bool receivedDHKey  = false;

        void stateMachine(int socket, struct sockaddr *client, socklen_t size);
        void hello(States *state, int socket, struct sockaddr *client, socklen_t size);
        void srsa(States *state, int socket, struct sockaddr *client, socklen_t size);
        void rrsa(States *state, int socket, struct sockaddr *client, socklen_t size);
        void sdh(States *state, int socket, struct sockaddr *client, socklen_t size);
        void rdh(States *state, int socket, struct sockaddr *client, socklen_t size);
        void dt(States *state, int socket, struct sockaddr *client, socklen_t size);

        /* Envia Client Hello para o Server. */
        char* sendClientHello();

        /* Envia Client Done para o Server. */
        char* sendClientDone();

        /* Envia a confirmação do pedido de fim de conexão do Servidor. */
        char* sendClientACKDone();

        /* Recebe o Server Hello. */
        bool receiveServerHello(char buffer[]);

        /* Recebe o Server Done. */
        bool receiveServerDone(char buffer[]);

        /* Realiza o envio da chave RSA para o Server. */
        // char* sendRSAKey();
        RSAKeyExchange sendRSAKey();

        /* Recebe a chave RSA do Server. */
        bool receiveRSAKey(RSAKeyExchange *keyExchange);

        /* Realiza o envio da chave Diffie-Hellman para o Server. */
        int* sendDiffieHellmanKey();

        /* Recebe a chave Diffie-Hellman do Server. */
        bool receiveDiffieHellmanKey(int* encryptedDHExchange);

        /* Realiza o envio da mensagem cifrada para o Servidor. */
        string sendEncryptedMessage(char message[], int size);

        /* Realiza o envio do Done para o Server. */
        void done();

        /* Verifica se a mensagem vinda do servidor é um DONE. */
        bool checkDoneServer(char buffer[]);

    private:

        IotAuth iotAuth;
        KeyManager keyManager;

        Utils utils;

        /*  Retorna toda a string anterior ao símbolo "*".
            Essa string representa o Hash encriptado. */
        string getHashEncrypted(string package);

        /*  Retorna toda a string logo após o símbolo "*".
            Essa string representa o pacote com os dados DH recebidos
            do Server. */
        string getPackage(string package);

        /*  Verifica se a resposta do FDR fornecida pelo Servidor é válida. */
        bool checkAnsweredFDR(int answeredFdr);

        /* Calcula a resposta do FDR. */
        int calculateFDRValue(int iv, FDR* fdr);
};

#endif
