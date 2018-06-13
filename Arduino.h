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

        /* Resposta do FDR do servidor recebido no passo RSA Key Exchange e
        enviado no passo DH Key Exchange. */
        int answerFDR = 0;;

        void stateMachine(int socket, struct sockaddr *client, socklen_t size);

        /*  Waiting Done Confirmation
            Verifica se a mensagem vinda do Cliente é uma confirmação do pedido de
            fim de conexão enviado pelo Servidor (DONE_ACK).
            Em caso positivo, altera o estado para HELLO, senão, mantém em WDC. 7
        */
        void wdc(States *state, int socket, struct sockaddr *client, socklen_t size);

        /*  Request for Termination
            Envia uma confirmação (DONE_ACK) para o pedido de término de conexão
            vindo do Cliente, e seta o estado para HELLO.
        */
        void rft(States *state, int socket, struct sockaddr *client, socklen_t size);

        /*  Hello
            Envia um pedido de início de conexão (HELLO) para o Servidor
        */
        void hello(States *state, int socket, struct sockaddr *client, socklen_t size);

        /*  Done
            Envia um pedido de término de conexão ao Cliente, e seta o estado atual
            para WDC (Waiting Done Confirmation).
        */
        void done(States *state, int socket, struct sockaddr *client, socklen_t size);

        /*  Send RSA
            Realiza o envio da chave RSA para o Servidor.
        */
        void srsa(States *state, int socket, struct sockaddr *client, socklen_t size);

        /*  Receive RSA
            Realiza o recebimento da chave RSA vinda do Servidor.
        */
        void rrsa(States *state, int socket, struct sockaddr *client, socklen_t size);

        /*  Send Diffie-Hellman
            Realiza o envio da chave Diffie-Hellman para o Servidor.
        */
        void sdh(States *state, int socket, struct sockaddr *client, socklen_t size);

        /*  Receive Diffie-Hellman
            Realiza o recebimento da chave Diffie-Hellman vinda do Servidor.
        */
        void rdh(States *state, int socket, struct sockaddr *client, socklen_t size);

        /*  Data Transfer
            Realiza a transferência de dados cifrados para o Servidor.
        */
        void dt(States *state, int socket, struct sockaddr *client, socklen_t size);

        /*  Encrypt Message
            Encripta a mensagem utilizando a chave de sessão.
        */
        string encryptMessage(char message[], int size);

    private:

        IotAuth iotAuth;
        KeyManager keyManager;

        Utils utils;

        /*  Check Answered FDR
            Verifica a validade da resposta da FDR gerada pelo Servidor.
        */
        bool checkAnsweredFDR(int answeredFdr);

        /*  Calculate FDR Value
            Calcula a resposta de uma dada FDR. */
        int calculateFDRValue(int iv, FDR* fdr);
};

#endif
