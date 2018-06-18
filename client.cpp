#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <array>
#include <iostream>
#include "iotAuth.h"
#include "utils.h"
#include "settings.h"
#include "Arduino.h"
#include <sys/time.h>

using namespace std;

Arduino arduino;

int main(int argc, char *argv[]){

    struct sockaddr_in servidor;
    int meuSocket;
    socklen_t tam_cliente;
    char envia[556];
    char recebe[10000];
    struct hostent *server;

    if (argv[1] == NULL) {
        fprintf(stderr, "ERROR, no such host\n");
        exit(0);
    }
    server = gethostbyname(argv[1]);
    if (server == NULL) {
        fprintf(stderr, "ERROR, no such host\n");
        exit(0);
    }

    bcopy((char *)server->h_addr,
         (char *)&servidor.sin_addr.s_addr,
         server->h_length);

    meuSocket=socket(PF_INET,SOCK_DGRAM,0);
    servidor.sin_family=AF_INET; // familia de endereços
    servidor.sin_port=htons(DEFAULT_PORT); // porta
    // para usar um ip qualquer use inet_addr("10.10.10.10"); ao invés de htonl(INADDR_ANY)
    // servidor.sin_addr.s_addr=htonl(INADDR_ANY);
    // servidor.sin_addr.s_addr=inet_addr("150.162.237.172");

    memset(envia, 0, sizeof(envia));
    memset(recebe, 0, sizeof(recebe));

    tam_cliente=sizeof(struct sockaddr_in);

    while(1){

        arduino.stateMachine(meuSocket, (struct sockaddr*)&servidor, tam_cliente);

       //  /* Se ainda não foi enviado um HELLO, inicia o pedido de conexão. */
       // if (!arduino.clientHello) {
       //     printf("########## ENTER para enviar um HELLO ao Server ##########\n");
       //     fgets(envia,556,stdin);
       //
       //     /* Recupera a mensagem de pedido de conexão e a envia ao Servidor. */
       //     char* message = arduino.sendClientHello();
       //     sendto(meuSocket,message,strlen(message),0,(struct sockaddr*)&servidor,sizeof(struct sockaddr_in));
       //
       //     /* Enquanto o Cliente não receber uma confirmação: */
       //     while (!arduino.clientHello) {
       //         recvfrom(meuSocket,recebe,1480,MSG_WAITALL,(struct sockaddr*)&servidor,&tam_cliente);
       //
       //         /* Se a mensagem do Servidor não for um DONE: */
       //         if (!arduino.checkDoneServer(recebe)) {
       //             /* Prossegue com o recebimento da confirmação. */
       //             arduino.receiveServerHello(recebe);
       //
       //         } else { /* Se o Servidor pediu fim de conexão: */
       //             /* Inicia o fim da conexão. */
       //             arduino.done();
       //
       //             /* Envia uma confirmação ao pedido de fim de conexão. */
       //             char *message = arduino.sendClientACKDone();
       //
       //             cout << "Sent: " << message << endl;
       //             sendto(meuSocket,message,strlen(message),0,(struct sockaddr*)&servidor,sizeof(struct sockaddr_in));
       //         }
       //     }
       // }
       //
       // /* Se a conexão já foi estabelecida, mas ainda não houve a troca de chaves RSA: */
       // else if (arduino.clientHello && !arduino.receivedRSAKey) {
       //     printf("########## ENTER para enviar a chave RSA ao Server ##########\n");
       //     fgets(envia, 556, stdin);
       //
       //     /* Recupera a mensagem com a chave para enviar ao Servidor. */
       //     // char *message = arduino.sendClientDone();
       //     RSAKeyExchange keyExchange = arduino.sendRSAKey();
       //     sendto(meuSocket, (RSAKeyExchange*)&keyExchange, sizeof(keyExchange),0,(struct sockaddr*)&servidor,sizeof(struct sockaddr_in));
       //     // sendto(meuSocket,message,strlen(message),0,(struct sockaddr*)&servidor,sizeof(struct sockaddr_in));
       //
       //     /* Enquanto não ocorre a troca de chaves RSA e nem um DONE do Servidor: */
       //     while (!arduino.receivedRSAKey && !arduino.clientDone) {
       //         RSAKeyExchange* keyExchange = (RSAKeyExchange*)malloc(sizeof(RSAKeyExchange));
       //         recvfrom(meuSocket, keyExchange, sizeof(*keyExchange), MSG_WAITALL, (struct sockaddr*)&servidor, &tam_cliente);
       //
       //         /* Processa a mensagem vinda do Servidor. */
       //         bool validIV = arduino.receiveRSAKey(keyExchange);
       //
       //         /* Se o IV não for válido, envia pedido de fim de conexão. */
       //         if (!validIV) {
       //             arduino.done();
       //             char *message = arduino.sendClientDone();
       //
       //             cout << "Sent: " << message << endl;
       //             sendto(meuSocket,message,strlen(message),0,(struct sockaddr*)&servidor,sizeof(struct sockaddr_in));
       //
       //             cout << "Waiting ACK to end the connection...\n" << endl;
       //
       //             recvfrom(meuSocket,recebe,10000,MSG_WAITALL,(struct sockaddr*)&servidor,&tam_cliente);
       //             arduino.receiveServerDone(recebe);
       //         }
       //     }
       // }
       //
       // /* Se a troca de chaves RSA já ocorreu, porém a troca Diffie-Hellman ainda não: */
       // else if (arduino.receivedRSAKey && !arduino.receivedDHKey) {
       //     printf("########## ENTER para enviar a chave DH ao Server ##########\n");
       //     fgets(envia, 556, stdin);
       //
       //     /* Recupera a mensagem com a chave Diffie-Hellman para enviar ao Servidor. */
       //     int *encryptedMessage = arduino.sendDiffieHellmanKey();
       //     sendto(meuSocket,(int*)encryptedMessage,sizeof(DHKeyExchange)*sizeof(int),0,(struct sockaddr*)&servidor,sizeof(struct sockaddr_in));
       //
       //     /* Enquanto não receber a chave Diffie-Helmann ou um DONE do Servidor: */
       //     while (!arduino.receivedDHKey && !arduino.clientDone) {
       //         int *encryptedDHExchange = (int*)malloc(sizeof(DHKeyExchange)*sizeof(int));
       //         recvfrom(meuSocket, encryptedDHExchange, sizeof(DHKeyExchange)*sizeof(int), MSG_WAITALL, (struct sockaddr*)&servidor, &tam_cliente);
       //
       //         /* Processa a mensagem do Servidor. */
       //         bool validHash = arduino.receiveDiffieHellmanKey(encryptedDHExchange);
       //
       //         /* Se o Hash não for válido, realiza o término da conexão. */
       //         if (!validHash) {
       //             arduino.done();
       //             /* Envia um pedido de fim de conexão e aguarda confirmação do Servidor. */
       //             char *message = arduino.sendClientDone();
       //             sendto(meuSocket,message,strlen(message),0,(struct sockaddr*)&servidor,sizeof(struct sockaddr_in));
       //
       //             cout << "Waiting ACK..." << endl;
       //
       //             recvfrom(meuSocket,recebe,10000,MSG_WAITALL,(struct sockaddr*)&servidor,&tam_cliente);
       //             arduino.receiveServerDone(recebe);
       //         }
       //     }
       // }
       //
       // /* Se a troca de chaves RSA e Diffie-Hellman já ocorreram: */
       // else if (arduino.receivedRSAKey && arduino.receivedDHKey){
       //     cout << "Envio de dados criptografados com AES." << endl << endl;
       //
       //     printf("########## Escreva uma mensagem para o servidor ##########\n");
       //     printf("------------- Linha em branco para finalizar -------------\n");
       //     /* Captura a mensagem digitada no terminal para a criptografia. */
       //     fgets(envia, 665, stdin);
       //
       //     /* Enquanto o usuário não digitar um 'Enter': */
       //     while (strcmp(envia, "\n") != 0) {
       //
       //         /* Encripta a mensagem digitada pelo usuário. */
       //         string encryptedMessage = arduino.sendEncryptedMessage(envia, sizeof(envia));
       //         cout << "Sent" << endl << encryptedMessage << endl << endl;
       //
       //         /* Converte a string em um array de char. */
       //         char encryptedMessageChar[encryptedMessage.length()];
       //         memset(encryptedMessageChar, '\0', sizeof(encryptedMessageChar));
       //         strncpy(encryptedMessageChar, encryptedMessage.c_str(), sizeof(encryptedMessageChar));
       //
       //         /* Envia a mensagem cifrada ao Servidor. */
       //         sendto(meuSocket,encryptedMessageChar,strlen(encryptedMessageChar),0,(struct sockaddr*)&servidor,sizeof(struct sockaddr_in));
       //         memset(envia, '\0', sizeof(envia));
       //         fgets(envia, 665, stdin);
       //     }
       // }
       //
       // memset(envia, '\0', sizeof(envia));
       // memset(recebe, '\0', sizeof(recebe));
    }
    close(meuSocket);
}
