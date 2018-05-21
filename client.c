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

Utils utils;
Arduino arduino;

int main(int argc, char *argv[]){

    struct sockaddr_in servidor,cliente;
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

       printf("\n*** Bem vindo ao cliente ***\n");

       if (!arduino.clientHello) {
           printf("########## ENTER para enviar um HELLO ao Server #####\n");
           fgets(envia,556,stdin);

           char* message = arduino.sendClientHello();
           sendto(meuSocket,message,strlen(message),0,(struct sockaddr*)&servidor,sizeof(struct sockaddr_in));

           while (!arduino.clientHello) {
               recvfrom(meuSocket,recebe,1480,MSG_WAITALL,(struct sockaddr*)&cliente,&tam_cliente);
               arduino.receiveServerHello(recebe);

           }



           // auto resultado = std::chrono::high_resolution_clock::now() - inicio;
           // long long microseconds = std::chrono::duration_cast<std::chrono::microseconds>(resultado).count();

           // double Tempo = Ticks[1] - Ticks[0];
           // cout << "Tempo decorrido nas etapas 1 e 2: " << microseconds << "ms." << endl;
       }

       if (arduino.clientHello && !arduino.receivedRSAKey) {
           printf("########## ENTER para enviar a chave RSA ao Server ##########\n");
           fgets(envia, 556, stdin);

           char* message = arduino.sendRSAKey();
           sendto(meuSocket,message,strlen(message),0,(struct sockaddr*)&servidor,sizeof(struct sockaddr_in));

           while (!arduino.receivedRSAKey && !arduino.clientDone) {
               recvfrom(meuSocket,recebe,1480,MSG_WAITALL,(struct sockaddr*)&cliente,&tam_cliente);
               arduino.receiveRSAKey(recebe);
           }
       }

       if (arduino.receivedRSAKey && !arduino.receivedDHKey) {
           printf("########## ENTER para enviar a chave DH ao Server ##########\n");
           fgets(envia, 556, stdin);

           string message = arduino.sendDiffieHellmanKey();
           char messageChar[message.length()];
           memset(messageChar, '\0', sizeof(messageChar));
           strncpy(messageChar, message.c_str(), sizeof(messageChar));

           cout << "Size Message Char: " << strlen(messageChar) << endl;

           sendto(meuSocket,messageChar,strlen(messageChar),0,(struct sockaddr*)&servidor,sizeof(struct sockaddr_in));

           while (!arduino.receivedDHKey && !arduino.clientDone) {
               recvfrom(meuSocket,recebe,10000,MSG_WAITALL,(struct sockaddr*)&cliente,&tam_cliente);
               arduino.receiveDiffieHellmanKey(recebe);
           }
       }

       if (arduino.receivedRSAKey && arduino.receivedDHKey){
           cout << "Envio de dados criptografados com AES." << endl << endl;
           printf("########## Escreva uma mensagem para o servidor: ##########\n");
           fgets(envia, 665, stdin);

           string encryptedMessage = arduino.sendEncryptedMessage(envia, 64);
           cout << "Sent: " << encryptedMessage << endl;

           char encryptedMessageChar[encryptedMessage.length()];
           memset(encryptedMessageChar, '\0', sizeof(encryptedMessageChar));
           strncpy(encryptedMessageChar, encryptedMessage.c_str(), sizeof(encryptedMessageChar));

           sendto(meuSocket,encryptedMessageChar,strlen(encryptedMessageChar),0,(struct sockaddr*)&servidor,sizeof(struct sockaddr_in));
       }




       // /* PASSO 1: Envio de HELLO. */
       // char a[] = "HELLO\n";
       // sendto(meuSocket, a, sizeof(a),0,(struct sockaddr*)&servidor,sizeof(struct sockaddr_in));

       // /* PASSO 3: Envio do pacote RSA (Chave pública, iv, FDR). */
       // RSAKeyPair keys = iotAuth.generateRSAKeyPair();
       // RSAExchange RSAExchangeStruct = {keys.publicRSAKey, 0, 111, '+', 100};
       // sendto(meuSocket, (RSAExchange*)&RSAExchangeStruct, sizeof(RSAExchangeStruct),0,(struct sockaddr*)&servidor,sizeof(struct sockaddr_in));

       /* PASSO 5:
            (DH, g, p, iv, F(iv)) -> HASH,                              }   ->  Cifrado com a chave
            (DH, g, p, iv, F(iv)) -> Cifrado com chave privada de A     }   ->  pública de B
        */


       // sendto(meuSocket,cipherHex,strlen(cipherHex),0,(struct sockaddr*)&servidor,sizeof(struct sockaddr_in));
       // sendto(meuSocket, (DHExchange*)&teste, sizeof(teste),0,(struct sockaddr*)&servidor,sizeof(struct sockaddr_in)); // Envio de struct
       sendto(meuSocket,envia,strlen(envia),0,(struct sockaddr*)&servidor,sizeof(struct sockaddr_in));
       tam_cliente=sizeof(struct sockaddr_in);
       recvfrom(meuSocket,recebe,1480,MSG_WAITALL,(struct sockaddr*)&cliente,&tam_cliente);

       // printf("Recebi:%s",recebe);
       memset(envia, 0, sizeof(envia));
       memset(recebe, 0, sizeof(recebe));
    }
    close(meuSocket);
}
