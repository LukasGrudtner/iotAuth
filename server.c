#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <string>
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sstream>
#include "keyManager.h"
#include "settings.h"
#include "stringHandler.h"

KeyManager KeyManager;
StringHandler StringHandler;

bool CHANGED_KEYS = false;
bool CLIENT_HELLO = false;
bool CLIENT_DONE = false;
bool RECEIVED_RSA_KEY = false;
bool RECEIVED_DH_KEY = false;

void processClientHello(char buffer[], int socket, struct sockaddr* client, int size)
{
    printf("\n******HELLO CLIENT AND SERVER******\n");

    if (strcmp(buffer, HELLO_MESSAGE) == 0) {
        int sended = sendto(socket, HELLO_ACK, strlen(HELLO_ACK), 0, client, size);

        if (sended >= 0) {
           printf("Hello Client and Server Successful!\n");
           CLIENT_HELLO = true;
           CLIENT_DONE = true;
        } else {
            herror("sendto");
            printf("Hello Client and Server failed!\n");
        }
    }

    printf("***********************************\n");
}

void processClientDone(char buffer[], int socket, struct sockaddr* client, int size)
{
    printf("\n*******DONE CLIENT AND SERVER*******\n");

    if (strcmp(buffer, DONE_MESSAGE) == 0) {
        int sended = sendto(socket, DONE_ACK, strlen(DONE_ACK), 0, client, size);

        if (sended >= 0) {
           printf("Done Client and Server Successful!\n");
           CLIENT_DONE = true;
           CLIENT_HELLO = false;
           RECEIVED_RSA_KEY = false;
           RECEIVED_DH_KEY = false;
        } else {
            herror("sendto");
            printf("Done Client and Server failed!\n");
        }
    }

    printf("***********************************\n");
}

void processRSAKeyExchange(char buffer[], int socket, struct sockaddr* client, int size)
{
    printf("******RSA KEY CLIENT RECEIVED******");
    // std::string clientPublicKey = StringHandler.getClientPublicKey;
}

int main(int argc, char *argv[]){

    /* Testes STRING HANDLER */
    char buf[] = "123#456#789#101112";
    std::cout << "DH Client Key: " << StringHandler.getDHClientKey(buf) << std::endl;
    std::cout << "Client Base: " << StringHandler.getClientBase(buf) << std::endl;
    std::cout << "Client Modulus: " << StringHandler.getClientModulus(buf) << std::endl;
    std::cout << "DH IV: " << StringHandler.getDHIvClient(buf) << std::endl;
    /* Testes STRING HANDLER */

    /* Testes FDR */
    char buf2[] = "029#029#+123";
    // FDR* fdr = new FDR('+', 5);
    // std::cout << "FDR operator = " << fdr->getOperator() << std::endl;
    // std::cout << "FDR operand = " << fdr->getOperand() << std::endl;
    std::cout << "FDR operator = " << StringHandler.getRSAClientFdr(buf2).getOperator() << std::endl;
    std::cout << "FDR operand = " << StringHandler.getRSAClientFdr(buf2).getOperand() << std::endl;
    /* Testes FDR */

    struct sockaddr_in cliente, servidor;
    int meuSocket,enviei=0;
    socklen_t tam_cliente;
    // MTU padrão pela IETF
    char buffer[556];

    meuSocket=socket(PF_INET,SOCK_DGRAM,0);
    servidor.sin_family=AF_INET;
    servidor.sin_port=htons(20000);
    servidor.sin_addr.s_addr=INADDR_ANY;

    memset(buffer, 0, sizeof(buffer));

    bind(meuSocket,(struct sockaddr*)&servidor,sizeof(struct sockaddr_in));

    printf("*** Servidor de Mensagens ***\n");
    while(1){
       tam_cliente=sizeof(struct sockaddr_in);
       recvfrom(meuSocket,buffer,556,MSG_WAITALL,(struct sockaddr*)&cliente,&tam_cliente);
       // printf("Recebi:%s de <endereço:%s> <porta:%d>\n",buffer,inet_ntoa(cliente.sin_addr),ntohs(cliente.sin_port));

       if (!CLIENT_HELLO) {
           processClientHello(buffer, meuSocket, (struct sockaddr*)&cliente, sizeof(struct sockaddr_in));
       } else {
           processClientDone(buffer, meuSocket, (struct sockaddr*)&cliente, sizeof(struct sockaddr_in));
       }

       // printf("%s", buffer);
       // int enviei=sendto(meuSocket,"ACK!",strlen("ACK!"),0,(struct sockaddr*)&cliente,sizeof(struct sockaddr_in));
       // if (enviei>=0)
       //    printf("Envio de ACK!\n");
       // else{
       //     herror("sendto");
       //     printf("Envio de ACK falhou!\n");
       // }
       memset(buffer, 0, sizeof(buffer));
    }
    close(meuSocket);
}
