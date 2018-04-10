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

StringHandler StringHandler;

bool CHANGED_KEYS = false;
bool CLIENT_HELLO = false;
bool CLIENT_DONE = false;
bool RECEIVED_RSA_KEY = false;
bool RECEIVED_DH_KEY = false;
KeyManager* keyManager;
FDR* fdr;

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

    printf("***********************************\n\n");
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

int handleIV(int _iv, FDR* _fdr)
{
    int result = 0;
    if (_fdr->getOperator() == '+')
        result = _iv+_fdr->getOperand();

    return result;
}

void processRSAKeyExchange(char buffer[], int socket, struct sockaddr* client, int size)
{
    /* Recebe chave pública do cliente e o IV */
    printf("******RSA KEY CLIENT RECEIVED******\n");
    keyManager->setClientPublicKey(StringHandler.getClientPublicKey(buffer));
    keyManager->setFDR(StringHandler.getRSAClientFdr(buffer));
    keyManager->setIV(StringHandler.getRSAExchangeIv(buffer));

    std::cout << "Client RSA Public Key: " << keyManager->getClientPublicKey() << std::endl;
    std::cout << "IV: " << keyManager->getIV() << std::endl;
    std::cout << "FDR: IV (" << keyManager->getIV() << ") " << keyManager->getFDR()->getOperator()
              << " " << keyManager->getFDR()->getOperand() << std::endl;

    RECEIVED_RSA_KEY = true;
    printf("***********************************\n\n");

    /* Envia a chave pública do server e o IV */
    printf("*******SEND RSA SERVER KEY*********\n");
    std::string sendString;
    std::string spacer (SPACER_S);
    sendString = std::to_string(keyManager->getServerPublicKey()) + spacer +
                 std::to_string(handleIV(keyManager->getIV(), keyManager->getFDR()));
    char sendBuffer[sendString.length()];
    strcpy(sendBuffer, sendString.c_str());

    std::cout << "Sended Message: " << sendBuffer << std::endl;

    int sended = sendto(socket, sendBuffer, sendString.length(), 0, client, size);

    if (sended >= 0) {
       printf("RSA KEY Client and Server Successful!\n");
    } else {
        herror("sendto");
        printf("RSA KEY Client and Server failed!\n");
    }

    std::cout << "Server RSA Public Key: " << keyManager->getServerPublicKey() << std::endl;
    std::cout << "Handled IV: " << handleIV(keyManager->getIV(), keyManager->getFDR()) << std::endl;
    std::cout << "***********************************\n" << std::endl;


}



int main(int argc, char *argv[]){

    keyManager = new KeyManager();

    /* Testes STRING HANDLER */
    // char buf[] = "123#456#789#101112";
    // std::cout << "DH Client Key: " << StringHandler.getDHClientKey(buf) << std::endl;
    // std::cout << "Client Base: " << StringHandler.getClientBase(buf) << std::endl;
    // std::cout << "Client Modulus: " << StringHandler.getClientModulus(buf) << std::endl;
    // std::cout << "DH IV: " << StringHandler.getDHIvClient(buf) << std::endl;
    /* Testes STRING HANDLER */


    /* Testes FDR */
    // char buf2[] = "029#029#+123";
    // char a = StringHandler.getRSAClientFdr(buf2)->getOperator();
    // int b = StringHandler.getRSAClientFdr(buf2)->getOperand();
    // fdr = StringHandler.getRSAClientFdr(buf2);
    // std::cout << "A: " << fdr->getOperand() << std::endl;
    // fdr = StringHandler.getRSAClientFdr(buf2);
    // keyManager->setClientPublicKey(123);
    // processRSAKeyExchange(buf2);
    // FDR* fdr = new FDR('+', 5);
    // // std::cout << "FDR operator = " << fdr->getOperator() << std::endl;
    // // std::cout << "FDR operand = " << fdr->getOperand() << std::endl;
    // std::cout << "FDR operator = " << StringHandler.getRSAClientFdr(buf2).getOperator() << std::endl;
    // std::cout << "FDR operand = " << StringHandler.getRSAClientFdr(buf2).getOperand() << std::endl;
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
       } else if (strcmp(buffer, DONE_MESSAGE) == 0) {
           processClientDone(buffer, meuSocket, (struct sockaddr*)&cliente, sizeof(struct sockaddr_in));
       } else if (CLIENT_HELLO && !RECEIVED_RSA_KEY) {
           processRSAKeyExchange(buffer, meuSocket, (struct sockaddr*)&cliente, sizeof(struct sockaddr_in));
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
