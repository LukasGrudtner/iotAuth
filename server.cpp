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
#include "iotAuth.h"

using namespace std;

StringHandler StringHandler;

bool CHANGED_KEYS = false;
bool CLIENT_HELLO = false;
bool CLIENT_DONE = false;
bool RECEIVED_RSA_KEY = false;
bool RECEIVED_DH_KEY = false;
KeyManager* keyManager;
FDR* fdr;
iotAuth iotAuth;

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

    int sended = sendto(socket, sendBuffer, strlen(sendBuffer), 0, client, size);

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

void processDiffieHellmanKeyExchange(char buffer[], int socket, struct sockaddr* client, int size)
{
    /* Recebe chave Diffie-Hellman e IV. */
    printf("*******RECEIVED DH CLIENT KEY******\n");
    keyManager->setBase(StringHandler.getClientBase(buffer));
    keyManager->setModulus(StringHandler.getClientModulus(buffer));
    keyManager->setSessionKey(keyManager->getDiffieHellmanKey(StringHandler.getDHClientKey(buffer)));
    int ivClient = StringHandler.getDHIvClient(buffer);

    RECEIVED_DH_KEY = true;
    std::cout << "Diffie-Hellman Key: " << StringHandler.getDHClientKey(buffer) << std::endl;
    std::cout << "Base: " << StringHandler.getClientBase(buffer) << std::endl;
    std::cout << "Modulus: " << StringHandler.getClientModulus(buffer) << std::endl;
    std::cout << "IV Client: " << StringHandler.getDHIvClient(buffer) << std::endl;
    std::cout << "Session Key: " << keyManager->getSessionKey() << std::endl;
    std::cout << "***********************************\n" << std::endl;

    /* Envia chave Diffie-Hellman e IV. */
    printf("*********SEND DH SERVER KEY********\n");
    std::string sendString;
    std::string spacer (SPACER_S);
    sendString = std::to_string(keyManager->getDiffieHellmanKey()) + spacer +
                 std::to_string(handleIV(ivClient, keyManager->getFDR()));
    char sendBuffer[sendString.length()];
    strcpy(sendBuffer, sendString.c_str());

    std::cout << "Sended Message: " << sendBuffer << std::endl;

    int sended = sendto(socket, sendBuffer, strlen(sendBuffer), 0, client, size);

    if (sended >= 0) {
       printf("DH KEY Client and Server Successful!\n");
    } else {
        herror("sendto");
        printf("DH KEY Client and Server failed!\n");
    }

    std::cout << "Diffie-Hellman Key: " << keyManager->getSessionKey() << std::endl;
    std::cout << "***********************************\n" << std::endl;

    std::cout << "*SYMMETRICAL SESSION CLIENT-SERVER*" << std::endl;
    std::cout << "Session Key: " << keyManager->getSessionKey() << std::endl;
    std::cout << "***********************************\n" << std::endl;
}

std::string byteToHex(char data[], int len)
{
    std::stringstream ss;
    ss<<std::hex;
    for(int i = 0;i<len;++i)
        ss<<(int)data[i];
    return ss.str();
}

void CharToByte(char* chars, byte* bytes, unsigned int count){
    for(unsigned int i = 0; i < count; i++)
        bytes[i] = (byte)chars[i];
}

void ByteToChar(byte* bytes, char* chars, unsigned int count){
    for(unsigned int i = 0; i < count; i++)
         chars[i] = (char)bytes[i];
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

    // char buf3[] = "20#40#60#80";
    // processDiffieHellmanKeyExchange(buf3);

    byte *key = (unsigned char*)"1234567891234567";
    byte plain[] = "Segurança é muito importante para IoT!";
    byte cipher[64];
    byte plain2[64];
    unsigned long long int iv = 11111111;

    iotAuth.encryptAES(256, 64, key, plain, iv, cipher);
    cout << "Cifrado: " << cipher << endl;
    iotAuth.decryptAES(256, 64, key, plain, iv, cipher);
    cout << "Decifrado: " << plain2 << endl;

    struct sockaddr_in cliente, servidor;
    int meuSocket,enviei=0;
    socklen_t tam_cliente;
    // MTU padrão pela IETF
    char buffer[556];

    meuSocket=socket(PF_INET,SOCK_DGRAM,0);
    servidor.sin_family=AF_INET;
    servidor.sin_port=htons(DEFAULT_PORT);
    servidor.sin_addr.s_addr=INADDR_ANY;

    memset(buffer, 0, sizeof(buffer));

    bind(meuSocket,(struct sockaddr*)&servidor,sizeof(struct sockaddr_in));

    printf("*** Servidor de Mensagens ***\n");
    while(1){
       tam_cliente=sizeof(struct sockaddr_in);
       recvfrom(meuSocket,buffer,556,MSG_WAITALL,(struct sockaddr*)&cliente,&tam_cliente);
       // printf("Recebi:%s de <endereço:%s> <porta:%d>\n",buffer,inet_ntoa(cliente.sin_addr),ntohs(cliente.sin_port));

       /* HELLO */
       if (!CLIENT_HELLO) {
           processClientHello(buffer, meuSocket, (struct sockaddr*)&cliente, sizeof(struct sockaddr_in));
         /* DONE */
       } else if (strcmp(buffer, DONE_MESSAGE) == 0) {
           processClientDone(buffer, meuSocket, (struct sockaddr*)&cliente, sizeof(struct sockaddr_in));
           /* CLIENT_KEY_PUBLIC # IV # FDR */
       } else if (CLIENT_HELLO && !RECEIVED_RSA_KEY) {
           processRSAKeyExchange(buffer, meuSocket, (struct sockaddr*)&cliente, sizeof(struct sockaddr_in));
           /* DH_KEY_CLIENT # BASE # MODULUS # CLIENT_IV */
       } else if (CLIENT_HELLO && !RECEIVED_DH_KEY) {
           processDiffieHellmanKeyExchange(buffer, meuSocket, (struct sockaddr*)&cliente, sizeof(struct sockaddr_in));
       } else {
           std::cout << "Recebido: " << buffer << std::endl;
           byte *key21 = (unsigned char*)"1234567891234567";
            byte plain[64];
            byte cipher[64];
            CharToByte(buffer, cipher, 64);
            unsigned long long int my_iv = 11111111;
            iotAuth.decryptAES(256, 41, key21, plain, my_iv, cipher);
            char plain2[64];
            ByteToChar(plain, plain2, 64);
            std::cout << "Decifrado: " << plain2 << std::endl;
       }

       memset(buffer, 0, sizeof(buffer));
    }
    close(meuSocket);
}
