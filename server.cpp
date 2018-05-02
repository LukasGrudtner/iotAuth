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
#include <vector>
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
Utils utils;

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
    cout << "Received: " << buffer << endl;
    /* Realiza a geração das chaves pública e privada (RSA). */
    printf("*******GENERATION OF RSA KEYS******\n");
    keyManager->setRSAKeyPair(iotAuth.generateRSAKeyPair());
    cout << "PUBLIC SERVER KEY: (" << keyManager->getServerPublicKey().d << ", " << keyManager->getServerPublicKey().n << ")" << endl;
    cout << "PRIVATE SERVER KEY: (" << keyManager->getServerPrivateKey().e << ", " << keyManager->getServerPrivateKey().n << ")" << endl;
    printf("***********************************\n\n");

    /* Recebe chave pública do cliente e o IV */
    printf("******CLIENT RSA KEY RECEIVED******\n");
    keyManager->setClientPublicKey(StringHandler.getClientPublicKey(buffer));
    keyManager->setFDR(StringHandler.getRSAClientFdr(buffer));
    keyManager->setIV(StringHandler.getRSAExchangeIv(buffer));

    std::cout << "Client RSA Public Key: (" << keyManager->getClientPublicKey().d << ", " << keyManager->getClientPublicKey().n << ")" << std::endl;
    std::cout << "IV: " << keyManager->getIV() << std::endl;
    std::cout << "FDR: IV (" << keyManager->getIV() << ") " << keyManager->getFDR()->getOperator()
              << " " << keyManager->getFDR()->getOperand() << std::endl;

    RECEIVED_RSA_KEY = true;
    printf("***********************************\n\n");

    /* Envia a chave pública do server e o IV */
    printf("*******SEND SERVER RSA KEY*********\n");
    std::string sendString;
    std::string spacer (SPACER_S);
    sendString = std::to_string(keyManager->getServerPublicKey().d) + spacer +
                 std::to_string(keyManager->getServerPublicKey().n) + spacer +
                 std::to_string(handleIV(keyManager->getIV(), keyManager->getFDR()));

    char sendBuffer[sendString.length()];
    strcpy(sendBuffer, sendString.c_str());

    std::cout << "Sent Message: " << sendBuffer << std::endl;

    int sended = sendto(socket, sendBuffer, strlen(sendBuffer), 0, client, size);

    if (sended >= 0) {
       printf("Client and Server RSA KEY Successful!\n");
    } else {
        herror("sendto");
        printf("Client and Server RSA KEY failed!\n");
    }

    std::cout << "Server RSA Public Key: (" << keyManager->getServerPublicKey().d
              << ", " << keyManager->getServerPublicKey().n << ")" << std::endl;
    std::cout << "IV Obtained: " << handleIV(keyManager->getIV(), keyManager->getFDR()) << std::endl;
    std::cout << "***********************************\n" << std::endl;


}

void processDiffieHellmanKeyExchange(char buffer[], int socket, struct sockaddr* client, int size)
{
    /* Recebe chave Diffie-Hellman e IV. */
    printf("*******CLIENT DH KEY RECEIVED******\n");
    keyManager->setBase(StringHandler.getClientBase(buffer));
    keyManager->setModulus(StringHandler.getClientModulus(buffer));
    keyManager->setSessionKey(keyManager->getDiffieHellmanKey(StringHandler.getDHClientKey(buffer)));
    int ivClient = StringHandler.getDHIvClient(buffer);

    RECEIVED_DH_KEY = true;
    std::cout << "Diffie-Hellman Key: " << StringHandler.getDHClientKey(buffer) << std::endl;
    std::cout << "Base: " << StringHandler.getClientBase(buffer) << std::endl;
    std::cout << "Modulus: " << StringHandler.getClientModulus(buffer) << std::endl;
    std::cout << "Client IV: " << StringHandler.getDHIvClient(buffer) << std::endl;
    std::cout << "Session Key: " << keyManager->getSessionKey() << std::endl;
    std::cout << "***********************************\n" << std::endl;

    /* Envia chave Diffie-Hellman e IV. */
    printf("*********SEND SERVER DH KEY********\n");
    std::string sendString;
    std::string spacer (SPACER_S);
    sendString = std::to_string(keyManager->getDiffieHellmanKey()) + spacer +
                 std::to_string(keyManager->getBase()) + spacer +
                 std::to_string(keyManager->getModulus()) + spacer +
                 std::to_string(keyManager->getIV()) + spacer +
                 std::to_string(handleIV(ivClient, keyManager->getFDR()));
    char sendBuffer[sendString.length()];
    memset(sendBuffer, 0, sizeof(sendBuffer));
    strncpy(sendBuffer, sendString.c_str(), sizeof(sendBuffer));

    cout << sendBuffer << endl;

    // /* Geração do HASH */
    // string hash = iotAuth.hash(sendString);
    // cout << "Hash: " << hash << endl;
    //
    // /* Codificação da mensagem com a chave privada de B (server) */
    // char enc[sizeof(sendString)];
    // strncpy(enc, sendString.c_str(), sizeof(enc));
    // int* encrypted = iotAuth.encryptRSAPrivateKey(enc, keyManager->getServerPrivateKey(), sizeof(enc));
    //
    // string encrypted_string = "";
    // for (int i = 0; i < sizeof(enc); i++)
    //     encrypted_string += to_string(encrypted[i]);
    //
    // cout << "Encriptado: " << encrypted_string << endl << endl;
    //
    // /* Concatenação do bloco */
    // string package = hash + spacer + encrypted_string;
    // cout << "Pacote: " << package << endl << endl;
    //
    // /* Codificação do bloco com a chave pública de A (client) */
    // char packageChar[package.length()];
    // strncpy(packageChar, package.c_str(), sizeof(packageChar));
    //
    // int* encryptedPackage = iotAuth.encryptRSAPublicKey(packageChar, keyManager->getClientPublicKey(), sizeof(packageChar));
    //
    // string encryptedPackage_string = "";
    // for (int i = 0; i < sizeof(packageChar); i++)
    //     encryptedPackage_string += to_string(encryptedPackage[i]);
    // cout << "Encrypted Package: " << encryptedPackage_string << endl<< endl;
    //
    // char sendBuffer[encryptedPackage_string.length()];
    // strncpy(sendBuffer, encryptedPackage_string.c_str(), encryptedPackage_string.length());
    // std::cout << "Sent Message: " << sendBuffer << std::endl;

    int sended = sendto(socket, sendBuffer, sizeof(sendBuffer), 0, client, size);

    if (sended >= 0) {
       printf("Client and Server DH KEY Successful!\n");
    } else {
        herror("sendto");
        printf("Client and Server DH KEY failed!\n");
    }

    std::cout << "Diffie-Hellman Key: " << keyManager->getSessionKey() << std::endl;
    std::cout << "***********************************\n" << std::endl;

    std::cout << "*SYMMETRICAL SESSION CLIENT-SERVER*" << std::endl;
    std::cout << "Session Key: " << keyManager->getSessionKey() << std::endl;
    std::cout << "***********************************\n" << std::endl;
}

int main(int argc, char *argv[]){
    keyManager = new KeyManager();

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

       recvfrom(meuSocket, buffer, sizeof(buffer), MSG_WAITALL, (struct sockaddr*)&cliente, &tam_cliente);
       cout << "*** RECEBIDO *** :" << buffer << endl<< endl;
       // printf("Recebi:%s de <endereço:%s> <porta:%d>\n",buffer,inet_ntoa(cliente.sin_addr),ntohs(cliente.sin_port));

       /* HELLO */
       if (!CLIENT_HELLO) {
           processClientHello(buffer, meuSocket, (struct sockaddr*)&cliente, sizeof(struct sockaddr_in));
         /* DONE */
       } else if (strcmp(buffer, DONE_MESSAGE) == 0) {
           processClientDone(buffer, meuSocket, (struct sockaddr*)&cliente, sizeof(struct sockaddr_in));
           /* CLIENT_PUBLIC_KEY (D) # CLIENT_PUBLIC_KEY (N) # ANSWER FDR # IV # FDR */
       } else if (CLIENT_HELLO && !RECEIVED_RSA_KEY) {
           processRSAKeyExchange(buffer, meuSocket, (struct sockaddr*)&cliente, sizeof(struct sockaddr_in));
           /* DH_KEY_CLIENT # BASE # MODULUS # CLIENT_IV */
       } else if (CLIENT_HELLO && !RECEIVED_DH_KEY) {
           processDiffieHellmanKeyExchange(buffer, meuSocket, (struct sockaddr*)&cliente, sizeof(struct sockaddr_in));
       } else {
           // char received_hexa[sizeof(buffer)*2];
           // byte received_byte[64];
           // CharToByte((unsigned char*)buffer, received_byte, sizeof(buffer));
           // byteArrayToHexString(received_byte, sizeof(received_byte), received_hexa, sizeof(received_hexa));


           // byteArrayToHexString(teste_byte, sizeof(teste_byte), cipherHexa, sizeof(cipherHexa));
           // cout << "Cipher Hexa: " << cipherHexa << endl;
           // // CharToByte(buffer, cipher, sizeof(cipher));
           // iotAuth.decryptAES(256, 41, key, plain, iv, (byte*)received_byte);
           // cout << "Decifrado " << plain << endl;
       }

       memset(buffer, 0, sizeof(buffer));
    }
    close(meuSocket);
}
