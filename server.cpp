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
IotAuth iotAuth;
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
    cout << "PUBLIC SERVER KEY: (" << keyManager->getMyPublicKey().d << ", " << keyManager->getMyPublicKey().n << ")" << endl;
    cout << "PRIVATE SERVER KEY: (" << keyManager->getMyPrivateKey().e << ", " << keyManager->getMyPrivateKey().n << ")" << endl;
    printf("***********************************\n\n");

    /* Recebe chave pública do cliente e o IV */
    printf("******CLIENT RSA KEY RECEIVED******\n");
    keyManager->setPartnerPublicKey(StringHandler.getPartnerPublicKey(buffer));
    keyManager->setFDR(StringHandler.getRSAExchangeFdr(buffer));
    keyManager->setIV(StringHandler.getRSAExchangeIv(buffer));

    std::cout << "Client RSA Public Key: (" << keyManager->getPartnerPublicKey().d << ", " << keyManager->getPartnerPublicKey().n << ")" << std::endl;
    std::cout << "IV: " << keyManager->getIV() << std::endl;
    std::cout << "FDR: IV (" << keyManager->getIV() << ") " << keyManager->getFDR()->getOperator()
              << " " << keyManager->getFDR()->getOperand() << std::endl;

    RECEIVED_RSA_KEY = true;
    printf("***********************************\n\n");

    /* Envia a chave pública do server e o IV */
    printf("*******SEND SERVER RSA KEY*********\n");
    std::string sendString;
    std::string spacer (SPACER_S);
    long int iv = 9;
    string fdr = "+3";
    sendString = std::to_string(keyManager->getMyPublicKey().d) + spacer +
                 std::to_string(keyManager->getMyPublicKey().n) + spacer +
                 std::to_string(iv) + spacer +
                 std::to_string(handleIV(keyManager->getIV(), keyManager->getFDR()))
                 + spacer + fdr;

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

    std::cout << "Server RSA Public Key: (" << keyManager->getMyPublicKey().d
              << ", " << keyManager->getMyPublicKey().n << ")" << std::endl;
    std::cout << "IV Obtained: " << handleIV(keyManager->getIV(), keyManager->getFDR()) << std::endl;
    std::cout << "***********************************\n" << std::endl;


}

string getPackage(string package)
{
    string resultado = "";
    int i = 0;

    while (package.at(i) != '*') {
        resultado += package.at(i);
        i++;
    }

    return resultado;
}

string getHashEncrypted(string package)
{
    string resultado = "";
    int i = 0;

    while (package.at(i) != '*') {
        i++;
    }
    i++;

    for (int j = i; j < package.length(); j++) {
        resultado += package.at(j);
    }

    return resultado;
}
void receiveDiffieHellmanKey(char buffer[], int socket, struct sockaddr* client, int size)
{
    /* Decodifica o pacote recebido do cliente. */
    string encryptedPackage (buffer);
    int* decryptedPackageInt = (int*)malloc(encryptedPackage.length() * sizeof(int));
    decryptedPackageInt = utils.RSAToIntArray(buffer, encryptedPackage.length());

    /* Decodifica o pacote e converte para um array de char. */
    string decryptedPackageString = iotAuth.decryptRSAPrivateKey(decryptedPackageInt, keyManager->getMyPrivateKey(), encryptedPackage.length());

    /* Recupera o pacote com os dados Diffie-Hellman do Client. */
    string dhPackage = getPackage(decryptedPackageString);

    /***** HASH *****/
    /* Recupera o hash cifrado com a chave Privada do Server. */
    string encryptedHash = getHashEncrypted(decryptedPackageString);
    char encryptedHashChar[encryptedHash.length()];
    strncpy(encryptedHashChar, encryptedHash.c_str(), sizeof(encryptedHashChar));

    cout << "Encrypted HASH: " << encryptedHash << endl;

    int* encryptedHashInt = (int*)malloc(encryptedHash.length() * sizeof(int));
    encryptedHashInt = utils.RSAToIntArray(encryptedHashChar, 128);

    /* Decifra o HASH com a chave pública do Server. */
    string decryptedHashString = iotAuth.decryptRSAPublicKey(encryptedHashInt, keyManager->getMyPublicKey(), encryptedHash.length());

    cout << "Client Decrypted HASH: " << decryptedHashString << endl;
    /***** HASH *****/

    /* Recebe chave Diffie-Hellman e IV. */
    printf("\n*******CLIENT DH KEY RECEIVED******\n");
    char dhPackageChar[dhPackage.length()];
    strncpy(dhPackageChar, dhPackage.c_str(), sizeof(dhPackageChar));
    keyManager->setBase(StringHandler.getClientBase(dhPackageChar));
    keyManager->setModulus(StringHandler.getClientModulus(dhPackageChar));
    keyManager->setSessionKey(keyManager->getDiffieHellmanKey(StringHandler.getDHClientKey(dhPackageChar)));
    int ivClient = StringHandler.getDHIvClient(dhPackageChar);

    RECEIVED_DH_KEY = true;
    std::cout << "Diffie-Hellman Key: " << StringHandler.getDHClientKey(dhPackageChar) << std::endl;
    std::cout << "Base: " << StringHandler.getClientBase(dhPackageChar) << std::endl;
    std::cout << "Modulus: " << StringHandler.getClientModulus(dhPackageChar) << std::endl;
    std::cout << "Client IV: " << StringHandler.getDHIvClient(dhPackageChar) << std::endl;
    std::cout << "Session Key: " << keyManager->getSessionKey() << std::endl;
    std::cout << "***********************************\n" << std::endl;

}

void processDiffieHellmanKeyExchange(char buffer[], int socket, struct sockaddr* client, int size)
{
    /* Decofificação */
    string encrypted (buffer);
    int* decInt = (int*)malloc(encrypted.length() * sizeof(int));
    decInt = utils.RSAToIntArray(buffer, encrypted.length());

    string packageDecrypted = iotAuth.decryptRSAPrivateKey(decInt, keyManager->getMyPrivateKey(), encrypted.length());
    char packageDecryptedChar[packageDecrypted.length()];
    strncpy(packageDecryptedChar, packageDecrypted.c_str(), sizeof(packageDecryptedChar));

    /* Recupera as chaves */
    string package = getPackage(packageDecrypted);

    string result = getHashEncrypted(packageDecrypted);
    char resultChar[result.length()];
    strncpy(resultChar, result.c_str(), sizeof(resultChar));
    int* decInt2 = (int*)malloc(result.length() * sizeof(int));

    decInt2 = utils.RSAToIntArray(resultChar, sizeof(resultChar));
    string hashDec = iotAuth.decryptRSAPublicKey(decInt2, keyManager->getMyPublicKey(), result.length());

    cout << "Hash decifrado: " << hashDec << endl;

    /* Recebe chave Diffie-Hellman e IV. */
    printf("\n*******CLIENT DH KEY RECEIVED******\n");
    char pkg[package.length()];
    strncpy(pkg, package.c_str(), sizeof(pkg));
    keyManager->setBase(StringHandler.getClientBase(pkg));
    keyManager->setModulus(StringHandler.getClientModulus(pkg));
    keyManager->setSessionKey(keyManager->getDiffieHellmanKey(StringHandler.getDHClientKey(pkg)));
    int ivClient = StringHandler.getDHIvClient(pkg);

    RECEIVED_DH_KEY = true;
    std::cout << "Diffie-Hellman Key: " << StringHandler.getDHClientKey(pkg) << std::endl;
    std::cout << "Base: " << StringHandler.getClientBase(pkg) << std::endl;
    std::cout << "Modulus: " << StringHandler.getClientModulus(pkg) << std::endl;
    std::cout << "Client IV: " << StringHandler.getDHIvClient(pkg) << std::endl;
    std::cout << "Session Key: " << keyManager->getSessionKey() << std::endl;
    std::cout << "***********************************\n" << std::endl;

    /* ENVIO */

    /* Envia chave Diffie-Hellman e IV. */
    printf("*********SEND SERVER DH KEY********\n");
    std::string sendString;
    std::string spacer (SPACER_S);
    sendString = std::to_string(keyManager->getDiffieHellmanKey()) + spacer +
                 std::to_string(keyManager->getBase()) + spacer +
                 std::to_string(keyManager->getModulus()) + spacer +
                 std::to_string(keyManager->getIV()) + spacer +
                 std::to_string(handleIV(ivClient, keyManager->getFDR()));

    char messageArray[sendString.length()];
    memset(messageArray, '0', sizeof(messageArray));
    strncpy(messageArray, package.c_str(), sizeof(messageArray));
    /* Geração do HASH */

    char hashArray[128];
    memset(hashArray, 0, sizeof(hashArray));
    iotAuth.hash(messageArray, hashArray);
    cout << "Hash: " << hashArray << endl;
    int* hashEncrypted = iotAuth.encryptRSAPrivateKey(hashArray, keyManager->getMyPrivateKey(), sizeof(hashArray));

    string hashEncryptedString = "";
    for (int i = 0; i < utils.intArraySize(hashEncrypted); i++) {
        hashEncryptedString += to_string(hashEncrypted[i]);
        if (i < (utils.intArraySize(hashEncrypted)-1))
            hashEncryptedString += ".";
    }

    /* Preparação do pacote */
    string sendData = sendString + "*" + hashEncryptedString;
    // cout << endl<< "Send Data: " << sendData << endl;

    char sendDataArray[sendData.length()];
    memset(sendDataArray, 0, sizeof(sendDataArray));
    strncpy(sendDataArray, sendData.c_str(), sizeof(sendDataArray));

    int* sendDataEncrypted = iotAuth.encryptRSAPublicKey(sendDataArray,
                keyManager->getPartnerPublicKey(), sizeof(sendDataArray));

    // int* sendDataEncrypted = iotAuth.encryptRSAPublicKey(sendDataArray,
    //             keyManager.getMyPublicKey(), sizeof(sendDataArray));

    string m = "";
    for (int i = 0; i < utils.intArraySize(sendDataEncrypted); i++) {
        m += to_string(sendDataEncrypted[i]);

        if (i < (utils.intArraySize(sendDataEncrypted)-1))
            m += ".";
    }

    // cout << endl << endl << "M: " << m << endl;
    char* message = (char*)malloc(m.length());
    memset(message, '0', sizeof(message));

    strncpy(message, m.c_str(), m.length());
    //
    // cout << endl << "Message: " << message << endl;
    // cout << "Message Length: " << m.length() << endl;






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

    int sended = sendto(socket, message, sizeof(m.length()), 0, client, size);

    if (sended >= 0) {
       printf("Client and Server DH KEY Successful!\n");
    } else {
        herror("sendto");
        printf("Client and Server DH KEY failed!\n");
    }

    // std::cout << "Diffie-Hellman Key: " << keyManager->getSessionKey() << std::endl;
    // std::cout << "***********************************\n" << std::endl;
    //
    // std::cout << "*SYMMETRICAL SESSION CLIENT-SERVER*" << std::endl;
    // std::cout << "Session Key: " << keyManager->getSessionKey() << std::endl;
    // std::cout << "***********************************\n" << std::endl;
}

int main(int argc, char *argv[]){
    keyManager = new KeyManager();

    struct sockaddr_in cliente, servidor;
    int meuSocket,enviei=0;
    socklen_t tam_cliente;
    // MTU padrão pela IETF
    char buffer[10000];

    meuSocket=socket(PF_INET,SOCK_DGRAM,0);
    servidor.sin_family=AF_INET;
    servidor.sin_port=htons(DEFAULT_PORT);
    servidor.sin_addr.s_addr=INADDR_ANY;

    memset(buffer, 0, sizeof(buffer));

    bind(meuSocket,(struct sockaddr*)&servidor,sizeof(struct sockaddr_in));

    printf("*** Servidor de Mensagens ***\n");
    while(1){

       tam_cliente=sizeof(struct sockaddr_in);

       memset(buffer, 0, sizeof(buffer));
       recvfrom(meuSocket, buffer, sizeof(buffer), MSG_WAITALL, (struct sockaddr*)&cliente, &tam_cliente);
       // printf("Recebi:%s de <endereço:%s> <porta:%d>\n",buffer,inet_ntoa(cliente.sin_addr),ntohs(cliente.sin_port));

       /* Aguarda o recebimento do HELLO do Client. */
       /* HELLO */
       if (!CLIENT_HELLO) {
           processClientHello(buffer, meuSocket, (struct sockaddr*)&cliente, sizeof(struct sockaddr_in));
         /* Se a mensagem recebida do Client for um DONE: */
         /* DONE */
       } else if (strcmp(buffer, DONE_MESSAGE) == 0) {
           processClientDone(buffer, meuSocket, (struct sockaddr*)&cliente, sizeof(struct sockaddr_in));
           /* Se já recebeu um CLIENT_HELLO, mas a troca de chaves RSA ainda não ocorreu: */
           /* CLIENT_PUBLIC_KEY (D) # CLIENT_PUBLIC_KEY (N) # ANSWER FDR # IV # FDR */
       } else if (CLIENT_HELLO && !RECEIVED_RSA_KEY) {
           processRSAKeyExchange(buffer, meuSocket, (struct sockaddr*)&cliente, sizeof(struct sockaddr_in));
           /* Se já realizou a troa de chaves RSA, mas ainda não realizou a troca de chaves DH: */
           /* DH_KEY_CLIENT # BASE # MODULUS # CLIENT_IV */
       } else if (RECEIVED_RSA_KEY && !RECEIVED_DH_KEY) {
           receiveDiffieHellmanKey(buffer, meuSocket, (struct sockaddr*)&cliente, sizeof(struct sockaddr_in));
           /* Aqui, todos as chaves foram trocadas, então é só receber os dados cifrados: */
       } else {
           /******* INCOMPLETO ***************/
           // cout << "Recebido: " << buffer << endl;
           // cout << "Tamanho buffer recebido: " << sizeof(buffer) << endl;
           //
           // byte plain[64];
           // char plain_char[sizeof(plain)];
           //
           // iotAuth.decryptHEX(plain, sizeof(plain), buffer, sizeof(buffer));
           // utils.ByteToChar(plain, plain_char, sizeof(plain));
           //
           // cout << "Decifrado " << plain_char << endl;
           //
           // byte plainTesteByte[64];
           // char plainTesteChar[] = "hello";
           // char hexTeste[128];
           // byte decifradoByte[64];
           // char decifradoChar[64];
           //
           // memset(plainTesteByte, 0, sizeof(plainTesteByte));
           // memset(hexTeste, '0', sizeof(hexTeste));
           // memset(decifradoByte, 0, sizeof(decifradoByte));
           // memset(decifradoChar, '0', sizeof(decifradoChar));
           //
           // for (int i = 0; i < sizeof(plainTesteChar); i++) {
           //     plainTesteByte[i] = plainTesteChar[i];
           // }
           //
           // iotAuth.encryptHEX(plainTesteByte, sizeof(plainTesteByte), hexTeste, sizeof(hexTeste));
           // cout << "Encriptado: " << hexTeste << endl;
           //
           // iotAuth.decryptHEX(decifradoByte, sizeof(decifradoByte), hexTeste, sizeof(hexTeste));
           // utils.ByteToChar(decifradoByte, decifradoChar, sizeof(decifradoByte));
           //
           // cout << "Decriptado: " << decifradoChar << endl;
           /******* INCOMPLETO ***************/
       }

       memset(buffer, 0, sizeof(buffer));
    }
    close(meuSocket);
}
