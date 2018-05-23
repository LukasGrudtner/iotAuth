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
int EXPONENT = 3;

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

int calculateFDRValue(int _iv, FDR* _fdr)
{
    int result = 0;
    if (_fdr->getOperator() == '+') {
        result = _iv+_fdr->getOperand();
    }

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

    /* Gera um IV para o servidor e o armazena no KeyManager. */
    keyManager->setMyIV(iotAuth.generateIV());

    /* Gera uma Função Desafio-Resposta para o servidor e o armazena no KeyManager. */
    keyManager->setMyFDR(iotAuth.generateFDR());

    /* Recebe chave pública do cliente e o IV */
    printf("******CLIENT RSA KEY RECEIVED******\n");
    keyManager->setPartnerPublicKey(StringHandler.getPartnerPublicKey(buffer));
    FDR* partnerFDR = StringHandler.getRSAExchangeFdr(buffer);
    cout << "Partner FDR: " << partnerFDR->getOperator() << partnerFDR->getOperand() << endl;
    int partnerIV = StringHandler.getRSAExchangeIv(buffer);

    std::cout << "Client RSA Public Key: (" << keyManager->getPartnerPublicKey().d << ", " << keyManager->getPartnerPublicKey().n << ")" << std::endl;
    std::cout << "Client IV: " << partnerIV << std::endl;
    std::cout << "Client FDR: IV (" << partnerIV << ") " << partnerFDR->getOperator()
              << " " << partnerFDR->getOperand() << std::endl;

    RECEIVED_RSA_KEY = true;
    printf("***********************************\n\n");

    /* Envia a chave pública do server e o IV */
    printf("*******SEND SERVER RSA KEY*********\n");
    std::string sendString;
    std::string spacer (SPACER_S);
    int answerFdr = calculateFDRValue(partnerIV, partnerFDR);
    // int answerFdr = calculateFDRValue(partnerIV, partnerFDR) + 1;

    sendString = std::to_string(keyManager->getMyPublicKey().d) + spacer +
                 std::to_string(keyManager->getMyPublicKey().n) + spacer +
                 std::to_string(answerFdr) + spacer +
                 std::to_string(keyManager->getMyIV()) + spacer +
                 StringHandler.FdrToString(keyManager->getMyFDR());

    char sendBuffer[sendString.length()];
    strcpy(sendBuffer, sendString.c_str());

    std::cout << "Sent Message: " << sendBuffer << std::endl;

    std::cout << "Server RSA Public Key: (" << keyManager->getMyPublicKey().d
              << ", " << keyManager->getMyPublicKey().n << ")" << std::endl;
    std::cout << "Answer FDR (Client): " << answerFdr << std::endl;
    std::cout << "My IV: " << keyManager->getMyIV() << std::endl;
    std::cout << "My FDR: " << StringHandler.FdrToString(keyManager->getMyFDR()) << std::endl;
    std::cout << "***********************************\n" << std::endl;

    int sended = sendto(socket, sendBuffer, strlen(sendBuffer), 0, client, size);
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

    while (package.at(i) != '!') {
        resultado += package.at(i);
        i++;
    }
    resultado += package.at(i);

    return resultado;
}

bool checkAnsweredFDR(int answeredFdr)
{
    int answer = calculateFDRValue(keyManager->getMyIV(), keyManager->getMyFDR());

    return answer == answeredFdr;
}

void receiveDiffieHellmanKey(char buffer[])
{
    printf("1\n");

    /* Decodifica o pacote recebido do cliente. */
    string encryptedPackage (buffer);
    // cout << "Recebido: " << encryptedPackage << endl << endl;
    // cout << "Size Recebido: " << encryptedPackage.length() << endl << endl;
    int decryptedPackageInt[utils.countMarks(encryptedPackage)+1];

    printf("2\n");

    utils.RSAToIntArray(decryptedPackageInt, encryptedPackage, (utils.countMarks(encryptedPackage)+1));

    printf("3\n");

    /* Decodifica o pacote e converte para um array de char. */
    string decryptedPackageString = iotAuth.decryptRSAPrivateKey(decryptedPackageInt, keyManager->getMyPrivateKey(), utils.countMarks(encryptedPackage)+1);

    printf("4\n");

    cout << "Decrypted Package String: " << decryptedPackageString << endl;

    /* Recupera o pacote com os dados Diffie-Hellman do Client. */
    string dhPackage = getPackage(decryptedPackageString);

    printf("5\n");

    /***** HASH *****/
    /* Recupera o hash cifrado com a chave Privada do Server. */
    string encryptedHash = getHashEncrypted(decryptedPackageString);

    printf("6\n");

    // cout << "Client Encrypted HASH: " << encryptedHash << endl << endl;

    int encryptedHashInt[128];
    utils.RSAToIntArray(encryptedHashInt, encryptedHash, 128);

    printf("7\n");

    /* Decifra o HASH com a chave pública do Server. */
    cout << "Decripta hash com a chave pública do cliente: (" << keyManager->getPartnerPublicKey().d << ", " << keyManager->getPartnerPublicKey().n << ")" << endl;
    string decryptedHashString = iotAuth.decryptRSAPublicKey(encryptedHashInt, keyManager->getPartnerPublicKey(), 128);

    printf("8\n");

    cout << "Client Decrypted HASH STRING: " << decryptedHashString << endl << endl;
    cout << "Client Decrypted HASH Lenght: " << decryptedHashString.length() << endl << endl;
    /***** HASH *****/

    /* Recebe chave Diffie-Hellman e IV. */
    printf("\n*******CLIENT DH KEY RECEIVED******\n");
    char dhPackageChar[dhPackage.length()];
    strncpy(dhPackageChar, dhPackage.c_str(), sizeof(dhPackageChar));

    keyManager->setBase(StringHandler.getClientBase(dhPackageChar));
    keyManager->setModulus(StringHandler.getClientModulus(dhPackageChar));
    keyManager->setSessionKey(keyManager->getDiffieHellmanKey(StringHandler.getDHClientKey(dhPackageChar)));
    int clientIV = StringHandler.getDHIvClient(dhPackageChar);
    int answeredFdr = StringHandler.getDHExchangeAnsweredFDR(dhPackageChar);


    std::cout << "Diffie-Hellman Key: " << StringHandler.getDHClientKey(dhPackageChar) << std::endl;
    std::cout << "Base: " << StringHandler.getClientBase(dhPackageChar) << std::endl;
    std::cout << "Modulus: " << StringHandler.getClientModulus(dhPackageChar) << std::endl;
    std::cout << "Client IV: " << clientIV << std::endl;
    std::cout << "Session Key: " << keyManager->getSessionKey() << std::endl;
    std::cout << "Answered FDR: " << answeredFdr << std::endl;

    if (checkAnsweredFDR(answeredFdr)) {
        RECEIVED_DH_KEY = true;
        cout << "Answered FDR ACCEPTED!" << endl;
    } else {
        cout << "Answered FDR REJECTED!" << endl;
        cout << "ENDING CONECTION..." << endl;
        // done();
        // sendServerDone();
        // receiveServerDone(buffer);
    }

    std::cout << "***********************************\n" << std::endl;
}

string sendDiffieHellmanKey()
{
    /* Envia chave Diffie-Hellman e IV. */
    printf("*********SEND SERVER DH KEY********\n\n");
    std::string sendString;
    std::string spacer (SPACER_S);
    sendString = std::to_string(keyManager->getDiffieHellmanKey()) + spacer +
                 std::to_string(keyManager->getBase()) + spacer +
                 std::to_string(keyManager->getModulus()) + spacer +
                 std::to_string(keyManager->getMyIV()) + spacer +
                 std::to_string(calculateFDRValue(keyManager->getMyIV(), keyManager->getMyFDR()));

    cout << "Sent: " << sendString << endl << endl;

    char messageArray[sendString.length()];
    memset(messageArray, 0, sizeof(messageArray));
    strncpy(messageArray, sendString.c_str(), sizeof(messageArray));

    /***************************** Geração do HASH *******************************/
    string hash = iotAuth.hash(messageArray);
    // cout << "Server Hash: " << hash << endl << endl;
    // cout << "Server Hash Length: " << hash.length() << endl << endl;
    string hashEncryptedString = iotAuth.encryptRSAPrivateKey(hash, keyManager->getMyPrivateKey(), hash.length());
    hashEncryptedString += "!";

    cout << "Server Hash Encrypted: " << hashEncryptedString << endl << endl;

    /************************* Preparação do pacote ******************************/
    string sendData = sendString + "*" + hashEncryptedString;

    char sendDataArray[sendData.length()];
    memset(sendDataArray, '0', sizeof(sendDataArray));
    strncpy(sendDataArray, sendData.c_str(), sizeof(sendDataArray));

    string sendDataEncrypted = iotAuth.encryptRSAPublicKey(sendDataArray,
                keyManager->getPartnerPublicKey(), sizeof(sendDataArray));
    sendDataEncrypted += "!";

    // cout << "Send Data Encrypted: " << sendDataEncrypted << endl << endl;

    return sendDataEncrypted;
}

void receiveEncryptedMessage(char buffer[])
{
    string encryptedMessage (buffer);

    // cout << "Encrypted Message Received: " << encryptedMessage << endl;

    char ciphertextChar[encryptedMessage.length()];
    uint8_t ciphertext[encryptedMessage.length()];
    memset(ciphertext, 0, encryptedMessage.length());

    utils.hexStringToCharArray(encryptedMessage, encryptedMessage.length(), ciphertextChar);

    uint8_t plaintext[encryptedMessage.length()];
    memset(plaintext, 0, encryptedMessage.length());

    uint8_t key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                      0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
    uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    utils.charToUint8_t(ciphertextChar, ciphertext, encryptedMessage.length());

    uint8_t *decrypted = iotAuth.decryptAES(ciphertext, key, iv, encryptedMessage.length());
    cout << "Decrypted: " << decrypted << endl;
}

int main(int argc, char *argv[]){
    keyManager = new KeyManager();
    keyManager->setExponent(EXPONENT);

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
           sleep(3); /* Agurda 5 segundos para gerar chaves RSA diferentes do client */
           processRSAKeyExchange(buffer, meuSocket, (struct sockaddr*)&cliente, sizeof(struct sockaddr_in));
           /* Se já realizou a troa de chaves RSA, mas ainda não realizou a troca de chaves DH: */
           /* DH_KEY_CLIENT # BASE # MODULUS # CLIENT_IV */
       } else if (RECEIVED_RSA_KEY && !RECEIVED_DH_KEY) {
           receiveDiffieHellmanKey(buffer);

           printf("Send Diffie Hellman Key\n");
           string message = sendDiffieHellmanKey();
           char messageArray[message.length()];
           strncpy(messageArray, message.c_str(), sizeof(messageArray));
           sendto(meuSocket, messageArray, sizeof(messageArray), 0, (struct sockaddr*)&cliente, sizeof(struct sockaddr_in));
           /* Aqui, todos as chaves foram trocadas, então é só receber os dados cifrados: */
       } else if(RECEIVED_RSA_KEY && RECEIVED_DH_KEY) {
           cout << "Envio de dados criptografados com AES." << endl << endl;
           receiveEncryptedMessage(buffer);
       }

       memset(buffer, 0, sizeof(buffer));
    }
    close(meuSocket);
}
