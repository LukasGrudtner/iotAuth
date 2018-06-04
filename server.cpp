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

void done()
{
    cout << "Ending the conection...\n" << endl;
    CHANGED_KEYS = false;
    CLIENT_HELLO = false;
    RECEIVED_RSA_KEY = false;
    RECEIVED_DH_KEY = false;
}

bool receiveClientDone(char buffer[])
{
    cout << "*************DONE SERVER**************" << endl;
    if (buffer[0] == DONE_ACK_CHAR) {
        CLIENT_DONE = true;
        cout << "Server Done: Successful" << endl;
        cout << "**************************************\n" << endl;
        return true;
    }

    return false;
}

char* sendServerDone()
{
    string done (DONE_MESSAGE);
    char *message = (char*)malloc(4);
    strncpy(message, done.c_str(), 4);
    return message;
}

char sendServerACKDone()
{
    return DONE_ACK_CHAR;
}

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
    /* Realiza a geração das chaves pública e privada (RSA). */
    keyManager->setRSAKeyPair(iotAuth.generateRSAKeyPair());

    /* Gera um IV para o servidor e o armazena no KeyManager. */
    keyManager->setMyIV(iotAuth.generateIV());

    /* Gera uma Função Desafio-Resposta para o servidor e o armazena no KeyManager. */
    keyManager->setMyFDR(iotAuth.generateFDR());

    /* Recebe chave pública do cliente e o IV */
    keyManager->setPartnerPublicKey(StringHandler.getPartnerPublicKey(buffer));
    FDR* partnerFDR = StringHandler.getRSAExchangeFdr(buffer);

    int partnerIV = StringHandler.getRSAExchangeIv(buffer);

    RECEIVED_RSA_KEY = true;

    if (VERBOSE) {
        printf("******CLIENT RSA KEY RECEIVED******\n");
        cout << "Received: " << buffer << endl;
        cout << "Generated RSA Key: {(" << keyManager->getMyPublicKey().d << ", " << keyManager->getMyPublicKey().n << "), ";
        cout << "(" << keyManager->getMyPrivateKey().d << ", " << keyManager->getMyPrivateKey().n << ")}" << endl;
        cout << "My IV: " << keyManager->getMyIV() << endl;
        cout << "My FDR: " << StringHandler.FdrToString(keyManager->getMyFDR()) << endl << endl;
        cout << "Client RSA Public Key: (" << keyManager->getPartnerPublicKey().d << ", " << keyManager->getPartnerPublicKey().n << ")" << endl;
        cout << "Client IV: " << partnerIV << endl;
        cout << "Client FDR: " << StringHandler.FdrToString(partnerFDR) << endl;
        cout << "Client FDR Answer: " << calculateFDRValue(partnerIV, partnerFDR) << endl;
        printf("***********************************\n\n");
    }

    /* Envia a chave pública do server e o IV */

    std::string sendString;
    std::string spacer (SPACER_S);
    int answerFdr = calculateFDRValue(partnerIV, partnerFDR);

    sendString = std::to_string(keyManager->getMyPublicKey().d) + spacer +
                 std::to_string(keyManager->getMyPublicKey().n) + spacer +
                 std::to_string(answerFdr) + spacer +
                 std::to_string(keyManager->getMyIV()) + spacer +
                 StringHandler.FdrToString(keyManager->getMyFDR()) + spacer;

    char sendBuffer[sendString.length()];
    strcpy(sendBuffer, sendString.c_str());

    if (VERBOSE) {
        printf("*******SEND SERVER RSA KEY*********\n");
        cout << "Server RSA Public Key: (" << keyManager->getMyPublicKey().d
                  << ", " << keyManager->getMyPublicKey().n << ")" << endl;
        cout << "Answer FDR (Client): " << answerFdr << endl;
        cout << "My IV: " << keyManager->getMyIV() << endl;
        cout << "My FDR: " << StringHandler.FdrToString(keyManager->getMyFDR()) << endl;
        cout << "Sent Message: " << sendBuffer << endl;
        cout << "***********************************\n" << endl;
    }

    int sended = sendto(socket, sendBuffer, strlen(sendBuffer), 0, client, size);
}

/* Extrai o pacote da string recebida por parâmetro. */
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

/* Extrai o hash encriptado da string recebida por parâmetro. */
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

/* Verifica se a resposta do FDR é válida. */
bool checkAnsweredFDR(int answeredFdr)
{
    int answer = calculateFDRValue(keyManager->getMyIV(), keyManager->getMyFDR());

    return answer == answeredFdr;
}

bool receiveDiffieHellmanKey(char buffer[])
{
    /* Decodifica o pacote recebido do cliente. */
    string encryptedPackage (buffer);

    int decryptedPackageInt[utils.countMarks(encryptedPackage)+1];
    utils.RSAToIntArray(decryptedPackageInt, encryptedPackage, (utils.countMarks(encryptedPackage)+1));

    /* Decodifica o pacote e converte para um array de char. */
    string decryptedPackageString = iotAuth.decryptRSA(decryptedPackageInt, keyManager->getMyPrivateKey(), utils.countMarks(encryptedPackage)+1);

    /* Recupera o pacote com os dados Diffie-Hellman do Client. */
    string dhPackage = getPackage(decryptedPackageString);

    /***** HASH *****/
    /* Recupera o hash cifrado com a chave Privada do Server. */
    string encryptedHash = getHashEncrypted(decryptedPackageString);

    int encryptedHashInt[128];
    utils.RSAToIntArray(encryptedHashInt, encryptedHash, 128);

    /* Decifra o HASH com a chave pública do Server. */
    string decryptedHashString = iotAuth.decryptRSA(encryptedHashInt, keyManager->getPartnerPublicKey(), 128);

    /* Se o hash é válido, continua com o recebimento. */
    if (iotAuth.isHashValid(dhPackage, decryptedHashString)) {

        /* Recebe chave Diffie-Hellman e IV. */
        char dhPackageChar[dhPackage.length()];
        strncpy(dhPackageChar, dhPackage.c_str(), sizeof(dhPackageChar));

        keyManager->setBase(StringHandler.getClientBase(dhPackageChar));
        keyManager->setModulus(StringHandler.getClientModulus(dhPackageChar));
        keyManager->setSessionKey(keyManager->getDiffieHellmanKey(StringHandler.getDHClientKey(dhPackageChar)));
        int clientIV = StringHandler.getDHIvClient(dhPackageChar);
        int answeredFdr = StringHandler.getDHExchangeAnsweredFDR(dhPackageChar);

        if (VERBOSE) {
            printf("\n*******CLIENT DH KEY RECEIVED******\n");

            cout << "Hash is valid!" << endl << endl;

            if (VERBOSE_2) {
                cout << "Client Encrypted Data" << endl << buffer << endl << endl;
                cout << "Client Encrypted Hash" << endl << encryptedHash << endl << endl;
            }

            cout << "Client Decrypted HASH: " << decryptedHashString << endl << endl;
            cout << "Diffie-Hellman Key: " << StringHandler.getDHClientKey(dhPackageChar) << endl;
            cout << "Base: " << StringHandler.getClientBase(dhPackageChar) << endl;
            cout << "Modulus: " << StringHandler.getClientModulus(dhPackageChar) << endl;
            cout << "Client IV: " << clientIV << endl;
            cout << "Session Key: " << keyManager->getSessionKey() << endl;
            cout << "Answered FDR: " << answeredFdr << endl;
        }

        if (checkAnsweredFDR(answeredFdr)) {
            RECEIVED_DH_KEY = true;
            if (VERBOSE) {
                cout << "Answered FDR ACCEPTED!" << endl;
                cout << "**************************************\n" << endl;
            }
            return true;
        } else {
            if (VERBOSE) {
                cout << "Answered FDR REJECTED!" << endl;
                cout << "ENDING CONECTION..." << endl;
                cout << "**************************************\n" << endl;
            }
            return false;
        }

    /* Senão, retorna falso e irá ocorrer o término da conexão. */
    } else {
        if (VERBOSE) {
            cout << "Hash is invalid!" << endl << endl;
        }

        return false;
    }
}

string sendDiffieHellmanKey()
{
    /* Envia chave Diffie-Hellman e IV. */
    std::string sendString;
    std::string spacer (SPACER_S);
    sendString = std::to_string(keyManager->getDiffieHellmanKey()) + spacer +
                 std::to_string(keyManager->getBase()) + spacer +
                 std::to_string(keyManager->getModulus()) + spacer +
                 std::to_string(keyManager->getMyIV()) + spacer +
                 std::to_string(calculateFDRValue(keyManager->getMyIV(), keyManager->getMyFDR()));

    /* Converte sendString para um array de chars. */
    char messageArray[sendString.length()];
    memset(messageArray, 0, sizeof(messageArray));
    strncpy(messageArray, sendString.c_str(), sizeof(messageArray));

    /***************************** Geração do HASH *******************************/
    string hash = iotAuth.hash(messageArray);
    string hashEncryptedString = iotAuth.encryptRSA(hash, keyManager->getMyPrivateKey(), hash.length());
    hashEncryptedString += "!";

    /************************* Preparação do pacote ******************************/
    string sendData = sendString + "*" + hashEncryptedString;
    // cout << "get partner public key: (" << stoi(getData(buffer, 0)) << ", " << stoi(getData(buffer, 1)) << ")" << endl;
    char sendDataArray[sendData.length()];
    memset(sendDataArray, '0', sizeof(sendDataArray));
    strncpy(sendDataArray, sendData.c_str(), sizeof(sendDataArray));

    string sendDataEncrypted = iotAuth.encryptRSA(sendDataArray,
                keyManager->getPartnerPublicKey(), sizeof(sendDataArray));
    sendDataEncrypted += "!";

    if (VERBOSE) {
        printf("*********SEND SERVER DH KEY********\n\n");

        cout << "Server Hash: " << hash << endl << endl;
        cout << "Server Package: " << sendString << endl;
        cout << "              (A | g | p | iv | ansFdr)" << endl;

        if (VERBOSE_2) {
            cout << endl << "Encrypted HASH" << endl << hashEncryptedString << endl << endl;
            cout << "Encrypted Data" << endl << sendDataEncrypted << endl << endl;
        }
        printf("***********************************\n\n");
    }

    return sendDataEncrypted;
}

void receiveEncryptedMessage(char buffer[])
{
    string encryptedMessage (buffer);

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

       /* Pega os 4 primeiros caracteres do buffer recebido para verificar
       se é um DONE. */
       char buffTest[5];
       buffTest[4] = '\0';
       for (int i = 0; i < 4; i++) {
           buffTest[i] = buffer[i];
       }

       /* Aguarda o recebimento do HELLO do Client. */
       /* HELLO */
       if (!CLIENT_HELLO) {
           processClientHello(buffer, meuSocket, (struct sockaddr*)&cliente, sizeof(struct sockaddr_in));
         /* Se a mensagem recebida do Client for um DONE: */
         /* DONE */
        } else if (strcmp(buffTest, DONE_MESSAGE) == 0) {

           done();
           sendto(meuSocket,DONE_ACK,strlen(DONE_ACK),0,(struct sockaddr*)&cliente,sizeof(struct sockaddr_in));
           cout << "CONECTION TERMINATED.\n" << endl;

           /* Se já recebeu um CLIENT_HELLO, mas a troca de chaves RSA ainda não ocorreu: */
           /* CLIENT_PUBLIC_KEY (D) # CLIENT_PUBLIC_KEY (N) # ANSWER FDR # IV # FDR */
       } else if (CLIENT_HELLO && !RECEIVED_RSA_KEY) {
           processRSAKeyExchange(buffer, meuSocket, (struct sockaddr*)&cliente, sizeof(struct sockaddr_in));
           /* Se já realizou a troa de chaves RSA, mas ainda não realizou a troca de chaves DH: */
           /* DH_KEY_CLIENT # BASE # MODULUS # CLIENT_IV */
       } else if (RECEIVED_RSA_KEY && !RECEIVED_DH_KEY) {
           bool valid = receiveDiffieHellmanKey(buffer);
           /* Se o hash recebido for válido, continua com o envio da chave Diffie-Hellman. */
           if (valid) {
               string message = sendDiffieHellmanKey();
               char messageArray[message.length()];
               strncpy(messageArray, message.c_str(), sizeof(messageArray));
               sendto(meuSocket, messageArray, sizeof(messageArray), 0, (struct sockaddr*)&cliente, sizeof(struct sockaddr_in));
        /* Senão, termina conexão. */
           } else {
               done();
               char *message = sendServerDone();
               sendto(meuSocket,message,strlen(message),0,(struct sockaddr*)&cliente,sizeof(struct sockaddr_in));

               recvfrom(meuSocket, buffer, sizeof(buffer), MSG_WAITALL, (struct sockaddr*)&cliente, &tam_cliente);
               receiveClientDone(buffer);
           }
           /* Aqui, todos as chaves foram trocadas, então ocorre a troca dos dados cifrados com AES. */
       } else if(RECEIVED_RSA_KEY && RECEIVED_DH_KEY) {
           cout << "Envio de dados criptografados com AES." << endl << endl;
           receiveEncryptedMessage(buffer);
       }

       memset(buffer, 0, sizeof(buffer));
    }
    close(meuSocket);
}
