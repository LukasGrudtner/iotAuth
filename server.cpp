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
#include "iotAuth.h"
#include "RSAKeyExchange.h"
#include "DiffieHellmanPackage.h"
#include "DHKeyExchange.h"

using namespace std;

KeyManager* keyManager;
FDR partnerFDR;
IotAuth iotAuth;
Utils utils;
int partnerIV = 0;

/*  Calculate FDR Value
    Calcula a resposta de uma dada FDR. */
int calculateFDRValue(int iv, FDR* fdr)
{
    int result = 0;
    if (fdr->getOperator() == '+') {
        result = iv + fdr->getOperand();
    }
    return result;
}

/*  Check Answered FDR
    Verifica a validade da resposta da FDR gerada pelo Servidor.
*/
bool checkAnsweredFDR(int answeredFdr)
{
    int answer = calculateFDRValue(keyManager->getMyIV(), keyManager->getMyFDR());
    return answer == answeredFdr;
}

/*  Check Request for Termination
    Verifica se a mensagem recebida é um pedido de término de conexão vinda
    do Cliente (DONE).
*/
bool checkRequestForTermination(char message[])
{
    char aux[strlen(DONE_MESSAGE)+1];
    aux[strlen(DONE_MESSAGE)] = '\0';
    for (int i = 0; i < strlen(DONE_MESSAGE); i++) {
        aux[i] = message[i];
    }

    /* Verifica se a mensagem recebida é um DONE. */
    if (strcmp(aux, DONE_MESSAGE) == 0) {
        return true;
    } else {
        return false;
    }
}

/*  Waiting Done Confirmation
    Verifica se a mensagem vinda do Cliente é uma confirmação do pedido de
    fim de conexão enviado pelo Servidor (DONE_ACK).
    Em caso positivo, altera o estado para HELLO, senão, mantém em WDC. 7
*/
void wdc(States *state, int socket, struct sockaddr *client, socklen_t size)
{
    char message[512];
    recvfrom(socket, message, sizeof(message), 0, client, &size);

    if (message[0] == DONE_ACK_CHAR) {
        *state = HELLO;
    } else {
        *state = WDC;
    }
}

/*  Request for Termination
    Envia uma confirmação (DONE_ACK) para o pedido de término de conexão
    vindo do Cliente, e seta o estado para HELLO.
*/
void rft(States *state, int socket, struct sockaddr *client, socklen_t size)
{
    sendto(socket, DONE_ACK, strlen(DONE_ACK), 0, client, size);
    *state = HELLO;

    if (VERBOSE) {
        printf("\n*******DONE CLIENT AND SERVER******\n");
        printf("Done Client and Server Successful!\n");
        printf("***********************************\n\n");
    }
}

/*  Hello
    Aguarda o recebimento de um pedido de início de conexão (HELLO) vindo
    do Cliente.
*/
void hello(States *state, int socket, struct sockaddr *client, socklen_t size)
{
    char message[512];
    recvfrom(socket, message, sizeof(message), 0, client, &size);

    if (checkRequestForTermination(message)) {
        *state = RFT;
    } else {
        /* Verifica se a mensagem recebida é um HELLO. */
        if (strcmp(message, HELLO_MESSAGE) == 0) {

            /* Se for, envia um HELLO ACK ao Cliente. */
            int sended = sendto(socket, HELLO_ACK, strlen(HELLO_ACK), 0, client, size);

            /* Se a mensagem foi enviada corretamente, troca o estado para RSAX. */
            if (sended >= 0) {
                *state = RRSA;

                if (VERBOSE) {
                    printf("\n******HELLO CLIENT AND SERVER******\n");
                    printf("Hello Client and Server Successful!\n");
                    printf("***********************************\n\n");
                }

            /* Senão, continua no estado HELLO. */
            } else {
                *state = HELLO;

                if (VERBOSE) {
                    printf("\n******HELLO CLIENT AND SERVER******\n");
                    printf("Hello Client and Server failed!\n");
                    printf("***********************************\n\n");
                }
            }
        }
    }
}

/*  Done
    Envia um pedido de término de conexão ao Cliente, e seta o estado atual
    para WDC (Waiting Done Confirmation).
*/
void done(States *state, int socket, struct sockaddr *client, socklen_t size)
{
    sendto(socket, DONE_MESSAGE, strlen(DONE_MESSAGE), 0, client, size);
    *state = WDC;
}

/*  Receive RSA
    Realiza o recebimento da chave RSA vinda do Cliente.
*/
void rrsa(States *state, int socket, struct sockaddr *client, socklen_t size)
{
    RSAKeyExchange* rsaReceived = (RSAKeyExchange*)malloc(sizeof(RSAKeyExchange));
    recvfrom(socket, rsaReceived, sizeof(RSAKeyExchange), 0, client, &size);

    /* Realiza a geração das chaves pública e privada (RSA). */
    keyManager->setRSAKeyPair(iotAuth.generateRSAKeyPair());

    /* Gera um IV para o servidor e o armazena no KeyManager. */
    keyManager->setMyIV(iotAuth.generateIV());

    /* Gera uma Função Desafio-Resposta para o servidor e o armazena no KeyManager. */
    keyManager->setMyFDR(iotAuth.generateFDR());

    /* Recebe chave pública do cliente e o IV */
    keyManager->setPartnerPublicKey(rsaReceived->getPublicKey());

    partnerFDR = rsaReceived->getFDR();
    partnerIV = rsaReceived->getIV();

    *state = SRSA;

    if (VERBOSE) {
        printf("******RECEIVED CLIENT RSA KEY******\n");
        cout << "Received: "                << rsaReceived->toString()              << endl;
        cout << "Generated RSA Key: {("     << keyManager->getMyPublicKey().d       << ", "
                                            << keyManager->getMyPublicKey().n       << "), ";
        cout << "("                         << keyManager->getMyPrivateKey().d      << ", "
                                            << keyManager->getMyPrivateKey().n      << ")}" << endl;
        cout << "My IV: "                   << keyManager->getMyIV()                << endl;
        cout << "My FDR: "                  << keyManager->getMyFDR()->toString()
                                            << endl                                 << endl;
        cout << "Client RSA Public Key: ("  << keyManager->getPartnerPublicKey().d  << ", "
                                            << keyManager->getPartnerPublicKey().n  << ")" << endl;
        cout << "Client IV: "               << partnerIV                            << endl;
        cout << "Client FDR: "              << partnerFDR.toString() << endl;
        cout << "Client FDR Answer: "       << calculateFDRValue(partnerIV, &partnerFDR) << endl;
        printf("***********************************\n\n");
    }
}

/*  Send RSA
    Realiza o envio da chave RSA para o Cliente.
*/
void srsa(States *state, int socket, struct sockaddr *client, socklen_t size)
{
    /* Calcula a resposta da FDR requisitada pelo Cliente. */
    int answerFdr = calculateFDRValue(partnerIV, &partnerFDR);

    /* Obtém a chave púbica do Servidor. */
    RSAKey publicKey = keyManager->getMyPublicKey();

    int iv = keyManager->getMyIV();
    FDR fdr = *keyManager->getMyFDR();

    /* Armazena todos os dados do pacote em um objeto RSAKeyExchange. */
    RSAKeyExchange rsaSent;
    rsaSent.setPublicKey(publicKey);
    rsaSent.setAnswerFDR(answerFdr);
    rsaSent.setIV(iv);
    rsaSent.setFDR(fdr);

    if (VERBOSE) {
        printf("*******SENT SERVER RSA KEY*********\n");
        cout << "Server RSA Public Key: (" << keyManager->getMyPublicKey().d
                  << ", " << keyManager->getMyPublicKey().n << ")" << endl;
        cout << "Answer FDR (Client): " << answerFdr << endl;
        cout << "My IV: " << keyManager->getMyIV() << endl;
        cout << "My FDR: " << keyManager->getMyFDR()->toString() << endl;
        cout << "Sent: " << rsaSent.toString() << endl;
        cout << "***********************************\n" << endl;
    }

    int sended = sendto(socket, (RSAKeyExchange*)&rsaSent, sizeof(rsaSent), 0, client, size);

    *state = RDH;
}

/*  Receive Diffie-Hellman
    Realiza o recebimento da chave Diffie-Hellman vinda do Cliente.
*/
int rdh(States *state, int socket, struct sockaddr *client, socklen_t size)
{
    int *encryptedDHExchange = (int*)malloc(sizeof(DHKeyExchange)*sizeof(int));
    recvfrom(socket, encryptedDHExchange, sizeof(DHKeyExchange)*sizeof(int), 0, client, &size);

    /* Decifra a mensagem com a chave privada do Servidor.*/
    byte *decryptedMessage = iotAuth.decryptRSA(encryptedDHExchange, keyManager->getMyPrivateKey(), sizeof(DHKeyExchange));

    /* Converte o array de bytes decifrado em uma classe DHKeyExchange. */
    DHKeyExchange encryptedDHReceived;
    utils.BytesToObject(decryptedMessage, encryptedDHReceived, sizeof(DHKeyExchange));

    /* Extrai o HASH encriptado da mensagem. */
    int *encryptedHash = encryptedDHReceived.getEncryptedHash();

    /* Decifra o HASH com a chave pública do Cliente. */
    byte *decryptedHash = iotAuth.decryptRSA(encryptedHash, keyManager->getPartnerPublicKey(), 128);
    char aux;
    string decryptedHashString = "";
    for (int i = 0; i < 128; i++) {
        aux = decryptedHash[i];
        decryptedHashString += aux;
    }

    /* Recupera o pacote com os dados Diffie-Hellman do Client. */
    byte* dhPackageBytes = encryptedDHReceived.getDiffieHellmanPackage();
    DiffieHellmanPackage dhPackage;
    utils.BytesToObject(dhPackageBytes, dhPackage, sizeof(DiffieHellmanPackage));

    /* Se o hash for válido, continua com o recebimento. */
    if (iotAuth.isHashValid(dhPackage.toString(), decryptedHashString)) {

        /* Armazena os valores Diffie-Hellman no KeyManager. */
        sleep(1);
        keyManager->setExponent(iotAuth.randomNumber(3)+2);
        keyManager->setBase(dhPackage.getBase());
        keyManager->setModulus(dhPackage.getModulus());
        keyManager->setSessionKey(keyManager->getDiffieHellmanKey(dhPackage.getResult()));
        int clientIV = dhPackage.getIV();
        int answeredFdr = dhPackage.getAnswerFDR();

        if (VERBOSE) {
            printf("\n*******CLIENT DH KEY RECEIVED******\n");

            cout << "Hash is valid!" << endl << endl;

            if (VERBOSE_2) {
                cout << "Client Encrypted Data" << endl;
                for (int i = 0; i < sizeof(DHKeyExchange)-1; i++) {
                    cout << encryptedDHExchange[i] << ":";
                }
                cout << encryptedDHExchange[sizeof(DHKeyExchange)-1] << endl << endl;

                cout << "Client Encrypted Hash" << endl;
                for (int i = 0; i < 127; i++) {
                    cout << encryptedHash[i] << ":";
                }
                cout << encryptedHash[127] << endl << endl;
            }

            cout << "Client Decrypted HASH: "   << decryptedHashString          << endl << endl;
            cout << "Diffie-Hellman Key: "      << dhPackage.getResult()        << endl;
            cout << "Exponent: "                << keyManager->getExponent()    << endl;
            cout << "Base: "                    << dhPackage.getBase()          << endl;
            cout << "Modulus: "                 << dhPackage.getModulus()       << endl;
            cout << "Client IV: "               << clientIV                     << endl;
            cout << "Session Key: "             << keyManager->getSessionKey()  << endl;
            cout << "Answered FDR: "            << answeredFdr                  << endl;
        }

        /*  Se a resposta estiver correta, altera o estado atual para SDH
            (Send Diffie-Hellman). */
        if (checkAnsweredFDR(answeredFdr)) {
            if (VERBOSE) {
                cout << "Answered FDR ACCEPTED!"                    << endl;
                cout << "**************************************\n"  << endl;
            }
            *state = SDH;

        /* Senão, altera o estado para DONE (Finaliza a conexão). */
        } else {
            if (VERBOSE) {
                cout << "Answered FDR REJECTED!"                    << endl;
                cout << "ENDING CONECTION..."                       << endl;
                cout << "**************************************\n"  << endl;
            }
            *state = DONE;
        }

    /* Caso contrário, termina a conexão. */
    } else {
        if (VERBOSE) {
            cout << "Hash is invalid!" << endl << endl;
        }
        *state = DONE;
    }
}

/*  Send Diffie-Hellman
    Realiza o envio da chave Diffie-Hellman para o Cliente.
*/
void sdh(States *state, int socket, struct sockaddr *client, socklen_t size)
{
    /******************** Criação do Pacote Diffie-Hellman ********************/
    DiffieHellmanPackage diffieHellmanPackage;
    diffieHellmanPackage.setResult(keyManager->getDiffieHellmanKey());
    diffieHellmanPackage.setBase(keyManager->getBase());
    diffieHellmanPackage.setModulus(keyManager->getModulus());

    diffieHellmanPackage.setIV(keyManager->getMyIV());
    diffieHellmanPackage.setAnswerFDR(calculateFDRValue(keyManager->getMyIV(), keyManager->getMyFDR()));

    /***************** Serialização do Pacote Diffie-Hellman ******************/

    byte* dhPackageBytes = (byte*)malloc(sizeof(DiffieHellmanPackage));
    utils.ObjectToBytes(diffieHellmanPackage, dhPackageBytes, sizeof(DiffieHellmanPackage));

    /***************************** Geração do HASH ****************************/
    /* Extrai o hash. */
    string hash = iotAuth.hash(diffieHellmanPackage.toString());

    /* Encripta o hash utilizando a chave privada do Servidor. */
    int* encryptedHash = iotAuth.encryptRSA(hash, keyManager->getMyPrivateKey(), hash.length());

    /********************** Preparação do Pacote Final ************************/

    DHKeyExchange* dhSent = new DHKeyExchange();
    dhSent->setEncryptedHash(encryptedHash);
    dhSent->setDiffieHellmanPackage(dhPackageBytes);

    /********************** Serialização do Pacote Final **********************/

    byte* dhSentBytes = (byte*)malloc(sizeof(DHKeyExchange));
    utils.ObjectToBytes(*dhSent, dhSentBytes, sizeof(DHKeyExchange));

    /******************** Cifragem e Envio do Pacote Final ********************/

    int* encryptedMessage = iotAuth.encryptRSA(dhSentBytes, keyManager->getPartnerPublicKey(), sizeof(DHKeyExchange));
    sendto(socket, (int*)encryptedMessage, sizeof(DHKeyExchange)*sizeof(int), 0, client, size);
    *state = DT;

    /******************************** VERBOSE *********************************/

    if (VERBOSE) {
        printf("*********SEND SERVER DH KEY********\n\n");

        cout << "Server Hash: "     << hash                                     << endl << endl;
        cout << "Server Package: "  << diffieHellmanPackage.toString()          << endl;

        if (VERBOSE_2) {
            cout << endl    << "Encrypted HASH" << endl;
            for (int i = 0; i < 128; i++) {
                cout << encryptedHash[i] << ":";
            }
            cout << encryptedHash[127]  << endl << endl;

            cout            << "Encrypted Data" << endl;
            for (int i = 0; i < sizeof(DHKeyExchange); i++) {
                cout << encryptedMessage[i] << ":";
            }
            cout << encryptedMessage[127] << endl << endl;
        }
        printf("***********************************\n\n");
    }
}

/*  Data Transfer
    Realiza a transferência de dados cifrados para o Cliente.
*/
void dt(States *state, int socket, struct sockaddr *client, socklen_t size)
{
    /********************* Recebimento dos Dados Cifrados *********************/

    char message[512];
    recvfrom(socket, message, sizeof(message), 0, client, &size);

    /******************* Verifica Pedido de Fim de Conexão ********************/

    if (checkRequestForTermination(message)) {
        *state = RFT;
    } else {

        /* Converte o array de chars (buffer) em uma string. */
        string encryptedMessage (message);

        /* Inicialização dos vetores ciphertext. */
        char ciphertextChar[encryptedMessage.length()];
        uint8_t ciphertext[encryptedMessage.length()];
        memset(ciphertext, '\0', encryptedMessage.length());

        /* Inicialização do vetor plaintext. */
        uint8_t plaintext[encryptedMessage.length()];
        memset(plaintext, '\0', encryptedMessage.length());

        /* Inicialização da chave e iv. */
        // uint8_t key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        //                   0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
        uint8_t key[32];
        for (int i = 0; i < 32; i++) {
            key[i] = keyManager->getSessionKey();
        }

        // uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
        uint8_t iv[16];
        for (int i = 0; i < 16; i++) {
            iv[i] = keyManager->getSessionKey();
        }

        /* Converte a mensagem recebida (HEXA) para o array de char ciphertextChar. */
        utils.hexStringToCharArray(encryptedMessage, encryptedMessage.length(), ciphertextChar);

        /* Converte ciphertextChar em um array de uint8_t (ciphertext). */
        utils.charToUint8_t(ciphertextChar, ciphertext, encryptedMessage.length());

        /* Decifra a mensagem em um vetor de uint8_t. */
        uint8_t *decrypted = iotAuth.decryptAES(ciphertext, key, iv, encryptedMessage.length());
        cout << "Decrypted: " << decrypted << endl;

        *state = DT;
    }
}

/*  State Machine
    Realiza o controle do estado atual da FSM.
*/
void stateMachine(int socket, struct sockaddr *client, socklen_t size)
{
    static States state = HELLO;

    switch (state) {

        /* Waiting Done Confirmation */
        case WDC:
        {
            cout << "WAITING DONE CONFIRMATION" << endl;
            wdc(&state, socket, client, size);
            break;
        }

        /* Request For Termination */
        case RFT:
        {
            cout << "REQUEST FOR TERMINATION RECEIVED" << endl;
            rft(&state, socket, client, size);
            break;
        }

        /* Done */
        case DONE:
        {
            cout << "SEND DONE" << endl;
            done(&state, socket, client, size);
            break;
        }

        /* Hello */
        case HELLO:
        {
            cout << "RECEIVE HELLO" << endl;
            hello(&state, socket, client, size);
            break;
        }

        /* Receive RSA */
        case RRSA:
        {
            cout << "RECEIVE RSA KEY" << endl;
            rrsa(&state, socket, client, size);
            break;
        }

        /* Send RSA */
        case SRSA:
        {
            cout << "SEND RSA KEY" << endl;
            srsa(&state, socket, client, size);
            break;
        }

        /* Receive Diffie-Hellman */
        case RDH:
        {
            cout << "RECEIVE DIFFIE HELLMAN KEY" << endl;
            rdh(&state, socket, client, size);
            break;
        }

        /* Send Diffie-Hellman */
        case SDH:
        {
            cout << "SEND DIFFIE HELLMAN KEY" << endl;
            sdh(&state, socket, client, size);
            break;
        }

        /* Data Transfer */
        case DT:
        {
            cout << "RECEIVE ENCRYPTED DATA" << endl;
            dt(&state, socket, client, size);
            break;
        }
    }
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
    tam_cliente=sizeof(struct sockaddr_in);

    while(1){
       stateMachine(meuSocket, (struct sockaddr*)&cliente, tam_cliente);
    }

    close(meuSocket);
}
