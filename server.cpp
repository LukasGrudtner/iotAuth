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
#include "settings.h"
#include "iotAuth.h"
#include "RSAKeyExchange.h"
#include "DiffieHellmanPackage.h"
#include "DHKeyExchange.h"
#include "RSAStorage.h"
#include "DHStorage.h"
#include "verbose_server.h"

using namespace std;

RSAStorage *rsaStorage;
DHStorage *diffieHellmanStorage;
IotAuth iotAuth;
Utils utils;

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
    int answer = calculateFDRValue(diffieHellmanStorage->getMyIV(), diffieHellmanStorage->getMyFDR());
    return answer == answeredFdr;
}

/*  Check Request for Termination
    Verifica se a mensagem recebida é um pedido de término de conexão vinda
    do Cliente (DONE).
*/
bool checkRequestForTermination(char* message)
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

    if (VERBOSE) {rft_verbose();}
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

                if (VERBOSE) {hello_sucessfull_verbose();}

            /* Senão, continua no estado HELLO. */
            } else {
                *state = HELLO;

                if (VERBOSE) {hello_failed_verbose();}
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

/*  Setup RSA
    Inicializa os valores pertinentes a troca de chaves RSA: IV, FDR e as próprias chaves RSA.
*/
void setupRSA(RSAKeyExchange *rsaKeyExchange)
{
    rsaStorage = new RSAStorage();

    rsaStorage->setKeyPair(iotAuth.generateRSAKeyPair());
    rsaStorage->setMyIV(iotAuth.generateIV());
    rsaStorage->setMyFDR(iotAuth.generateFDR());
    rsaStorage->setPartnerPublicKey(rsaKeyExchange->getPublicKey());
    rsaStorage->setPartnerIV(rsaKeyExchange->getIV());
    rsaStorage->setPartnerFDR(rsaKeyExchange->getFDR());
}

/*  Receive RSA
    Realiza o recebimento da chave RSA vinda do Cliente.
*/
void rrsa(States *state, int socket, struct sockaddr *client, socklen_t size)
{
    RSAKeyExchange* rsaReceived = new RSAKeyExchange();
    recvfrom(socket, rsaReceived, sizeof(RSAKeyExchange), 0, client, &size);

    setupRSA(rsaReceived);

    *state = SRSA;

    if (VERBOSE) {rrsa_verbose(rsaStorage);}

    delete rsaReceived;
}

/*  Send RSA
    Realiza o envio da chave RSA para o Cliente.
*/
void srsa(States *state, int socket, struct sockaddr *client, socklen_t size)
{
    /******************** Resposta FDR ********************/
    int answerFdr = calculateFDRValue(rsaStorage->getPartnerIV(), rsaStorage->getPartnerFDR());

    /******************** RSA Key Exchange ********************/
    RSAKeyExchange rsaSent;
    rsaSent.setPublicKey(*rsaStorage->getMyPublicKey());
    rsaSent.setIV(rsaStorage->getMyIV());
    rsaSent.setFDR(*rsaStorage->getMyFDR());
    rsaSent.setAnswerFDR(answerFdr);

    /******************** Envio ********************/
    int sended = sendto(socket, (RSAKeyExchange*)&rsaSent, sizeof(rsaSent), 0, client, size);
    *state = RDH;

    /******************** Verbose ********************/
    if (VERBOSE) {srsa_verbose(&rsaSent);}
}

/*  Decrypt DH Key Exchange
    Decifra o pacote de troca Diffie-Hellman utilizando a chave privada do Servidor.
    Recebe por parâmetro a mensagem cifrada e retorna por parâmetro o pacote decifrado.
*/
void decryptDHKeyExchange(int *encryptedMessage, DHKeyExchange *dhKeyExchange)
{
    byte* decryptedMessage = iotAuth.decryptRSA(encryptedMessage, rsaStorage->getMyPrivateKey(), sizeof(DHKeyExchange));
    utils.BytesToObject(decryptedMessage, *dhKeyExchange, sizeof(DHKeyExchange));

    delete[] decryptedMessage;
}

/*  Get Diffie-Hellman Package
    Obtém o pacote Diffie-Hellman em bytes, o transforma de volta em objeto, e retorna por parâmetro.
*/
void getDiffieHellmanPackage(DHKeyExchange *dhKeyExchange, DiffieHellmanPackage *diffieHellmanPackage)
{
    /******************** Recupera o pacote Diffie-Hellman ********************/
    byte *dhPackageBytes = dhKeyExchange->getDiffieHellmanPackage();
    utils.BytesToObject(dhPackageBytes, *diffieHellmanPackage, sizeof(DiffieHellmanPackage));
}

/*  Decrypt Hash
    Decifra o hash obtido do pacote utilizando a chave pública do Cliente.
    Retorna o hash em uma string.
*/
string decryptHash(DHKeyExchange *dhKeyExchange)
{
    int *encryptedHash = dhKeyExchange->getEncryptedHash();
    byte *decryptedHash = iotAuth.decryptRSA(encryptedHash, rsaStorage->getPartnerPublicKey(), 128);

    char aux;
    string decryptedHashString = "";
    for (int i = 0; i < 128; i++) {
        aux = decryptedHash[i];
        decryptedHashString += aux;
    }

    delete[] decryptedHash;

    return decryptedHashString;
}

/*  Setup Diffie-Hellman
    Inicializa os valores pertinentes a troca de chaves Diffie-Hellman:
    expoente, base, módulo, resultado e a chave de sessão.
*/
void setupDiffieHellman(DiffieHellmanPackage *diffieHellmanPackage)
{
    diffieHellmanStorage = new DHStorage();
    diffieHellmanStorage->setMyIV(rsaStorage->getMyIV());
    diffieHellmanStorage->setMyFDR(*rsaStorage->getMyFDR());

    diffieHellmanStorage->setExponent(iotAuth.randomNumber(3)+2);
    diffieHellmanStorage->setBase(diffieHellmanPackage->getBase());
    diffieHellmanStorage->setModulus(diffieHellmanPackage->getModulus());

    int result = diffieHellmanPackage->getResult();
    int sessionKey = diffieHellmanStorage->calculateSessionKey(result);
    diffieHellmanStorage->setSessionKey(sessionKey);

    diffieHellmanStorage->setPartnerIV(diffieHellmanPackage->getIV());
    diffieHellmanStorage->setAnswerFDR(diffieHellmanPackage->getAnswerFDR());
}

/*  Receive Diffie-Hellman
    Realiza o recebimento da chave Diffie-Hellman vinda do Cliente.
*/
int rdh(States *state, int socket, struct sockaddr *client, socklen_t size)
{
    /******************** Recebe os dados cifrados ********************/
    int encryptedMessage[sizeof(DHKeyExchange)];
    recvfrom(socket, encryptedMessage, sizeof(DHKeyExchange)*sizeof(int), 0, client, &size);

    /******************** Realiza a decifragem ********************/
    DHKeyExchange dhKeyExchange;
    decryptDHKeyExchange(encryptedMessage, &dhKeyExchange);

    DiffieHellmanPackage diffieHellmanPackage;
    getDiffieHellmanPackage(&dhKeyExchange, &diffieHellmanPackage);

    string hash = decryptHash(&dhKeyExchange);

    /******************** Validação do Hash ********************/
    string dhString = diffieHellmanPackage.toString();
    if (iotAuth.isHashValid(&dhString, &hash)) {

        setupDiffieHellman(&diffieHellmanPackage);

        if (VERBOSE) {rdh_verbose1(diffieHellmanStorage, &diffieHellmanPackage, &hash);}

        /*  Se a resposta estiver correta, altera o estado atual para SDH
            (Send Diffie-Hellman). */
        if (checkAnsweredFDR(diffieHellmanPackage.getAnswerFDR())) {
            if (VERBOSE) {rdh_verbose2();}
            *state = SDH;

        /* Senão, altera o estado para DONE (Finaliza a conexão). */
        } else {
            if (VERBOSE) {rdh_verbose3();}
            *state = DONE;
        }

    /* Caso contrário, termina a conexão. */
    } else {
        if (VERBOSE) {rdh_verbose4();}
        *state = DONE;
    }
}

/*  Mount Diffie-Hellman Package
    Monta o pacote Diffie-Hellman com os dados, e logo após realiza sua conversão para bytes,
    com o retorno deste array sendo por parâmetro.
*/
void mountDHPackage(DiffieHellmanPackage *dhPackage)
{
    /******************** Montagem do Pacote Diffie-Hellman ********************/
    dhPackage->setResult(diffieHellmanStorage->calculateResult());
    dhPackage->setBase(diffieHellmanStorage->getBase());
    dhPackage->setModulus(diffieHellmanStorage->getModulus());
    dhPackage->setIV(diffieHellmanStorage->getMyIV());

    int answerFDR = calculateFDRValue(diffieHellmanStorage->getMyIV(), diffieHellmanStorage->getMyFDR());
    dhPackage->setAnswerFDR(answerFDR);
}

/*  Get Encrypted Hash
    Realiza a cifragem do hash obtido do pacote Diffie-Hellman com a chave privada do Servidor.
    O retorno do hash cifrado é feito por parâmetro.
*/
int* getEncryptedHash(DiffieHellmanPackage *dhPackage)
{
    string dhString = dhPackage->toString();
    string hash = iotAuth.hash(&dhString);

    int *encryptedHash = iotAuth.encryptRSA(&hash, rsaStorage->getMyPrivateKey(), hash.length());

    return encryptedHash;
}

/*  Send Diffie-Hellman
    Realiza o envio da chave Diffie-Hellman para o Cliente.
*/
void sdh(States *state, int socket, struct sockaddr *client, socklen_t size)
{
    /***************** Montagem do Pacote Diffie-Hellman ******************/
    DiffieHellmanPackage dhPackage;
    mountDHPackage(&dhPackage);

    /***************** Serialização do Pacote Diffie-Hellman ******************/
    byte *dhPackageBytes = new byte[sizeof(DiffieHellmanPackage)];
    utils.ObjectToBytes(dhPackage, dhPackageBytes, sizeof(DiffieHellmanPackage));

    /***************************** Geração do HASH ****************************/
    /* Encripta o hash utilizando a chave privada do Servidor. */
    int *encryptedHash = getEncryptedHash(&dhPackage);

    /********************** Preparação do Pacote Final ************************/
    DHKeyExchange dhSent;
    dhSent.setEncryptedHash(encryptedHash);
    dhSent.setDiffieHellmanPackage(dhPackageBytes);

    /********************** Serialização do Pacote Final **********************/
    byte *dhSentBytes = new byte[sizeof(DHKeyExchange)];
    utils.ObjectToBytes(dhSent, dhSentBytes, sizeof(DHKeyExchange));

    /******************** Cifragem e Envio do Pacote Final ********************/
    int* encryptedMessage = iotAuth.encryptRSA(dhSentBytes, rsaStorage->getPartnerPublicKey(), sizeof(DHKeyExchange));
    
    sendto(socket, (int*)encryptedMessage, sizeof(DHKeyExchange)*sizeof(int), 0, client, size);
    *state = DT;

    /******************************** VERBOSE *********************************/

    if (VERBOSE) {sdh_verbose(&dhPackage);}

    delete[] dhPackageBytes;
    delete[] encryptedHash;
    delete[] dhSentBytes;
    delete[] encryptedMessage;

}

/*  Data Transfer
    Realiza a transferência de dados cifrados para o Cliente.
*/
void dt(States *state, int socket, struct sockaddr *client, socklen_t size)
{
    delete rsaStorage;
    /********************* Recebimento dos Dados Cifrados *********************/
    char message[1333];
    memset(message, '\0', sizeof(message));
    recvfrom(socket, message, sizeof(message)-1, 0, client, &size);

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
            key[i] = diffieHellmanStorage->getSessionKey();
        }

        // uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
        uint8_t iv[16];
        for (int i = 0; i < 16; i++) {
            iv[i] = diffieHellmanStorage->getSessionKey();
        }

        /* Converte a mensagem recebida (HEXA) para o array de char ciphertextChar. */
        utils.HexStringToCharArray(&encryptedMessage, encryptedMessage.length(), ciphertextChar);

        /* Converte ciphertextChar em um array de uint8_t (ciphertext). */
        utils.CharToUint8_t(ciphertextChar, ciphertext, encryptedMessage.length());

        /* Decifra a mensagem em um vetor de uint8_t. */
        uint8_t *decrypted = iotAuth.decryptAES(ciphertext, key, iv, encryptedMessage.length());
        cout << "Decrypted: " << decrypted << endl;

        *state = DT;
        // delete[] decrypted;
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
    // keyManager = new KeyManager();

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
