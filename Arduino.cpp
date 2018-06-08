#include "Arduino.h"

/* Envia um Hello para o Servidor. */
char* Arduino::sendClientHello()
{
    cout << "************HELLO CLIENT**************" << endl;
    string hello (HELLO_MESSAGE);
    char *message;
    strncpy(message, hello.c_str(), hello.length());
    cout << "Client Hello: Successful" << endl;
    cout << "**************************************\n" << endl;
    return message;
}

/* Envia um pedido de fim de conexão para o Servidor. */
char* Arduino::sendClientDone()
{
    string done (DONE_MESSAGE);
    char *message = (char*)malloc(4);
    strncpy(message, done.c_str(), 4);
    return message;
}

/* Envia um ACK para o pedido de fim de conexão vindo do Servidor. */
char* Arduino::sendClientACKDone()
{
    string doneACK (DONE_ACK);
    char *message = (char*)malloc(1);
    strncpy(message, doneACK.c_str(), 1);

    return message;
}

/* Seta as variáveis de controle para o estado de fim de conexão. */
void Arduino::done()
{
    clientHello     = false;
    receivedRSAKey  = false;
    receivedDHKey   = false;
}

/* Verifica se o Servidor confirmou o pedido de início de conexão. */
bool Arduino::receiveServerHello(char buffer[])
{
    cout << "************HELLO SERVER**************" << endl;
    if (buffer[0] == HELLO_ACK_CHAR) {
        clientHello = true;
        clientDone = false;
        cout << "Server Hello: Successful" << endl;
        cout << "**************************************\n" << endl;
        return true;
    }

    return false;
}

/* Verifica se o Servidor confirmou o pedido de fim de conexão. */
bool Arduino::receiveServerDone(char buffer[])
{
    cout << "*************DONE SERVER**************" << endl;
    if (buffer[0] == DONE_ACK_CHAR) {
        clientDone = true;
        cout << "Server Done: Successful" << endl;
        cout << "**************************************\n" << endl;
        return true;
    }

    return false;
}

RSAKeyExchange Arduino::sendRSAKey()
{
    /* Gera um par de chaves RSA e o armazena no keyManager. */
    keyManager.setRSAKeyPair(iotAuth.generateRSAKeyPair());

    /* Gera um valor de IV e o armazena no KeyManager. */
    keyManager.setMyIV(iotAuth.generateIV());

    /* Gera uma Função Desafio-Resposta e o armazena no KeyManager. */
    keyManager.setMyFDR(iotAuth.generateFDR());

    /* Organiza os dados que serão enviados para o Server:
        Chave Pública (D) + # + Chave Pública (N) + # + Resposta do DR + # +
        IV + # + Função Desafio Resposta
    */

    int answerFdr = 0;
    RSAKey publicKey = keyManager.getMyPublicKey();
    int iv = keyManager.getMyIV();
    /* Derreferenciando um ponteiro: obtém o valor armazenado na posição indicada pelo ponteiro, e não o endereço na memória. */
    FDR fdr = *keyManager.getMyFDR();

    RSAKeyExchange rsaSent;
    rsaSent.setPublicKey(publicKey);
    rsaSent.setAnswerFDR(answerFdr);
    rsaSent.setIV(iv);
    rsaSent.setFDR(fdr);

    if (VERBOSE) {
        cout << "************SEND RSA CLIENT***********" << endl;
        cout << "Generated RSA Key: {(" << keyManager.getMyPublicKey().d
             << ", " << keyManager.getMyPublicKey().n << "), ("
             << keyManager.getMyPrivateKey().d << ", "
             << keyManager.getMyPrivateKey().n << ")}" << endl;
        cout << "My IV: " << keyManager.getMyIV() << endl;
        cout << "My FDR: " << stringHandler.FdrToString(keyManager.getMyFDR()) << endl;
        cout << "Sent: " << rsaSent.toString() << endl;
        cout << "**************************************\n" << endl;
    }

    return rsaSent;
}

/* Calcula a resposta do FDR recebido por parâmetro. */
int Arduino::calculateFDRValue(int iv, FDR* fdr)
{
    int result = 0;
    if (fdr->getOperator() == '+') {
        result = iv+fdr->getOperand();
    }

    return result;
}

/* Verifica se a resposta do FDR é válida. */
bool Arduino::checkAnsweredFDR(int answeredFdr)
{
    int answer = calculateFDRValue(keyManager.getMyIV(), keyManager.getMyFDR());
    return answer == answeredFdr;
}

/* Realiza o recebimento da chave RSA vinda do Servidor. */
bool Arduino::receiveRSAKey(RSAKeyExchange *rsaReceived)
{
    /*  Armazena a chave pública do servidor obtida, passando como parâmetro
        uma chamada à função getPartnerPublicKey do StringHandler, que extrai
        a chave pública do servidor do buffer (recebido do server).
    */
    keyManager.setPartnerPublicKey(rsaReceived->getPublicKey());

    int answeredFdr = rsaReceived->getAnswerFDR();
    int partnerIV   = rsaReceived->getIV();
    FDR partnerFdr  = rsaReceived->getFDR();
    answerFDR       = calculateFDRValue(partnerIV, &partnerFdr);

    if (VERBOSE) {
        cout << "*********RECEIVED RSA SERVER**********" << endl;
        cout << "Received: " << rsaReceived->toString() << endl;
        cout << "RSA Server Public Key: (" << rsaReceived->getPublicKey().d <<
                ", " << rsaReceived->getPublicKey().n << ")" << endl;
        cout << "Answered FDR: " << answeredFdr << endl;
        cout << "Server IV: " << partnerIV << endl;
        cout << "Server FDR: " << partnerFdr.getOperator() << partnerFdr.getOperand() << endl;
        cout << "Server FDR Answer: " << answerFDR << endl;
    }

    /* Verifica se a resposta do FDR é válida. */
    if (checkAnsweredFDR(answeredFdr)) {
        receivedRSAKey = true;
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
}

/* Extrai o hash encriptado da mensagem. */
string Arduino::getHashEncrypted(string package)
{
    /*  Pega todos os caracteres anteriores ao símbolo "*", coloca-os em uma
        string e a retorna. Esta string é o HASH encriptado recebido do server.
    */
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

/* Realiza o envio da chave Diffie-Hellman para o Servidor. */
string Arduino::sendDiffieHellmanKey()
{
    /* Seta o expoente no KeyManager. */
    keyManager.setExponent(a);

    /*  Organiza o pacote com os dados Diffie-Hellman para enviar ao cliente. */
    long int pot    = pow(g, a);
    long int A      = pot % p;

    string spacer (SPACER_S);
    string package =    to_string(A)                    + spacer +
                        to_string(g)                    + spacer +
                        to_string(p)                    + spacer +
                        to_string(keyManager.getMyIV()) + spacer +
                        to_string(answerFDR);

    /**************************************************************************/
    /* Realiza o cálculo do HASH do pacote obtido acima. */
    char hashArray[128];
    char messageArray[package.length()];
    memset(hashArray, 0, sizeof(hashArray));

    /* Converte o pacote (string) para um array de char (messageArray). */
    strncpy(messageArray, package.c_str(), sizeof(messageArray));

    /* Armazena o hash no buffer hashArray */
    string hash = iotAuth.hash(messageArray);

    /* Encripta o hash utilizando a chave privada do cliente */
    string hashEncryptedString = iotAuth.encryptRSA(hash, keyManager.getMyPrivateKey(), hash.length());
    hashEncryptedString += "!";


    /**************************************************************************/

    /* Prepara o pacote completo que será enviado ao servidor. */
    string sendData = package + "*" + hashEncryptedString;

    /* Converte a string (sendData) para um array de chars (sendDataArray). */
    char sendDataArray[sendData.length()];
    memset(sendDataArray, 0, sizeof(sendDataArray));
    strncpy(sendDataArray, sendData.c_str(), sizeof(sendDataArray));

    /* Encripta o sendDataArray utilizando a chave pública do servidor. */
    string sendDataEncrypted = iotAuth.encryptRSA(sendData,
                keyManager.getPartnerPublicKey(), sendData.length());

    sendDataEncrypted += "!";

    if (VERBOSE) {
        cout << "************SEND DH CLIENT************" << endl;
        cout << "Client Hash: " << hash << endl << endl;
        cout << "Client Package: " << package << endl;
        cout << "                (A | g | p | iv | ansFdr)" << endl;

        if (VERBOSE_2) {
            cout << endl << "Encrypted HASH" << endl << hashEncryptedString << endl << endl;
            cout << "Used Key: (" << keyManager.getPartnerPublicKey().d << ", " << keyManager.getPartnerPublicKey().n << ")" << endl;
            cout << "Encrypted Data" << endl << sendDataEncrypted << endl << endl;
        }
        cout << "**************************************" << endl << endl;
    }

    return sendDataEncrypted;
}

/* Extrai o pacote (dados Diffie-Hellman) da string recebida por parâmetro. */
string Arduino::getPackage(string package)
{
    /*  Retorna o pacote recebido do servidor. */
    string resultado = "";
    int i = 0;

    while (package.at(i) != '*') {
        resultado += package.at(i);
        i++;
    }

    return resultado;
}

/* Realiza o recebimento da chave Diffie-Hellman vinda do Servidor. */
bool Arduino::receiveDiffieHellmanKey(char message[])
{
    /* Converte o array de char (message) em uma string. */
    string encryptedPackage (message);

    /* Cria um vetor de int para acomodar o valor RSA encriptado, e converte
        o array de char (message) neste vetor de inteiros. */
    int decryptedPackageInt[utils.countMarks(encryptedPackage)+1];
    utils.RSAToIntArray(decryptedPackageInt, message, encryptedPackage.length());

    /* Decodifica a string. */
    string decryptedString = iotAuth.decryptRSA(decryptedPackageInt, keyManager.getMyPrivateKey(), encryptedPackage.length());

    /* Recupera o pacote com os dados Diffie-Hellman do Client. */
    string dhPackage = getPackage(decryptedString);

    /***** HASH *****/
    /* Recupera o hash cifrado com a chave Privada do Server. */
    string encryptedHash = getHashEncrypted(decryptedString);

    /* Cria um vetor de int para acomodar o valor RSA encriptado, e converte
        a string (encryptedHash) neste vetor de inteiros. */
    int encryptedHashInt[128];
    utils.RSAToIntArray(encryptedHashInt, encryptedHash, 128);

    /* Decifra o HASH com a chave pública do Server. */
    string decryptedHashString = iotAuth.decryptRSA(encryptedHashInt, keyManager.getPartnerPublicKey(), 128);

    /* Se o hash for válido, prossegue com o recebimento.
        Se não, termina a conexão. */
    if (iotAuth.isHashValid(dhPackage, decryptedHashString)) {

        /* Recebe chave Diffie-Hellman e IV. */
        char dhPackageChar[dhPackage.length()];
        strncpy(dhPackageChar, dhPackage.c_str(), sizeof(dhPackageChar));
        keyManager.setBase(stringHandler.getClientBase(dhPackageChar));
        keyManager.setModulus(stringHandler.getClientModulus(dhPackageChar));
        keyManager.setSessionKey(keyManager.getDiffieHellmanKey(stringHandler.getDHClientKey(dhPackageChar)));
        int ivClient = stringHandler.getDHIvClient(dhPackageChar);

        receivedDHKey = true;

        if (VERBOSE) {
            printf("\n*******SERVER DH KEY RECEIVED******\n");

            if (VERBOSE_2) {
                cout << "Server Encrypted Data" << endl << encryptedPackage << endl << endl;
                cout << "Server Encrypted Hash" << endl << encryptedHash << endl << endl;
            }

            cout << "Server Decrypted Hash: "   << decryptedHashString                              << endl << endl;
            cout << "Diffie-Hellman Key: "      << stringHandler.getDHClientKey(dhPackageChar)      << endl;
            cout << "Base: "                    << stringHandler.getClientBase(dhPackageChar)       << endl;
            cout << "Modulus: "                 << stringHandler.getClientModulus(dhPackageChar)    << endl;
            cout << "Client IV: "               << stringHandler.getDHIvClient(dhPackageChar)       << endl;
            cout << "Session Key: "             << keyManager.getSessionKey()                       << endl;
            cout << "***********************************\n"                                         << endl;
        }

        return true;
    } else {
        if (VERBOSE) {
            cout << "Hash is invalid!" << endl << endl;
        }
        return false;
    }

}

/* Realiza o envio da mensagem encriptada. */
string Arduino::sendEncryptedMessage(char message[], int size) {

    /* Inicialização do vetor plaintext. */
    uint8_t plaintext[size];
    memset(plaintext, '\0', size);

    /* Inicialização da chave e do IV. */
    uint8_t key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                      0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
    uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    /* Converte o array de char (message) para uint8_t. */
    utils.charToUint8_t(message, plaintext, size);

    /* Encripta a mensagem utilizando a chave e o iv declarados anteriormente. */
    uint8_t *encrypted = iotAuth.encryptAES(plaintext, key, iv, size);

    return (utils.Uint8_t_to_Hex_String(encrypted, size));
}

/* Verifica se a mensagem recebida do Servidor é um DONE. */
bool Arduino::checkDoneServer(char buffer[])
{
    /* Pega os 4 primeiros caracteres do buffer recebido para verificar
    se é um DONE. */
    char buffTest[5];
    buffTest[4] = '\0';
    for (int i = 0; i < 4; i++) {
        buffTest[i] = buffer[i];
    }

    return (strcmp(buffTest, DONE_MESSAGE) == 0);
}
