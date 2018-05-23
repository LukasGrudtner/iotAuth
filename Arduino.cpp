#include "Arduino.h"

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

char* Arduino::sendClientDone()
{
    cout << "**************DONE CLIENT****************" << endl;
    string done (DONE_MESSAGE);
    printf("1\n");
    char *message = (char*)malloc(4);
    strncpy(message, done.c_str(), 4);
    printf("2\n");
    cout << "**************************************\n" << endl;
    return message;
}

void Arduino::done()
{
    clientHello = false;
    receivedRSAKey = false;
    receivedDHKey = false;
}

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

char* Arduino::sendRSAKey()
{
    cout << "************SEND RSA CLIENT***********" << endl;

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
    string spacer (SPACER_S);
    string sendData = "";
    string answerFdr = "null";
    sendData =  to_string(keyManager.getMyPublicKey().d) + spacer +
                to_string(keyManager.getMyPublicKey().n) + spacer +
                answerFdr + spacer +
                to_string(keyManager.getMyIV()) + spacer +
                stringHandler.FdrToString(keyManager.getMyFDR());

    cout << "Generated RSA Key: {(" << keyManager.getMyPublicKey().d
         << ", " << keyManager.getMyPublicKey().n << "), ("
         << keyManager.getMyPrivateKey().e << ", "
         << keyManager.getMyPrivateKey().n << ")}" << endl;
    cout << "Iv: " << keyManager.getMyIV() << endl;
    cout << "Fdr: " << stringHandler.FdrToString(keyManager.getMyFDR()) << endl;

    /*  Converte a string para um array de char (message), e retorna este
        array.
    */
    char* message = (char*)malloc(sendData.length());
    strcpy(message, sendData.c_str());

    cout << "Sent: " << message << endl;

    cout << "**************************************\n" << endl;

    return message;
}

int Arduino::calculateFDRValue(int iv, FDR* fdr)
{
    int result = 0;
    if (fdr->getOperator() == '+') {
        result = iv+fdr->getOperand();
    }

    return result;
}

bool Arduino::checkAnsweredFDR(int answeredFdr)
{
    int answer = calculateFDRValue(keyManager.getMyIV(), keyManager.getMyFDR());

    return answer == answeredFdr;
}

bool Arduino::receiveRSAKey(char buffer[])
{
    cout << "*********RECEIVED RSA SERVER**********" << endl;

    cout << "Received: " << buffer << endl;

    /*  Armazena a chave pública do servidor obtida, passando como parâmetro
        uma chamada à função getPartnerPublicKey do StringHandler, que extrai
        a chave pública do servidor do buffer (recebido do server).
    */
    keyManager.setPartnerPublicKey(stringHandler.getPartnerPublicKey(buffer));

    int answeredFdr = stringHandler.getRSAExchangeAnswerFdr(buffer);
    int partnerIV = stringHandler.getRSAExchangeIv(buffer);
    FDR* partnerFdr = stringHandler.getRSAExchangeFdr(buffer);
    answerFDR = calculateFDRValue(partnerIV, partnerFdr);

    cout << "RSA Server Public Key: (" <<stringHandler.getPartnerPublicKey(buffer).d <<
            ", " << stringHandler.getPartnerPublicKey(buffer).n << ")" << endl;
    cout << "Answered FDR: " << answeredFdr << endl;
    cout << "Server IV: " << partnerIV << endl;
    cout << "Server FDR: " << partnerFdr->getOperator() << partnerFdr->getOperand() << endl;
    cout << "Server FDR Answer: " << answerFDR << endl;

    if (checkAnsweredFDR(answeredFdr)) {
        receivedRSAKey = true;
        cout << "Answered FDR ACCEPTED!" << endl;
        return true;
    } else {
        cout << "Answered FDR REJECTED!" << endl;
        cout << "ENDING CONECTION..." << endl;
        return false;
    }

    cout << "**************************************\n" << endl;
}

/* Remove pacote da mensagem*/

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
        // printf(" %c", package.at(i));
        i++;
    }
    resultado += package.at(i);

    // for (int j = i; j < package.length(); j++) {
    //     resultado += package.at(j);
    //     printf(" %c", package.at(j));
    // }

    return resultado;
}


string Arduino::sendDiffieHellmanKey()
{
    keyManager.setExponent(a);
    cout << "************SEND DH CLIENT************" << endl;
    /*  Organiza o pacote com os dados Diffie-Hellman para enviar ao cliente. */
    long int pot = pow(g, a);
    long int A = pot % p;

    string spacer (SPACER_S);
    string package = to_string(A) + spacer +
                        to_string(g) + spacer +
                        to_string(p) + spacer +
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

    // cout << "Sent: " << package << endl << endl;
    cout << "Client Hash: " << hash << endl << endl;

    /* Encripta o hash utilizando a chave privada do cliente */
    // cout << "Encripta hash com a chave privada do cliente: (" << keyManager.getMyPrivateKey().e << ", " << keyManager.getMyPrivateKey().n << ")" << endl;
    string hashEncryptedString = iotAuth.encryptRSAPrivateKey(hash, keyManager.getMyPrivateKey(), hash.length());
    hashEncryptedString += "!";

    // cout << "Client Encrypted HASH: " << hashEncryptedString << endl << endl;

    /**************************************************************************/

    /* Prepara o pacote completo que será enviado ao servidor. */
    string sendData = package + "*" + hashEncryptedString;

    /* Converte a string (sendData) para um array de chars (sendDataArray). */
    char sendDataArray[sendData.length()];
    memset(sendDataArray, 0, sizeof(sendDataArray));
    strncpy(sendDataArray, sendData.c_str(), sizeof(sendDataArray));

    /* Encripta o sendDataArray utilizando a chave pública do servidor. */
    string sendDataEncrypted = iotAuth.encryptRSAPublicKey(sendData,
                keyManager.getPartnerPublicKey(), sendData.length());
    // cout << "Size of SendData: " << sendData.length() << endl;
    sendDataEncrypted += "!";

    // cout << "Send Data Encrypted Length: " << sendDataEncrypted.length() << endl << endl;

    // cout << "Send Data Encrypted: " << sendDataEncrypted << endl << endl;


    return sendDataEncrypted;
}

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

void Arduino::receiveDiffieHellmanKey(char message[])
{
    /* Decodifica o pacote recebido do cliente. */
    string encryptedPackage (message);

    int decryptedPackageInt[utils.countMarks(encryptedPackage)+1];
    utils.RSAToIntArray(decryptedPackageInt, message, encryptedPackage.length());

    /* Decodifica o pacote e converte para um array de char. */
    string decryptedPackageString = iotAuth.decryptRSAPrivateKey(decryptedPackageInt, keyManager.getMyPrivateKey(), encryptedPackage.length());

    /* Recupera o pacote com os dados Diffie-Hellman do Client. */
    string dhPackage = getPackage(decryptedPackageString);

    /***** HASH *****/
    /* Recupera o hash cifrado com a chave Privada do Server. */
    string encryptedHash = getHashEncrypted(decryptedPackageString);

    // cout << "Server Encrypted HASH: " << encryptedHash << endl << endl;

    int encryptedHashInt[128];
    utils.RSAToIntArray(encryptedHashInt, encryptedHash, 128);

    /* Decifra o HASH com a chave pública do Server. */
    string decryptedHashString = iotAuth.decryptRSAPublicKey(encryptedHashInt, keyManager.getPartnerPublicKey(), 128);

    cout << "Server Decrypted HASH: " << decryptedHashString << endl << endl;
    /***** HASH *****/

    /* Recebe chave Diffie-Hellman e IV. */
    printf("\n*******SERVER DH KEY RECEIVED******\n");
    char dhPackageChar[dhPackage.length()];
    strncpy(dhPackageChar, dhPackage.c_str(), sizeof(dhPackageChar));
    keyManager.setBase(stringHandler.getClientBase(dhPackageChar));
    keyManager.setModulus(stringHandler.getClientModulus(dhPackageChar));
    keyManager.setSessionKey(keyManager.getDiffieHellmanKey(stringHandler.getDHClientKey(dhPackageChar)));
    int ivClient = stringHandler.getDHIvClient(dhPackageChar);

    receivedDHKey = true;
    std::cout << "Diffie-Hellman Key: " << stringHandler.getDHClientKey(dhPackageChar) << std::endl;
    std::cout << "Base: " << stringHandler.getClientBase(dhPackageChar) << std::endl;
    std::cout << "Modulus: " << stringHandler.getClientModulus(dhPackageChar) << std::endl;
    std::cout << "Client IV: " << stringHandler.getDHIvClient(dhPackageChar) << std::endl;
    std::cout << "Session Key: " << keyManager.getSessionKey() << std::endl;
    std::cout << "***********************************\n" << std::endl;
}

string Arduino::sendEncryptedMessage(char message[], int size) {
    uint8_t plaintext[size];
    memset(plaintext, 0, size);

    uint8_t key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                      0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
    uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    // for (int i = 0; i < size; i++) {
    //     plaintext[i] = uint8_t(message[i]);
    // }

    utils.charToUint8_t(message, plaintext, size);

    uint8_t *encrypted = iotAuth.encryptAES(plaintext, key, iv, size);

    return (utils.Uint8_t_to_Hex_String(encrypted, size));



}
