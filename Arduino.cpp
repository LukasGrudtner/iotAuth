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
    char *message;
    strncpy(message, done.c_str(), done.length());
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

    keyManager.setRSAKeyPair(iotAuth.generateRSAKeyPair());

    string spacer (SPACER_S);
    string sendData = "";
    string answerFdr = "null";
    sendData =  to_string(keyManager.getMyPublicKey().d) + spacer +
                to_string(keyManager.getMyPublicKey().n) + spacer +
                answerFdr + spacer +
                to_string(iv) + spacer +
                fdr;

    cout << "Generated RSA Key: {(" << keyManager.getMyPublicKey().d
         << ", " << keyManager.getMyPublicKey().n << "), ("
         << keyManager.getMyPrivateKey().e << ", "
         << keyManager.getMyPrivateKey().n << ")}" << endl;
    cout << "Iv: " << iv << endl;
    cout << "Fdr: " << fdr << endl;

    char* message = (char*)malloc(sendData.length());
    strcpy(message, sendData.c_str());

    cout << "Sent: " << message << endl;

    cout << "**************************************\n" << endl;

    return message;
}

void Arduino::receiveRSAKey(char buffer[])
{
    cout << "*********RECEIVED RSA SERVER**********" << endl;

    cout << "Received: " << buffer << endl;

    keyManager.setPartnerPublicKey(stringHandler.getPartnerPublicKey(buffer));

    long int answerFdr = stringHandler.getRSAExchangeAnswerFdr(buffer);
    long int receivedIv = stringHandler.getRSAExchangeIv(buffer);
    FDR *fdr = stringHandler.getRSAExchangeFdr(buffer);

    cout << "RSA Server Public Key: (" <<stringHandler.getPartnerPublicKey(buffer).d <<
            ", " << stringHandler.getPartnerPublicKey(buffer).n << ")" << endl;
    cout << "Answer FDR: " << answerFdr << endl;
    cout << "Received IV: " << receivedIv << endl;
    cout << "FDR: " << fdr->getOperator() << fdr->getOperand() << endl;

    // if ((receivedIv-1) == iv) {
        receivedRSAKey = true;
    // } else {
    //     cout << "O IV recebido está incorreto." << endl;
    //     done();
    //     sendClientDone();
    //     receiveServerDone(buffer);
    // }

    cout << "**************************************\n" << endl;
}

/* Remove pacote da mensagem*/

string Arduino::getHashEncrypted(string package)
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


char* Arduino::sendDiffieHellmanKey()
{
    cout << "************SEND DH CLIENT************" << endl;
    long int pot = pow(g, a);
    long int A = pot % p;

    string answerFdr = "1";
    string spacer (SPACER_S);
    string package = to_string(A) + spacer +
                        answerFdr + spacer +
                        to_string(g) + spacer +
                        to_string(p) + spacer +
                        to_string(iv);

    char hashArray[128];
    char messageArray[package.length()];
    memset(hashArray, 0, sizeof(hashArray));
    strncpy(messageArray, package.c_str(), sizeof(messageArray));

    iotAuth.hash(messageArray, hashArray);

    cout << "Sent: " << package << endl;
    string h (hashArray);
    cout << "Hash: " << h << endl;

    int* hashEncrypted = iotAuth.encryptRSAPrivateKey(hashArray, keyManager.getMyPrivateKey(), sizeof(hashArray));
    // cout << "Hash Encrypted: ";
    // for (int i = 0; i < utils.intArraySize(hashEncrypted); i++) {
    //     cout << hashEncrypted[i];
    // }

    string hashEncryptedString = "";
    for (int i = 0; i < utils.intArraySize(hashEncrypted); i++) {
        hashEncryptedString += to_string(hashEncrypted[i]);
        if (i < (utils.intArraySize(hashEncrypted)-1))
            hashEncryptedString += ".";
    }

    string sendData = package + "*" + hashEncryptedString;
    // cout << endl<< "Send Data: " << sendData << endl;

    char sendDataArray[sendData.length()];
    memset(sendDataArray, 0, sizeof(sendDataArray));
    strncpy(sendDataArray, sendData.c_str(), sizeof(sendDataArray));

    int* sendDataEncrypted = iotAuth.encryptRSAPublicKey(sendDataArray,
                keyManager.getPartnerPublicKey(), sizeof(sendDataArray));

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
    cout << "Message Length: " << m.length() << endl;

    /* Decodificação */
    int* decInt = (int*)malloc(m.length() * sizeof(int));
    decInt = utils.RSAToIntArray(message, m.length());

    string packageDecrypted = iotAuth.decryptRSAPrivateKey(decInt, keyManager.getMyPrivateKey(), m.length());
    // cout << "Package Decrypted: " << packageDecrypted << endl;

    char packageDecryptedChar[packageDecrypted.length()];
    strncpy(packageDecryptedChar, packageDecrypted.c_str(), sizeof(packageDecryptedChar));

    string result = getHashEncrypted(packageDecrypted);
    char resultChar[result.length()];
    strncpy(resultChar, result.c_str(), sizeof(resultChar));
    int* decInt2 = (int*)malloc(result.length() * sizeof(int));

    decInt2 = utils.RSAToIntArray(resultChar, sizeof(resultChar));
    // for (int i = 0; i < utils.intArraySize(decInt2); i++) {
    //     cout << decInt2[i] << " ";
    // }
    string hashDec = iotAuth.decryptRSAPublicKey(decInt2, keyManager.getMyPublicKey(), result.length());

    // cout << endl << "Hash dec: " << hashDec << endl;

    return message;
}

string Arduino::getPackage(string package)
{
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
    string encrypted (message);
    int* decInt = (int*)malloc(encrypted.length() * sizeof(int));
    decInt = utils.RSAToIntArray(message, encrypted.length());

    string packageDecrypted = iotAuth.decryptRSAPrivateKey(decInt, keyManager.getMyPrivateKey(), encrypted.length());
    char packageDecryptedChar[packageDecrypted.length()];
    strncpy(packageDecryptedChar, packageDecrypted.c_str(), sizeof(packageDecryptedChar));

    /* Recupera as chaves */
    string package = getPackage(packageDecrypted);

    string result = getHashEncrypted(packageDecrypted);
    char resultChar[result.length()];
    strncpy(resultChar, result.c_str(), sizeof(resultChar));
    int* decInt2 = (int*)malloc(result.length() * sizeof(int));

    decInt2 = utils.RSAToIntArray(resultChar, sizeof(resultChar));
    string hashDec = iotAuth.decryptRSAPublicKey(decInt2, keyManager.getMyPublicKey(), result.length());

    cout << "Hash decifrado: " << hashDec << endl;

    /* Recebe chave Diffie-Hellman e IV. */
    printf("\n*******CLIENT DH KEY RECEIVED******\n");
    char pkg[package.length()];
    strncpy(pkg, package.c_str(), sizeof(pkg));
    keyManager.setBase(stringHandler.getClientBase(pkg));
    keyManager.setModulus(stringHandler.getClientModulus(pkg));
    keyManager.setSessionKey(keyManager.getDiffieHellmanKey(stringHandler.getDHClientKey(pkg)));
    int ivClient = stringHandler.getDHIvClient(pkg);

    receivedDHKey = true;
    std::cout << "Diffie-Hellman Key: " << stringHandler.getDHClientKey(pkg) << std::endl;
    std::cout << "Base: " << stringHandler.getClientBase(pkg) << std::endl;
    std::cout << "Modulus: " << stringHandler.getClientModulus(pkg) << std::endl;
    std::cout << "Client IV: " << stringHandler.getDHIvClient(pkg) << std::endl;
    std::cout << "Session Key: " << keyManager.getSessionKey() << std::endl;
    std::cout << "***********************************\n" << std::endl;
}
