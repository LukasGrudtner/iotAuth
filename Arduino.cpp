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
        cout << "My FDR: " << keyManager.getMyFDR()->toString() << endl;
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
int* Arduino::sendDiffieHellmanKey()
{
    /* Seta o expoente no KeyManager. */
    keyManager.setExponent(a);

    /*  Organiza o pacote com os dados Diffie-Hellman para enviar ao cliente. */
    long int pot    = pow(g, a);
    long int A      = pot % p;

    DiffieHellmanPackage diffieHellmanPackage;
    diffieHellmanPackage.setResult(A);
    diffieHellmanPackage.setBase(g);
    diffieHellmanPackage.setModulus(p);
    diffieHellmanPackage.setIV(keyManager.getMyIV());
    diffieHellmanPackage.setAnswerFDR(answerFDR);

    /**************************************************************************/
    /* Realiza o cálculo do HASH do pacote obtido acima. */
    char hashArray[128];
    char messageArray[diffieHellmanPackage.toString().length()];
    memset(hashArray, '\0', sizeof(hashArray));

    /* Converte o pacote (string) para um array de char (messageArray). */
    strncpy(messageArray, diffieHellmanPackage.toString().c_str(), sizeof(messageArray));

    /* Extrai o hash */
    string hash = iotAuth.hash(messageArray);

    /* Encripta o hash utilizando a chave privada do cliente */
    int* encryptedHash = iotAuth.encryptRSA(hash, keyManager.getMyPrivateKey(), hash.length());

    // cout << "EncryptedHash" << endl;
    // for (int i = 0; i < 128; i++) {
    //     cout << encryptedHash[i] << ":";
    // }

    /**************************************************************************/

    /* Prepara o pacote completo que será enviado ao servidor. */
    /* Transforma a struct 'diffieHellmanPackage' em um array de bytes. */
    byte* dhPackageBytes = (byte*)malloc(sizeof(DiffieHellmanPackage));
    utils.ObjectToBytes(diffieHellmanPackage, dhPackageBytes, sizeof(DiffieHellmanPackage));

    DHKeyExchange* dhSent = new DHKeyExchange();
    dhSent->setEncryptedHash(encryptedHash);
    dhSent->setDiffieHellmanPackage(dhPackageBytes);

    /* Converte o objeto dhSent em um array de bytes. */
    byte* dhSentBytes = (byte*)malloc(sizeof(DHKeyExchange));
    utils.ObjectToBytes(*dhSent, dhSentBytes, sizeof(DHKeyExchange));

    // cout << "DecryptedMessage" << endl;
    // for (int i = 0; i < sizeof(DHKeyExchange); i++) {
    //     cout << (int)dhSentBytes[i] << ":";
    // }


    int* encryptedMessage = iotAuth.encryptRSA(dhSentBytes, keyManager.getPartnerPublicKey(), sizeof(DHKeyExchange));

    // /* TESTE TESTE TESTE TESTE TESTE TESTE TESTE TESTE TESTE TESTE TESTE TESTE TESTE TESTE  */
    // byte* aByte = (byte*)malloc(sizeof(DHKeyExchange));
    // utils.ObjectToBytes(*dhSent, aByte, sizeof(DHKeyExchange));
    //
    // cout << "TEST STRUCT: " << dhSent->getEncryptedHash()[0] << endl;
    //
    // cout << "TEST DEC BYTE: " << endl;
    // for (int i = 0; i < sizeof(DHKeyExchange); i++) {
    //     cout << (int)aByte[i] << ", ";
    // }
    //
    // int* enc = iotAuth.encryptRSA(aByte, keyManager.getMyPublicKey(), sizeof(DHKeyExchange));
    //
    // cout << "TEST ENC BYTE: " << endl;
    // for (int i = 0; i < sizeof(DHKeyExchange); i++) {
    //     cout << (int)enc[i] << ", ";
    // }
    //
    // byte* dec = iotAuth.decryptRSA(enc, keyManager.getMyPrivateKey(), sizeof(DHKeyExchange));
    //
    // cout << "TEST DEC BYTE: " << endl;
    // for (int i = 0; i < sizeof(DHKeyExchange); i++) {
    //     cout << (int)dec[i] << ", ";
    // }
    //
    // DHKeyExchange b;
    // utils.BytesToObject(dec, b, sizeof(DHKeyExchange));
    //
    // cout << "TEST STRUCT: " << b.getEncryptedHash()[0] << endl;
    //
    // /* TESTE TESTE TESTE TESTE TESTE TESTE TESTE TESTE TESTE TESTE TESTE TESTE TESTE TESTE  */

    if (VERBOSE) {
        cout << "************SEND DH CLIENT************" << endl;
        cout << "Client Hash: " << hash << endl << endl;
        cout << "Client Package: " << diffieHellmanPackage.toString() << endl;
        cout << "**************************************" << endl << endl;
    }

    // cout << endl << "EncryptedMessage" << endl;
    // for (int i = 0; i < sizeof(DHKeyExchange); i++) {
    //     cout << encryptedMessage[i] << ":";
    // }

    return encryptedMessage;
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
bool Arduino::receiveDiffieHellmanKey(int* encryptedDHExchange)
{
    /* Decifra a mensagem com a chave privada do Cliente e a coloca em um array de bytes. */
    byte *decryptedMessage = iotAuth.decryptRSA(encryptedDHExchange, keyManager.getMyPrivateKey(), sizeof(DHKeyExchange));

    cout            << "Encrypted Data" << endl;
    for (int i = 0; i < sizeof(DHKeyExchange); i++) {
        cout << encryptedDHExchange[i] << ":";
    }
    cout << encryptedDHExchange[127] << endl << endl;

    /* Converte o array de bytes de volta na struct DHKeyExchange*/
   DHKeyExchange encryptedDHReceived;
   utils.BytesToObject(decryptedMessage, encryptedDHReceived, sizeof(DHKeyExchange));

   /* Extrai o HASH encriptado */
   int *encryptedHash = encryptedDHReceived.getEncryptedHash();

   /* Decifra o HASH com a chave pública do Servidor. */
   byte *decryptedHash = iotAuth.decryptRSA(encryptedHash, keyManager.getPartnerPublicKey(), 128);
   char aux;
   string decryptedHashString = "";
   for (int i = 0; i < 128; i++) {
       aux = decryptedHash[i];
       decryptedHashString += aux;
   }

   cout << "Decrypted Hash: " << decryptedHashString << endl;

   /* Recupera o pacote com os dados Diffie-Hellman do Servidor. */
   byte* dhPackageBytes = encryptedDHReceived.getDiffieHellmanPackage();
   DiffieHellmanPackage dhPackage;
   utils.BytesToObject(dhPackageBytes, dhPackage, sizeof(DiffieHellmanPackage));

   /* Se o hash for válido, continua com o recebimento. */
   if (iotAuth.isHashValid(dhPackage.toString(), decryptedHashString)) {

       /* Armazena os valores Diffie-Hellman no KeyManager. */
       keyManager.setBase(dhPackage.getBase());
       keyManager.setModulus(dhPackage.getModulus());
       keyManager.setSessionKey(keyManager.getDiffieHellmanKey(dhPackage.getResult()));
       int clientIV = dhPackage.getIV();
       int answeredFdr = dhPackage.getAnswerFDR();

       receivedDHKey = true;

       if (VERBOSE) {
           printf("\n*******SERVER DH KEY RECEIVED******\n");

           cout << "Hash is valid!" << endl << endl;

           if (VERBOSE_2) {
               cout << "Server Encrypted Data" << endl;
               for (int i = 0; i < sizeof(DHKeyExchange)-1; i++) {
                   cout << encryptedDHExchange[i] << ":";
               }
               cout << encryptedDHExchange[sizeof(DHKeyExchange)-1] << endl << endl;

               cout << "Server Encrypted Hash" << endl;
               for (int i = 0; i < 127; i++) {
                   cout << encryptedHash[i] << ":";
               }
               cout << encryptedHash[127] << endl << endl;
           }

           cout << "Server Decrypted HASH: "   << decryptedHashString          << endl << endl;
           cout << "Diffie-Hellman Key: "      << dhPackage.getResult()        << endl;
           cout << "Base: "                    << dhPackage.getBase()          << endl;
           cout << "Modulus: "                 << dhPackage.getModulus()       << endl;
           cout << "Client IV: "               << clientIV                     << endl;
           cout << "Session Key: "             << keyManager.getSessionKey()  << endl;
           cout << "Answered FDR: "            << answeredFdr                  << endl;
       }

       return true;

   /* Se não, retorna falso e irá ocorrer o término da conexão. */
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
