#include "Arduino.h"

/*  State Machine
    Realiza o controle do estado atual da FSM.
*/
void Arduino::stateMachine(int socket, struct sockaddr *server, socklen_t size)
{
    static States state = HELLO;

    switch (state) {

        /* Waiting Done Confirmation */
        case WDC:
        {
            cout << "WAITING DONE CONFIRMATION" << endl;
            wdc(&state, socket, server, size);
            break;
        }

        /* Request For Termination */
        case RFT:
        {
            cout << "REQUEST FOR TERMINATION RECEIVED" << endl;
            rft(&state, socket, server, size);
            break;
        }

        /* Done */
        case DONE:
        {
            cout << "SEND DONE" << endl;
            done(&state, socket, server, size);
            break;
        }

        /* Hello */
        case HELLO:
        {
            hello(&state, socket, server, size);
            break;
        }

        /* Receive RSA */
        case RRSA:
        {
            cout << "RECEIVE RSA KEY" << endl;
            rrsa(&state, socket, server, size);
            break;
        }

        /* Send RSA */
        case SRSA:
        {
            cout << "SEND RSA KEY" << endl;
            srsa(&state, socket, server, size);
            break;
        }

        /* Receive Diffie-Hellman */
        case RDH:
        {
            cout << "RECEIVE DIFFIE HELLMAN KEY" << endl;
            rdh(&state, socket, server, size);
            break;
        }

        /* Send Diffie-Hellman */
        case SDH:
        {
            cout << "SEND DIFFIE HELLMAN KEY" << endl;
            sdh(&state, socket, server, size);
            break;
        }

        /* Data Transfer */
        case DT:
        {
            cout << "SEND ENCRYPTED DATA" << endl;
            dt(&state, socket, server, size);
            break;
        }
    }
}

/*  Waiting Done Confirmation
    Verifica se a mensagem vinda do Cliente é uma confirmação do pedido de
    fim de conexão enviado pelo Servidor (DONE_ACK).
    Em caso positivo, altera o estado para HELLO, senão, mantém em WDC. 7
*/
void Arduino::wdc(States *state, int socket, struct sockaddr *server, socklen_t size)
{
    char message[1];
    recvfrom(socket, message, sizeof(message), 0, server, &size);

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
void Arduino::rft(States *state, int socket, struct sockaddr *server, socklen_t size)
{
    sendto(socket, DONE_ACK, strlen(DONE_ACK), 0, server, size);
    *state = HELLO;

    if (VERBOSE) {
        cout << "\n*******DONE CLIENT AND SERVER******"   << endl;
        cout << "Done Client and Server Successful!"      << endl;
        cout << "***********************************\n"   << endl;
    }
}

/*  Hello
    Envia um pedido de início de conexão (HELLO) para o Servidor
*/
void Arduino::hello(States *state, int socket, struct sockaddr *server, socklen_t size)
{
    cout << "SEND HELLO" << endl;

    string hello (HELLO_MESSAGE);
    char *message;
    strncpy(message, hello.c_str(), hello.length());

    sendto(socket, message, strlen(message), 0, server, size);

    char received[1];
    recvfrom(socket, received, sizeof(received), 0, server, &size);

    /* Verifica se a mensagem recebida é um HELLO. */
    if (received[0] == HELLO_ACK_CHAR) {
        *state = SRSA;
        if (VERBOSE) {
            cout << "******HELLO CLIENT AND SERVER******"     << endl;
            cout << "Hello Client and Server Successful!"     << endl;
            cout << "***********************************\n"   << endl;
        }
    } else {
        *state = HELLO;
    }
}

/*  Done
    Envia um pedido de término de conexão ao Cliente, e seta o estado atual
    para WDC (Waiting Done Confirmation).
*/
void Arduino::done(States *state, int socket, struct sockaddr *server, socklen_t size)
{
    sendto(socket, DONE_MESSAGE, strlen(DONE_MESSAGE), 0, server, size);
    *state = WDC;
}

/*  Send RSA
    Realiza o envio da chave RSA para o Servidor.
*/
void Arduino::srsa(States *state, int socket, struct sockaddr *server, socklen_t size)
{
    /* Gera um par de chaves RSA e o armazena no keyManager. */
    keyManager.setRSAKeyPair(iotAuth.generateRSAKeyPair());

    /* Gera um valor de IV e o armazena no KeyManager. */
    keyManager.setMyIV(iotAuth.generateIV());

    /* Gera uma Função Desafio-Resposta e o armazena no KeyManager. */
    keyManager.setMyFDR(iotAuth.generateFDR());

    int answerFdr = 0;
    RSAKey* publicKey = keyManager.getMyPublicKey();
    int iv = keyManager.getMyIV();

    /* Derreferenciando um ponteiro: obtém o valor armazenado na posição indicada pelo ponteiro, e não o endereço na memória. */
    FDR fdr = *keyManager.getMyFDR();

    RSAKeyExchange rsaSent;
    rsaSent.setPublicKey(*publicKey);
    rsaSent.setAnswerFDR(answerFdr);
    rsaSent.setIV(iv);
    rsaSent.setFDR(fdr);

    if (VERBOSE) {
        cout << "************SEND RSA CLIENT***********" << endl;
        cout << "Generated RSA Key: {(" << keyManager.getMyPublicKey()->d
             << ", " << keyManager.getMyPublicKey()->n << "), ("
             << keyManager.getMyPrivateKey()->d << ", "
             << keyManager.getMyPrivateKey()->n << ")}" << endl;
        cout << "My IV: " << keyManager.getMyIV() << endl;
        cout << "My FDR: " << keyManager.getMyFDR()->toString() << endl;
        cout << "Sent: " << rsaSent.toString() << endl;
        cout << "**************************************\n" << endl;
    }

    int sended = sendto(socket, (RSAKeyExchange*)&rsaSent, sizeof(rsaSent), 0, server, size);

    *state = RRSA;
}

/*  Receive RSA
    Realiza o recebimento da chave RSA vinda do Servidor.
*/
void Arduino::rrsa(States *state, int socket, struct sockaddr *server, socklen_t size)
{
    RSAKeyExchange* rsaReceived = new RSAKeyExchange();
    recvfrom(socket, rsaReceived, sizeof(RSAKeyExchange), 0, server, &size);

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
        if (VERBOSE) {
            cout << "Answered FDR ACCEPTED!" << endl;
            cout << "**************************************\n" << endl;
        }
        *state = SDH;
    } else {
        if (VERBOSE) {
            cout << "Answered FDR REJECTED!" << endl;
            cout << "ENDING CONECTION..." << endl;
            cout << "**************************************\n" << endl;
        }
        *state = DONE;
    }

    delete rsaReceived;
}

/*  Send Diffie-Hellman
    Realiza o envio da chave Diffie-Hellman para o Servidor.
*/
void Arduino::sdh(States *state, int socket, struct sockaddr *server, socklen_t size)
{
    /* Gera os valores Diffie-Hellman. */
    sleep(1);
    int a = iotAuth.randomNumber(3)+2;
    sleep(1);
    int g = iotAuth.randomNumber(100);
    sleep(1);
    int p = iotAuth.randomNumber(100);

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
    /* Extrai o hash */
    string dhString = diffieHellmanPackage.toString();
    string hash = iotAuth.hash(&dhString);

    /* Encripta o hash utilizando a chave privada do cliente */
    int* encryptedHash = iotAuth.encryptRSA(&hash, keyManager.getMyPrivateKey(), hash.length());

    /**************************************************************************/

    /* Prepara o pacote completo que será enviado ao servidor. */
    /* Transforma a struct 'diffieHellmanPackage' em um array de bytes. */
    byte* dhPackageBytes = new byte[sizeof(DiffieHellmanPackage)];
    utils.ObjectToBytes(diffieHellmanPackage, dhPackageBytes, sizeof(DiffieHellmanPackage));

    DHKeyExchange* dhSent = new DHKeyExchange();
    dhSent->setEncryptedHash(encryptedHash);
    dhSent->setDiffieHellmanPackage(dhPackageBytes);

    /* Converte o objeto dhSent em um array de bytes. */
    byte* dhSentBytes = new byte[sizeof(DHKeyExchange)];
    utils.ObjectToBytes(*dhSent, dhSentBytes, sizeof(DHKeyExchange));

    int* encryptedMessage = iotAuth.encryptRSA(dhSentBytes, keyManager.getPartnerPublicKey(), sizeof(DHKeyExchange));

    if (VERBOSE) {
        cout << "************SEND DH CLIENT************" << endl;
        cout << "Client Hash: " << hash << endl << endl;
        cout << "a: " << a << endl << "g: " << g << endl << "p: " << p << endl;
        cout << "Client Package: " << diffieHellmanPackage.toString() << endl;
        cout << "**************************************" << endl << endl;
    }

    sendto(socket,(int*)encryptedMessage, sizeof(DHKeyExchange)*sizeof(int), 0, server, size);
    *state = RDH;

    delete[] dhPackageBytes;
    delete[] encryptedHash;
    delete[] dhSent;
    delete[] dhSentBytes;
    delete[] encryptedMessage;
}

/*  Receive Diffie-Hellman
    Realiza o recebimento da chave Diffie-Hellman vinda do Servidor.
*/
void Arduino::rdh(States *state, int socket, struct sockaddr *server, socklen_t size)
{
    /******************** Recebe os dados cifrados ********************/
    int encryptedMessage[sizeof(DHKeyExchange)];
    recvfrom(socket, encryptedMessage, sizeof(DHKeyExchange)*sizeof(int), 0, server, &size);

    /******************** Realiza a decifragem ********************/
    DHKeyExchange dhKeyExchange;
    decryptDHKeyExchange(encryptedMessage, &dhKeyExchange);

    DiffieHellmanPackage diffieHellmanPackage;
    getDiffieHellmanPackage(&dhKeyExchange, &diffieHellmanPackage);

    string hash = decryptHash(&dhKeyExchange);

    /******************** Validação do Hash ********************/
   /* Se o hash for válido, continua com o recebimento. */
   string dhString = diffieHellmanPackage.toString();
   if (iotAuth.isHashValid(&dhString, &hash)) {

       /* Armazena os valores Diffie-Hellman no KeyManager. */
       keyManager.setBase(diffieHellmanPackage.getBase());
       keyManager.setModulus(diffieHellmanPackage.getModulus());
       keyManager.setSessionKey(keyManager.getDiffieHellmanKey(diffieHellmanPackage.getResult()));
       int clientIV = diffieHellmanPackage.getIV();
       int answeredFdr = diffieHellmanPackage.getAnswerFDR();

       *state = DT;

       if (VERBOSE) {
           cout << "\n*******SERVER DH KEY RECEIVED******" << endl;

           cout << "Hash is valid!" << endl << endl;

           if (VERBOSE_2) {
               cout << "Server Encrypted Data" << endl;
               for (int i = 0; i < sizeof(DHKeyExchange)-1; i++) {
                   cout << encryptedMessage[i] << ":";
               }
               cout << encryptedMessage[sizeof(DHKeyExchange)-1] << endl << endl;
           }

           cout << "Server Decrypted HASH: "   << hash          << endl << endl;
           cout << "Diffie-Hellman Key: "      << diffieHellmanPackage.getResult()  << endl;
           cout << "Base: "                    << diffieHellmanPackage.getBase()    << endl;
           cout << "Modulus: "                 << diffieHellmanPackage.getModulus() << endl;
           cout << "Client IV: "               << clientIV                          << endl;
           cout << "Session Key: "             << keyManager.getSessionKey()        << endl;
           cout << "Answered FDR: "            << answeredFdr                       << endl;
           cout << "***********************************\n"                          << endl;
       }

   /* Se não, altera o estado para DONE e realiza o término da conexão. */
   } else {
       if (VERBOSE) {
           cout << "Hash is invalid!" << endl << endl;
       }
       *state = DONE;
   }
}

/*  Decrypt DH Key Exchange
    Decifra o pacote de troca Diffie-Hellman utilizando a chave privada do Servidor.
    Recebe por parâmetro a mensagem cifrada e retorna por parâmetro o pacote decifrado.
*/
void Arduino::decryptDHKeyExchange(int *encryptedMessage, DHKeyExchange *dhKeyExchange)
{
    byte* decryptedMessage = iotAuth.decryptRSA(encryptedMessage, keyManager.getMyPrivateKey(), sizeof(DHKeyExchange));
    
    utils.BytesToObject(decryptedMessage, *dhKeyExchange, sizeof(DHKeyExchange));

    delete[] decryptedMessage;
}

/*  Get Diffie-Hellman Package
    Obtém o pacote Diffie-Hellman em bytes, o transforma de volta em objeto, e retorna por parâmetro.
*/
void Arduino::getDiffieHellmanPackage(DHKeyExchange *dhKeyExchange, DiffieHellmanPackage *diffieHellmanPackage)
{
    /******************** Recupera o pacote Diffie-Hellman ********************/
    byte *dhPackageBytes = dhKeyExchange->getDiffieHellmanPackage();

    utils.BytesToObject(dhPackageBytes, *diffieHellmanPackage, sizeof(DiffieHellmanPackage));
}

/*  Decrypt Hash
    Decifra o hash obtido do pacote utilizando a chave pública do Cliente.
    Retorna o hash em uma string.
*/
string Arduino::decryptHash(DHKeyExchange *dhKeyExchange)
{
    int *encryptedHash = dhKeyExchange->getEncryptedHash();
    byte *decryptedHash = iotAuth.decryptRSA(encryptedHash, keyManager.getPartnerPublicKey(), 128);

    char aux;
    string decryptedHashString = "";
    for (int i = 0; i < 128; i++) {
        aux = decryptedHash[i];
        decryptedHashString += aux;
    }

    delete[] decryptedHash;

    return decryptedHashString;
}

/*  Data Transfer
    Realiza a transferência de dados cifrados para o Servidor.
*/
void Arduino::dt(States *state, int socket, struct sockaddr *server, socklen_t size)
{
    char envia[666];
    cout << "Envio de dados criptografados com AES." << endl << endl;

    printf("########## Escreva uma mensagem para o servidor ##########\n");
    printf("------------- Linha em branco para finalizar -------------\n");
    /* Captura a mensagem digitada no terminal para a criptografia. */
    fgets(envia, 666, stdin);

    /* Enquanto o usuário não digitar um 'Enter': */
    while (strcmp(envia, "\n") != 0) {

        /* Encripta a mensagem digitada pelo usuário. */
        string encryptedMessage = encryptMessage(envia, sizeof(envia));
        cout << "Sent" << endl << encryptedMessage << endl << endl;

        /* Converte a string em um array de char. */
        char encryptedMessageChar[encryptedMessage.length()];
        memset(encryptedMessageChar, '\0', sizeof(encryptedMessageChar));
        strncpy(encryptedMessageChar, encryptedMessage.c_str(), sizeof(encryptedMessageChar));

        // delete[] encryptedMessage;

        /* Envia a mensagem cifrada ao Servidor. */
        sendto(socket, encryptedMessageChar, strlen(encryptedMessageChar), 0, server, size);
        memset(envia, '\0', sizeof(envia));
        fgets(envia, 665, stdin);
    }
}

/*  Calculate FDR Value
    Calcula a resposta de uma dada FDR. */
int Arduino::calculateFDRValue(int iv, FDR* fdr)
{
    int result = 0;
    if (fdr->getOperator() == '+') {
        result = iv+fdr->getOperand();
    }

    return result;
}

/*  Check Answered FDR
    Verifica a validade da resposta da FDR gerada pelo Servidor.
*/
bool Arduino::checkAnsweredFDR(int answeredFdr)
{
    int answer = calculateFDRValue(keyManager.getMyIV(), keyManager.getMyFDR());
    return answer == answeredFdr;
}

/*  Encrypt Message
    Encripta a mensagem utilizando a chave de sessão.
*/
string Arduino::encryptMessage(char* message, int size) 
{
    /* Inicialização do vetor plaintext. */
    uint8_t plaintext[size];
    memset(plaintext, '\0', size);

    /* Inicialização da chave e do IV. */
    // uint8_t key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    //                   0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
    uint8_t key[32];
    for (int i = 0; i < 32; i++) {
        key[i] = keyManager.getSessionKey();
    }

    // uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    uint8_t iv[16];
    for (int i = 0; i < 16; i++) {
        iv[i] = keyManager.getSessionKey();
    }

    /* Converte o array de char (message) para uint8_t. */
    utils.CharToUint8_t(message, plaintext, size);

    /* Encripta a mensagem utilizando a chave e o iv declarados anteriormente. */
    uint8_t *encrypted = iotAuth.encryptAES(plaintext, key, iv, size);

    string result = utils.Uint8_tToHexString(encrypted, size);

    // delete[] encrypted;

    return result;
}
