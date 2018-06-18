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

    if (VERBOSE) {rft_verbose();}
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
        if (VERBOSE) {hello_sucessfull_verbose();}
    } else {
        if (VERBOSE) {hello_failed_verbose();}
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
    /******************** Configurando valores RSA ********************/
    setupRSA();

    /******************** RSA Key Exchange ********************/
    RSAKeyExchange rsaSent;
    rsaSent.setPublicKey(*rsaStorage->getMyPublicKey());
    rsaSent.setIV(rsaStorage->getMyIV());
    rsaSent.setFDR(*rsaStorage->getMyFDR());
    rsaSent.setAnswerFDR(0);

    /******************** Envio ********************/
    int sended = sendto(socket, (RSAKeyExchange*)&rsaSent, sizeof(rsaSent), 0, server, size);
    *state = RRSA;

    /******************** Verbose ********************/
    if (VERBOSE) {srsa_verbose(rsaStorage, &rsaSent);}
}

/*  Receive RSA
    Realiza o recebimento da chave RSA vinda do Servidor.
*/
void Arduino::rrsa(States *state, int socket, struct sockaddr *server, socklen_t size)
{
    RSAKeyExchange* rsaKeyExchange = new RSAKeyExchange();
    recvfrom(socket, rsaKeyExchange, sizeof(RSAKeyExchange), 0, server, &size);

    rsaStorage->setPartnerPublicKey(rsaKeyExchange->getPublicKey());
    rsaStorage->setPartnerIV(rsaKeyExchange->getIV());
    rsaStorage->setPartnerFDR(rsaKeyExchange->getFDR());

    if (VERBOSE) {rrsa_verbose1(rsaKeyExchange, rsaStorage);}

    /* Verifica se a resposta do FDR é válida. */
    if (checkAnsweredFDR(rsaKeyExchange->getAnswerFDR())) {
        if (VERBOSE) {rrsa_verbose2();}
        *state = SDH;
    } else {
        if (VERBOSE) {rrsa_verbose3();}
        *state = DONE;
    }

    delete rsaKeyExchange;
}

void Arduino::setupDiffieHellman()
{
    dhStorage = new DHStorage();
    dhStorage->setMyIV(rsaStorage->getMyIV());
    dhStorage->setMyFDR(*rsaStorage->getMyFDR());

    dhStorage->setExponent(iotAuth.randomNumber(3)+2);
    dhStorage->setBase(iotAuth.randomNumber(100));
    dhStorage->setModulus(iotAuth.randomNumber(100));
}

void Arduino::mountDHPackage(DiffieHellmanPackage *dhPackage)
{
    dhPackage->setResult(dhStorage->calculateResult());
    dhPackage->setBase(dhStorage->getBase());
    dhPackage->setModulus(dhStorage->getModulus());
    dhPackage->setIV(dhStorage->getMyIV());

    int answerFDR = calculateFDRValue(rsaStorage->getPartnerIV(), rsaStorage->getPartnerFDR());
    dhPackage->setAnswerFDR(answerFDR);
}

/*  Get Encrypted Hash
    Realiza a cifragem do hash obtido do pacote Diffie-Hellman com a chave privada do Servidor.
    O retorno do hash cifrado é feito por parâmetro.
*/
int* Arduino::getEncryptedHash(DiffieHellmanPackage *dhPackage)
{
    string dhString = dhPackage->toString();
    string hash = iotAuth.hash(&dhString);

    int *encryptedHash = iotAuth.encryptRSA(&hash, rsaStorage->getMyPrivateKey(), hash.length());
    return encryptedHash;
}

/*  Send Diffie-Hellman
    Realiza o envio da chave Diffie-Hellman para o Servidor.
*/
void Arduino::sdh(States *state, int socket, struct sockaddr *server, socklen_t size)
{
    setupDiffieHellman();
    /***************** Montagem do Pacote Diffie-Hellman ******************/
    DiffieHellmanPackage diffieHellmanPackage;
    mountDHPackage(&diffieHellmanPackage);

    /***************** Serialização do Pacote Diffie-Hellman ******************/
    byte* dhPackageBytes = new byte[sizeof(DiffieHellmanPackage)];
    utils.ObjectToBytes(diffieHellmanPackage, dhPackageBytes, sizeof(DiffieHellmanPackage));

    /***************************** Geração do HASH ****************************/
    /* Encripta o hash utilizando a chave privada do Servidor. */
    int *encryptedHash = getEncryptedHash(&diffieHellmanPackage);

    /********************** Preparação do Pacote Final ************************/
    DHKeyExchange dhSent;
    dhSent.setEncryptedHash(encryptedHash);
    dhSent.setDiffieHellmanPackage(dhPackageBytes);

    /********************** Serialização do Pacote Final **********************/
    byte* dhSentBytes = new byte[sizeof(DHKeyExchange)];
    utils.ObjectToBytes(dhSent, dhSentBytes, sizeof(DHKeyExchange));

    /******************** Cifragem e Envio do Pacote Final ********************/
    int* encryptedMessage = iotAuth.encryptRSA(dhSentBytes, rsaStorage->getPartnerPublicKey(), sizeof(DHKeyExchange));

    sendto(socket,(int*)encryptedMessage, sizeof(DHKeyExchange)*sizeof(int), 0, server, size);
    *state = RDH;

    /******************************** VERBOSE *********************************/
    if (VERBOSE) {sdh_verbose(&diffieHellmanPackage);}

    delete[] dhPackageBytes;
    delete[] encryptedHash;
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
   string dhString = diffieHellmanPackage.toString();
   if (iotAuth.isHashValid(&dhString, &hash)) {

       dhStorage->setSessionKey(dhStorage->calculateSessionKey(diffieHellmanPackage.getResult()));

       if (VERBOSE) {rdh_verbose1(dhStorage, &diffieHellmanPackage, &hash);}

        if (checkAnsweredFDR(diffieHellmanPackage.getAnswerFDR())) {
            *state = DT;
            if (VERBOSE) {rdh_verbose2();}
        } else {
            *state = DONE;
            if (VERBOSE) {rdh_verbose3();}
        }


   /* Se não, altera o estado para DONE e realiza o término da conexão. */
   } else {
       if (VERBOSE) {rdh_verbose4();}
       *state = DONE;
   }
}

/*  Decrypt DH Key Exchange
    Decifra o pacote de troca Diffie-Hellman utilizando a chave privada do Servidor.
    Recebe por parâmetro a mensagem cifrada e retorna por parâmetro o pacote decifrado.
*/
void Arduino::decryptDHKeyExchange(int *encryptedMessage, DHKeyExchange *dhKeyExchange)
{
    byte* decryptedMessage = iotAuth.decryptRSA(encryptedMessage, rsaStorage->getMyPrivateKey(), sizeof(DHKeyExchange));
    
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

/*  Data Transfer
    Realiza a transferência de dados cifrados para o Servidor.
*/
void Arduino::dt(States *state, int socket, struct sockaddr *server, socklen_t size)
{
    delete rsaStorage;

    char envia[666];
    memset(envia, '\0', sizeof(envia));

    if (VERBOSE) {dt_verbose1();}
    
    /* Captura a mensagem digitada no terminal para a criptografia. */
    fgets(envia, 666, stdin);

    /* Enquanto o usuário não digitar um 'Enter': */
    while (strcmp(envia, "\n") != 0) {

        /* Encripta a mensagem digitada pelo usuário. */
        string encryptedMessage = encryptMessage(envia, sizeof(envia));
        if (VERBOSE) {dt_verbose2(&encryptedMessage);}

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
    int answer = calculateFDRValue(rsaStorage->getMyIV(), rsaStorage->getMyFDR());
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
        key[i] = dhStorage->getSessionKey();
    }

    // uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    uint8_t iv[16];
    for (int i = 0; i < 16; i++) {
        iv[i] = dhStorage->getSessionKey();
    }

    /* Converte o array de char (message) para uint8_t. */
    utils.CharToUint8_t(message, plaintext, size);

    /* Encripta a mensagem utilizando a chave e o iv declarados anteriormente. */
    uint8_t *encrypted = iotAuth.encryptAES(plaintext, key, iv, size);

    string result = utils.Uint8_tToHexString(encrypted, size);

    // delete[] encrypted;

    return result;
}

/*  Setup RSA
    Inicializa os valores pertinentes a troca de chaves RSA: IV, FDR e as próprias chaves RSA.
*/
void Arduino::setupRSA()
{
    rsaStorage = new RSAStorage();

    rsaStorage->setKeyPair(iotAuth.generateRSAKeyPair());
    rsaStorage->setMyIV(iotAuth.generateIV());
    rsaStorage->setMyFDR(iotAuth.generateFDR());
}
