#include "verbose_client.h"

void rft_verbose()
{
    cout << "\n*******DONE CLIENT AND SERVER******"   << endl;
    cout << "Done Client and Server Successful!"      << endl;
    cout << "***********************************\n"   << endl;
}

void hello_sucessfull_verbose()
{
    cout << "******HELLO CLIENT AND SERVER******"     << endl;
    cout << "Hello Client and Server Successful!"     << endl;
    cout << "***********************************\n"   << endl; 
}

void hello_failed_verbose()
{
    cout << "\n******HELLO CLIENT AND SERVER******"   << endl;
    cout << "Hello Client and Server failed!"         << endl;
    cout << "***********************************\n"   << endl;
}

void srsa_verbose(RSAStorage *rsaStorage, RSAKeyExchange *rsaKeyExchange)
{
    cout << "************SEND RSA CLIENT***********" << endl;
    cout << "Generated RSA Key: {(" << rsaStorage->getMyPublicKey()->d
         << ", " << rsaStorage->getMyPublicKey()->n << "), ("
         << rsaStorage->getMyPrivateKey()->d << ", "
         << rsaStorage->getMyPrivateKey()->n << ")}" << endl;
    cout << "My IV: " << rsaStorage->getMyIV() << endl;
    cout << "My FDR: " << rsaStorage->getMyFDR()->toString() << endl;
    cout << "Sent: " << rsaKeyExchange->toString() << endl;
    cout << "**************************************\n" << endl;
}

void rrsa_verbose1(RSAKeyExchange *rsaKeyExchange, RSAStorage *rsaStorage)
{
    cout << "*********RECEIVED RSA SERVER**********" << endl;
    cout << "Received: " << rsaKeyExchange->toString() << endl;
    cout << "RSA Server Public Key: (" << rsaKeyExchange->getPublicKey().d <<
            ", " << rsaKeyExchange->getPublicKey().n << ")" << endl;
    cout << "Answered FDR: " << rsaKeyExchange->getAnswerFDR() << endl;
    cout << "Server IV: " << rsaStorage->getPartnerIV() << endl;
    cout << "Server FDR: " << rsaStorage->getPartnerFDR()->getOperator() 
         << rsaStorage->getPartnerFDR()->getOperand() << endl;
}

void rrsa_verbose2()
{
    cout << "Answered FDR ACCEPTED!" << endl;
    cout << "**************************************\n" << endl;
}

void rrsa_verbose3()
{
    cout << "Answered FDR REJECTED!" << endl;
    cout << "ENDING CONECTION..." << endl;
    cout << "**************************************\n" << endl;
}

void sdh_verbose(DiffieHellmanPackage *dhPackage)
{
    cout << "************SEND DH CLIENT************" << endl;
    cout << "Client Package: " << dhPackage->toString() << endl;
    cout << "**************************************" << endl << endl;
}

void rdh_verbose1(DiffieHellmanPackage *dhPackage, DHStorage *dhStorage)
{
    cout << "\n*******SERVER DH KEY RECEIVED******" << endl;
    cout << "Hash is valid!" << endl << endl;

    cout << "Diffie-Hellman Key: "      << dhPackage->getResult()       << endl;
    cout << "Base: "                    << dhPackage->getBase()         << endl;
    cout << "Modulus: "                 << dhPackage->getModulus()      << endl;
    cout << "Session Key: "             << dhStorage->getSessionKey()   << endl;
    cout << "Answered FDR: "            << dhPackage->getAnswerFDR()    << endl;
    cout << "***********************************\n"                     << endl;
}

void rdh_verbose2()
{
    cout << "Hash is invalid!" << endl << endl;
}

void dt_verbose1()
{
    cout << "Envio de dados criptografados com AES." << endl << endl;
    cout << "########## Escreva uma mensagem para o servidor ##########" << endl;
    cout << "------------- Linha em branco para finalizar -------------" << endl;
}

void dt_verbose2(string *sent)
{
    cout << "Sent" << endl << *sent << endl << endl;
}