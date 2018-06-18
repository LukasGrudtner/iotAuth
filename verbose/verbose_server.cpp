#include "verbose_server.h"

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

void rrsa_verbose(RSAKeyExchange *rsaKeyExchange, RSAStorage *rsaStorage)
{
        cout << "******RSA | RECEIVE FROM CLIENT******" << endl;
        cout << "Generated RSA Key: {(" << rsaStorage->getMyPublicKey()->d      << ", "
                                        << rsaStorage->getMyPublicKey()->n      << "), ";
        cout << "("                     << rsaStorage->getMyPrivateKey()->d     << ", "
                                        << rsaStorage->getMyPrivateKey()->n     << ")}" << endl;
        cout << "My IV: "               << rsaStorage->getMyIV()                << endl;
        cout << "My FDR: "              << rsaStorage->getMyFDR()->toString()   << endl;
        cout << "Received: "            << rsaKeyExchange->toString()           << endl;    
        cout << "***********************************\n" << endl;
}

void srsa_verbose(RSAKeyExchange *rsaKeyExchange)
{
        cout << "*******RSA | SEND TO CLIENT*********" << endl;
        cout << "Server RSA Public Key: ("      << rsaKeyExchange->getPublicKey().d
                                        << ", " << rsaKeyExchange->getPublicKey().n << ")" << endl;
        cout << "Answer Client's FDR: "         << rsaKeyExchange->getAnswerFDR() << endl;
        cout << "Sent: "                        << rsaKeyExchange->toString() << endl;
        cout << "***********************************\n" << endl;
}

void rdh_verbose1(DHStorage *dhStorage, DiffieHellmanPackage *dhPackage, string *hash)
{
        cout << "\n*******DH | RECEIVE FROM CLIENT******" << endl;
        cout << "THE HASH IS VALID!"            << endl                     << endl;
        cout << "Client Decrypted HASH: "       << *hash                    << endl << endl;
        cout << "Result: "                      << dhPackage->getResult()           << endl;
        cout << "Base: "                        << dhPackage->getBase()             << endl;
        cout << "Modulus: "                     << dhPackage->getModulus()          << endl;
        cout << "Client IV: "                   << dhStorage->getPartnerIV()        << endl;
        cout << "Session Key: "                 << dhStorage->getSessionKey()       << endl;
        cout << "Received Answer: "             << dhStorage->getAnswerFDR()        << endl;
}

void rdh_verbose2()
{
        cout << "Answered FDR ACCEPTED!"                    << endl;
        cout << "**************************************\n"  << endl;
}

void rdh_verbose3()
{
        cout << "Answered FDR REJECTED!"                    << endl;
        cout << "ENDING CONECTION..."                       << endl;
        cout << "**************************************\n"  << endl;
}

void rdh_verbose4()
{
        cout << "THE HASH IS INVALID!" << endl << endl;
}

void sdh_verbose(DiffieHellmanPackage *dhPackage)
{
        cout << "*********DH | SEND TO CLIENT********"                   << endl;
        cout << "Result: "              << dhPackage->getResult()       << endl;
        cout << "My IV: "               << dhPackage->getIV()           << endl;
        cout << "Answer Client's FDR: " << dhPackage->getAnswerFDR()    << endl;
        cout << "Server Package: "      << dhPackage->toString()        << endl;
        cout << "***********************************\n" << endl;
}