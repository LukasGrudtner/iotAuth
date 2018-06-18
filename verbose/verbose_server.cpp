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

void rrsa_verbose(RSAStorage *rsaStorage)
{
        cout << "******RECEIVED CLIENT RSA KEY******" << endl;
        cout << "Generated RSA Key: {("     << rsaStorage->getMyPublicKey()->d       << ", "
                                            << rsaStorage->getMyPublicKey()->n       << "), ";
        cout << "("                         << rsaStorage->getMyPrivateKey()->d      << ", "
                                            << rsaStorage->getMyPrivateKey()->n      << ")}" << endl;
        cout << "My IV: "                   << rsaStorage->getMyIV()                << endl;
        cout << "My FDR: "                  << rsaStorage->getMyFDR()->toString()       << endl << endl;
        cout << "Client RSA Public Key: ("  << rsaStorage->getPartnerPublicKey()->d  << ", "
                                            << rsaStorage->getPartnerPublicKey()->n  << ")" << endl;
        cout << "***********************************\n" << endl;
}

void srsa_verbose(RSAKeyExchange *rsaKeyExchange)
{
        cout << "*******SENT SERVER RSA KEY*********" << endl;
        cout << "Server RSA Public Key: ("      << rsaKeyExchange->getPublicKey().d
                                        << ", " << rsaKeyExchange->getPublicKey().n << ")" << endl;
        cout << "Answer FDR (Client): "         << rsaKeyExchange->getAnswerFDR() << endl;
        cout << "My IV: "                       << rsaKeyExchange->getIV() << endl;
        cout << "My FDR: "                      << rsaKeyExchange->getFDR().toString() << endl;
        cout << "Sent: "                        << rsaKeyExchange->toString() << endl;
        cout << "***********************************\n" << endl;
}

void rdh_verbose1(DHStorage *dhStorage, DiffieHellmanPackage *dhPackage, string *hash)
{
        cout << "\n*******CLIENT DH KEY RECEIVED******" << endl;
        cout << "Hash is valid!" << endl << endl;  

        cout << "Client Decrypted HASH: "   << *hash                    << endl << endl;
        cout << "Diffie-Hellman Key: "      << dhPackage->getResult()           << endl;
        cout << "Base: "                    << dhPackage->getBase()             << endl;
        cout << "Modulus: "                 << dhPackage->getModulus()          << endl;
        cout << "Client IV: "               << dhStorage->getPartnerIV()        << endl;
        cout << "Session Key: "             << dhStorage->getSessionKey()       << endl;
        cout << "Answer FDR: "              << dhStorage->getAnswerFDR()        << endl;
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
        cout << "Hash is invalid!" << endl << endl;
}

void sdh_verbose(DiffieHellmanPackage *dhPackage)
{
        cout << "*********SEND SERVER DH KEY********" << endl;
        cout << "Server Package: "  << dhPackage->toString()    << endl;
        cout << "***********************************\n" << endl;
}