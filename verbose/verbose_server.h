#ifndef VERBOSE_SERVER_H
#define VERBOSE_SERVER_H

#include <iostream>
#include <string>
#include "../RSA/RSAStorage.h"
#include "../Diffie-Hellman/DHStorage.h"
#include "../Diffie-Hellman/DiffieHellmanPackage.h"
#include "../RSA/RSAKeyExchange.h"

using namespace std;

void rft_verbose();
void hello_sucessfull_verbose();
void hello_failed_verbose();
void rrsa_verbose(RSAStorage *rsaStorage);
void srsa_verbose(RSAKeyExchange *rsaKeyExchange);
void rdh_verbose1(DHStorage *dhStorage, DiffieHellmanPackage *dhPackage, string *hash);
void rdh_verbose2();
void rdh_verbose3();
void rdh_verbose4();
void sdh_verbose(DiffieHellmanPackage *dhPackage);

#endif