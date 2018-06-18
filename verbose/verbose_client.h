#ifndef VERBOSE_CLIENT_H
#define VERBOSE_CLIENT_H

#include <iostream>
#include <string>
#include "../RSA/RSAStorage.h"
#include "../RSA/RSAKeyExchange.h"
#include "../Diffie-Hellman/DHStorage.h"
#include "../Diffie-Hellman/DiffieHellmanPackage.h"

using namespace std;

void rft_verbose();
void hello_sucessfull_verbose();
void hello_failed_verbose();
void srsa_verbose(RSAStorage *rsaStorage, RSAKeyExchange *rsaKeyExchange);
void rrsa_verbose1(RSAKeyExchange *rsaKeyExchange, RSAStorage *rsaStorage);
void rrsa_verbose2();
void rrsa_verbose3();
void sdh_verbose(DiffieHellmanPackage *dhPackage);
void rdh_verbose1(DHStorage *dhStorage, DiffieHellmanPackage *dhPackage, string *hash);
void rdh_verbose2();
void rdh_verbose3();
void rdh_verbose4();
void dt_verbose1();
void dt_verbose2(string *sent);

#endif