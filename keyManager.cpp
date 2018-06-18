#include "keyManager.h"

/*  KeyManager()
    Construtor, inicializa o atributo FDR do objeto.
*/
KeyManager::KeyManager()
{

}

/*  getDiffieHellmanKey()
    Calcula a retorna o valor da chave Diffie-Hellman utilizando o atributo
    'base' armazenado no objeto.
*/
int KeyManager::getDiffieHellmanKey()
{
    int r = pow(base, exponent);
    return r % modulus;
}

/*  getDiffieHellmanKey()
    Calcula a retorna o valor da chave Diffie-Hellman utilizando o atributo
    'base' recebido por parâmetro.
*/
int KeyManager::getDiffieHellmanKey(int base)
{
    int r = pow(base, exponent);
    return r % modulus;
}

/*  getServerPublicKey()
    Retorna a chave pública do servidor armazenada no objeto.
*/
RSAKey* KeyManager::getMyPublicKey()
{
    return &rsaKeys.publicKey;
}

/*  getServerPrivateKey()
    Retorna a chave privada do servidor armazenada no objeto.
*/
RSAKey* KeyManager::getMyPrivateKey()
{
    return &rsaKeys.privateKey;
}

/*  getClientPublicKey()
    Retorna a chave pública do cliente armazenada no objeto.
*/
RSAKey* KeyManager::getPartnerPublicKey()
{
    return &partnerPublicKey;
}

/*  setClientPublicKey()
    Armazena a chave pública do cliente no objeto.
*/
void KeyManager::setPartnerPublicKey(RSAKey publicKey)
{
    partnerPublicKey = publicKey;
}

/*  setSessionKey()
    Armazena a chave de sessão (chave secreta) no objeto.
*/
void KeyManager::setSessionKey(int _sessionKey)
{
    sessionKey = _sessionKey;
}

/*  getSessionKey()
    Retorna a chave de sessão (chave secreta) armazenada no objeto.
*/
int KeyManager::getSessionKey()
{
    return sessionKey;
}

/*  setBase()
    Armazena o valor do atributo 'base' para o cálculo da chave Diffie-Hellman.
*/
void KeyManager::setBase(int _base)
{
    base = _base;
}

/*  setModulus()
    Armazena o valor do atributo 'módulo' para o cálculo da chave Diffie-Hellman.
*/
void KeyManager::setModulus(int _modulus)
{
    modulus = _modulus;
}

/*  getIV()
    Retorna o valor do atributo 'IV' armazenado no objeto.
*/
int KeyManager::getMyIV()
{
    return myIV;
}

/*  getFDR()
    Retorna o valor do atributo 'FDR' armazenado no objeto.
*/
FDR* KeyManager::getMyFDR()
{
    return &myFdr;
}

/*  setFDR()
    Armazena o valor do atributo 'FDR' no objeto.
*/
void KeyManager::setMyFDR(FDR _fdr)
{
    myFdr = _fdr;
}

/*  Armazena o par de chaves RSA */
void KeyManager::setRSAKeyPair(RSAKeyPair keys)
{
    rsaKeys = keys;
}

/* Retorna a base utlizada no cálculo do Diffie-Hellman. */
int KeyManager::getBase()
{
    return base;
}

/* Retorna o módulo utilizado no cálculo do Diffie-Hellman. */
int KeyManager::getModulus()
{
    return modulus;
}

/* Seta o expoente. */
void KeyManager::setExponent(int _exponent)
{
    exponent = _exponent;
}

int KeyManager::getExponent()
{
    return exponent;
}

/*  setMyIV()
    Armazena o valor do atributo 'IV' da entidade no objeto.
*/
void KeyManager::setMyIV(int _myIV)
{
    myIV = _myIV;
}
