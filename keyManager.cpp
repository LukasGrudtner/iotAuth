#include "keyManager.h"

/*  KeyManager()
    Construtor, inicializa o atributo FDR do objeto.
*/
KeyManager::KeyManager()
{
    fdr = new FDR();
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
int KeyManager::getServerPublicKey()
{
    return serverPublicKey;
}

/*  getServerPrivateKey()
    Retorna a chave privada do servidor armazenada no objeto.
*/
int KeyManager::getServerPrivateKey()
{
    return serverPrivateKey;
}

/*  getClientPublicKey()
    Retorna a chave pública do cliente armazenada no objeto.
*/
int KeyManager::getClientPublicKey()
{
    return clientPublicKey;
}

/*  setClientPublicKey()
    Armazena a chave pública do cliente no objeto.
*/
void KeyManager::setClientPublicKey(int _clientPublicKey)
{
    clientPublicKey = _clientPublicKey;
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
int KeyManager::getIV()
{
    return iv;
}

/*  setIV()
    Armazena o valor do atributo 'IV' no objeto.
*/
void KeyManager::setIV(int _iv)
{
    iv = _iv;
}

/*  getFDR()
    Retorna o valor do atributo 'FDR' armazenado no objeto.
*/
FDR* KeyManager::getFDR()
{
    return fdr;
}

/*  setFDR()
    Armazena o valor do atributo 'FDR' no objeto.
*/
void KeyManager::setFDR(FDR* _fdr)
{
    fdr = _fdr;
}
