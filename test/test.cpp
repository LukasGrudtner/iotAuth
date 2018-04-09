// #include "../iotAuth.h"
#include "../keyManager.h"
#include <iostream>

// iotAuth iotAuth;
KeyManager KeyManager;

using namespace std;

int main()
{
    // unsigned long long int iv = 11111111;
    // byte *key = (unsigned char*) "1234567891234567";
    // byte plain[] = "Segurança é muito importante para IoT!";
    // byte plain2[48];
    // byte cipher[48];
    //
    // cout << plain << endl;
    // iotAuth.encryptAES(256, 48, key, plain, iv, cipher);
    // cout << cipher << endl;
    //
    // iotAuth.decryptAES(256, 48, key, plain2, iv, cipher);
    // cout << plain2 << endl;

    KeyManager.setSimpleKey(10);
    cout << "Simple Key: " << KeyManager.getSimpleKey() << endl;
}
