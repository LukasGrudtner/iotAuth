#ifndef ARDUINO_H
#define ARDUINO_H

#include "iotAuth.h"
#include "keyManager.h"
#include "stringHandler.h"
#include "settings.h"
#include "utils.h"

using namespace std;

class Arduino
{
    public:

        int a = 2;
        int g = 23;
        int p = 86;
        long int iv = 7;
        string fdr = "+1";

        bool clientHello = false;
        bool clientDone = false;
        bool receivedRSAKey = false;
        bool receivedDHKey = false;

        char* sendClientHello();
        char* sendClientDone();
        bool receiveServerHello(char buffer[]);
        bool receiveServerDone(char buffer[]);

        char* sendRSAKey();
        void receiveRSAKey(char message[]);

        char* sendDiffieHellmanKey();
        void receiveDiffieHellmanKey(char message[]);

    private:

        IotAuth iotAuth;
        KeyManager keyManager;
        StringHandler stringHandler;
        Utils utils;

        string getHashEncrypted(string package);
        string getPackage(string package);
        void done();
};

#endif
