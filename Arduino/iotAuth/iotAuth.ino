#include <SPI.h>         // needed for Arduino versions later than 0018
#include <Ethernet.h>
#include <EthernetUdp.h>         // UDP library from: bjoern@cs.stanford.edu 12/30/2008
#include <math.h>
#include <string.h>
#include "AES.h"
#include "./printf.h"
#include "iotAuth.h"
#include "keyManager.h"
#include "stringHandler.h"

#define SEPARATOR "#"
#define SEPARATOR_CHAR '#'

#define FDR "+1"
#define IV 8

#define EXPONENT 2
#define BASE 23
#define MODULUS 86

iotAuth iotAuth;
//unsigned long tempo_conexao;/
KeyManager keyManager;
StringHandler stringHandler;

// Enter a MAC address and IP address for your controller below.
byte mac[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED};
// The IP address will be dependent on your local network:
IPAddress ip(150, 162, 63, 205);
IPAddress pc(150, 162, 63, 204);

int localPort = 8080;      // local port to listen on

// buffers for receiving and sending data
char packetBuffer[UDP_TX_PACKET_MAX_SIZE];  //buffer to hold incoming packet,

#define a 2
#define g 23
#define p 86

boolean clientHello = false;
boolean clientDone = false;
boolean receivedRSAKey = false;
boolean receivedDiffieHellmanKey = false;

// An EthernetUDP instance to let us send and receive packets over UDP
EthernetUDP Udp;

void setup() {
  
  printf_begin();
  // start the Ethernet and UDP:
  Ethernet.begin(mac, ip);
  Udp.begin(localPort);
  Serial.begin(9600);
  Serial.println("********INICIO TROCA DE CHAVES********\n");
}

void sendsRSAKey() {
  keyManager.setRSAKeyPair(iotAuth.generateRSAKeyPair());
  Serial.print("Chave: ");
  Serial.println(keyManager.getClientPublicKeyD());
  
  Serial.println("************SEND RSA CLIENT***********"); 
  char sendData[32];
  char cPublicKeyN[8];
  char iv[8];
  memset(sendData, 0, sizeof(sendData));

  sprintf(sendData, "%li", keyManager.getClientPublicKeyD());
  sprintf(cPublicKeyN, "%li", keyManager.getClientPublicKeyN());
  sprintf(iv, "%i", IV);

  /* Concatena chave pública, # e iv em rsabuf. */
  strcat(sendData, SEPARATOR);
  strcat(sendData, cPublicKeyN);
  strcat(sendData, SEPARATOR);
  strcat(sendData, "0"); // answerFDR, não utilizado neste passo
  strcat(sendData, iv);
  strcat(sendData, SEPARATOR);
  strcat(sendData, FDR);
    
  /* Realiza envio da chave. */
  Udp.beginPacket(pc, localPort);
  Udp.write(sendData);
  Udp.endPacket();

//  Serial.print("Sent: ");
//  Serial.println(sendData);
//  Serial.print("RSA Client Public Key: (");
//  Serial.print(keyManager.getClientPublicKeyD());    Serial.print(", ");
//  Serial.print(keyManager.getClientPublicKeyN());   Serial.println(")");
//  Serial.print("IV: ");
//  Serial.println(IV);
  Serial.println("**************************************\n");

  delay(3000);
}

void receiveRSAKey() {
	
  int packetSize = Udp.parsePacket();

  if (packetSize) {
    Serial.println("*********RECEIVED RSA SERVER**********"); 
    memset(packetBuffer, 0, sizeof(packetBuffer));
    Udp.read(packetBuffer, UDP_TX_PACKET_MAX_SIZE);

    Serial.print("RECEBIDO: ");
    Serial.println(packetBuffer);

    /* Remove chave pública (D) do Servidor do buffer. */
    int i = 0;
    char publicKeyServerAuxD[8];
    memset(publicKeyServerAuxD, 0, sizeof(publicKeyServerAuxD));
    while (packetBuffer[i] != SEPARATOR_CHAR) {
      publicKeyServerAuxD[i] = packetBuffer[i];
      i++;
    }
    i++;

    int publicKeyServerD = atol(publicKeyServerAuxD);

    /***************************************************/

    /* Remove chave pública (N) do Servidor do buffer. */
    
    int j = 0;
    char publicKeyServerAuxN[8];
    memset(publicKeyServerAuxN, 0, sizeof(publicKeyServerAuxN));
    while (packetBuffer[i] != SEPARATOR_CHAR) {
      publicKeyServerAuxN[j] = packetBuffer[i];
      j++;
      i++;
    }
    i++;

    int publicKeyServerN = atol(publicKeyServerAuxN);

    /***************************************************/
      
    /* Remove iv do buffer. */
    int receivedIv;
    char receivedIvAux[8];
    int k = 0;

    while (packetBuffer[i] != '\0') {
      receivedIvAux[k] = packetBuffer[i];
      k++;
      i++;
    }
    receivedIv = atoi(receivedIvAux);

    /***************************************************/
    /* Seta a chave do servidor no keyManager em forma de struct */

    PublicRSAKey publicKeyServer = {publicKeyServerD, publicKeyServerN};
    keyManager.setServerPublicKey(publicKeyServer);

    /***************************************************/
    
    Serial.print("RSA Server Public Key: (");
    Serial.print(keyManager.getServerPublicKeyD());    Serial.print(", ");
    Serial.print(keyManager.getServerPublicKeyN());   Serial.println(")");
    Serial.print("IV: ");
    Serial.println(receivedIv);

    /***************************************************/

    if ((receivedIv-1) == IV){
      //Serial.println("O iv recebido está correto.");
      receivedRSAKey = true;
    } else{
      Serial.println("O iv recebido está incorreto.");
      done();
      sendClientDone();
      receiveServerDone();
    } 

    /***************************************************/
    // clear the char arrays for the next receive packet and send
    memset(packetBuffer, 0, sizeof(packetBuffer));
    delay(3000);
    Serial.println("**************************************\n");
  }
}

void sendDiffieHellmanKey() {
  /* Envio da primeira chave. */
  Serial.println("************SEND DH CLIENT************");  
  byte aux = (int) pow(BASE, EXPONENT);
  byte dhKey = aux % MODULUS;
  char base[2];
  char modulus[2];
  char iv[2];
  char sendData[134];

  /* Passa os valores p, g e iv para string. */  
  sprintf(base, "%i", BASE);
  sprintf(modulus, "%i", MODULUS);
  sprintf(iv, "%i", IV);
    
  sprintf(sendData, "%i", dhKey);

  /* Concatena p, g e iv no buffer. */
  strcat(sendData, SEPARATOR);
  strcat(sendData, base);
  strcat(sendData, SEPARATOR);
  strcat(sendData, modulus);
  strcat(sendData, SEPARATOR);
  strcat(sendData, iv);
//  char hash[128];
//  iotAuth.hash(sendData, hash);
//
//  Serial.print("Hash: ");
//  Serial.println(hash);

  

  
    
  /* Realiza envio da chave. */
  Udp.beginPacket(pc, localPort);
  Udp.write(sendData);
  Udp.endPacket();

//  Serial.print("Diffie-Hellman Key: ");
//  Serial.println(dhKey);
//  Serial.print("g: ");
//  Serial.println(base);
//  Serial.print("p: ");
//  Serial.println(modulus);
//  Serial.print("IV: ");
//  Serial.println(iv);
//  Serial.println("**************************************\n");

  delay(3000);
}

void receiveDiffieHellmanKey() {
  int packetSize = Udp.parsePacket();
  /* Recebeu chave. */
  if (packetSize) {
//    Serial.println("*********RECEIVED DH SERVER*********");/
    Udp.read(packetBuffer, UDP_TX_PACKET_MAX_SIZE);
  
    /* Recupera chave do Servidor do buffer. */
    char B_aux[8];
    memset(B_aux, 0, sizeof(B_aux));

    byte i = 0;
    while (packetBuffer[i] != SEPARATOR_CHAR) {
      B_aux[i] = packetBuffer[i];
      i++;
    }
    i++;

    byte B = atoi(B_aux);
    
    byte pot = (int) pow(B, a);
    byte simpleKeyServer = pot % p;

    Serial.print("Session Key: ");
    Serial.println(simpleKeyServer);
      
//    /* Remove iv do buffer. */
//    int iv_recebidoDH;
//    char iv_recebido_stringDH[8];
//    int j = 0;
//    i = 0;
//    int cont = 0;
//    while (packetBuffer[i] != '\0') {
//      if (packetBuffer[i] == SEPARATOR_CHAR)
//        cont++;
//      i++;
//      if (cont == 4)
//        break;
//    }
//    
//    while (packetBuffer[i] != '\0') {
//      iv_recebido_stringDH[j] = packetBuffer[i];
//      j++;
//      i++;
//    }
//    
//    iv_recebidoDH = atoi(iv_recebido_stringDH);
//
//    
//    Serial.print("IV: ");
//    Serial.println(iv_recebidoDH);
//    
//    if ((iv_recebidoDH-1) == IV){
//      //Serial.println("O iv recebido está correto.");
//      receivedDiffieHellmanKey = true;
//    }else{
//      Serial.println("O iv recebido est/á incorreto.");
//      done();
//      sendClientDone();
//      receiveServerDone();
//    }

//    Serial.print("Tempo para estabelecimento da conexão: ");/
//    Serial.print(micros()-tempo_conexao);/
//    Serial.println();/
    
    // clear the char arrays for the next receive packet and send
    memset(packetBuffer, 0, sizeof(packetBuffer));

//    Serial.println("**************************************\n");
//  
//    Serial.println("***SYMMETRICAL SESSION CLIENT-SERVER***");
//    Serial.print("Session Key: ");
//    Serial.println(simpleKeyServer);
    delay(3000);
//    Serial.println("**************************************\n");
  }
}

void sendClientHello(){
//    tempo_conexao = micros ();/
    char message[] = HELLO_MESSAGE;

//    Serial.println("************HELLO CLIENT**************");
//    Serial.println("Hello Client: Successful");
    Udp.beginPacket(pc, localPort);
    Udp.write(message);
    Udp.endPacket();
    Serial.println("**************************************\n");
}

void receiveServerHello(){
    
    int packetSize = Udp.parsePacket();

    if (packetSize) {
      Serial.println("************HELLO SERVER**************");
      Udp.read(packetBuffer, UDP_TX_PACKET_MAX_SIZE);
      char recebido[8];
      if (packetBuffer[0] == HELLO_ACK_CHAR){
        Serial.println("Server Client: Successful");
        clientHello = true;
        clientDone = false;
      }
      Serial.println("**************************************\n");
    }
        // clear the char arrays for the next receive packet and send
    memset(packetBuffer, 0, sizeof(packetBuffer));
}



void done() {
  clientHello = false;
  receivedRSAKey = false;
  receivedDiffieHellmanKey = false;
}

void sendClientDone() {
  char message[] = DONE_MESSAGE;
//  Serial.println("**************DONE CLIENT****************");
//  Serial.println("Done Client: Successful");
  Udp.beginPacket(pc, localPort);
  Udp.write(message);
  Udp.endPacket();
  Serial.println("**************************************\n");
}

void receiveServerDone() {
  int packetSize = Udp.parsePacket();

  if (packetSize) {
    Serial.println("**************DONE SERVER****************");
    Udp.read(packetBuffer, UDP_TX_PACKET_MAX_SIZE);
    if (packetBuffer[0] == DONE_ACK_CHAR) {
      Serial.println("Server Client: Successful");
      clientDone = true;
    }
    Serial.println("**************************************\n");
  }
         // clear the char arrays for the next receive packet and send
    memset(packetBuffer, 0, sizeof(packetBuffer));
}

void loop() {


  if(!clientHello){
    sendClientHello();
    Serial.println("--------Esperando Hello Server--------\n");
    while(clientHello!=true){
      receiveServerHello();
    }
  }

  /* Realiza a troca de chaves RSA. */
  if (clientHello && !receivedRSAKey) {
    sendsRSAKey();
    while(!receivedRSAKey && !clientDone){
      receiveRSAKey();
    }
  }

  /* Realiza a troca de chaves Diffie-Hellman sem criptografia. */
  if (receivedRSAKey && !receivedDiffieHellmanKey) {
    sendDiffieHellmanKey();
    while(!receivedDiffieHellmanKey && !clientDone){
      receiveDiffieHellmanKey();
    }
  }
  
  /* Com as chaves trocadas, inicia a troca de dados. */
  if (receivedRSAKey && receivedDiffieHellmanKey) {

    char message[] = "hello";
    byte plain[64];
    memset(plain, '0', sizeof(plain));
    
    for (int i = 0; i < sizeof(message); i++) {
      plain[i] = message[i];
    }
    
    char hex[128];
    memset(hex, 0, sizeof(hex));
    iotAuth.encryptHEX(plain, sizeof(plain), hex, sizeof(hex));
    
    Serial.print("Encriptado: ");
    Serial.println(hex);

    Udp.beginPacket(pc, localPort);
    Udp.write(hex); // envia em hexa//
    Udp.endPacket();

    delay(5000);
    Serial.println("**************************************\n");
  }
}
