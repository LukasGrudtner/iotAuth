#include <SPI.h>         // needed for Arduino versions later than 0018
#include <Ethernet.h>
#include <EthernetUdp.h>         // UDP library from: bjoern@cs.stanford.edu 12/30/2008
#include <math.h>
#include <string.h>
#include "AES.h"
#include "./printf.h"
#include "iotAuth.h"

#define SEPARATOR "#"
#define SEPARATOR_CHAR '#'

#define HELLO_ACK '#'
#define HELLO_MESSAGE "HELLO"

#define DONE_ACK '!'
#define DONE_MESSAGE "DONE"

#define FDR "+1"

#define PUBLIC_KEY_CLIENT 9827
#define PRIVATE_KEY_CLIENT 3786
#define IV 8

#define EXPONENT 2
#define BASE 23
#define MODULUS 86

iotAuth iotAuth;
unsigned long tempo_conexao;

// Enter a MAC address and IP address for your controller below.
byte mac[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED};
// The IP address will be dependent on your local network:
IPAddress ip(150, 162, 63, 156);
IPAddress pc(150, 162, 63, 202);

int localPort = 8888;      // local port to listen on

// buffers for receiving and sending data
char packetBuffer[UDP_TX_PACKET_MAX_SIZE];  //buffer to hold incoming packet,
char  ReplyBuffer[38];//[] = "acknowledged";       // a string to send back
char  temp[38];
String replay;

int a = 2;
int g = 23;
int p = 86;

boolean clientHello = false;
boolean clientDone = false;
boolean receivedRSAKey = false;
boolean receivedDiffieHellmanKey = false;

int publicKeyServer;

int iv = 8;
int simpleKey = 0;
int simpleKeyServer = 0;

// An EthernetUDP instance to let us send and receive packets over UDP
EthernetUDP Udp;

void setup() {
  
  printf_begin();
  // start the Ethernet and UDP:
  Ethernet.begin(mac, ip);
  Udp.begin(localPort);
  Serial.begin(9600);
//  Serial.println("********INICIO TROCA DE CHAVES********\n");/
}

void sendsRSAKey() {
//  Serial.println("************SEND RSA CLIENT***********");  /
  char sendData[32];
  char iv[8];

  sprintf(sendData, "%i", PUBLIC_KEY_CLIENT);
  sprintf(iv, "%i", IV);

  /* Concatena chave pública, # e iv em rsabuf. */
  strcat(sendData, SEPARATOR);
  strcat(sendData, iv);
  strcat(sendData, SEPARATOR);
  strcat(sendData, FDR);
    
  /* Realiza envio da chave. */
  Udp.beginPacket(pc, localPort);
  Udp.write(sendData);
  Udp.endPacket();
//
//  Serial.print("RSA Public Key: ");
//  Serial.println(PUBLIC_KEY_CLIENT);
//  Serial.print("IV: ");
//  Serial.println(IV);
//  Serial.println("**************************************\n");

//  delay(3000);/
}

void receiveRSAKey() {
	
  int packetSize = Udp.parsePacket();

  if (packetSize) {
//    Serial.println("*********RECEIVED RSA SERVER**********"); / 
    Udp.read(packetBuffer, UDP_TX_PACKET_MAX_SIZE);

    /* Remove chave pública do Servidor do buffer. */
    int i = 0;
    char publicKeyServerAux[32];
    while (packetBuffer[i] != SEPARATOR_CHAR) {
      publicKeyServerAux[i] = packetBuffer[i];
      i++;
    }
    i++;
    publicKeyServer = atoi(publicKeyServerAux);
      
    /* Remove iv do buffer. */
    int receivedIv;
    char receivedIvAux[8];
    int j = 0;
    while (packetBuffer[i] != '\0') {
      receivedIvAux[j] = packetBuffer[i];
      j++;
      i++;
    }
    receivedIv = atoi(receivedIvAux);

    
//    Serial.print("RSA Public Key: ");
//    Serial.println(publicKeyServer);
//    Serial.print("IV: ");
//    Serial.println(receivedIv);

    if ((receivedIv-1) == IV){
      //Serial.println("O iv recebido está correto.");
      receivedRSAKey = true;
    }else{
//      Serial.println("O iv recebido está incorreto.");/
      done();
      sendClientDone();
      receiveServerDone();
    } 
    // clear the char arrays for the next receive packet and send
    memset(ReplyBuffer, 0, sizeof(ReplyBuffer));
    memset(packetBuffer, 0, sizeof(packetBuffer));
//    delay(3000);
//    Serial.println("**************************************\n");
  }
}

void sendDiffieHellmanKey() {
  /* Envio da primeira chave. */
//  Serial.println("************SEND DH CLIENT************");  /
  int aux = (int) pow(BASE, EXPONENT);
  int dhKey = aux % MODULUS;
  char base[10];
  char modulus[10];
  char iv[10];
  char sendData[32];

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

  
    
  /* Realiza envio da chave. */
  Udp.beginPacket(pc, localPort);
  Udp.write(sendData);
  Udp.endPacket();
//
//  Serial.print("Diffie-Hellman Key: ");
//  Serial.println(dhKey);
//  Serial.print("g: ");
//  Serial.println(base);
//  Serial.print("p: ");
//  Serial.println(modulus);
//  Serial.print("IV: ");
//  Serial.println(iv);
//  Serial.println("**************************************\n");

//  delay(3000);
}

void receiveDiffieHellmanKey() {
  int packetSize = Udp.parsePacket();
  /* Recebeu chave. */
  if (packetSize) {
//    Serial.println("*********RECEIVED DH SERVER*********");/
    Udp.read(packetBuffer, UDP_TX_PACKET_MAX_SIZE);
  
    /* Recupera chave do Servidor do buffer. */
    int value;
    char valueBuf[32] = {' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' '};

    int i = 0;
    while (packetBuffer[i] != SEPARATOR_CHAR) {
      valueBuf[i] = packetBuffer[i];
      i++;
    }
    i++;

    value = atoi(valueBuf);
    int aux1 = (int) pow(value, a);
    simpleKeyServer = aux1 % p;
//    //simpleKeyServer = value;
//    Serial.print("Diffie-Hellman Key: ");
//    Serial.println(value);

    int aux = (int) pow(value, a);
    simpleKey = aux % p;
      
    /* Remove iv do buffer. */
    int iv_recebidoDH;
    char iv_recebido_stringDH[8];
    int j = 0;
    while (packetBuffer[i] != '\0') {
      iv_recebido_stringDH[j] = packetBuffer[i];
      j++;
      i++;
    }
    iv_recebidoDH = atoi(iv_recebido_stringDH);

    
//    Serial.print("IV: ");
//    Serial.println(iv_recebidoDH);
    
    if ((iv_recebidoDH-1) == iv){
      //Serial.println("O iv recebido está correto.");
      receivedDiffieHellmanKey = true;
    }else{
//      Serial.println("O iv recebido está incorreto.");/
      done();
      sendClientDone();
      receiveServerDone();
    }

    Serial.print("Tempo para estabelecimento da conexão: ");
    Serial.print(micros()-tempo_conexao);
    Serial.println();
    
    // clear the char arrays for the next receive packet and send
    memset(ReplyBuffer, 0, sizeof(ReplyBuffer));
    memset(packetBuffer, 0, sizeof(packetBuffer));

    Serial.println("**************************************\n");
  
    Serial.println("***SYMMETRICAL SESSION CLIENT-SERVER***");
    Serial.print("Session Key: ");
    Serial.println(simpleKeyServer);
//    delay(3000);/
    Serial.println("**************************************\n");
  }
}

void sendClientHello(){
    tempo_conexao = micros ();
    char message[] = HELLO_MESSAGE;
//
//    Serial.println("************HELLO CLIENT**************");
//    Serial.println("Hello Client: Successful");
    Udp.beginPacket(pc, localPort);
    Udp.write(message);
    Udp.endPacket();
//    Serial.println("**************************************\n");/
}

void receiveServerHello(){
    
    int packetSize = Udp.parsePacket();

    if (packetSize) {
//      Serial.println("************HELLO SERVER**************");/
      Udp.read(packetBuffer, UDP_TX_PACKET_MAX_SIZE);
      char recebido[32];
      if (packetBuffer[0] == HELLO_ACK){
//        Serial.println("Server Client: Successful");/
        clientHello = true;
        clientDone = false;
      }
//      Serial.println("**************************************\n");/
    }
        // clear the char arrays for the next receive packet and send
    memset(ReplyBuffer, 0, sizeof(ReplyBuffer));
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
//  Serial.println("**************************************\n");/
}

void receiveServerDone() {
  int packetSize = Udp.parsePacket();

  if (packetSize) {
//    Serial.println("**************DONE SERVER****************");/
    Udp.read(packetBuffer, UDP_TX_PACKET_MAX_SIZE);
    if (packetBuffer[0] == DONE_ACK) {
//      Serial.println("Server Client: Successful");/
      clientDone = true;
    }
//    Serial.println("**************************************\n");/
  }
         // clear the char arrays for the next receive packet and send
    memset(ReplyBuffer, 0, sizeof(ReplyBuffer));
    memset(packetBuffer, 0, sizeof(packetBuffer));
}

void loop() {

  if(!clientHello){
    sendClientHello();
//    Serial.println("--------Esperando Hello Server--------\n");/
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
    uint8_t key[16];
    uint8_t iv[16];
    int j;
    for (j = 0; j < 16; j++) {
      key[j] = simpleKey;
      iv[j] = j+1;
    }
    
    const uint16_t data_len = 16;
    
    char *key21 = (unsigned char*)"1234567891234567";
    char plain1[] = "Segurança é muito importante para IoT!";
//    unsigned long long int my_iv = iv;
    unsigned long long int my_iv = 11111111;
    char cipher[64];
    memset(cipher, 0, sizeof(cipher));
    
        /* Encripta e envia os dados para o server */
    iotAuth.encryptAES(256, 41, key21, plain1, my_iv, cipher);//
    Udp.beginPacket(pc, localPort);
    Udp.write(cipher);
    Udp.endPacket();

    Serial.print("Enviado: ");
    Serial.println(cipher);
//    for (int i = 0; i < 64; i++) {
//      Serial.print(cipher[i]);
//    }
//    Serial.println();

    char plain2[64];
    iotAuth.decryptAES(256, 41, key21, plain2, my_iv, cipher);
    Serial.print("Decifrado: ");
    Serial.println(plain2);

    delay(5000);
    Serial.println("**************************************\n");
  }
}
