/**
* ESP8266 based power meter M-Bus to mqtt gateway
* - Tobias Ecker OE3TEC 2022
* - Matthias Preymann PreyMa 2022
* 
* project url: https://github.com/Tobias0110/EVN_Kaifa_ESP_MQTT
**/

/**
* Building the project using the Arduino IDE
* - Install the ESP-Module as a compilation target
*   - Add board config repository: File --> Preferences --> Paste URL into "Additional boards manager URLs": http://arduino.esp8266.com/stable/package_esp8266com_index.json
*   - Install the toolchain: Tools --> Boards Manager --> Install: esp8266
*   - Select the specific ESP module: Tools --> Board --> ESP2866 Boards --> NodeMCU 1.0 (ESP-12E Modul)
* - Click verify to check if the project buildes without errors
* - Connect the ESP module and click upload like for any other Arduino-like micro controller
* 
* Resources:
* M-Bus Specification (version "late 90s"):
* - https://m-bus.com/assets/downloads/MBDOC48.PDF
* 
* Smart meter customer data port description (Multiple Austrian energy companies):
* - https://www.netz-noe.at/Download-(1)/Smart-Meter/218_9_SmartMeter_Kundenschnittstelle_lektoriert_14.aspx
* - https://stadtwerkeschwaz.at/pdfs/Technische%20Beschreibung%20Kundenschnittstelle%20SWS%20Smart%20Meter.pdf
* - https://www.salzburgnetz.at/content/dam/salzburgnetz/dokumente/stromnetz/Technische-Beschreibung-Kundenschnittstelle.pdf
* - https://www.tinetz.at/infobereich/smart-meter/anleitungen-fragen-antworten/?no_cache=1&tx_bh_page%5Baction%5D=download&tx_bh_page%5Bcontroller%5D=File&tx_bh_page%5Bfile%5D=101&cHash=7b38017b8f4066394c0f5119ee1ae342
* 
* Python implementation of a DLMS to XML converter:
* - https://github.com/Gurux/Gurux.DLMS.Python/
**/

#ifndef ARDUINO
#include <iostream>
#include <string>
#include <iomanip>
#include <cassert>

#include "Crypto-0.4.0/src/Crypto.h"
#include "Crypto-0.4.0/src/AES.h"
#include "Crypto-0.4.0/src/GCM.h"

#else 

/**
* Dependencies:
* - ESP8266 Arduino support (Arduino team - GNU LGPL v2.1): https://github.com/esp8266/Arduino
* - Crypto: (Rhys Weatherley - MIT) https://rweather.github.io/arduinolibs/crypto.html
* - PubSubClient: (Nicholas O'Leary - MIT) https://pubsubclient.knolleary.net/
**/

#include <ESP8266WiFi.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <EEPROM.h>
#include <Arduino.h>
#include <Crypto.h>
#include <AES.h>
#include <GCM.h>

#endif


using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;
using i8 = int8_t;
using i16 = int16_t;
using i32 = int32_t;
using i64 = int64_t;

char ssid[33], password[64], MQTT_BROKER[21], mqtt_user[21], mqtt_password[21], clientId[21], mqtt_path[101];
int MQTT_PORT = 1883;

// contains encrypted data
uint8_t for_tx[282];

// for user inputs during setup
char input[101];

// for decryption
uint8_t key[16];
uint8_t authdata[1] = {0x30}; //aad (is 0x30 wen there is no auth key)
uint8_t iv[12]; //for clients system title (8 byte) + frame counter (4 byte)
size_t authsize = 1;
size_t ivsize = 12;
// contains encrypted data at the beginning and decrypted data after decryption
byte buffer[254];

WiFiClient espClient;
PubSubClient client(espClient);
//Decryption setup
GCM <AES128> *gcm=0;

void create_iv()
{
  for(uint8_t i = 0; i < 8; i++)
  {
    //System Title
    iv[i] = for_tx[i+11];
  }
  for(uint8_t i = 0; i < 4; i++)
  {
    //frame counter
    iv[i+8] = for_tx[i+22];
  }
}

void decrypt(AuthenticatedCipher *cipher, size_t datasize){
    size_t posn, len;
    uint8_t tag[16];
    
    cipher->clear();
    cipher->setKey(key, cipher->keySize());
    cipher->setIV(iv, ivsize);
    for (posn = 0; posn < authsize; posn += datasize) {
        len = authsize - posn;
        if (len > datasize)
            len = datasize;
        cipher->addAuthData(authdata + posn, len);
    }

    for (posn = 0; posn < datasize; posn += datasize) {
        len = datasize - posn;
        if (len > datasize)
            len = datasize;
        cipher->decrypt((uint8_t*)buffer + posn, buffer + posn, len);
    }

    /*Serial.print("\nOutput: ");
    for(uint16_t i=0; i<254;i++) Serial.printf("%c",(char)buffer[i]);
    Serial.println();*/

}

void flush_serial()
{
  while (Serial.available() > 0)
    {
      char k = Serial.read();
    }
}

void read_input(uint8_t max)
{
  char one[1];
  uint8_t cnt = 0;
  do
  {
    Serial.readBytes(one, 1);
    Serial.write(one[0]);
    input[cnt] = one[0];
    cnt++;
   }
   while((one[0] != 0x0d) && (cnt < max));
   if (cnt >= max) input[cnt] = 0;
   else input[cnt-1] = 0;
}

long stringToLong(String s)
{
    char arr[33];
    s.toCharArray(arr, sizeof(arr));
    return atol(arr);
}

void load_settings()
{
  Serial.println("Current settings:");
      Serial.println("WLAN SSID:");
      for(uint16_t i = 0; i < 33; i++)
      {
        input[i] = EEPROM[i];
      }
      Serial.println(input);
      strcpy(ssid, input);
      Serial.println("WLAN password:");
      for(uint16_t i = 33; i < 33+64; i++)
      {
        input[i-33] = EEPROM[i];
      }
      Serial.println(input);
      strcpy(password, input);
      Serial.println("MQTT borker address:");
      for(uint16_t i = 33+64; i < 33+64+21; i++)
      {
        input[i-33-64] = EEPROM[i];
      }
      Serial.println(input);
      strcpy(MQTT_BROKER, input);
      Serial.println("MQTT port:");
      for(uint16_t i = 33+64+21; i < 33+64+21+6; i++)
      {
        input[i-33-64-21] = EEPROM[i];
      }
      Serial.println(input);
      MQTT_PORT = atoi(input);
      Serial.println("MQTT user:");
      for(uint16_t i = 33+64+21+6; i < 33+64+21+6+21; i++)
      {
        input[i-33-64-21-6] = EEPROM[i];
      }
      //Serial.println(input);
      Serial.println("*");
      strcpy(mqtt_user, input);
      Serial.println("MQTT password:");
      for(uint16_t i = 33+64+21+6+21; i < 33+64+21+6+21+21; i++)
      {
        input[i-33-64-21-6-21] = EEPROM[i];
      }
      //Serial.println(input);
      Serial.println("*");
      strcpy(mqtt_password, input);
      Serial.println("MQTT client ID:");
      for(uint16_t i = 33+64+21+6+21+21; i < 33+64+21+6+21+21+21; i++)
      {
        input[i-33-64-21-6-21-21] = EEPROM[i];
      }
      Serial.println(input);
      strcpy(clientId, input);
      
      Serial.println("MQTT path:");
      for(uint16_t i = 33+64+21+6+21+21+21; i < 33+64+21+6+21+21+21+101; i++)
      {
        input[i-33-64-21-6-21-21-21] = EEPROM[i];
      }
      Serial.println(input);
      strcpy(mqtt_path, input);
      
      Serial.println("EVN key:");
      for(uint16_t i = 33+64+21+6+21+21+21+101; i < 33+64+21+6+21+21+21+101+33; i++)
      {
        input[i-33-64-21-6-21-21-21-101] = EEPROM[i];
      }
      Serial.println(input);
      //convert string to array of uint8_t
      char key_buffer [3];
      uint8_t key_pos = 0;
      for(uint8_t i = 0; i < 32; i=i+2)
      {
      key_buffer[0] = input[i];
      key_buffer[1] = input[i+1];
      key_buffer[2] = 0;
      key[key_pos] = (uint8_t)strtol(key_buffer, NULL, 16);
      key_pos++;
      }
      //print key from int (removes leading zerros from bytes)
      //for(uint8_t i = 0; i < 16; i++) Serial.print(key[i], HEX);
}

void setup() {
  Serial.begin(115200, SERIAL_8N1);
  Serial.setTimeout(10000);
  EEPROM.begin(1000);
  Serial.println("\nPress s for setup. Waiting for 10s...");
  flush_serial();
  Serial.readBytes(input, 1);
  if(input[0] == 's')
  {
    Serial.println("0 - Show current settings");
    Serial.println("1 - Set WLAN SSID");
    Serial.println("2 - Set WLAN password");
    Serial.println("3 - Set MQTT borker address");
    Serial.println("4 - Set MQTT port");
    Serial.println("5 - Set MQTT user");
    Serial.println("6 - Set MQTT password");
    Serial.println("7 - Set MQTT client ID");
    Serial.println("8 - Set MQTT path");
    Serial.println("9 - Set EVN Key");

    Serial.setTimeout(30000);
    while(1)
    {
    Serial.readBytes(input, 1);

    switch (input[0])
    {
      case '0':
      load_settings();
      break;
      
      case '1':
      Serial.println("Enter WLAN SSID (max. 32 symbols). Finish with ENTER.");
      read_input(32);
      Serial.println("\nSaved:");
      Serial.println(input);
      for(uint16_t i = 0; i < 33; i++)
      {
        EEPROM[i] = input[i];
      }
      EEPROM.commit();
      break;

      case '2':
      Serial.println("Enter WLAN password (max. 63 symbols). Finish with ENTER.");
      read_input(63);
      Serial.println("\nSaved:");
      Serial.println(input);
      for(uint16_t i = 33; i < 33+64; i++)
      {
        EEPROM[i] = input[i-33];
      }
      EEPROM.commit();
      break;

      case '3':
      Serial.println("Enter MQTT broker address (max. 20 symbols). Finish with ENTER.");
      read_input(20);
      Serial.println("\nSaved:");
      Serial.println(input);
      for(uint16_t i = 33+64; i < 33+64+21; i++)
      {
        EEPROM[i] = input[i-33-64];
      }
      EEPROM.commit();
      break;
      
      case '4':
      Serial.println("Enter MQTT port (max. 5 symbols). Finish with ENTER.");
      read_input(5);
      Serial.println("\nSaved:");
      Serial.println(input);
      for(uint16_t i = 33+64+21; i < 33+64+21+6; i++)
      {
        EEPROM[i] = input[i-33-64-21];
      }
      EEPROM.commit();
      break;

      case '5':
      Serial.println("Enter MQTT user (max. 20 symbols). Finish with ENTER.");
      read_input(20);
      Serial.println("\nSaved:");
      Serial.println(input);
      for(uint16_t i = 33+64+21+6; i < 33+64+21+6+21; i++)
      {
        EEPROM[i] = input[i-33-64-21-6];
      }
      EEPROM.commit();
      break;

      case '6':
      Serial.println("Enter MQTT password (max. 20 symbols). Finish with ENTER.");
      read_input(20);
      Serial.println("\nSaved:");
      Serial.println(input);
      for(uint16_t i = 33+64+21+6+21; i < 33+64+21+6+21+21; i++)
      {
        EEPROM[i] = input[i-33-64-21-6-21];
      }
      EEPROM.commit();
      break;

      case '7':
      Serial.println("Enter MQTT client ID (max. 20 symbols). Finish with ENTER.");
      read_input(20);
      Serial.println("\nSaved:");
      Serial.println(input);
      for(uint16_t i = 33+64+21+6+21+21; i < 33+64+21+6+21+21+21; i++)
      {
        EEPROM[i] = input[i-33-64-21-6-21-21];
      }
      EEPROM.commit();
      break;

      case '8':
      Serial.println("Enter MQTT path (max. 100 symbols). Finish with ENTER.");
      read_input(100);
      Serial.println("\nSaved:");
      Serial.println(input);
      for(uint16_t i = 33+64+21+6+21+21+21; i < 33+64+21+6+21+21+21+101; i++)
      {
        EEPROM[i] = input[i-33-64-21-6-21-21-21];
      }
      EEPROM.commit();
      break;

      case '9':
      Serial.println("Enter EVN key in HEX ( 32 symbols). Finish with ENTER.");
      read_input(32);
      Serial.println("\nSaved:");
      Serial.println(input);
      for(uint16_t i = 33+64+21+6+21+21+21+101; i < 33+64+21+6+21+21+21+101+33; i++)
      {
        EEPROM[i] = input[i-33-64-21-6-21-21-21-101];
      }
      EEPROM.commit();
      break;
    }
    }
    
  }
  else Serial.println("Timeout or unknown command. Starting...");
  load_settings();
  delay(2000);
  Serial.end();
  delay(1000);
  // Stromzaehler
  Serial.begin(2400, SERIAL_8E1);
  Serial.setTimeout(30000);

  pinMode(D0, OUTPUT);

  // Connect to WIFI
  Serial.print("Connecting to WiFi");
  WiFi.hostname("EVN-Stromzaehler");
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  // Show IP on Serial Port
  Serial.println("");
  Serial.println("WiFi connected");
  Serial.println("IP address: ");
  Serial.println(WiFi.localIP());

  client.setServer(MQTT_BROKER, MQTT_PORT);
  client.setBufferSize(1000);

  //Decryption setup
  gcm = new GCM<AES128>();
  gcm->setKey(key, 16);
}

void loop() {

  uint32_t wirkenergie_p, wirkenergie_n, leistung_p, leistung_n;
  float u1, u2, u3, i1, i2, i3, phi;
  char mqtt_out[10], mqtt_full_path[110];

  //Hardbeat
  digitalWrite(D0, HIGH);
  delay(100);
  digitalWrite(D0, LOW);

  Serial.readBytes(for_tx, 282);
 
  //Search for the MBus Start bytes
  if((for_tx[0] == 0x68) && (for_tx[1] == 0xFA) && (for_tx[2] == 0xFA) && (for_tx[3] == 0x68))
  {
    if (!client.connected()) {
    while (!client.connected()) {
      client.connect(clientId , mqtt_user, mqtt_password);
      delay(100);
        }
   }
    //Send binnary over MQTT
    strcpy(mqtt_full_path, mqtt_path);
    strcat(mqtt_full_path, "/raw");
    client.publish(mqtt_full_path, for_tx, 282, false);

  //decrypt
  create_iv();
  gcm->setIV(iv, 12);
  memset(buffer, (int)'\0', sizeof(buffer));

  for(uint16_t i = 0; i < 254; i++)
  {
    buffer[i] = for_tx[i+26];
  }
  
  decrypt(gcm,254);
  //delete gcm;

  wirkenergie_p = buffer[43]<<24 | buffer[44]<<16 | buffer[45]<<8 | buffer[46];
  Serial.println(wirkenergie_p);
  strcpy(mqtt_full_path, mqtt_path);
  strcat(mqtt_full_path, "/w_p");
  sprintf(mqtt_out, "%d", wirkenergie_p);
  client.publish(mqtt_full_path, mqtt_out, false);
  
  wirkenergie_n = buffer[62]<<24 | buffer[63]<<16 | buffer[64]<<8 | buffer[65];
  Serial.println(wirkenergie_n);
  strcpy(mqtt_full_path, mqtt_path);
  strcat(mqtt_full_path, "/w_n");
  sprintf(mqtt_out, "%d", wirkenergie_n);
  client.publish(mqtt_full_path, mqtt_out, false);
  
  leistung_p = buffer[81]<<24 | buffer[82]<<16 | buffer[83]<<8 | buffer[84];
  Serial.println(leistung_p);
  strcpy(mqtt_full_path, mqtt_path);
  strcat(mqtt_full_path, "/p_p");
  sprintf(mqtt_out, "%d", leistung_p);
  client.publish(mqtt_full_path, mqtt_out, false);
  
  leistung_n = buffer[100]<<24 | buffer[101]<<16 | buffer[102]<<8 | buffer[103];
  Serial.println(leistung_n);
  strcpy(mqtt_full_path, mqtt_path);
  strcat(mqtt_full_path, "/p_n");
  sprintf(mqtt_out, "%d", leistung_n);
  client.publish(mqtt_full_path, mqtt_out, false);
  
  u1 = ((float)((uint16_t) buffer[119]<<8 | buffer[120])) / 10;
  Serial.println(u1);
  strcpy(mqtt_full_path, mqtt_path);
  strcat(mqtt_full_path, "/u1");
  sprintf(mqtt_out, "%f", u1);
  client.publish(mqtt_full_path, mqtt_out, false);
  
  u2 = ((float)((uint16_t) buffer[136]<<8 | buffer[137])) / 10;
  Serial.println(u2);
  strcpy(mqtt_full_path, mqtt_path);
  strcat(mqtt_full_path, "/u2");
  sprintf(mqtt_out, "%f", u2);
  client.publish(mqtt_full_path, mqtt_out, false);
  
  u3 = ((float)((uint16_t) buffer[153]<<8 | buffer[154])) / 10;
  Serial.println(u3);
  strcpy(mqtt_full_path, mqtt_path);
  strcat(mqtt_full_path, "/u3");
  sprintf(mqtt_out, "%f", u3);
  client.publish(mqtt_full_path, mqtt_out, false);
  
  i1 = ((float)((int16_t) buffer[170]<<8 | buffer[171])) / 100;
  Serial.println(i1);
  strcpy(mqtt_full_path, mqtt_path);
  strcat(mqtt_full_path, "/i1");
  sprintf(mqtt_out, "%f", i1);
  client.publish(mqtt_full_path, mqtt_out, false);
  
  i2 = ((float)((int16_t) buffer[187]<<8 | buffer[188])) / 100;
  Serial.println(i2);
  strcpy(mqtt_full_path, mqtt_path);
  strcat(mqtt_full_path, "/i2");
  sprintf(mqtt_out, "%f", i2);
  client.publish(mqtt_full_path, mqtt_out, false);
  
  i3 = ((float)((int16_t) buffer[204]<<8 | buffer[205])) / 100;
  Serial.println(i3);
  strcpy(mqtt_full_path, mqtt_path);
  strcat(mqtt_full_path, "/i3");
  sprintf(mqtt_out, "%f", i3);
  client.publish(mqtt_full_path, mqtt_out, false);
  
  phi = ((float)((int16_t) buffer[221]<<8 | buffer[222])) / 1000;
  Serial.println(phi);
  strcpy(mqtt_full_path, mqtt_path);
  strcat(mqtt_full_path, "/phi");
  sprintf(mqtt_out, "%f", phi);
  client.publish(mqtt_full_path, mqtt_out, false);
  }
  else
  {
    //Synchronisation
    //Search for the longer pause between the messages
    //Will be terminated if there is no data for 2 seconds
    uint8_t last_ok = 0;
    while ((Serial.available() > 0) || (last_ok < 2))
    {
    while (Serial.available() > 0)
    {
      char k = Serial.read();
    }
    delay(1000);
    if (Serial.available() == 0) last_ok++;
    else last_ok = 0;
    }
  }
}
