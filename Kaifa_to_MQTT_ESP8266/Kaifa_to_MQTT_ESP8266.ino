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

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

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


// Based on https://stackoverflow.com/questions/35087781/using-line-in-a-macro-definition
// ... and based on SerenityOS' ErrorOr/Try pattern (see below). This could be way nicer
// if MSVC supported GCC expression statements ({ ... })
#define TOKEN_PASTE(x, y) x##y
#define CAT(x,y) TOKEN_PASTE(x,y)

#define TRYGET( varName, expression ) \
    auto CAT(maybeValue_, __LINE__) = expression; \
    if( CAT(maybeValue_, __LINE__).isError() ) { \
        return CAT(maybeValue_, __LINE__).error(); \
    } \
    auto varName= NoStl::move(CAT(maybeValue_, __LINE__).value())

#define TRY( expression ) \
    { \
        auto CAT(maybeValue_, __LINE__) = expression; \
        if( CAT(maybeValue_, __LINE__).isError() ) { \
            return CAT(maybeValue_, __LINE__).error(); \
        } \
    }

#define RETHROW( expression, message ) \
    { \
        auto CAT(maybeValue_, __LINE__) = expression; \
        if( CAT(maybeValue_, __LINE__).isError() ) { \
            return Error{ message }; \
        } \
    }

#ifndef ARDUINO

#define debugOut std::cout

void delay(uint32_t);

#else

namespace std { constexpr int endl = 0; }

struct DebugSink {
    template<typename T>
    const DebugSink& operator<<(const T&) const { return *this; }
};

#define debugOut DebugSink()

#undef assert
#define assert(...) do{}while(0)

#endif


using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;
using i8 = int8_t;
using i16 = int16_t;
using i32 = int32_t;
using i64 = int64_t;


namespace NoStl {

    template<typename>
    constexpr bool isLValueReference = false;

    template<typename T>
    constexpr bool isLValueReference<T&> = true;

    template<typename T>
    struct removeReference { using type = T; };

    template<typename T>
    struct removeReference<T&> { using type = T; };

    template<typename T>
    struct removeReference<T&&> { using type = T; };

    template<typename T>
    constexpr typename removeReference<T>::type&& move(T&& arg) {
        return static_cast<typename removeReference<T>::type&&>(arg);
    }

    template<typename T>
    constexpr T&& forward(typename removeReference<T>::type& x) noexcept { // forward an lvalue as either an lvalue or an rvalue
        return static_cast<T&&>(x);
    }

    template<typename T>
    constexpr T&& forward(typename removeReference<T>::type&& x) noexcept { // forward an rvalue as an rvalue
        static_assert(!isLValueReference<T>, "bad forward call");
        return static_cast<T&&>(x);
    }


    template<typename> class Optional;
    template<typename> class UniquePtr;
}

class Error;
template<typename>
class ErrorType;
class Buffer;
template<int>
class LocalBuffer;
class OwnedBuffer;

/**
* Reimplement a few useful standard classes in the absence of the STL
**/
namespace NoStl {
    template<typename T>
    class Optional {
    public:
        Optional() : data{ .placeholder= 0 }, valueFlag{ false } {}

        Optional(const Optional&) = delete;
        Optional(Optional&& other) : valueFlag{ other.valueFlag } {
            if (valueFlag) {
                new(&data.value) T(move(other.data.value));
            }
        }

        template<typename ... TArgs>
        Optional(TArgs&& ... args) : data{ .value{ NoStl::forward<TArgs>(args)... } }, valueFlag{ true } {}

        ~Optional() {
            if (valueFlag) {
                data.value.~T();
            }
        }

        bool hasValue() const { return valueFlag; }
        operator bool() const { return valueFlag; }

        T& value() { assert(valueFlag); return data.value; }
        const T& value() const { assert(valueFlag); return data.value; }

        template<typename U>
        Optional& operator=(U&& val) {
            if (valueFlag) {
                data.value = forward<U>(val);
            }
            else {
                new(&data.value) T(forward<U>(val));
                valueFlag = true;
            }
            return *this;
        }

    private:
        union Storage {
            char placeholder;
            T value;

            ~Storage();
        };
        
        Storage data;
        bool valueFlag{ false };
    };

    // Implement the union destructor out of line to prevent the Arduino IDE from creating
    // bogus prototypes all over the file
    template<typename T>
    Optional<T>::Storage::~Storage() {}

    template<typename T>
    class UniquePtr {
    public:
        UniquePtr() : ptr{ nullptr } {};
        UniquePtr(const UniquePtr&) = delete;
        UniquePtr(UniquePtr&& other) : ptr{ other.release() } {}
        UniquePtr(T* p) : ptr{ p } {}

        ~UniquePtr() {
            reset();
        }

        UniquePtr& operator=(UniquePtr&& other) {
            reset();
            ptr = other.ptr;
            other.ptr = nullptr;
            return *this;
        }

        T& operator*() { assert(ptr); return *ptr; }
        const T& operator*() const { assert(ptr); return *ptr; }

        T* operator->() { assert(ptr); return ptr; }
        const T* operator->() const { assert(ptr); return ptr; }

        operator bool() const { return ptr; }

        void reset() {
            if (ptr) {
                delete ptr;
                ptr = nullptr;
            }
        }

        T* release() {
            auto* p = ptr;
            ptr = nullptr;
            return p;
        }

        T* get() {
            return ptr;
        }
    
    private:
        T* ptr{ nullptr };
    };
}

// Heavily inspired by SerenityOS: https://github.com/SerenityOS/serenity/blob/master/AK/Error.h

class Error {
public:
    explicit Error(const char* m) : msg( m ) {}

    const char* message() const { return msg; }

private:
    const char* msg;
};

struct EmptyType {};

template<typename T>
class ErrorOr {
public:
    ErrorOr(Error e) : storage{ .error{NoStl::move(e)} }, storesError{ true } {}
    
    template<typename ...Args>
    ErrorOr(Args&& ... args) : storage{ .value{NoStl::forward<Args>(args)...} }, storesError{ false } {}

    ~ErrorOr() {
        if (storesError) {
            storage.error.~Error();
        }
        else {
            storage.value.~T();
        }
    }

    bool isError() const { return storesError; }
    Error& error() { assert(isError()); return storage.error; }
    T& value() { assert(!isError()); return storage.value; }

private:
    union Storage {
        Error error;
        T value;

        ~Storage();
    } storage;

    bool storesError;
};

// Implement the union destructor out of line to prevent the Arduino IDE from creating
// bogus prototypes all over the file
template<typename T>
ErrorOr<T>::Storage::~Storage() {}

template<>
class ErrorOr<void> : public ErrorOr<EmptyType> {
public:
    using ErrorOr<EmptyType>::ErrorOr;
};

class Buffer {
public:
    Buffer(u8* p, u32 l) : ptr(p), byteCount(l) {}

    Buffer(const OwnedBuffer&) = delete;
    Buffer(OwnedBuffer&&) = delete;

    template<typename T>
    void printHex(T& stream) const {
        for (u32 i = 0; i < byteCount; i++) {
            const char c[] = "0123456789abcdef";

            stream << c[ptr[i] >> 4] << c[ptr[i] & 0xF] << ' ';

            if ((i+1) % 16 == 0) {
                stream << '\n';
            }
        }

        if (byteCount % 16) {
            stream << '\n';
        }
    }

    template<typename T>
    void parseHex(const T& source, u32 nibbleCount, u32 maxReadBytes= 0, u32 sourceOffset= 0) {
        u32 writeIdx = 0;
        for (u32 readIdx = 0; nibbleCount > 0 && writeIdx < byteCount && (readIdx < maxReadBytes || !maxReadBytes); readIdx++) {
            u8 value;
            u8 c = source[readIdx+ sourceOffset];
            if (c >= '0' && c <= '9') {
                value = c - '0';
            }
            else if (c >= 'a' && c <= 'f') {
                value = c - 'a' + 10;
            }
            else if (c >= 'A' && c <= 'F') {
                value = c - 'A' + 10;
            }
            else {
                continue;
            }

            if (nibbleCount % 2 == 0) {
                ptr[writeIdx] = value << 4;
            }
            else {
                ptr[writeIdx] |= value;
                writeIdx++;
            }
            nibbleCount--;
        }
    }

    static OwnedBuffer allocate(u32 size);
    static ErrorOr<OwnedBuffer> fromHexString(const char* hexString);

    auto length() const { return byteCount; }
    auto at(u32 idx) const { assert(idx < byteCount);  return ptr[idx]; }

    Buffer slice(u32 begin, u32 end) const {
        assert(begin < byteCount&& end <= byteCount);
        return { ptr + begin, end - begin };
    }

    void insertAt(const Buffer& other, u32 pos) {
        assert(other.byteCount + pos <= byteCount); // Buffer overflow
        memcpy(ptr + pos, other.ptr, other.byteCount);
    }

    void shrinkLength(u32 size) {
        assert(size <= byteCount);
        byteCount = size;
    }

    u8* begin() { return ptr; }
    const u8* begin() const { return ptr; }
    const char* charBegin() const { return reinterpret_cast<const char*>(ptr); }
    const u8* end() const { return ptr + byteCount; }

    u8& operator[](u32 idx) {
        assert(idx < byteCount);
        return ptr[idx];
    }

    u8 operator[](u32 idx) const {
        assert(idx < byteCount);
        return ptr[idx];
    }

protected:
    u8* ptr;
    u32 byteCount;
};

template<int Length>
class LocalBuffer : public Buffer {
public:
    LocalBuffer() : Buffer(storage, Length) {}

private:
    u8 storage[Length];
};

class OwnedBuffer : public Buffer {
public:

    OwnedBuffer() : Buffer(nullptr, -1) {}
    OwnedBuffer(u8* p, u32 l) : Buffer(p, l) {}
    OwnedBuffer(const OwnedBuffer&) = delete;
    OwnedBuffer(OwnedBuffer&& other) : Buffer(other.ptr, other.byteCount) {
        other.ptr = nullptr;
    }

    virtual ~OwnedBuffer() {
        free();
    }

    void free() {
        if (ptr) {
            delete[] ptr;
            ptr = nullptr;
            byteCount = -1;
        }
    }

    OwnedBuffer& operator=(OwnedBuffer&& other) {
        free();
        ptr = other.ptr;
        byteCount = other.byteCount;
        other.ptr = nullptr;
        other.byteCount = -1;
        return *this;
    }
};


OwnedBuffer Buffer::allocate(u32 size) {
    return { new u8[size], size };
}

ErrorOr<OwnedBuffer> Buffer::fromHexString(const char* hexString) {
    u32 nibbleCount = 0;

    for (auto it = hexString; *it; it++) {
        if ((*it >= '0' && *it <= '9') || (*it >= 'a' && *it <= 'f') || (*it >= 'A' && *it <= 'F')) {
            nibbleCount++;
        }
    }

    if (nibbleCount % 2 != 0) {
        return Error{ "uneven number of nibbles" };
    }

    auto bufferSize = nibbleCount / 2;
    auto bufferPointer = new u8[bufferSize];
    OwnedBuffer buffer{ bufferPointer, bufferSize };
    buffer.parseHex(hexString, nibbleCount);

    return { NoStl::move(buffer) };
}

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
