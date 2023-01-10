/**
* ESP8266 based power meter M-Bus to mqtt gateway v2.0
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
* - Open the Library Manager and intstall the dependencies listed below (Crypto, PubSubClient)
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
#include <conio.h>
#include <stdio.h>
#include <windows.h>

#include "Crypto-0.4.0/src/Crypto.h"
#include "Crypto-0.4.0/src/AES.h"
#include "Crypto-0.4.0/src/GCM.h"
#include "CRC-master/CRC32.h"

#else 

/**
* Dependencies:
* - ESP8266 Arduino support (Arduino team - GNU LGPL v2.1): https://github.com/esp8266/Arduino
* - Crypto: (Rhys Weatherley - MIT) https://rweather.github.io/arduinolibs/crypto.html
* - PubSubClient: (Nicholas O'Leary - MIT) https://pubsubclient.knolleary.net/
* - CRC: (Rob Tillaart - MIT) https://github.com/RobTillaart/CRC
**/

#include <ESP8266WiFi.h>
#include <WiFiClientSecure.h>
#include <ESP8266WebServerSecure.h>
#include <PubSubClient.h>
#include <EEPROM.h>
#include <Arduino.h>
#include <Crypto.h>
#include <AES.h>
#include <GCM.h>
#include <CRC32.h>

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


#ifdef _DEBUG
#define DEBUG_PRINTING 1
#else
#define DEBUG_PRINTING 0
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

template<typename>
class SerialStream;
class Error;
template<typename>
class ErrorType;
class Buffer;
template<int>
class LocalBuffer;
class OwnedBuffer;
template<typename>
class IndexReader;
template<typename>
class SerialUnbufferedReader;
class BufferReaderBase;
class BufferReader;
template<typename>
class SerialBufferReader;
class BufferPrinter;
class MqttSender;
class SettingsField;
template<typename>
class EEPROMSettings;
class MBusLinkFrame;
class MBusTransportFrame;
class DlmsApplicationFrame;
class DlmsStructureNode;
class DlmsNodeAllocator;
class DlmsReader;
class CosemDataField;
class CosemScaledValue;
class CosemTimestamp;
class CosemMeterNumber;
class CosemData;
template<typename>
class MqttSenderImplBase;
template<typename>
class MqttRawSender;
template<typename>
class MqttTopicSender;
template<typename>
class MqttJsonSender;

/**
* Reimplement a few useful standard classes in the absence of the STL
**/
namespace NoStl {
    template<typename T>
    class Optional {
    public:
        Optional() : data{ .placeholder = 0 }, valueFlag{ false } {}

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

        template<typename U>
        UniquePtr(UniquePtr<U>&& other) : ptr{ other.release() } {}

        template<typename U>
        explicit UniquePtr(U* p) : ptr{ p } {}

        explicit UniquePtr(T* p) : ptr{ p } {}

        ~UniquePtr() {
            reset();
        }

        template<typename U>
        UniquePtr& operator=(UniquePtr<U>&& other) {
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
        template<typename U>
        friend class UniquePtr;

        T* ptr{ nullptr };
    };

    template<typename T, typename ...Args>
    UniquePtr<T> makeUnique(Args&&... args) {
        return UniquePtr<T>{ new T(forward<Args>(args)...) };
    }
}


template<typename T>
class SerialStream {
public:
    SerialStream(T& s) : serial{ s } {}

    template<typename U>
    SerialStream& operator << (const U& x) {
        serial.print(x);
        return *this;
    }

private:
    T& serial;
};

#if DEBUG_PRINTING

#ifdef ARDUINO

SerialStream<decltype(Serial)> debugSerialStream{ Serial };

#define debugOut debugSerialStream
#define debugEndl "\r\n"

void handleAssertionFailure(u32 lineNumber) {
    debugOut << "\r\n\r\nAssertion failed on line number " << lineNumber << debugEndl;
    Serial.flush();

    // Halt the system
    while (true) {}
}

#undef assert
#define assert( cond ) \
    do {\
        if( !(cond) ) { \
            handleAssertionFailure( __LINE__ ); \
        } \
    } while(0)

#else

#define debugOut std::cout
#define debugEndl std::endl;

void delay(uint32_t);

#endif

#else

struct DebugSink {
    template<typename T>
    const DebugSink& operator<<(const T&) const { return *this; }
};

#define debugOut DebugSink()
#define debugEndl 0;

#undef assert
#define assert(...) do{}while(0)

#endif


// Heavily inspired by SerenityOS: https://github.com/SerenityOS/serenity/blob/master/AK/Error.h

class Error {
public:
    explicit Error(const char* m) : msg(m) {}

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

            if ((i + 1) % 16 == 0) {
                stream << "\r\n";
            }
        }

        if (byteCount % 16) {
            stream << "\r\n";
        }
    }

    template<typename T>
    void parseHex(T reader, u32 nibbleCount) {
        u32 writeIdx = 0;
        while (nibbleCount > 0 && writeIdx < byteCount && reader.hasNext()) {
            u8 value;
            u8 c = reader.nextU8();
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

    template<typename T>
    ErrorOr<u32> parseBase64(T reader) {
        auto nextCharToBits = [&]() -> ErrorOr<u8> {

            u8 x;
            do {
                TRYGET(c, reader.nextU8());
                x = c;
            } while (x == ' ' || x == '\r' || x == '\n');

            if (x >= 'A' && x <= 'Z') {
                return (u8)(x - 'A');
            }
            if (x >= 'a' && x <= 'z') {
                return (u8)(x - 'a' + 0x1a);
            }
            if (x >= '0' && x <= '9') {
                return (u8)(x - '0' + 0x34);
            }
            switch (x) {
            case '+': return (u8)0x3e;
            case '/': return (u8)0x3f;
            case '=': return (u8)0xf0;
            default: return Error{ "Bad Base64 character" };
            }
        };

        u32 bytesDecoded = 0;
        while (reader.hasNext() && bytesDecoded < byteCount) {
            TRYGET(a, nextCharToBits());
            TRYGET(b, nextCharToBits());
            TRYGET(c, nextCharToBits());
            TRYGET(d, nextCharToBits());

            if (a == 0xf0 || b == 0xf0) {
                return Error{ "Bad Base64 format" };
            }

            if (c == 0xf0) {
                ptr[bytesDecoded++] = (a << 2) | (b >> 4);
                break;
            }

            if (d == 0xf0) {
                ptr[bytesDecoded++] = (a << 2) | (b >> 4);
                ptr[bytesDecoded++] = (b << 4) | (c >> 2);
                break;
            }

            u32 bits = (a << 18) | (b << 12) | (c << 6) | d;
            ptr[bytesDecoded++] = bits >> 16;
            ptr[bytesDecoded++] = (bits >> 8) & 0xff;
            ptr[bytesDecoded++] = bits & 0xff;
        }

        return bytesDecoded;
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

    void resetLength() {
        byteCount = Length;
    }

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

template<typename T>
class IndexReader {
public:
    IndexReader(const T& s, u32 m, u32 o = 0) : maxBytesToRead{ m }, readOffset{ o }, source{ s } {}

    bool hasNext(u32 c = 1) const {
        return index + c <= maxBytesToRead;
    }

    u8 nextU8() {
        assert(hasNext());
        return at(index++);
    }

    u8 peakU8() const {
        assert(hasNext());
        return at(index);
    }

    void skip(u32 num = 1) {
        assert(hasNext(num));
        index += num;
    }

private:
    u8 at(u32 i) const {
        return source[readOffset + i];
    }

    u32 maxBytesToRead;
    u32 readOffset;
    u32 index{ 0 };
    const T& source;
};

OwnedBuffer Buffer::allocate(u32 size) {
    return { new u8[size], size };
}

ErrorOr<OwnedBuffer> Buffer::fromHexString(const char* hexString) {
    u32 nibbleCount = 0;
    u32 byteCount = 0;

    for (auto it = hexString; *it; it++) {
        if ((*it >= '0' && *it <= '9') || (*it >= 'a' && *it <= 'f') || (*it >= 'A' && *it <= 'F')) {
            nibbleCount++;
        }
        byteCount++;
    }

    if (nibbleCount % 2 != 0) {
        return Error{ "uneven number of nibbles" };
    }

    auto bufferSize = nibbleCount / 2;
    auto bufferPointer = new u8[bufferSize];
    OwnedBuffer buffer{ bufferPointer, bufferSize };
    buffer.parseHex(IndexReader<const char*>{hexString, byteCount}, nibbleCount);

    return { NoStl::move(buffer) };
}

template<typename T>
class SerialUnbufferedReader {
public:
    SerialUnbufferedReader(T& s) : serial{ s } {}

    bool hasNext(u32 c = 1) const {
        return true;
    }

    ErrorOr<u8> nextU8() {
        u8 c;
        if (serial.readBytes(&c, 1) != 1) {
            return Error{ "Could not read byte from serial" };
        }
        return c;
    }

private:
    T& serial;
};

class BufferReaderBase {
protected:
    u16 readU16(const Buffer& buffer, u32 index) const {
        return (buffer.at(index) << 8) | buffer.at(index + 1);
    }

    u32 readU32(const Buffer& buffer, u32 index) const {
        return (buffer.at(index) << 24) | (buffer.at(index + 1) << 16) | (buffer.at(index + 2) << 8) | buffer.at(index + 3);
    }

    u64 readU64(const Buffer& buffer, u32 index) const {
        u64 upper = (buffer.at(index + 0) << 24) | (buffer.at(index + 1) << 16) | (buffer.at(index + 2) << 8) | buffer.at(index + 3);
        u32 lower = (buffer.at(index + 4) << 24) | (buffer.at(index + 5) << 16) | (buffer.at(index + 6) << 8) | buffer.at(index + 7);
        return (upper << 32) | lower;
    }

    u64 readUptToU64(const Buffer& buffer, u32 index, u32 remainingBytes, u8* bytesRead) const {
        u64 value = 0;
        auto num = *bytesRead = remainingBytes < 8 ? remainingBytes : 8;
        for (u32 i = 0; i != num; i++) {
            value = (value << 8) | buffer.at(index + i);
        }

        return value;
    }
};

class BufferReader : public BufferReaderBase {
public:
    explicit BufferReader(const Buffer& b) : buffer(b) {}

    bool hasNext(u32 c = 1) const {
        return index + c <= buffer.length();
    }

    u8 nextU8() {
        assert(hasNext());
        return buffer.at(index++);
    }

    u8 peakU8() {
        assert(hasNext());
        return buffer.at(index);
    }

    u16 nextU16() {
        assert(hasNext(2));
        u16 val = readU16(buffer, index);
        index += 2;
        return val;
    }

    u32 nextU32() {
        assert(hasNext(4));
        u32 val = readU32(buffer, index);
        index += 4;
        return val;
    }

    u64 nextU64() {
        assert(hasNext(8));
        u64 val = readU64(buffer, index);
        index += 8;
        return val;
    }

    ErrorOr<void> assertU8(u8 val) {
        if (!hasNext()) {
            return Error{ "No remaining bytes to read" };
        }
        auto actualVal = nextU8();
        if (val != actualVal) {
            return Error{ "Unexpected byte" };
        }
        return {};
    }

    ErrorOr<void> assertRemaining(u32 num) const {
        if (remainingBytes() < num) {
            return Error{ "Less bytes remaining than expected" };
        }
        return {};
    }

    void skip(u32 num = 1) {
        assert(hasNext(num));
        index += num;
    }

    Buffer slice(i32 len = 0) {
        auto end = len >= 0 ? index + len : len + buffer.length() + 1;
        Buffer sliced = buffer.slice(index, end);
        index = end;
        return sliced;
    }

    u32 remainingBytes() const {
        return buffer.length() - index;
    }

    u64 nextUpToU64() {
        u8 bytesRead;
        u64 val = readUptToU64(buffer, index, remainingBytes(), &bytesRead);
        index += bytesRead;
        return val;
    }

private:
    Buffer buffer;
    u32 index{ 0 };
};

template<typename T>
class SerialBufferReader : public BufferReaderBase {
public:
    SerialBufferReader(T& serialIntf, const Buffer& buf, u8 e)
        : serialInterface{ serialIntf }, endChar{ e }, buffer{ buf } {}

    bool hasNext(u32 c = 1) const {
        return readIndex + c <= writeIndex;
    }

    ErrorOr<u8> nextU8() {
        TRY(ensureBytes(1));
        return buffer.at(readIndex++);
    }

    ErrorOr<u8> peakU8() {
        TRY(ensureBytes(1));
        return buffer.at(readIndex);
    }

    ErrorOr<u16> nextU16() {
        TRY(ensureBytes(2));
        u16 val = readU16(buffer, readIndex);
        readIndex += 2;
        return val;
    }

    ErrorOr<u32> nextU32() {
        TRY(ensureBytes(4));
        u32 val = readU32(buffer, readIndex);
        readIndex += 4;
        return val;
    }

    ErrorOr<u64> nextU64() {
        TRY(ensureBytes(8));
        u64 val = readU64(buffer, readIndex);
        readIndex += 8;
        return val;
    }

    ErrorOr<void> assertU8(u8 val) {
        if (!hasNext()) {
            return Error{ "No remaining bytes to read" };
        }
        TRYGET(actualVal, nextU8());
        if (val != actualVal) {
            return Error{ "Unexpected byte" };
        }
        return {};
    }

    ErrorOr<void> skip(u32 num = 1) {
        TRY(ensureBytes(num));
        readIndex += num;
    }

    ErrorOr<Buffer> slice(i32 len = 0) {
        assert(len >= 0); // SerialBuffer does not support negative slice lengths
        TRY(ensureBytes(len));
        Buffer sliced = buffer.slice(readIndex, readIndex + len);
        readIndex += len;
        return sliced;
    }

    Buffer allDataRead() const {
        return buffer.slice(0, writeIndex);
    }

private:
    ErrorOr<void> readBlock(u32 readAtLeast) {
        assert(writeIndex + readAtLeast <= buffer.length()); // Buffer is too small to read the requested number of bytes
        if (readAtLeast) {
            auto bytesWritten = serialInterface.readBytes((char*)&buffer[writeIndex], readAtLeast);
            writeIndex += bytesWritten;
            // Timeout occured before requested number of bytes could be read
            if (bytesWritten < readAtLeast) {
                return Error{ "Could not read enough bytes from serial before timeout" };
            }
        }

        // Do try to read even more if the end char was just read
        if (!(readAtLeast && writeIndex && buffer.at(writeIndex - 1) == endChar)) {
            writeIndex += serialInterface.readBytesUntil(endChar, (char*)&buffer[writeIndex], buffer.length() - writeIndex);
            assert(writeIndex < buffer.length()); // Buffer was too small 
            buffer[writeIndex++] = endChar; // Add end byte
        }

        return {};
    }

    ErrorOr<void> ensureBytes(u32 num) {
        if (!hasNext(num)) {
            auto availableBytes = writeIndex - readIndex;
            TRY(readBlock(num - availableBytes));
        }

        return {};
    }

    T& serialInterface;
    u8 endChar;
    Buffer buffer;
    u32 readIndex{ 0 };
    u32 writeIndex{ 0 };
};

class BufferPrinter {
public:
    explicit BufferPrinter(Buffer& b) : buffer(b), cursor{ b.begin() } {}

    void clear() {
        cursor = buffer.begin();
    }

    bool isEmpty() const {
        return cursor == buffer.begin();
    }

    BufferPrinter& print(i64 x, u8 minLeadingDigits = 0, i8 decimalPointPosition = 0) {
        if (x < 0) {
            if (!push('-')) {
                return *this;
            }

            x *= -1;
        }
        printUnsigned((u64)x, minLeadingDigits, decimalPointPosition);
        return *this;
    }

    BufferPrinter& printUnsigned(u64 x, u8 minLeadingDigits = 0, i8 decimalPointPosition = 0) {
        auto preDecimalDigits = decimalPointPosition;

        if (!x) {
            if (!minLeadingDigits) {
                minLeadingDigits = 1;
            }
            while (minLeadingDigits--) {
                if (!push('0')) {
                    break;
                }
            }
            return *this;
        }

        if (decimalPointPosition > 0) {
            if (decimalPointPosition > minLeadingDigits) {
                minLeadingDigits = 0;
            }
            else {
                minLeadingDigits -= decimalPointPosition;
            }
        }

        // Print each digit by dividing by 10 -> prints the full number in reverse
        auto begin = cursor;
        while (x) {
            if (decimalPointPosition && !preDecimalDigits) {
                if (!push('.')) {
                    break;
                }
            }
            preDecimalDigits++;

            if (preDecimalDigits > 0 && minLeadingDigits > 0) {
                minLeadingDigits--;
            }

            u8 digit = x % 10;
            x /= 10;
            if (!push(digit + '0')) {
                break;
            }
        }

        // Add leading zeros for negative exponent (after flipping they end up in front)
        if (decimalPointPosition && preDecimalDigits <= 0) {
            while (preDecimalDigits++ < 0) {
                if (!push('0')) {
                    break;
                }
            }
            push('.');
            push('0');

            if (minLeadingDigits > 0) {
                minLeadingDigits--;
            }
        }

        // Add leading zeros
        while (minLeadingDigits--) {
            if (!push('0')) {
                break;
            }
        }

        // Flip the digits
        auto end = cursor - 1;
        while ((end - begin) >= 1) {
            auto temp = *begin;
            *begin = *end;
            *end = temp;
            end--;
            begin++;
        }

        // Add trailing zeros for positive exponent
        while (decimalPointPosition-- > 0) {
            if (!push('0')) {
                break;
            }
        }

        return *this;
    }

    BufferPrinter& print(const char* str) {
        assert(str); // Cannot print empty string
        auto len = strlen(str);
        if (cursor + len >= buffer.end()) {
            len = (buffer.end() - cursor) - 1;
        }
        memcpy(cursor, str, len);
        cursor += len;
        return *this;
    }

    BufferPrinter& printChar(char c) {
        push(c);
        return *this;
    }

    const char* cString() {
        *cursor = '\0';
        return (const char*)buffer.begin();
    }

protected:
    bool push(u8 c) {
        if (cursor >= buffer.end() - 1) { // Leave space for '\0'
            return false;
        }

        *(cursor++) = c;
        return true;
    }

    Buffer buffer;
    u8* cursor;
};

class MqttSender {
public:
    MqttSender() = default;
    virtual ~MqttSender() = default;

    virtual ErrorOr<void> connect() = 0;
    virtual void publishRaw(const Buffer&) = 0;

    class FieldTransmission {
    public:
        explicit FieldTransmission(MqttSender& s) : sender{ s } {}

        ~FieldTransmission() {
            sender.endFieldTransmission();
        }

        void appendField(const CosemTimestamp& timestamp) {
            sender.appendField(timestamp);
        }

        void appendField(const CosemScaledValue& value) {
            sender.appendField(value);
        }

        void appendField(const CosemMeterNumber& value) {
            sender.appendField(value);
        }

        void appendField(const char* name, const char* value) {
            sender.appendField(name, value);
        }

    private:
        MqttSender& sender;
    };

    FieldTransmission transmitFields() {
        return FieldTransmission{ *this };
    }

protected:
    virtual void appendField(const CosemTimestamp&) = 0;
    virtual void appendField(const CosemScaledValue&) = 0;
    virtual void appendField(const CosemMeterNumber&) = 0;
    virtual void appendField(const char* name, const char* value) = 0;
    virtual void endFieldTransmission() = 0;
};


class SettingsField {
public:
    enum Type : u8 {
        WifiSSID = 0,
        WifiPassword,
        MqttBrokerAddress,
        MqttBrokerPort,
        MqttCertificateFingerprint,
        MqttBrokerUser,
        MqttBrokerPassword,
        MqttBrokerClientId,
        MqttBrokerPath,
        MqttMessageMode,
        DslmCosemDecryptionKey,
        WebServerSSLCertificate,
        WebServerSSLKey,

        NumberOfFields
    };

    struct FieldInfo {
        const Type type;
        const char* name;
        const char* defaultValue;
        const u32 maxLength;
    };

    SettingsField(Type t) : type(t) {}
    SettingsField(const SettingsField&) = default;

    u32 calcOffset() const {
        u32 offset = 0;
        for (u32 i = 0; i < type; i++) {
            offset += fields[i].maxLength;
        }

        return offset;
    }

    bool operator==(const SettingsField& x) const { return type == x.type; }

    u32 maxLength() const { return fields[type].maxLength; }
    const char* name() const { return fields[type].name; }
    const char* defaultValue() const { return fields[type].defaultValue; }
    Type enumType() const { return type; }
    bool isDerFile() const { return type == WebServerSSLCertificate || type == WebServerSSLKey; }

    bool isSecure() const {
        switch (type) {
        case WifiPassword:
        case MqttBrokerPassword:
        case MqttCertificateFingerprint:
        case DslmCosemDecryptionKey:
        case WebServerSSLCertificate:
        case WebServerSSLKey:
            return true;
        default:
            return false;
        }
    }


    ErrorOr<void> validate(Buffer& buffer) const {
        auto validateAndCompactHexString = [&buffer](i32 numDigits) -> ErrorOr<void> {
            u32 compactingOffset = 0;
            for (u32 i = 0; i != buffer.length() - 1; i++) {
                auto c = buffer[i];
                if (!(c >= 'a' && c <= 'f') && !(c >= 'A' && c <= 'F') && !(c >= '0' && c <= '9') && (c != ' ')) {
                    return Error{ "Bad hex character. Expected range is [a-fA-F0-9 ]" };
                }

                if (c != ' ') {
                    buffer[compactingOffset++] = c;
                    numDigits--;
                }
            }

            buffer[compactingOffset] = '\0';
            buffer.shrinkLength(compactingOffset + 1);

            if (numDigits > 0) {
                return Error{ "Too few hex digits" };
            }
            if (numDigits < 0) {
                return Error{ "Too many hex digits" };
            }

            return {};
        };

        auto validatePrintableASCII = [&buffer]() -> ErrorOr<void> {
            for (u32 i = 0; i != buffer.length() - 1; i++) {
                if (buffer[i] < 32 || buffer[i] > 126) {
                    return Error{ "Bad unprintable ASCII character found" };
                }
            }

            return {};
        };

        auto validateDomainNameASCII = [&buffer]() -> ErrorOr<void> {
            for (u32 i = 0; i != buffer.length() - 1; i++) {
                auto c = buffer[i];
                if (!(c >= 'A' && c <= 'Z') && !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && (c != '.') && (c != '-')) {
                    return Error{ "Bad domain name character found. Expected range is [a-zA-Z0-9.-]" };
                }
            }

            return {};
        };

        auto validateLength = [&buffer](u32 len) -> ErrorOr<void> {
            if (buffer.length() - 1 != len) {
                return Error{ "" };
            }
            return {};
        };

        switch (type) {
        case MqttBrokerAddress:
            if (buffer.length() < 2 || buffer.length() > 63) {
                return Error{ "Bad domain name length. Expected range is 2..63" };
            }
            if (buffer[0] == '-') {
                return Error{ "Bad domain name. May not begin with '-'" };
            }
            TRY(validateDomainNameASCII());
            break;
        case MqttBrokerPort:
            for (u32 i = 0; i != buffer.length() - 1; i++) {
                if (buffer[i] < '0' || buffer[i] > '9') {
                    return Error{ "Bad digit. Expected positive integer" };
                }
            }
            if (atoi(buffer.charBegin()) > 65535) {
                return Error{ "Port number greater than 65535" };
            }
            break;
        case MqttMessageMode:
            RETHROW(validateLength(1), "Expected 1 digit");
            if (buffer[0] != '0' && buffer[0] != '1' && buffer[0] != '2') {
                return Error{ "Expected 0, 1 or 2" };
            }
            break;
        case DslmCosemDecryptionKey:
            TRY(validateAndCompactHexString(32));
            break;
        case MqttCertificateFingerprint:
            if (strncmp(buffer.charBegin(), "[insecure]", buffer.length())) {
                TRY(validateAndCompactHexString(40));
            }
            break;
        default:
            if (buffer.length() > maxLength()) {
                return Error{ "Input is too long. Not enough space. " };
            }
            TRY(validatePrintableASCII());
            break;
        }

        return {};
    }

    template<typename T>
    static void forEach(const T& lam) {
        for (u32 i = 0; i != NumberOfFields; i++) {
            SettingsField field{ (Type)i };
            lam(field);
        }
    }

    static u32 requiredStorage() {
        u32 len = 0;
        for (u32 i = 0; i != NumberOfFields; i++) {
            len += fields[i].maxLength;
        }
        return len;
    }

private:
    static const FieldInfo fields[NumberOfFields];

    Type type;
};

const SettingsField::FieldInfo SettingsField::fields[SettingsField::NumberOfFields] = {
    {WifiSSID, "wifi ssid", nullptr, 33},
    {WifiPassword, "wifi password", nullptr, 65},
    {MqttBrokerAddress, "mqtt broker network address", nullptr, 21},
    {MqttBrokerPort, "mqtt broker network port", "1883", 7},
    {MqttCertificateFingerprint, "mqtt broker certificate sha1 fingerprint ('[insecure]' disables TLS)", "[insecure]", 45},
    {MqttBrokerUser, "mqtt broker user name", "power-meter", 21},
    {MqttBrokerPassword, "mqtt broker password", nullptr, 21},
    {MqttBrokerClientId, "mqtt broker client id", nullptr, 21},
    {MqttBrokerPath, "mqtt broker path", nullptr, 101},
    {MqttMessageMode, "mqtt message mode (0 - raw, 1 - topics, 2 - json)", "2", 2},
    {DslmCosemDecryptionKey, "dslm/cosem decryption key (meter key)", nullptr, 33},
    {WebServerSSLCertificate, "web server ssl certificate", "[default]", 1000},
    {WebServerSSLKey, "web server ssl private key", "[default]", 1300},
};

template<typename T>
class EEPROMSettings {
public:
    EEPROMSettings(T& e) : eeprom(e) {}

    ErrorOr<void> begin() {
        if (!checkChecksum()) {
            return Error{ "Bad EEPROM checksum" };
        }

        return {};
    }

    void copyCString(SettingsField field, Buffer& buffer) {
        assert(buffer.length() >= field.maxLength());
        assert(eeprom.getDataPtr());
        auto offset = field.calcOffset();
        auto maxLength = field.maxLength();

        strncpy((char*)buffer.begin(), (const char*)eeprom.getDataPtr() + offset, maxLength);
        buffer[maxLength - 1] = '\0';
    }

    Buffer getCStringBuffer(SettingsField field) {
        assert(eeprom.getDataPtr());
        auto offset = field.calcOffset();
        auto maxLength = field.maxLength();
        auto ptr = eeprom.getDataPtr() + offset;
        auto len = strnlen((const char*)ptr, maxLength)+ 1;
        return {ptr, len};
    }

    u16 getDerFileLength(SettingsField field) {
        assert(field.isDerFile());
        auto offset = field.calcOffset();
        return (eeprom[offset + 1] << 8) | eeprom[offset];
    }

    void copyHexBytes(SettingsField field, Buffer& buffer) {
        assert(buffer.length() >= (field.maxLength() - 1) / 2); // Ignore the null termination byte and convert nibble count to byte count

        auto offset = field.calcOffset();
        buffer.parseHex(IndexReader<T>{eeprom, field.maxLength() - 1, offset}, field.maxLength() - 1);
    }

    void save() {
        auto storageSize = SettingsField::requiredStorage();
        writeChecksum(storageSize, calcChecksum(storageSize));

        eeprom.commit();
    }

    void set(SettingsField field, const Buffer& buffer) {
        assert(eeprom.getDataPtr());
        auto offset = field.calcOffset();
        auto maxLength = field.maxLength() < buffer.length() ? field.maxLength() : buffer.length();

        strncpy((char*)eeprom.getDataPtr() + offset, buffer.charBegin(), maxLength);
        eeprom[offset + field.maxLength() - 1] = '\0';
    }

    void setDerFile(SettingsField field, const Buffer& buffer) {
        assert(field.isDerFile());
        auto offset = field.calcOffset();

        for (u32 i = 0; i + 2 < field.maxLength() && i < buffer.length(); i++) {
            eeprom[offset + i + 2] = buffer[i];
        }
    }

    void setDerFileLength(SettingsField field, u16 value) {
        assert(field.isDerFile());
        assert(value <= (field.maxLength() - 2));
        auto offset = field.calcOffset();
        eeprom[offset + 1] = value >> 8;
        eeprom[offset] = value & 0xff;
    }

    template<typename U>
    void printConfiguration(U& stream) {
        assert(eeprom.getDataPtr());

        SettingsField::forEach([&](SettingsField field) {
            if (field.isDerFile()) {
                auto length = getDerFileLength(field);
                stream << "* " << field.name() << ": " << (!length ? "[default]" : "<custom-bytes>") << "\r\n";
            }
            // Hide password fields
            if (!field.isSecure()) {
                auto buffer= getCStringBuffer(field);
                stream << "* " << field.name() << ": " << buffer.charBegin() << "\r\n";
            }
            });
    }

    void erase() {
        auto storageSize = SettingsField::requiredStorage();
        for (u32 i = 0; i != storageSize; i++) {
            eeprom[i] = 0;
        }
        writeChecksum(storageSize, 0xff00ff00); // Set bad checksum
        eeprom.commit();
    }


private:

    u32 calcChecksum(u32 storageSize) {
        CRC32 checkSummer;
        checkSummer.enableYield();
        for (u32 i = 0; i != storageSize; i++) {
            checkSummer.add(eeprom[i]);
        }
        return checkSummer.getCRC();
    }

    u32 readChecksum(u32 storageSize) {
        return (eeprom[storageSize + 3] << 24) | (eeprom[storageSize + 2] << 16) | (eeprom[storageSize + 1] << 8) | eeprom[storageSize];
    }

    void writeChecksum(u32 storageSize, u32 value) {
        eeprom[storageSize + 3] = (value >> 24) & 0xFF;
        eeprom[storageSize + 2] = (value >> 16) & 0xFF;
        eeprom[storageSize + 1] = (value >> 8) & 0xFF;
        eeprom[storageSize] = value & 0xFF;
    }

    bool checkChecksum() {
        auto storageSize = SettingsField::requiredStorage();
        return calcChecksum(storageSize) == readChecksum(storageSize);
    }

    T& eeprom;
};

class MBusLinkFrame {
public:
    static constexpr u8 packetEndByte = 0x16;
    enum class Type : u8 { SingleChar, Short, Control, Long };

    MBusLinkFrame(Type type, u8 c = 0, u8 a = 0, u8 l = 0, Buffer p = { nullptr, 0 })
        : frameType(type), cField(c), aField(a), lField(l), payloadBuffer(p) {}

    template<typename T>
    static ErrorOr<MBusLinkFrame> decodeBuffer(SerialBufferReader<T>& reader) {
        Type type;

        TRYGET(typeField, reader.nextU8());
        switch (typeField) {
        case 0xe5: return { Type::SingleChar };
        case 0x10: type = Type::Short; break;
        case 0x68: type = Type::Control; break;
        default: return Error{ "Invalid transport frame type" };
        }

        if (type == Type::Short) {
            TRYGET(cField, reader.nextU8());
            TRYGET(aField, reader.nextU8());
            TRYGET(checksumField, reader.nextU8());
            TRY(reader.assertU8(packetEndByte));

            if (((cField + aField) & 0xFF) != checksumField) {
                return Error{ "Checksum missmatch" };
            }

            return { Type::Short, cField, aField };
        }

        TRYGET(lField, reader.nextU8());
        TRY(reader.assertU8(lField));
        TRY(reader.assertU8(0x68));

        TRYGET(cField, reader.nextU8());
        TRYGET(aField, reader.nextU8());

        TRYGET(userData, reader.slice(lField - 2));
        TRYGET(checksumField, reader.nextU8());
        TRY(reader.assertU8(packetEndByte));

        u8 checksum = cField + aField;
        for (auto b : userData) {
            checksum += b;
        }

        if (checksum != checksumField) {
            return Error{ "Checksum missmatch" };
        }

        return { lField == 3 ? Type::Control : Type::Long, cField, aField, lField, userData };
    }

    const Buffer& payload() const {
        return payloadBuffer;
    }

    bool isLongFrame() const {
        return frameType == Type::Long;
    }

private:
    Type frameType;
    u8 cField, aField, ciField, lField;
    Buffer payloadBuffer;
};


class MBusTransportFrame {
public:

    MBusTransportFrame(u8 c, Buffer p)
        : ciField(c), payloadBuffer(p) {}

    static ErrorOr<MBusTransportFrame> fromLinkFrame(const MBusLinkFrame& frame) {
        BufferReader reader{ frame.payload() };

        auto ciField = reader.nextU8();
        if (ciField & 0xE0) {
            return Error{ "Did not expect a separate mbus header" };
        }

        RETHROW(reader.assertU8(0x01), "Expected logical devide id to be 1"); // STSAP (management logical device id 1 of the meter)
        RETHROW(reader.assertU8(0x67), "Expected client id to be 103");       // DTSAP (consumer information push client id 103)

        return { ciField, reader.slice(-1) };
    }

    const Buffer& payload() const {
        return payloadBuffer;
    }

    bool isLastFrame() const {
        return ciField & 0x10;
    }

private:
    u8 ciField;
    Buffer payloadBuffer;
};

class DlmsApplicationFrame {
public:

    DlmsApplicationFrame(Buffer st, u32 l, u8 s, u32 f, Buffer p)
        : systemTitleBuffer(st), length(l), security(s), frameCounter(f), payloadBuffer(p) {}

    template<typename T>
    static ErrorOr<DlmsApplicationFrame> decodeBuffer(SerialBufferReader<T>& serialReader, Buffer& appDataBuffer) {
        u32 appDataBufferPos = 0;

        while (true) {
            TRYGET(linkFrame, MBusLinkFrame::decodeBuffer(serialReader));

            if (!linkFrame.isLongFrame()) {
                return Error{ "Expected long link frame" };
            }

            TRYGET(transportFrame, MBusTransportFrame::fromLinkFrame(linkFrame));
            appDataBuffer.insertAt(transportFrame.payload(), appDataBufferPos);
            appDataBufferPos += transportFrame.payload().length();

            if (transportFrame.isLastFrame()) {
                break;
            }
        }

        appDataBuffer.shrinkLength(appDataBufferPos);
        BufferReader appDataReader{ appDataBuffer };

        RETHROW(appDataReader.assertU8(0xdb), "Expected general glo ciphering for application frame"); // general-glo-ciphering

        auto systemTitleLength = appDataReader.nextU8();
        auto systemTitle = appDataReader.slice(systemTitleLength);

        u32 appDataLength = appDataReader.nextU8();
        switch (appDataLength) {
        case 0x81: appDataLength = appDataReader.nextU8(); break;
        case 0x82: appDataLength = appDataReader.nextU16(); break;
        default:
            if (appDataLength > 127) {
                return Error{ "Invalid application data length of application frame" };
            }
        }

        if (appDataLength != appDataReader.remainingBytes()) {
            return Error{ "Application frame data length does not match payload size" };
        }

        // Bit 0..3 -> Security suit id
        // Bit 4    -> Authentication
        // Bit 5    -> Encryption
        // Bit 6    -> Key_Set subfield (0 = Unicast, 1 = Broadcast)
        // Bit 7    -> Compression
        auto security = appDataReader.nextU8();

        // Why do 20 and 21 both describe aes 128 gcm with 96it iv?
        if (security != 0x20 && security != 0x21) {
            return Error{ "Expected encrypted data in application frame" };
        }

        auto frameCounter = appDataReader.nextU32();

        return { systemTitle, appDataLength, security, frameCounter, appDataReader.slice(-1) };
    }

    void decrypt(const Buffer& key) {
        auto gcm = GCM<AES128>{};

        assert(key.length() == gcm.keySize());

        gcm.clear();
        gcm.setKey(key.begin(), gcm.keySize());

        u8 initVector[12];
        memcpy(initVector, systemTitleBuffer.begin(), 8);
        initVector[8] = 0xFF & (frameCounter >> 24);
        initVector[9] = 0xFF & (frameCounter >> 16);
        initVector[10] = 0xFF & (frameCounter >> 8);
        initVector[11] = 0xFF & (frameCounter);

        gcm.setIV(initVector, 12);

        u8 authData[1] = { 0x30 };
        gcm.addAuthData(authData, 1);

        // Decrypt the data buffer in place
        gcm.decrypt(payloadBuffer.begin(), payloadBuffer.begin(), payloadBuffer.length());
    }

    const Buffer& payload() const {
        return payloadBuffer;
    }

private:
    Buffer systemTitleBuffer;
    u32 length;
    u8 security;
    u32 frameCounter;
    Buffer payloadBuffer;
};

class DlmsStructureNode {
public:
    enum class Type : u8 {
        None,
        Structure,
        OctetString,
        Enum,
        I8, I16, I32, I64,
        U8, U16, U32, U64
    };

    DlmsStructureNode* asStructure() {
        type = Type::Structure;
        next = nullptr;
        content.childrenList.begin = nullptr;
        content.childrenList.end = nullptr;
        return this;
    }

    DlmsStructureNode* asInteger(Type newType, u64 value) {
        type = newType;
        content.value = value;
        next = nullptr;
        assert(isInteger());
        return this;
    }

    DlmsStructureNode* asOctetString(Buffer buffer) {
        type = Type::OctetString;
        assert(buffer.length());
        content.buffer = buffer;
        next = nullptr;
        return this;
    }

    DlmsStructureNode* asEnum(u8 id) {
        type = Type::Enum;
        content.value = id;
        next = nullptr;
        return this;
    }

    Buffer stringBuffer() const {
        assert(type == Type::OctetString);
        return content.buffer;
    }

    u64 u64Value() const {
        assert(isInteger());
        return content.value;
    }

    u8 enumValue() const {
        assert(type == Type::Enum);
        return (u8)content.value;
    }

    void append(DlmsStructureNode* node) {
        assert(isStructure());
        assert(!node->next); // "Cannot append dsml structure node which is already part of another strcutre node"

        if (!content.childrenList.begin) {
            content.childrenList.begin = node;
        }
        else {
            content.childrenList.end->next = node;
        }

        content.childrenList.end = node;
    }

    bool isStructure() const { return type == Type::Structure; }
    bool isOctetString() const { return type == Type::OctetString; }
    bool isEnum() const { return type == Type::Enum; }
    bool isInteger() const {
        return type == Type::I8 || type == Type::I16 || type == Type::I32 || type == Type::I64 ||
            type == Type::U8 || type == Type::U16 || type == Type::U32 || type == Type::U64;
    }

    class Iterator {
    public:
        explicit Iterator(const DlmsStructureNode* node = nullptr) : ptr(node) {}

        const DlmsStructureNode& get() { assert(ptr); return *ptr; }
        const DlmsStructureNode& operator*() { assert(ptr); return *ptr; }
        const DlmsStructureNode* operator->() { assert(ptr); return ptr; }

        bool isEnd() const { return !ptr; }
        bool hasNext() const { return ptr && ptr->next; }
        void next() {
            assert(!isEnd());
            ptr = ptr->next;
        }
        void operator++() { next(); }
        bool operator==(const Iterator& other) const { return ptr == other.ptr; }
        bool operator!=(const Iterator& other) const { return ptr != other.ptr; }
    private:
        const DlmsStructureNode* ptr;
    };

    Iterator begin() const { return isStructure() ? Iterator(content.childrenList.begin) : Iterator(); }
    Iterator end() const { return Iterator(); }

    template<typename T>
    void print(T& stream) const {
        char indentString[17];  // Space for up to 8 indents and one \0
        indentString[0] = '\0';
        printImpl(stream, indentString, 0, 8);
    }

private:
    template<typename T>
    void printImpl(T& stream, char* indentString, u32 currentIndent, u32 maxIndent) const {
        stream << indentString;

        bool doIndent;
        switch (type) {
        case Type::None: stream << "<Empty>\r\n"; break;
        case Type::Enum: stream << "Enum: " << (int)(u8)content.value << "\r\n"; break;
        case Type::U8: stream << "u8: " << (int)(u8)content.value << "\r\n"; break;
        case Type::U16: stream << "u16: " << (u16)content.value << "\r\n"; break;
        case Type::U32: stream << "u32: " << (u32)content.value << "\r\n"; break;
        case Type::U64: stream << "u64: " << (u64)content.value << "\r\n"; break;
        case Type::I8: stream << "i8: " << (int)(i8)content.value << "\r\n"; break;
        case Type::I16: stream << "i16: " << (i16)content.value << "\r\n"; break;
        case Type::I32: stream << "i32: " << (i32)content.value << "\r\n"; break;
        case Type::I64: stream << "i64: " << (i64)content.value << "\r\n"; break;
        case Type::OctetString:
            stream << "OctetString [" << content.buffer.length() << "]: ";
            content.buffer.printHex(stream);
            break;
        case Type::Structure:
            stream << "Structure: \r\n";
            doIndent = currentIndent < maxIndent;
            if (doIndent) {
                indentString[currentIndent * 2 + 0] = ' ';
                indentString[currentIndent * 2 + 1] = ' ';
                indentString[currentIndent * 2 + 2] = '\0';
                currentIndent++;
            }
            for (auto& childNode : *this) {
                childNode.printImpl(stream, indentString, currentIndent, maxIndent);
            }
            if (doIndent) {
                currentIndent--;
                indentString[currentIndent * 2] = '\0';
            }
            break;
        default:
            assert(false); // "Cannot print dsml structure node with unknown type"
        }
    }

    union {
        struct {
            DlmsStructureNode* begin;
            DlmsStructureNode* end;
        } childrenList;             // Structure
        Buffer buffer;              // OctetString
        u64 value;                  // Integer, Enum
    } content{ .value = 0 };

    Type type{ Type::None };
    DlmsStructureNode* next{ nullptr };
};

class DlmsNodeAllocator {
public:
    DlmsNodeAllocator() = default;
    DlmsNodeAllocator(DlmsNodeAllocator&& other)
        : begin(NoStl::move(other.begin)), end(other.end) {
        other.end = nullptr;
    }

    DlmsStructureNode* allocate() {
        if (!end || end->slotsUsed >= 64) {
            NoStl::UniquePtr<Bucket> newBucket{ new Bucket() };
            auto bucketPtr = newBucket.get();
            if (!end) {
                begin = NoStl::move(newBucket);
            }
            else {
                end->next = NoStl::move(newBucket);
            }
            end = bucketPtr;
        }

        auto* value = end->items + end->slotsUsed;
        end->slotsUsed++;
        return value;
    }

    void freeAll() {
        end = nullptr;
        begin.reset();
    }

    virtual ~DlmsNodeAllocator() {
        freeAll();
    }

private:
    struct Bucket {
        DlmsStructureNode items[64];
        u8 slotsUsed{ 0 };
        NoStl::UniquePtr<Bucket> next{ nullptr };
    };

    NoStl::UniquePtr<Bucket> begin;
    Bucket* end{ nullptr };
};

class DlmsReader {
public:
    explicit DlmsReader(const Buffer& buffer)
        : reader(buffer) {}

    void skipHeader() {
        reader.skip(6 + 12); // 6 unknown byte + 1 full timestamp
    }

    ErrorOr<DlmsStructureNode*> readNext(DlmsNodeAllocator& allocator) {
        switch (reader.peakU8()) {
        case 0x02: return readStructure(allocator); // Structure
        case 0x09: return readOctetString(allocator); // Octet String
        case 0x0F: return readInteger(allocator); // i8
        case 0x10: return readInteger(allocator); // i16
        case 0x05: return readInteger(allocator); // i32
        case 0x14: return readInteger(allocator); // i64
        case 0x11: return readInteger(allocator); // u8
        case 0x12: return readInteger(allocator); // u16
        case 0x06: return readInteger(allocator); // u32
        case 0x15: return readInteger(allocator); // u64
        case 0x16: return readEnum(allocator); // Unit Enum
        default:
            debugOut << "bad byte" << (int)reader.peakU8() << debugEndl;
            return Error{ "Unsupported dlms structure node type" };
        }
    }

    ErrorOr<DlmsStructureNode*> readStructure(DlmsNodeAllocator& allocator) {
        // debugOut << "found struct" << debugEndl;
        TRY(reader.assertU8(0x02));

        auto* node = allocator.allocate()->asStructure();

        // Could this be a multi-byte value for structures containing more than 256 items?
        auto itemCount = reader.nextU8();
        while (itemCount--) {
            TRYGET(childNode, readNext(allocator));
            node->append(childNode);
        }

        return node;
    }

    ErrorOr<DlmsStructureNode*> readInteger(DlmsNodeAllocator& allocator) {
        DlmsStructureNode::Type nodeType;
        u64 value;

        auto intType = reader.nextU8();
        switch (intType) {
        case 0x0F: nodeType = DlmsStructureNode::Type::I8;   value = reader.nextU8();  break;
        case 0x10: nodeType = DlmsStructureNode::Type::I16;  value = reader.nextU16(); break;
        case 0x05: nodeType = DlmsStructureNode::Type::I32;  value = reader.nextU32(); break;
        case 0x14: nodeType = DlmsStructureNode::Type::I64;  value = reader.nextU64(); break;
        case 0x11: nodeType = DlmsStructureNode::Type::U8;   value = reader.nextU8();  break;
        case 0x12: nodeType = DlmsStructureNode::Type::U16;  value = reader.nextU16(); break;
        case 0x06: nodeType = DlmsStructureNode::Type::U32;  value = reader.nextU32(); break;
        case 0x15: nodeType = DlmsStructureNode::Type::U64;  value = reader.nextU64(); break;
        default:
            return Error{ "Invalid dlms interger type" };
        }

        //debugOut << "found integer (" << (int)intType << ") " << value << debugEndl;

        return allocator.allocate()->asInteger(nodeType, value);
    }

    ErrorOr<DlmsStructureNode*> readOctetString(DlmsNodeAllocator& allocator) {
        TRY(reader.assertU8(0x09));

        // Could this be a multi-byte value for octet sttings containing more than 255 bytes?
        auto length = reader.nextU8();
        auto string = reader.slice(length);

        //debugOut << "found string" << debugEndl;
        //string.printHex(std::cout);

        return allocator.allocate()->asOctetString(string);
    }

    ErrorOr<DlmsStructureNode*> readEnum(DlmsNodeAllocator& allocator) {
        TRY(reader.assertU8(0x16));

        //debugOut << "found enum " << (int)reader.peakU8() << debugEndl;
        return allocator.allocate()->asEnum(reader.nextU8());
    }

private:
    BufferReader reader;
};


class CosemDataField {
public:
    enum Type : u8 {
        None = 0,
        ActiveEnergyAPlus,
        ActiveEnergyAMinus,
        InstantaneousPowerPPlus,
        InstantaneousPowerPMinus,
        VoltageL1,
        VoltageL2,
        VoltageL3,
        CurrentL1,
        CurrentL2,
        CurrentL3,
        PowerFactor,
        NumberOfFields
    };

    CosemDataField(Type t = None) : type(t) {}

    const char* name() const {
        return fieldDescriptions[type].name;
    }

    const char* endpoint() const {
        return fieldDescriptions[type].endpoint;
    }

    bool operator ==(Type t) const {
        return type == t;
    }

    static NoStl::Optional<CosemDataField> fromCosemId(const Buffer& buffer) {
        BufferReader reader{ buffer };
        auto id = reader.nextUpToU64();
        for (u32 i = 1; i != NumberOfFields; i++) {
            if (id == fieldDescriptions[i].id) {
                return { fieldDescriptions[i].type };
            }
        }

        return {};
    }

private:
    struct FieldDescription {
        const Type type;
        const u64 id;
        const char* const name;
        const char* const  endpoint;
    };

    static const FieldDescription fieldDescriptions[NumberOfFields];
    static const u32 fieldDescriptionCount;

    Type type;
};

const CosemDataField::FieldDescription CosemDataField::fieldDescriptions[NumberOfFields] = {
    {None, 0x00, "<none>", ""},
    {ActiveEnergyAPlus, 0x0100010800FF, "active energy A+", "w_p"},
    {ActiveEnergyAMinus, 0x0100020800FF, "active energy A-", "w_n"},
    {InstantaneousPowerPPlus, 0x0100010700FF, "instantaneous power P+", "p_p"},
    {InstantaneousPowerPMinus, 0x0100020700FF, "instantaneous power P-", "p_n"},
    {VoltageL1, 0x0100200700FF, "voltage L1", "u1"},
    {VoltageL2, 0x0100340700FF, "voltage L2", "u2"},
    {VoltageL3, 0x0100480700FF, "voltage L3", "u3"},
    {CurrentL1, 0x01001F0700FF, "current L1", "i1"},
    {CurrentL2, 0x0100330700FF, "current L2", "i2"},
    {CurrentL3, 0x0100470700FF, "current L3", "i3"},
    {PowerFactor, 0x01000D0700FF, "power factor", "phi"}
};


class CosemScaledValue {
public:
    CosemScaledValue() = default;

    CosemScaledValue(CosemDataField f, i32 v, i8 s, u8 u)
        : label{ f }, value{ v }, scale{ s }, unit{ u } {}

    static NoStl::Optional<CosemScaledValue> fromStructureNodes(DlmsStructureNode::Iterator& it) {
        assert(it->isOctetString());
        auto type = CosemDataField::fromCosemId(it->stringBuffer());
        if (!type) { return {}; }

        ++it;
        if (it.isEnd() || !it->isInteger()) { return {}; }
        auto value = (i32)it->u64Value(); // FIXME: This cast is probably bad

        ++it;
        if (it.isEnd() || !it->isStructure()) { return {}; }
        auto innerIt = it->begin();
        if (innerIt.isEnd() || !innerIt->isInteger()) { return {}; }
        auto scale = (i8)innerIt->u64Value();

        ++innerIt;
        if (innerIt.isEnd() || !innerIt->isEnum()) { return {}; }
        auto unit = innerIt->enumValue();

        return { type.value(), value, scale, unit };
    }

    template<typename T>
    void print(T& stream) const {
        stream << label.name() << ": " << value;

        if (scale) {
            stream << " x10^" << (int)scale;
        }

        stream << " [" << (int)unit << "]\r\n";
    }

    const CosemDataField& fieldLabel() const {
        return label;
    }

    void serialize(BufferPrinter& printer) const {
        printer.print(value, 0, scale);
    }

private:
    CosemDataField label;
    i32 value;
    i8 scale;
    u8 unit;
};

class CosemTimestamp {
public:
    CosemTimestamp() = default;

    CosemTimestamp(u16 y, u8 m, u8 d, u8 w, u8 h, u8 mm, u8 s, i16 tz)
        : year{ y }, month{ m }, day{ d }, weekday{ w }, hours{ h }, minutes{ mm }, seconds{ s }, timezoneOffsetMinutes{ tz } {}

    static ErrorOr<CosemTimestamp> decodeBuffer(const Buffer& buffer) {
        BufferReader reader{ buffer };
        TRY(reader.assertRemaining(12));

        u16 year = reader.nextU16();
        u8 month = reader.nextU8();
        u8 day = reader.nextU8();
        u8 weekday = reader.nextU8();
        u8 hours = reader.nextU8();
        u8 minutes = reader.nextU8();
        u8 seconds = reader.nextU8();
        reader.skip(); // Unknown byte
        i16 timezoneOffsetMinutes = ((i16)reader.nextU16()) * -1; // Timezone offset is negative for some reason
        reader.skip(); // Unknown byte

        return { year, month, day, weekday, hours, minutes, seconds, timezoneOffsetMinutes };
    }

    template<typename T>
    void print(T& stream) const {
        i16 offsetHours = timezoneOffsetMinutes / 60;
        i16 offsetMinutes = timezoneOffsetMinutes % 60;

        stream << (int)day << '.' << (int)month << '.' << year << ' ';
        stream << (int)hours << ':' << (int)minutes << ':' << (int)seconds << " (+/- " << offsetHours << ':' << offsetMinutes << ")\r\n";
    }

    void serialize(BufferPrinter& printer) const {
        // Print date in ISO format
        printer.print(year, 4).printChar('-').print(month, 2).printChar('-').print(day, 2);
        printer.printChar('T').print(hours, 2).printChar(':').print(minutes, 2).printChar(':').print(seconds, 2);

        if (!timezoneOffsetMinutes) {
            printer.printChar('Z');
            return;
        }

        auto offset = timezoneOffsetMinutes;
        if (offset < 0) {
            printer.printChar('-');
            offset = offset * -1;
        }
        else {
            printer.printChar('+');
        }

        auto offsetHours = offset / 60;
        auto offsetMinutes = offset % 60;
        printer.print(offsetHours, 2).printChar(':').print(offsetMinutes, 2);
    }

private:
    u16 year;
    u8 month;
    u8 day;
    u8 weekday;
    u8 hours;
    u8 minutes;
    u8 seconds;
    i16 timezoneOffsetMinutes;
};

class CosemMeterNumber {
public:
    CosemMeterNumber() {
        data[0] = '\0';
    }

    CosemMeterNumber(const Buffer& buffer) {
        u32 numBytes = buffer.length() > 12 ? 12 : buffer.length();
        memcpy(data, buffer.begin(), numBytes);
        data[numBytes] = '\0';
    }

    const char* cString() const { return data; }
private:
    char data[13];
};

class CosemData {
public:
    CosemData() = default;

    static ErrorOr<CosemData> fromApplicationFrame(const DlmsApplicationFrame& applicationFrame) {
        DlmsReader reader{ applicationFrame.payload() };

        reader.skipHeader();

        DlmsNodeAllocator allocator;
        TRYGET(rootNode, reader.readNext(allocator));
        // rootNode->print(std::cout);

        if (!rootNode->isStructure()) {
            return Error{ "Expected structure node as root of dslm data" };
        }
        auto it = rootNode->begin();

        TRYGET(timestamp, CosemTimestamp::decodeBuffer(it->stringBuffer()));

        CosemData cosemData;
        cosemData.timestamp = timestamp;
        ++it;

        for (; !it.isEnd(); ++it) {
            if (!it->isOctetString()) {
                // Ignore value
                continue;
            }

            // Meter number is the last octet string in the structure
            if (!it.hasNext()) {
                cosemData.meterNumber = { it->stringBuffer() };
                continue;
            }

            auto scaledValue = CosemScaledValue::fromStructureNodes(it);
            if (scaledValue) {
                cosemData.addField(scaledValue.value());
            }
        }

        return cosemData;
    }

    template<typename T>
    void print(T& stream) const {
        stream << "Meter Number: " << meterNumber.cString() << "\r\n";
        stream << "Timestamp: ";
        timestamp.print(stream);

        for (u32 i = 0; i != fieldCount; i++) {
            fields[i].print(stream);
        }
    }

    void mqttPublish(MqttSender::FieldTransmission& transmission) {
        transmission.appendField(meterNumber);
        transmission.appendField(timestamp);

        for (u32 i = 0; i != fieldCount; i++) {
            transmission.appendField(fields[i]);
        }
    }

private:
    void addField(const CosemScaledValue& val) {
        if (fieldCount < CosemDataField::NumberOfFields) {
            fields[fieldCount++] = val;
        }
    }

    CosemTimestamp timestamp;
    CosemMeterNumber meterNumber;
    u32 fieldCount{ 0 };
    CosemScaledValue fields[CosemDataField::NumberOfFields];
};



template<typename T>
class MqttSenderImplBase : public MqttSender {
public:
    MqttSenderImplBase(T& cl, const char* basePath, const char* client, const char* user, const char* pwd)
        : MqttSender(), client{ cl }, basePathLength{ strlen(basePath) } {

        strncpy(clientId, client, 21);
        clientId[20] = '\0';

        strncpy(username, user, 21);
        username[20] = '\0';

        strncpy(password, pwd, 21);
        password[20] = '\0';

        assert(basePathLength < maxPathLength - 20);
        strcpy(path, basePath);
        if (!basePathLength || path[basePathLength - 1] != '/') {
            path[basePathLength] = '/';
            basePathLength++;
        }
    }

    virtual ErrorOr<void> connect() final {
        debugOut << "Connecting to mqtt broker";

        u32 counter = 0;
        while (!client.connected()) {
            client.connect(clientId, username, password);
            if (counter++ > 300) {
                debugOut << debugEndl;
                return Error{ "Could not connect to mqtt broker" };
            }

            debugOut << '.';
            delay(100);
        }

        debugOut << debugEndl;
        return {};
    }

protected:
    void setEndpointName(const char* endpointName) {
        auto nameLength = strlen(endpointName);
        assert(nameLength + basePathLength < maxPathLength); // Mqtt path too long
        memcpy(path + basePathLength, endpointName, nameLength + 1); // Copy including the null byte
    }

    T& client;
    static constexpr u32 maxPathLength = 120;  // 100 for base path + 20 for endpoint name
    char clientId[21];
    char username[21];
    char password[21];
    char path[maxPathLength];
    u32 basePathLength;
};

template<typename T>
class MqttRawSender final : public MqttSenderImplBase<T> {
public:
    using MqttSenderImplBase<T>::MqttSenderImplBase;

    virtual void publishRaw(const Buffer& rawData) override {
        this->setEndpointName("raw");
        this->client.publish(this->path, rawData.begin(), rawData.length(), false);
    }

protected:
    virtual void appendField(const CosemTimestamp& timestamp) override {}
    virtual void appendField(const CosemScaledValue& value) override {}
    virtual void appendField(const CosemMeterNumber&) override {}
    virtual void appendField(const char* name, const char* value) override {}
    virtual void endFieldTransmission() override {}
};

template<typename T>
class MqttTopicSender final : public MqttSenderImplBase<T> {
public:
    using MqttSenderImplBase<T>::MqttSenderImplBase;

    virtual void publishRaw(const Buffer&) override {}

protected:
    virtual void appendField(const CosemTimestamp& timestamp) override {
        LocalBuffer<100> printingBuffer;
        BufferPrinter printer{ printingBuffer };
        timestamp.serialize(printer);
        this->setEndpointName("timestamp");

        this->client.publish(this->path, printer.cString(), false);
    }

    virtual void appendField(const CosemMeterNumber& meterNumber) override {
        this->setEndpointName("meternumber");

        this->client.publish(this->path, meterNumber.cString(), false);
    }

    virtual void appendField(const CosemScaledValue& value) override {
        LocalBuffer<100> printingBuffer;
        BufferPrinter printer{ printingBuffer };
        value.serialize(printer);
        this->setEndpointName(value.fieldLabel().endpoint());

        this->client.publish(this->path, printer.cString(), false);
    }

    virtual void appendField(const char* name, const char* value) override {}

    virtual void endFieldTransmission() override {}
};

template<typename T>
class MqttJsonSender final : public MqttSenderImplBase<T> {
public:
    MqttJsonSender(T& cl, const char* basePath, const char* client, const char* user, const char* password)
        : MqttSenderImplBase<T>(cl, basePath, client, user, password) {
        init();
    }

    virtual void publishRaw(const Buffer&) override {}

protected:
    virtual void appendField(const CosemTimestamp& timestamp) override {
        beginField("timestamp");
        printer.printChar('"');
        timestamp.serialize(printer);
        printer.printChar('"');
    }

    virtual void appendField(const CosemMeterNumber& meterNumber) override {
        appendField("meternumber", meterNumber.cString());
    }

    virtual void appendField(const CosemScaledValue& value) override {
        beginField(value.fieldLabel().endpoint());
        value.serialize(printer);
    }

    void appendField(const char* name, const char* value) override {
        beginField(name);
        printer.printChar('"');
        printer.print(value);
        printer.printChar('"');
    }

    void init() {
        printer.clear();
        printer.printChar('{');
        hasAtLeastOneField = false;
    }

    void beginField(const char* name) {
        if (hasAtLeastOneField) {
            printer.printChar(',');
        }

        hasAtLeastOneField = true;
        printer.printChar('"').print(name).printChar('"').printChar(':');
    }

    virtual void endFieldTransmission() override {
        printer.printChar('}');

        this->setEndpointName("json");

        debugOut << "Sending JSON -> '" << this->path << "'" << debugEndl;
        this->client.publish(this->path, printer.cString(), false);
        debugOut << "Sent JSON\r\n";

        init();
    }

private:
    constexpr static u32 bufferSize = CosemDataField::NumberOfFields * 25 + 100;
    LocalBuffer<bufferSize> printBuffer;
    BufferPrinter printer{ printBuffer };
    bool hasAtLeastOneField{ false };
};


/**
* Mock a bunch of different classes, functions and globals from the Arduino Libraries,
* to make the same code compile on a Desktop machine. There compilation is way faster
* and a real debugger is available, wich improves developer (my) happiness.
**/
#ifndef ARDUINO

#define SERIAL_8N1 0x00
#define SERIAL_8E1 0x01
#define D0     0x00
#define OUTPUT 0x00
#define LOW    0x00
#define HIGH   0x01
#define WL_CONNECTED 0x0A
#define PROGMEM

class DummyIPAddress {
public:
    DummyIPAddress(u8 a, u8 b, u8 c, u8 d) : octets{ a, b, c, d } {}

    u8 operator[](u8 x) const {
        return octets[x];
    }
private:
    u8 octets[4];
};

std::ostream& operator<<(std::ostream& o, const DummyIPAddress addr) {
    o << (int)addr[0] << '.' << (int)addr[1] << '.' << (int)addr[2] << '.' << (int)addr[3];
    return o;
}

class DummySerial {
public:
    DummySerial(OwnedBuffer buf) : buffer(NoStl::move(buf)) {
        stdinHandle = GetStdHandle(STD_INPUT_HANDLE);
    }

    void begin(u32, u32) { didBegin = true; }
    void end() { didBegin = false; }
    void setTimeout(u32) {}

    u32 available() {
        if (!readFromBuffer) {
            return WaitForSingleObject(stdinHandle, 0) == WAIT_OBJECT_0;
        }

        return index < buffer.length();
    }

    void setReadSourceFromBuffer(bool b) {
        readFromBuffer = b;
    }

    u8 read() {
        assert(didBegin);
        if (!readFromBuffer) {
            return _getch();
        }

        return buffer.at(index++);
    }

    u32 readBytes(u8* writePtr, u32 bytesToRead) {
        return readBytes((char*)writePtr, bytesToRead);
    }

    u32 readBytes(char* writePtr, u32 bytesToRead) {
        assert(didBegin);
        if (!readFromBuffer) {
            for (u32 i = 0; i < bytesToRead; i++) {
                *(writePtr++) = read();
            }
            return bytesToRead;
        }

        bytesToRead = limitBytesToRead(bytesToRead);
        memcpy(writePtr, buffer.begin() + index, bytesToRead);
        index += bytesToRead;
        return bytesToRead;
    }

    u32 readBytesUntil(char terminator, char* writePtr, u32 maxBytesToRead) {
        assert(didBegin);
        if (!readFromBuffer) {
            for (u32 i = 0; i != maxBytesToRead; i++) {
                auto c = read();
                if (c == terminator) {
                    return i;
                }
                writePtr[i] = c;
            }
            return maxBytesToRead;
        }

        maxBytesToRead = limitBytesToRead(maxBytesToRead);
        for (u32 i = 0; i != maxBytesToRead; i++) {
            u8 byte = buffer.at(index++);
            if (byte == (u8)terminator) {
                return i;
            }

            writePtr[i] = byte;
        }

        return maxBytesToRead;
    }

    u32 println(const char* str) {
        assert(didBegin);
        std::cout << str << std::endl;
        return strlen(str);
    }

    u32 print(const char* str) {
        assert(didBegin);
        std::cout << str;
        return strlen(str);
    }

    u32 print(char c) {
        assert(didBegin);
        std::cout << c;
        return 1;
    }

    u32 print(i32 val) {
        assert(didBegin);
        std::cout << val;
        return 1;
    }

    u32 print(u32 val) {
        assert(didBegin);
        std::cout << val;
        return 1;
    }

    u32 print(const DummyIPAddress& addr) {
        assert(didBegin);
        std::cout << addr;
        return 1;
    }

    void write(char c) {
        assert(didBegin);
        std::cout << c;
    }

    void flush() {}

private:
    u32 limitBytesToRead(u32 bytesToRead) const {
        return index + bytesToRead > buffer.length() ? buffer.length() - index : bytesToRead;
    }

    bool readFromBuffer{ false };
    bool didBegin{ false };

    u32 index{ 0 };
    OwnedBuffer buffer;
    HANDLE stdinHandle;
};

class DummyWiFiClient {
public:
    void stop() {}
};

class DummyWiFiClientSecure : public DummyWiFiClient {
public:
    void setFingerprint(const char* hash) {
        std::cout << "[!] Secure client: Allow certificate with fingerprint: " << hash << std::endl;
    }
};

class DummyPubSubClient {
public:
    bool connected() {
        return isConnected;
    }

    void connect(const char* id, const char* user, const char* pwd) {
        std::cout << "[!] Mqtt-Connect as '" << id << "' '" << user << "' with password '" << pwd << "'\r\n";
        isConnected = true;
    }

    void publish(const char* path, const char* data, bool x) {
        std::cout << "[!] Mqtt-Publish '" << path << "' -> string: '" << data << "'\r\n";
    }

    void publish(const char* path, const u8* data, u32 length, bool x) {
        std::cout << "Mqtt-Publish '" << path << "' -> buffer: \r\n";
        Buffer buffer{ const_cast<u8*>(data), length }; // Ugly const cast
        buffer.printHex(std::cout);
    }

    void setBufferSize(u32) {}

    void setServer(const char* address, u32 port) {
        std::cout << "[!] Mqtt set server: " << address << " " << port << std::endl;
    }

    void setClient(DummyWiFiClient&) {}

private:
    bool isConnected{ false };
};

class DummyEEPROM {
public:

    explicit DummyEEPROM(const char* entries[], bool goodChecksum) : buffer{ Buffer::allocate(4096) } {
        SettingsField::forEach([&](SettingsField field) {
            auto offset = field.calcOffset();
            memcpy((char*)buffer.begin() + offset, entries[field.enumType()], field.maxLength());
            std::cout << "[!] EEPROM - Inserting field '" << field.name() << "' at offset " << offset << std::endl;
            });

        auto len = SettingsField::requiredStorage();
        CRC32 summer;
        for (u32 i = 0; i < len; i++) {
            summer.add(buffer.at(i));
        }
        auto checksum = goodChecksum ? summer.getCRC() : summer.getCRC() + 1; // Deliberatly set a bad checksum
        std::cout << "[!] EEPROM - Calculated CRC32: " << checksum << std::endl;
        buffer[len + 3] = (checksum >> 24) & 0xFF;
        buffer[len + 2] = (checksum >> 16) & 0xFF;
        buffer[len + 1] = (checksum >> 8) & 0xFF;
        buffer[len] = checksum & 0xFF;
    }

    void begin(u32 size) { didBegin = true; }

    void end() {
        std::cout << "[!] EEPROM ended\r\n";
        didBegin = false;
        buffer.free();
    }

    void commit() {
        std::cout << "[!] EEPROM commit\r\n";
    }

    u8& operator[](u32 idx) {
        assert(buffer.begin());
        assert(didBegin);
        return buffer[idx];
    }

    u8 operator[](u32 idx) const {
        assert(buffer.begin());
        assert(didBegin);
        return buffer[idx];
    }

    u8* getDataPtr() {
        return buffer.begin();
    }

private:
    OwnedBuffer buffer;
    bool didBegin{ false };
};

class DummyWifi {
public:

    u32 status() {
        return statusCounter++;
    }

    void hostname(const char*) {}

    DummyIPAddress localIP() const { return { 1,2,3,4 }; }
    i8 RSSI() const { return -83; }

    void begin(const char* ssid, const char* pwd) {
        std::cout << "[!] WIFI ssid: '" << ssid << "' password: '" << pwd << "'\r\n";
    }

private:
    u32 statusCounter{ 0 };
};

class DummyServerSessions {};

class DummyX509List {
public:
    DummyX509List(const u8*, u32) {}
    DummyX509List(const char*) {}
};

class DummyPrivateKey {
public:
    DummyPrivateKey(const u8*, u32) {}
    DummyPrivateKey(const char*) {}
};

class DummyWiFiServerSecure {
public:
    void setRSACert(DummyX509List*, DummyPrivateKey*) {
        std::cout << "[!] WebServer: Set certificate and private key" << std::endl;
    }

    void setCache(DummyServerSessions*) {}
};

class DummyWebServerSecure {
public:
    DummyWebServerSecure(u16 port) {}

    void begin() {
        std::cout << "[!] WebServer: Begin" << std::endl;
    }

    DummyWiFiServerSecure getServer() {
        return {};
    }

    template<typename T>
    void on(const char*, const T&) {}
    
    template<typename T>
    void onNotFound(const T&) {}

    void send(u32 status, const char*, const char*) {}

    void handleClient() {}

    void stop() {}
    void close() {}
};

void delay(u32) {}
void pinMode(u32, u32) {}
void digitalWrite(u32, u32) {}



/** Globals **/

// M-bus link frame (example provided by EVN)
auto serialDataFrame = Buffer::fromHexString(
    "68FAFA6853FF000167DB084B464D6750"
    "00000981F8200000002388D5AB4F9751"
    "5AAFC6B88D2F85DAA7A0E3C0C40D0045"
    "35C397C9D037AB7DBDA3291076154448"
    "94A1A0DD7E85F02D496CECD3FF46AF5F"
    "B3C9229CFE8F3EE4606AB2E1F409F36A"
    "AD2E50900A4396FC6C2E083F373233A6"
    "9616950758BFC7D63A9E9B6E99E21B2C"
    "BC2B934772CA51FD4D69830711CAB1F8"
    "CFF25F0A329337CBA51904F0CAED88D6"
    "1968743C8454BA922EB00038182C22FE"
    "316D16F2A9F544D6F75D51A4E92A1C4E"
    "F8AB19A2B7FEAA32D0726C0ED80229AE"
    "6C0F7621A4209251ACE2B2BC66FF0327"
    "A653BB686C756BE033C7A281F1D2A7E1"
    "FA31C3983E15F8FD16CC5787E6F51716"
    "6814146853FF110167419A3CFDA44BE4"
    "38C96F0E38BF83D98316"
);

const char* eepromInitData[] = {
    "some-wifi",         // WifiSSID
    "a-secure-password", // WifiPassword
    "192.168.1.1",       // MqttBrokerAddress
    "1883",              // MqttBrokerPort
    "0123456789ABCDEF0123456789ABCDEF01234567", // MqttCertificateFingerprint
    "username",          // MqttBrokerUser
    "user-passphrase",   // MqttBrokerPassword
    "client-id",         // MqttBrokerClientId
    "a/base/path",       // MqttBrokerPath
    "2",                 // MqttMessageMode
    "36C66639E48A8CA4D6BC8B282A793BBB", // DslmCosemDecryptionKey (example provided by EVN)
    "\0\0\0",            // WebServerSSLCertificate
    "\0\0\0",            // WebServerSSLKey
};

using WiFiClient = DummyWiFiClient;
using WiFiClientSecure = DummyWiFiClientSecure;

namespace BearSSL {
    using ESP8266WebServerSecure = DummyWebServerSecure;
    using X509List = DummyX509List;
    using PrivateKey = DummyPrivateKey;
}

DummyEEPROM EEPROM{ eepromInitData, true };

DummySerial Serial{ NoStl::move(serialDataFrame.value()) };
DummyWifi WiFi;
NoStl::UniquePtr<WiFiClient> wifiClient;
DummyPubSubClient pubsubClient;

DummyServerSessions serverSessionsCache;
NoStl::UniquePtr<DummyX509List> webServerCertificate;
NoStl::UniquePtr<DummyPrivateKey> webServerPrivateKey;
NoStl::UniquePtr<DummyWebServerSecure> webServer;

void setup();
void loop();


int main()
{

    setup();

    Serial.setReadSourceFromBuffer(true);

    loop();

    return 0;
}

#else

NoStl::UniquePtr<WiFiClient> wifiClient;
PubSubClient pubsubClient{};

static constexpr auto serverSessionsStorageCount = 3;
BearSSL::ServerSession serverSessionsStorage[serverSessionsStorageCount];
BearSSL::ServerSessions serverSessionsCache{ serverSessionsStorage, serverSessionsStorageCount };

NoStl::UniquePtr<BearSSL::X509List> webServerCertificate;
NoStl::UniquePtr<BearSSL::PrivateKey> webServerPrivateKey;
NoStl::UniquePtr<BearSSL::ESP8266WebServerSecure> webServer;

#endif

static const char webServerDefaultSSLPrivateKeyData[] PROGMEM=
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQDLvMyy8rvWwMmr\n"
    "GrcronFVQ7ReXTAhzAjdlCyo2HQ39WDwRAJb26clRRL/rakw8EpGQS0we4pamhBB\n"
    "HmR4Mb2lT9Q64ZGMu8tEOYxBr1uYM1PmkEfwFq6w6x2C/oeY+arMdSOa/KcnYuUn\n"
    "JyboYqMhCECWPJzCQJMX3iayguBSa2bcVGqxaXevdLAeLNdavwh5F0AvBfGY0agU\n"
    "6q8RUlHKRLMqBA7n0ZGnpAC1gWFuzQs9tgMu0zDdOeJ2zbOVPXDBizYgsvBL9GjK\n"
    "MRoWJI2nulHLE8F72b0PaGscFJ9XquOMVoo4ldHhOv/3VxdovkahZSLtwA6EI4RL\n"
    "F8SepC4ZAgMBAAECggEBAJZd3LJCBjKEjRL0n7XbqUulsYxnuKto/C4VOzTOtE/M\n"
    "kWQivZ7wKZePOGttz05oOllJp0F+HGmsBU0aUkqHY5GLrnZanuLAg0/yLTsZYj+d\n"
    "ulGTsRRYmUvH6zsQAiH8Onu2BLZRvEiMa9YOxl+C1ST/AzQevg98O1PFSMg9YbRR\n"
    "cTcOVmfufodZaKWCYRjNhhuuUxP57HB/VWnKvvErw2hAwOa3kTrOK/qMcH7xP7RA\n"
    "PRWJqot3FDw7tlzMXptvJHuBamLQ3lErUvlz3xxxcZ6z2AMBtZCWay88v/Lm5Dqd\n"
    "o4o9e9NDmaDWWN8zErFdsiTAEfQXhewyGtD/BsFXo9ECgYEA5VoSkhVJ36/bl8Nq\n"
    "UDX8pHF0YyVhkFh2XXuaLJfJ2Zud7x97VtJguIHqXzwchdi1wnjXfPA/4/2ojj+w\n"
    "50o9qwCCn5aRSAIGofR/BZQ4s/Sd5j+bsiyzhIYZOwhG3CcCs2N9rQci7J36zKa+\n"
    "Yq67bfDzLiPIwA1iGkl/Y7PuWx0CgYEA42jYI5LPEwQnw4OLfIlCE4hre4Ir6Wm/\n"
    "DY7hwHqA0YsODQugjVlVL0lif2ig00eMYzexy7nAzYEOo8makKVYjUBphf+zcqna\n"
    "yTJKkZ++Dt5pudsHjmkWsYR6PLksX4QqQQsylaoU85/navgq0hPJyKJgS9S32lbk\n"
    "xjFo6lq0si0CgYEAvGkIRHW0oEvJa50fIxGWoEiLwj8dLQVfB2DYwLVZHqjWT3Bf\n"
    "VG2zAx/Gt8Gb9OCYQFAhRgPfmJ3y8BimbPryOh5LMGryomL3q+g8yQqAomTbqiCq\n"
    "+O3782xuIa6k94ocj921ioUITbViKOj6EftVAfYk78x5yDu2Ub37Jp7TuokCgYEA\n"
    "p7WOkM2YQWHzIVFF8VYYkOcuvStGzyDZcVpKSvUNQ3vVpPFKOnQDSphIN8YltSsy\n"
    "8YkFakVXVzcyYMAxaTNHlwRFzjjBUnLJk0+vhq3UMIr+Vb6eV/xQbCJTM60seFS0\n"
    "BLwJVi7UvMbUmCLlEYDec0Ss17/Mxw0GMtQFl6/FSxECgYEAw6nRF6arWW/q1uii\n"
    "3oHsjBw0vl7OuH4ykl8EaOf4T1DkG3l0zXwkA7i1wemrEhPO1/1kDKlW27LEuYXf\n"
    "84oVNgfxt/zeDDSoD1B6xCxdEln68h+A9UVRIx1VfQG1lJti5ZePkvrHHoR/rXCB\n"
    "GWMDJKW1Y0evqF8zvuyZ0wvcBjs=\n"
    "-----END PRIVATE KEY-----\n";

static const char webServerDefaultCertificateData[] PROGMEM =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDQzCCAiugAwIBAgIJAJxmg5ahlCD/MA0GCSqGSIb3DQEBCwUAMDcxCzAJBgNV\n"
    "BAYTAkFUMRYwFAYDVQQIDA1Mb3dlciBBdXN0cmlhMRAwDgYDVQQKDAdlZ2ltb3Rv\n"
    "MCAXDTIyMTIzMDIyMTAzMFoYDzIxMjEwNzI0MjIxMDMwWjA3MQswCQYDVQQGEwJB\n"
    "VDEWMBQGA1UECAwNTG93ZXIgQXVzdHJpYTEQMA4GA1UECgwHZWdpbW90bzCCASIw\n"
    "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMu8zLLyu9bAyasatyuicVVDtF5d\n"
    "MCHMCN2ULKjYdDf1YPBEAlvbpyVFEv+tqTDwSkZBLTB7ilqaEEEeZHgxvaVP1Drh\n"
    "kYy7y0Q5jEGvW5gzU+aQR/AWrrDrHYL+h5j5qsx1I5r8pydi5ScnJuhioyEIQJY8\n"
    "nMJAkxfeJrKC4FJrZtxUarFpd690sB4s11q/CHkXQC8F8ZjRqBTqrxFSUcpEsyoE\n"
    "DufRkaekALWBYW7NCz22Ay7TMN054nbNs5U9cMGLNiCy8Ev0aMoxGhYkjae6UcsT\n"
    "wXvZvQ9oaxwUn1eq44xWijiV0eE6//dXF2i+RqFlIu3ADoQjhEsXxJ6kLhkCAwEA\n"
    "AaNQME4wHQYDVR0OBBYEFLJ7xtb3b//khVOHxSWVaDUgcdMVMB8GA1UdIwQYMBaA\n"
    "FLJ7xtb3b//khVOHxSWVaDUgcdMVMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEL\n"
    "BQADggEBAIQ6PoQ5nPNfhwM3boqQNJcJ9YT8pg9X9Jefcaj0WdFh2vy2hAzvmjhn\n"
    "tlpSuajxNL3OqrZ521FQknJFg/uc7UiYssRG+RxqU7QOriSQPHMbNZIRE94daYqK\n"
    "KxaKeyn3D9PAzkjmN9YQuTmbKF4ls9NV1vN479KzPMH6IwLydMm6qUybHuBVMGqS\n"
    "OaVVuxm+TJxxbQSQwW2TPbetjqZ0piTeeYoRWMMzVemQMGo1YyyBwy/vsnGKNrvF\n"
    "vDnyEUYJC8cgO5BrM7a7Ay9lupo7BBbaAi25AjKA5RbAoNzS5LYkfglBDPN53k+Q\n"
    "gARMeDpuLXKHiW3OUTkh5LEIfzWJR7I=\n"
    "-----END CERTIFICATE-----\n";

EEPROMSettings<decltype(EEPROM)> Settings{ EEPROM };
NoStl::UniquePtr<MqttSender> mqttSender;
LocalBuffer<16> dlmsDecryptionKey;
LocalBuffer<45> mqttServerCertFingerprint;

// The domain has to be stored globally, because the PubSubClient lib does not create
// a copy of the string it is provided. The lifetime has to be managed by the user (us).
LocalBuffer<21> mqttServerDomain;


void flushSerial() {
    while (Serial.available()) {
        Serial.read();
    }
}

u32 readSerialLine(Buffer& buffer) {
    u32 index = 0;
    while (index < buffer.length() - 1) {
        u8 c;
        if (Serial.readBytes(&c, 1) != 1) {
            continue;
        }

        // Return key or new line
        if (c == 0x0d || c == 0xa) {
            break;
        }

        // Backspace key
        if (c == 0x08) {
            if (index > 0) {
                buffer[--index] = '\0';
                Serial.print("\r\n");
                Serial.print(buffer.charBegin());
            }
            continue;
        }

        Serial.write(c);
        buffer[index++] = c;
    }

    buffer[index] = '\0';
    return index;
}

void connectToWifi() {
    WiFi.hostname("Stromzaehler");

    const auto ssid= Settings.getCStringBuffer(SettingsField::WifiSSID);
    const auto password= Settings.getCStringBuffer(SettingsField::WifiPassword);
    WiFi.begin(ssid.charBegin(), password.charBegin());

    Serial.print("Connecting to WiFi");
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.print("\r\n");

    debugOut << "Wifi connected to '" << ssid.charBegin() << "' " << " with IP '" << WiFi.localIP() << "'\r\n";
}

void initMqttWifiClient() {
    if (wifiClient) {
        wifiClient->stop();
        wifiClient.reset();
    }

    if (!mqttServerCertFingerprint.length()) {
        debugOut << "Creating insecure wifi client" << debugEndl;
        wifiClient = NoStl::makeUnique<WiFiClient>();
    }
    else {
        debugOut << "Creating secure wifi client with fingerprint: " << mqttServerCertFingerprint.charBegin() << debugEndl;

        auto client = NoStl::makeUnique<WiFiClientSecure>();
        client->setFingerprint(mqttServerCertFingerprint.charBegin());
        wifiClient = NoStl::move(client);
    }

    pubsubClient.setClient(*wifiClient);
}

void initMqtt() {
    {
        Settings.copyCString(SettingsField::MqttCertificateFingerprint, mqttServerCertFingerprint);
        if (strstr(mqttServerCertFingerprint.charBegin(), "[insecure]")) {
            mqttServerCertFingerprint.shrinkLength(0);
        }
        initMqttWifiClient();
    }

    {
        Settings.copyCString(SettingsField::MqttBrokerAddress, mqttServerDomain);
        const auto port= Settings.getCStringBuffer(SettingsField::MqttBrokerPort);
        auto portNumber = atoi(port.charBegin());
        debugOut << "Setting mqtt server at '" << mqttServerDomain.charBegin() << "' on port '" << portNumber << "'\r\n";

        pubsubClient.setServer(mqttServerDomain.charBegin(), portNumber);
        pubsubClient.setBufferSize(1024);
    }

    {
        const auto basePath= Settings.getCStringBuffer(SettingsField::MqttBrokerPath);
        const auto mqttMessageMode= Settings.getCStringBuffer(SettingsField::MqttMessageMode);
        const auto mqttClient= Settings.getCStringBuffer(SettingsField::MqttBrokerClientId);
        const auto mqttUser= Settings.getCStringBuffer(SettingsField::MqttBrokerUser);
        const auto mqttPassword= Settings.getCStringBuffer(SettingsField::MqttBrokerPassword);

        switch (mqttMessageMode.at(0)) {
        case '0':
            debugOut << "Creating mqtt RAW sender" << debugEndl;
            mqttSender = NoStl::makeUnique<MqttRawSender<decltype(pubsubClient)>>(pubsubClient, basePath.charBegin(), mqttClient.charBegin(), mqttUser.charBegin(), mqttPassword.charBegin());
            break;
        case '1':
            debugOut << "Creating mqtt TOPIC sender" << debugEndl;
            mqttSender = NoStl::makeUnique<MqttTopicSender<decltype(pubsubClient)>>(pubsubClient, basePath.charBegin(), mqttClient.charBegin(), mqttUser.charBegin(), mqttPassword.charBegin());
            break;
        case '2':
        default:
            debugOut << "Creating mqtt JSON sender" << debugEndl;
            mqttSender = NoStl::makeUnique<MqttJsonSender<decltype(pubsubClient)>>(pubsubClient, basePath.charBegin(), mqttClient.charBegin(), mqttUser.charBegin(), mqttPassword.charBegin());
            break;
        }
    }
}

void initWebServer() {
    if (!webServerPrivateKey || !webServerCertificate) {
        webServerPrivateKey = NoStl::makeUnique<BearSSL::PrivateKey>(webServerDefaultSSLPrivateKeyData);
        webServerCertificate = NoStl::makeUnique<BearSSL::X509List>(webServerDefaultCertificateData);
    }

    if (webServer) {
        webServer->stop();
        webServer->close();
        webServer.reset();
    }

    webServer = NoStl::makeUnique<BearSSL::ESP8266WebServerSecure>(443);
    webServer->getServer().setRSACert(webServerCertificate.get(), webServerPrivateKey.get());
    webServer->getServer().setCache(&serverSessionsCache);

    webServer->on("/", []() {
        debugOut << "Root route\r\n";
        webServer->send(200, "text/plain", "this is the root page");
        });

    webServer->onNotFound([]() {
        debugOut << "Route not found\r\n";
        webServer->send(404, "text/plain", "unknown url");
        });

    debugOut << "(Re-)Starting webserver" << debugEndl;
    webServer->begin();
}

bool loadPemFileFromSerial(SettingsField field, bool oldDataIsValid) {
    assert(field.isDerFile());

    SerialStream serialStream{ Serial };

    if (oldDataIsValid) {
        u16 storedDataLength = Settings.getDerFileLength(field);

        serialStream << " or just press enter to confirm the current settings ";
        if (storedDataLength) {
            serialStream << "(<custom-bytes>)\r\n";
        }
        else {
            serialStream << "([default])\r\n";
        }
    }
    else {
        serialStream << " or just press enter to confirm the default ssl settings ([default]) \r\n";
    }

    LocalBuffer<150> header;
    auto length = readSerialLine(header);
    serialStream << "\r\n";

    if (!length && oldDataIsValid) {
        return true;
    }

    if ((!length && !oldDataIsValid) || !strncmp(header.charBegin(), "[default]", 150)) {
        Settings.setDerFileLength(field, 0);
        return true;
    }

    if (field == SettingsField::WebServerSSLCertificate) {
        if (strncmp(header.charBegin(), "-----BEGIN CERTIFICATE-----", 150)) {
            serialStream << "Error: Expected certificate pem header\r\n";
            return false;
        }
    }
    else {
        if (strncmp(header.charBegin(), "-----BEGIN PRIVATE KEY-----", 150)) {
            serialStream << "Error: Expected private key pem header\r\n";
            return false;
        }
    }

    SerialUnbufferedReader<decltype(Serial)> reader{ Serial };
    LocalBuffer<1500> derBuffer;

    auto derLengthOrError = derBuffer.parseBase64(reader);
    if (derLengthOrError.isError()) {
        serialStream << "Error: Could not parse base64: " << derLengthOrError.error().message() << "\r\n";
        return false;
    }

    if (derLengthOrError.value() >= derBuffer.length() || derBuffer.length() > field.maxLength() - 2) {
        serialStream << "Error: Too much data received. (Max pem file size is ~" << field.maxLength()* 4 / 3 + 90 << " bytes, or " << field.maxLength() << " bytes der data)\r\n";
        return false;
    }

    derBuffer.shrinkLength(derLengthOrError.value());
    //derBuffer.printHex(debugOut);

    // Sanity check, that DER file starts with a SEQUENCE tag (0x30)
    if (derBuffer[0] != 0x30) {
        serialStream << "Error: Invalid data format.\r\n";
        return false;
    }

    readSerialLine(header);
    readSerialLine(header);
    if (!strstr(header.charBegin(), "-----END ")) {
        serialStream << "Expected certificate pem footer\r\n";
        return false;
    }

    serialStream << "\r\n";

    Settings.setDerFileLength(field, derLengthOrError.value());
    Settings.setDerFile(field, derBuffer);

    return true;
}

void runSetupWizard(bool oldDataIsValid) {
    flushSerial();
    Serial.setTimeout(10000);
    SerialStream serialStream{ Serial };

    SettingsField::forEach([&](SettingsField field) {
        while (true) {
            serialStream << "Enter value for '" << field.name() << '\'';

            if (field.isDerFile()) {
                auto ok = loadPemFileFromSerial(field, oldDataIsValid);
                flushSerial();
                if (ok) {
                    break;
                }
                continue;
            }

            // Try to get a default value
            LocalBuffer<150> oldValueBuffer;
            const char* defaultValue = nullptr;
            if (oldDataIsValid) {
                Settings.copyCString(field, oldValueBuffer);
                defaultValue = oldValueBuffer.charBegin();
                auto shownValue = field.isSecure() ? "<hidden-value>" : defaultValue;
                serialStream << " or just press enter to confirm old value (" << shownValue << ") ";

            }
            else if (field.defaultValue()) {
                defaultValue = field.defaultValue();
                serialStream << " or just press enter to confirm default value (" << defaultValue << ") ";
            }
            serialStream << "\r\n(up to " << field.maxLength() - 1 << " chars) ";

            // Read user input
            LocalBuffer<150> buffer;
            auto length = readSerialLine(buffer);
            serialStream << "\r\n";

            // Accept default value if the user only hit return
            if (!length) {
                if (!defaultValue) {
                    serialStream << "Error: Did not enter a value.\r\n";
                    continue;
                }

                strncpy((char*)buffer.begin(), defaultValue, 150);
                length = strnlen(buffer.charBegin(), 150);
            }

            if (length >= 150) {
                length = 149;
            }
            buffer[length] = '\0';
            buffer.shrinkLength(length + 1);

            // Validation
            auto validationError = field.validate(buffer);
            if (validationError.isError()) {
                serialStream << "Error: The value '" << buffer.charBegin() << "' is invalid: " << validationError.error().message() << "\r\n";
                continue;
            }

            Settings.set(field, buffer);
            break;
        }
        });

    serialStream << "Committing EEPROM...\r\n";
    Settings.save();
}

ErrorOr<void> waitForAndProcessPacket() {
    LocalBuffer<600> serialReaderBuffer, applicationDataBuffer;
    SerialBufferReader<decltype(Serial)> serialReader{ Serial, serialReaderBuffer, MBusLinkFrame::packetEndByte };

    TRYGET(applicationFrame, DlmsApplicationFrame::decodeBuffer(serialReader, applicationDataBuffer));
    debugOut << "Received application frame\r\n";

    applicationFrame.decrypt(dlmsDecryptionKey);
    debugOut << "Received application frame\r\n";

    TRYGET(cosemData, CosemData::fromApplicationFrame(applicationFrame));

#if DEBUG_PRINTING
    cosemData.print(debugOut);
#endif
    TRY(mqttSender->connect());
    mqttSender->publishRaw(serialReader.allDataRead());
    {
        auto transmission = mqttSender->transmitFields();
        cosemData.mqttPublish(transmission);

        LocalBuffer<20> printBuffer;
        BufferPrinter printer{ printBuffer };

        // Append additional fields only sent via JSON
        auto ip = WiFi.localIP();
        printer.printUnsigned(ip[0]).printChar('.').printUnsigned(ip[1]).printChar('.').printUnsigned(ip[2]).printChar('.').printUnsigned(ip[3]);
        transmission.appendField("ip", printer.cString());

        printer.clear();
        printer.print((i16)WiFi.RSSI()).print("dBm");
        transmission.appendField("rssi", printer.cString());
    }

    return {};
}

void setup() {
    Serial.begin(115200, SERIAL_8N1);

    Serial.println("Starting smart meter mqtt gateway v2.0");
    Serial.println("Initializing...");

    constexpr auto EEPROMBytesToLoad = 2700;
    assert(EEPROMBytesToLoad >= SettingsField::requiredStorage() + 4);
    EEPROM.begin(EEPROMBytesToLoad);

    bool showSetup = false;
    bool settingsDataIsValid = true;
    auto settingsError = Settings.begin();
    if (settingsError.isError()) {
        Serial.println("EEPROM checksum missmatch. The stored settings are likely broken. Entering setup...");
        showSetup = true;
        settingsDataIsValid = false;

    }
    else {
        Serial.println("\r\nPress 's' for setup.");
        Serial.println("Press 'c' too clear all stored settings. Waiting for 10s...");
        flushSerial();

        char input;
        Serial.setTimeout(10000);
        Serial.readBytes(&input, 1);  // Read bytes respects the time out

        switch (input) {
        case 's':
        case 'S':
            showSetup = true;
            break;
        case 'c':
        case 'C':
            Serial.println("\r\nAre you sure, that you want to erase the current settings? (y/N)");
            Serial.readBytes(&input, 1);
            if (input == 'y' || input == 'Y') {
                Serial.println("\r\nErasing EEPROM...");
                Settings.erase();
                showSetup = true;
                settingsDataIsValid = false;
            }
        }
    }

    if (showSetup) {
        runSetupWizard(settingsDataIsValid);
    }

    SerialStream serialStream{ Serial };
    Settings.printConfiguration(serialStream);

    // Heart beat LED
    pinMode(D0, OUTPUT);

    // Connect to WIFI
    connectToWifi();

    initMqtt();

    initWebServer();

    Settings.copyHexBytes(SettingsField::DslmCosemDecryptionKey, dlmsDecryptionKey);

    EEPROM.end();

    // Setup serial connection for Mbus communication
    debugOut << "Switching serial connection to mbus mode" << debugEndl;
    Serial.flush();
    delay(2000);
    Serial.end();
    delay(1000);

    Serial.begin(2400, SERIAL_8E1);
    Serial.setTimeout(25000);  // Be carefull with long timeouts, as they might never expire -> timemax(): https://github.com/esp8266/Arduino/blob/master/cores/esp8266/PolledTimeout.h
}

void loop() {
    // Try to read a mbus packet and transmit it via mqtt
    if (Serial.available()) {
        debugOut << "Waiting..." << debugEndl;
        auto error = waitForAndProcessPacket();
        if (error.isError()) {
            debugOut << "\r\n\r\nCaught error in ::waitForAndProcessPacket: " << error.error().message() << debugEndl;

            // Resync
            u8 secondsWithoutSerialData = 0;
            while ((Serial.available() > 0) || (secondsWithoutSerialData < 2)) {
                flushSerial();
                delay(1000);
                secondsWithoutSerialData = !Serial.available() ? secondsWithoutSerialData + 1 : 0;
            }
        }

        // Heart beat LED blink
        digitalWrite(D0, HIGH);
        delay(100);
        digitalWrite(D0, LOW);

        // Complete destroy and reallocate the WifiServerSecure (web server) and WifiClientSecure (mqtt pubsub client)
        // to unblock them, as only one of them can work at a time, due to a bug in the TLS handling of the Arduino libraries.
        // Just calling .stop() is not enough, both have to be completely removed and have their destructors called
        initMqttWifiClient();
        initWebServer();
    }

    webServer->handleClient();
}
