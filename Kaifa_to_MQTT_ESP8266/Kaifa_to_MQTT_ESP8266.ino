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
class BufferReaderBase;
class BufferReader;
template<typename T>
class SerialBufferReader;

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
        auto num = *bytesRead= remainingBytes < 8 ? remainingBytes : 8;
        for (u32 i = 0; i != num; i++) {
            value = (value << 8) | buffer.at(index+ i);
        }

        return value;
    }
};

class BufferReader : public BufferReaderBase{
public:
    explicit BufferReader(const Buffer& b) : buffer( b ) {}

    bool hasNext(u32 c= 1) const {
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
        u16 val= readU16(buffer, index);
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

    void skip(u32 num= 1) {
        assert(hasNext(num));
        index += num;
    }

    Buffer slice(i32 len= 0) {
        auto end = len >= 0 ? index+ len : len + buffer.length() + 1;
        Buffer sliced = buffer.slice(index, end);
        index= end;
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
    SerialBufferReader(T& serialIntf, const Buffer& buf) : serialInterface(serialIntf), buffer(buf) {}

    bool hasNext(u32 c = 1) const {
        return readIndex+ c <= writeIndex;
    }

    u8 nextU8() {
        ensureBytes(1);
        return buffer.at(readIndex++);
    }

    u8 peakU8() {
        ensureBytes(1);
        return buffer.at(readIndex);
    }

    u16 nextU16() {
        ensureBytes(2);
        u16 val = readU16(buffer, readIndex);
        readIndex += 2;
        return val;
    }

    u32 nextU32() {
        ensureBytes(4);
        u32 val = readU32(buffer, readIndex);
        readIndex += 4;
        return val;
    }

    u64 nextU64() {
        ensureBytes(8);
        u64 val = readU64(buffer, readIndex);
        readIndex += 8;
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

    void skip(u32 num = 1) {
        ensureBytes(num);
        readIndex += num;
    }

    Buffer slice(i32 len = 0) {
        assert(len >= 0); // SerialBuffer does not support negative slice lengths
        ensureBytes(len);
        Buffer sliced = buffer.slice(readIndex, readIndex + len);
        readIndex += len;
        return sliced;
    }

    Buffer allDataRead() const {
        return buffer.slice(0, writeIndex);
    }

private:
    void readBlock(u32 readAtLeast) {
        assert(writeIndex + readAtLeast <= buffer.length()); // Buffer is too small to read the requested number of bytes
        if (readAtLeast) {
            auto bytesWritten= serialInterface.readBytes((char*)&buffer[writeIndex], readAtLeast);
            writeIndex += bytesWritten;
            assert(bytesWritten >= readAtLeast); // Timeout occured before requested number of bytes could be read
        }

        // Do try to read even more if the end char was just read
        if (!(readAtLeast && writeIndex && buffer.at(writeIndex - 1) == 0x16)) {
            writeIndex += serialInterface.readBytesUntil(0x16, (char*)&buffer[writeIndex], buffer.length()- writeIndex);
            assert(writeIndex < buffer.length()); // Buffer was too small 
            buffer[writeIndex++] = 0x16; // Add end byte
        }
    }

    void ensureBytes(u32 num) {
        if (!hasNext(num)) {
            auto availableBytes = writeIndex - readIndex;
            readBlock(num - availableBytes);
        }
    }

    T& serialInterface;
    Buffer buffer;
    u32 readIndex{ 0 };
    u32 writeIndex{ 0 };
};
