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
class BufferPrinter;
class MBusLinkFrame;
class MBusTransportFrame;
class DlmsApplicationFrame;
class DlmsStructureNode;
class DlmsNodeAllocator;
class DlmsReader;

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

class BufferPrinter {
public:
    explicit BufferPrinter(Buffer& b) : buffer(b), cursor{ b.begin() } {}

    void clear() {
        cursor = buffer.begin();
    }

    BufferPrinter& print(i64 x, u8 minLeadingDigits= 0, i8 decimalPointPosition= 0) {
        if (x < 0) {
            if (!push('-')) {
                return *this;
            }

            x *= -1;
        }
        printUnsigned((u64)x, minLeadingDigits, decimalPointPosition);
        return *this;
    }

    BufferPrinter& printUnsigned(u64 x, u8 minLeadingDigits = 0, i8 decimalPointPosition= 0) {
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
        assert( str ); // Cannot print empty string
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

private:
    bool push(u8 c) {
        if (cursor >= buffer.end()-1) { // Leave space for '\0'
            return false;
        }

        *(cursor++) = c;
        return true;
    }

    Buffer buffer;
    u8* cursor;
};

class MBusLinkFrame {
public:
    enum class Type : u8 {SingleChar, Short, Control, Long};

    MBusLinkFrame(Type type, u8 c = 0, u8 a = 0, u8 l = 0, Buffer p = { nullptr, 0 })
        : frameType( type ), cField( c ), aField( a ), lField( l ), payloadBuffer( p ) {}

    template<typename T>
    static ErrorOr<MBusLinkFrame> decodeBuffer(SerialBufferReader<T>& reader) {
        Type type;

        switch (reader.nextU8()) {
        case 0xe5: return { Type::SingleChar };
        case 0x10: type = Type::Short; break;
        case 0x68: type = Type::Control; break;
        default: return Error{ "Invalid transport frame type" };
        }

        if (type == Type::Short) {
            auto cField = reader.nextU8();
            auto aField = reader.nextU8();
            auto checksumField = reader.nextU8();
            TRY(reader.assertU8( 0x16 ));

            if (((cField + aField) & 0xFF) != checksumField) {
                return Error{ "Checksum missmatch" };
            }

            return { Type::Short, cField, aField };
        }

        auto lField = reader.nextU8();
        TRY(reader.assertU8(lField));
        TRY(reader.assertU8(0x68));

        auto cField = reader.nextU8();
        auto aField = reader.nextU8();

        auto userData = reader.slice(lField - 2);
        auto checksumField = reader.nextU8();
        TRY(reader.assertU8(0x16));

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
        : ciField(c), payloadBuffer( p ) {}

    static ErrorOr<MBusTransportFrame> fromLinkFrame(const MBusLinkFrame& frame) {
        BufferReader reader{ frame.payload() };

        auto ciField= reader.nextU8();
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

            TRYGET( transportFrame, MBusTransportFrame::fromLinkFrame(linkFrame) );
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
        explicit Iterator(const DlmsStructureNode* node= nullptr) : ptr( node ) {}

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
        case Type::None: stream << "<Empty>\n"; break;
        case Type::Enum: stream << "Enum: " << (int)(u8)content.value << '\n'; break;
        case Type::U8: stream << "u8: " << (int)(u8)content.value << '\n'; break;
        case Type::U16: stream << "u16: " << (u16)content.value << '\n'; break;
        case Type::U32: stream << "u32: " << (u32)content.value << '\n'; break;
        case Type::U64: stream << "u64: " << (u64)content.value << '\n'; break;
        case Type::I8: stream << "i8: " << (int)(i8)content.value << '\n'; break;
        case Type::I16: stream << "i16: " << (i16)content.value << '\n'; break;
        case Type::I32: stream << "i32: " << (i32)content.value << '\n'; break;
        case Type::I64: stream << "i64: " << (i64)content.value << '\n'; break;
        case Type::OctetString:
            stream << "OctetString [" << content.buffer.length() << "]: ";
            content.buffer.printHex(stream);
            break;
        case Type::Structure:
            stream << "Structure: \n";
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
    } content{.value= 0};

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
        : reader( buffer ) {}

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
            debugOut << "bad byte" << (int)reader.peakU8() << std::endl;
            return Error{ "Unsupported dlms structure node type" };
        }
    }

    ErrorOr<DlmsStructureNode*> readStructure(DlmsNodeAllocator& allocator) {
        // debugOut << "found struct\n";
        TRY(reader.assertU8(0x02));

        auto* node = allocator.allocate()->asStructure();

        // Could this be a multi-byte value for structures containing more than 256 items?
        auto itemCount= reader.nextU8();
        while (itemCount--) {
            TRYGET(childNode, readNext(allocator));
            node->append( childNode );
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

        //debugOut << "found integer (" << (int)intType << ") " << value << std::endl;;

        return allocator.allocate()->asInteger(nodeType, value);
    }

    ErrorOr<DlmsStructureNode*> readOctetString(DlmsNodeAllocator& allocator) {
        TRY(reader.assertU8(0x09));

        // Could this be a multi-byte value for octet sttings containing more than 255 bytes?
        auto length = reader.nextU8();
        auto string = reader.slice(length);

        //debugOut << "found string\n";
        //string.printHex(std::cout);

        return allocator.allocate()->asOctetString(string);
    }

    ErrorOr<DlmsStructureNode*> readEnum(DlmsNodeAllocator& allocator) {
        TRY(reader.assertU8(0x16));

        //debugOut << "found enum " << (int)reader.peakU8() << std::endl;
        return allocator.allocate()->asEnum( reader.nextU8() );
    }

private:
    BufferReader reader;
};

void setup() {}
void loop() {}
