#pragma once

#include <cstdint>
#include <vector>

namespace uid2 {
class BigEndianByteReader {
public:
    BigEndianByteReader(const std::uint8_t* byteArray, int size) : bytes(byteArray), size(size), position(0) {}

    explicit BigEndianByteReader(const std::vector<std::uint8_t>& byteArray) : bytes(&byteArray[0]), size(byteArray.size()), position(0) {}

    BigEndianByteReader(const BigEndianByteReader&) = delete;
    BigEndianByteReader& operator=(const BigEndianByteReader&) = delete;

    int GetPosition() const { return position; }
    int GetRemainingSize() const { return size - position; }
    const std::uint8_t* GetCurrentData() const { return bytes + GetPosition(); }

    uint8_t ReadByte()
    {
        CheckCanRead(1);
        return bytes[position++];
    }

    void ReadBytes(std::uint8_t* buf, int start, int len)
    {
        CheckCanRead(len);
        while (len-- > 0) {
            buf[start++] = bytes[position++];
        }
    }

    std::int32_t ReadInt32()
    {
        CheckCanRead(sizeof(std::int32_t));
        std::int32_t value = bytes[position++];
        value <<= 8;
        value |= bytes[position++];
        value <<= 8;
        value |= bytes[position++];
        value <<= 8;
        value |= bytes[position++];
        return value;
    }

    std::int64_t ReadInt64()
    {
        CheckCanRead(sizeof(std::int64_t));
        std::int64_t value = bytes[position++];
        value <<= 8;
        value |= bytes[position++];
        value <<= 8;
        value |= bytes[position++];
        value <<= 8;
        value |= bytes[position++];
        value <<= 8;
        value |= bytes[position++];
        value <<= 8;
        value |= bytes[position++];
        value <<= 8;
        value |= bytes[position++];
        value <<= 8;
        value |= bytes[position++];
        return value;
    }

private:
    void CheckCanRead(int n) const
    {
        if (size - position < n)
            throw "insufficient bytes to read";
    }

    const std::uint8_t* bytes;
    int position;
    int size;
};

class BigEndianByteWriter {
public:
    BigEndianByteWriter(std::uint8_t* byteArray, int size) : bytes(byteArray), size(size), position(0) {}

    explicit BigEndianByteWriter(std::vector<std::uint8_t>& byteArray) : bytes(&byteArray[0]), size(byteArray.size()), position(0) {}

    BigEndianByteWriter(const BigEndianByteWriter&) = delete;
    BigEndianByteWriter& operator=(const BigEndianByteWriter&) = delete;

    int GetPosition() const { return position; }

    void WriteByte(std::uint8_t value)
    {
        CheckCanWrite(1);
        bytes[position++] = value;
    }

    void WriteBytes(const std::uint8_t* buf, int start, int len)
    {
        CheckCanWrite(len);
        while (len-- > 0) {
            bytes[position++] = buf[start++];
        }
    }

    void WriteInt32(std::int32_t value)
    {
        CheckCanWrite(sizeof(std::int32_t));
        if (bytes != nullptr) {
            bytes[position++] = (value >> 24) & 0xFF;
            bytes[position++] = (value >> 16) & 0xFF;
            bytes[position++] = (value >> 8) & 0xFF;
            bytes[position++] = (value)&0xFF;
        }
    }

    void WriteInt64(std::int64_t value)
    {
        CheckCanWrite(sizeof(std::int64_t));
        if (bytes != nullptr) {
            bytes[position++] = (value >> 56) & 0xFF;
            bytes[position++] = (value >> 48) & 0xFF;
            bytes[position++] = (value >> 40) & 0xFF;
            bytes[position++] = (value >> 32) & 0xFF;
            bytes[position++] = (value >> 24) & 0xFF;
            bytes[position++] = (value >> 16) & 0xFF;
            bytes[position++] = (value >> 8) & 0xFF;
            bytes[position++] = (value)&0xFF;
        }
    }

private:
    void CheckCanWrite(int n) const
    {
        if (size - position < n)
            throw "insufficient bytes to write";
    }

    std::uint8_t* bytes;
    int position;
    int size;
};
}  // namespace uid2
