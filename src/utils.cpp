#include "utils.h"
#include <sstream>

void addPadding(string &message, size_t blockSize)
{
    unsigned char l[8];
    uint64_t padding, length = message.length();
    length += 8;
    padding = blockSize - (length % blockSize);
    if (padding == 0) padding = blockSize;

    length = message.length();
    message.append(1, (char)0x80);
    message.append(padding - 1, (char)0x00);
    ltob(length, l);
    message.append((const char *)l, 8);
}

string removePadding(string message)
{
    uint64_t length;
    btol((unsigned char *)((message.substr(message.length() - 8, 8)).data()), &length);

    return message.substr(0, length);
}

// Convert an array of bytes to a hex string
string btoh(const char *b, size_t len)
{
    const char *digits = "0123456789ABCDEF";
    std::stringstream ss;

    for (size_t i = 0; i < len; i++)
    {
        char d = b[i];
        ss << digits[(d >> 4) & 0xF];
        ss << digits[d & 0xF];
    }

    return ss.str();
}

// Convert a 64-bit integer to an array of bytes
void ltob(uint64_t l, unsigned char *b)
{
    for (int i = 7; i >= 0; i--)
    {
        b[i] = (uint8_t) (l & 0xFF);
        l >>= 8;
    }
}

// Convert an array of bytes to a 64-bit integer
void btol(const unsigned char *b, uint64_t *l)
{
    *l = 0;
    for (int i = 0; i < 8; i++)
    {
        *l <<= 8;
        *l |= b[i];
    }
}
