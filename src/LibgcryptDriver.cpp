#include "LibgcryptDriver.h"
#include <iostream>
using std::cout;
using std::endl;

void addPadding(string &, size_t);
string removePadding(string);
void ltob(uint64_t, unsigned char *);
void btol(const unsigned char *, uint64_t *);
void checkError(gcry_error_t);

LibgcryptDriver::LibgcryptDriver()
{
    
}

LibgcryptDriver::~LibgcryptDriver()
{
    
}

string LibgcryptDriver::encryptAES256(string key, string message)
{
    addPadding(message, gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256));
    unsigned char buffer[message.length()];
    gcry_cipher_hd_t hd;
    gcry_error_t error;

    checkError(gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB, 0));
    checkError(gcry_cipher_setkey(hd, key.data(), key.length()));
    checkError(gcry_cipher_encrypt(hd, buffer, message.length(), message.data(), message.length()));

    return string((const char *)buffer, message.length());
}

string LibgcryptDriver::decryptAES256(string key, string cipher)
{
    unsigned char buffer[cipher.length()];
    string message;
    gcry_cipher_hd_t hd;
    gcry_error_t error;

    checkError(gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB, 0));
    checkError(gcry_cipher_setkey(hd, key.data(), key.length()));
    checkError(gcry_cipher_decrypt(hd, buffer, cipher.length(), cipher.data(), cipher.length()));

    return removePadding(string((const char *)buffer, cipher.length()));
}

string LibgcryptDriver::encryptBlowfish(string key, string message)
{
    addPadding(message, gcry_cipher_get_algo_blklen(GCRY_CIPHER_BLOWFISH));
    unsigned char buffer[message.length()];
    gcry_cipher_hd_t hd;
    gcry_error_t error;

    checkError(gcry_cipher_open(&hd, GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_ECB, 0));
    checkError(gcry_cipher_setkey(hd, key.data(), key.length()));
    checkError(gcry_cipher_encrypt(hd, buffer, message.length(), message.data(), message.length()));

    return string((const char *)buffer, message.length());
}

string LibgcryptDriver::decryptBlowfish(string key, string cipher)
{
    unsigned char buffer[cipher.length()];
    string message;
    gcry_cipher_hd_t hd;
    gcry_error_t error;

    checkError(gcry_cipher_open(&hd, GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_ECB, 0));
    checkError(gcry_cipher_setkey(hd, key.data(), key.length()));
    checkError(gcry_cipher_decrypt(hd, buffer, cipher.length(), cipher.data(), cipher.length()));

    return removePadding(string((const char *)buffer, cipher.length()));
}

string LibgcryptDriver::processSalsa20(string key, string iv, string message)
{
    unsigned char buffer[message.length()];
    gcry_cipher_hd_t hd;
    gcry_error_t error;

    checkError(gcry_cipher_open(&hd, GCRY_CIPHER_SALSA20, GCRY_CIPHER_MODE_STREAM, 0));
    checkError(gcry_cipher_setkey(hd, key.data(), key.length()));
    checkError(gcry_cipher_setiv(hd, iv.data(), iv.length()));
    checkError(gcry_cipher_encrypt(hd, buffer, message.length(), message.data(), message.length()));

    return string((const char *)buffer, message.length());
}

string LibgcryptDriver::processArc4(string key, string message)
{
    unsigned char buffer[message.length()];
    gcry_cipher_hd_t hd;
    gcry_error_t error;

    checkError(gcry_cipher_open(&hd, GCRY_CIPHER_ARCFOUR, GCRY_CIPHER_MODE_STREAM, 0));
    checkError(gcry_cipher_setkey(hd, key.data(), key.length()));
    checkError(gcry_cipher_encrypt(hd, buffer, message.length(), message.data(), message.length()));

    return string((const char *)buffer, message.length());
}

void LibgcryptDriver::generateRSAKeypair(gcry_sexp_t *keypair)
{
    gcry_sexp_t params;

    checkError(gcry_sexp_build(&params, NULL, "(genkey (rsa (nbits 4:2048)))"));
    checkError(gcry_pk_genkey(keypair, params));
}

string LibgcryptDriver::encryptRSA(gcry_sexp_t keypair, string message)
{
    gcry_sexp_t msg, m, k, cipher;

    checkError(gcry_sexp_find_token(keypair, "public-key", 0));
    checkError(gcry_mpi_scan(&msg, GCRYMPI_FMT_USG, message.data, message.length(), NULL));
    checkError(gcry_sexp_build(&m, NULL, "(data (flags raw) (value %m))", msg));
    checkError(gcry_pk_encrypt(&cipher, m, k));
}

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

void checkError(gcry_error_t e)
{
    if (e)
    {
        cout << "gcry error: " << gcry_strsource(e)
            << "/" << gcry_strerror(e) << endl;

        exit(EXIT_FAILURE);
    }
}