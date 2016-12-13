#include "LibgcryptDriver.h"
#include <iostream>
using std::cout;
using std::endl;

#include <fstream>

#define CHUNKSIZE 1048576 // encrypt 1MB at a time;
// #define CHUNKSIZE 1024 // encrypt 1KB at a time

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

void LibgcryptDriver::generateRSAKeypair(gcry_sexp_t *pub, gcry_sexp_t *priv)
{
    gcry_sexp_t params, keypair;

    std::ifstream f("rsakey", std::ios::in | std::ios::binary | std::ios::ate);
    size_t len = f.tellg();
    void *buffer = new char[len];
    f.seekg(0, std::ios::beg);
    f.read((char *)buffer, len);
    f.close();
    checkError(gcry_sexp_new(&keypair, buffer, len, 0));

    // checkError(gcry_sexp_build(&params, NULL, "(genkey (rsa (nbits 4:2048)))"));
    // checkError(gcry_pk_genkey(&keypair, params));
    *pub = gcry_sexp_find_token(keypair, "public-key", 0);
    *priv = gcry_sexp_find_token(keypair, "private-key", 0);

    // const size_t size = 100000; // should be plenty
    // size_t len;
    // void *buffer = malloc(size);
    // len = gcry_sexp_sprint(keypair, GCRYSEXP_FMT_CANON, buffer, size);
    // std::ofstream f("rsakey", std::ios::out | std::ios::binary);
    // f.write((const char *)buffer, len);
    // f.close();
}

size_t LibgcryptDriver::encryptRSA(gcry_sexp_t key, string message, gcry_sexp_t **chunks)
{
    gcry_sexp_t m;
    gcry_mpi_t mpi;
    const char *format = "(data (flags raw) (value %m))";
    const size_t numChunks = (message.length() / CHUNKSIZE) + 1;
    *chunks = new gcry_sexp_t[numChunks];

    for (size_t i = 0; i < message.length(); i += CHUNKSIZE)
    {
        size_t l = (i + CHUNKSIZE) < message.length() ? CHUNKSIZE : message.length() % CHUNKSIZE;
        checkError(gcry_mpi_scan(&mpi, GCRYMPI_FMT_USG, message.substr(i, l).data(), l, NULL));
        checkError(gcry_sexp_build(&m, NULL, format, mpi));
        // checkError(gcry_sexp_build(&m, NULL, format, l, message.substr(i, l)));
        // cout << "Creating chunk from substring:" << message.substr(i, l) << endl;
        // cout << "Encrypting chunk:" << endl;
        // gcry_sexp_dump(m);
        cout << "About to call encrypt" << endl;
        checkError(gcry_pk_encrypt(&((*chunks)[i]), m, key));
        cout << "Successfully called encrypt" << endl;
        // cout << "Encrypted value:" << endl;
        // gcry_sexp_dump((*chunks)[i]);
    }
    
    return numChunks;
}

string LibgcryptDriver::decryptRSA(gcry_sexp_t key, gcry_sexp_t *chunks, size_t numChunks)
{
    gcry_sexp_t out;
    gcry_mpi_t m;
    size_t bufsize = 10485760; // 10 MB
    unsigned char *message = new unsigned char[bufsize];
    size_t s = 0, bytesRead = 0;

    for (int i = 0; i < numChunks; i++)
    {
        // cout << "Decrypting chunk:" << endl;
        // gcry_sexp_dump(chunks[i]);

        checkError(gcry_pk_decrypt(&out, chunks[i], key));
        // cout << "Decrypted value:" << endl;
        // gcry_sexp_dump(out);

        m = gcry_sexp_nth_mpi(out, 0, GCRYMPI_FMT_USG);
        // gcry_mpi_dump(m);
        gcry_mpi_print(GCRYMPI_FMT_USG, &(message[s]), bufsize - s, &bytesRead, m);
        s += bytesRead;
        // cout << endl << "s = " << s << endl;
    }

    return string((const char *)message, s);
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