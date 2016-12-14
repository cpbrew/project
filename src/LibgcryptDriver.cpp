#include "LibgcryptDriver.h"
#include "utils.h"

#include <iostream>
using std::cout;
using std::endl;

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

    checkError(gcry_sexp_build(&params, NULL, "(genkey (rsa (nbits 4:2048)))"));
    checkError(gcry_pk_genkey(&keypair, params));
    *pub = gcry_sexp_find_token(keypair, "public-key", 0);
    *priv = gcry_sexp_find_token(keypair, "private-key", 0);
}

void LibgcryptDriver::encryptRSA(gcry_sexp_t key, string message, gcry_sexp_t *cipher)
{
    gcry_sexp_t m;
    gcry_mpi_t mpi;
    const char *format = "(data (flags raw) (value %m))";

    checkError(gcry_mpi_scan(&mpi, GCRYMPI_FMT_USG, message.data(), message.length(), NULL));
    checkError(gcry_sexp_build(&m, NULL, format, mpi));
    checkError(gcry_pk_encrypt(cipher, m, key));
}

string LibgcryptDriver::decryptRSA(gcry_sexp_t key, gcry_sexp_t cipher)
{
    gcry_sexp_t m;
    gcry_mpi_t mpi;
    const size_t bufsize = 10485760; // 10 MB
    unsigned char *buffer = new unsigned char[bufsize];
    size_t bytesRead;

    checkError(gcry_pk_decrypt(&m, cipher, key));
    mpi = gcry_sexp_nth_mpi(m, 0, GCRYMPI_FMT_USG);
    gcry_mpi_print(GCRYMPI_FMT_USG, buffer, bufsize, &bytesRead, mpi);

    return string((const char *)buffer, bytesRead);
}

void LibgcryptDriver::generateElGamalKeypair(gcry_sexp_t *pub, gcry_sexp_t *priv)
{
    gcry_sexp_t params, keypair;

    checkError(gcry_sexp_build(&params, NULL, "(genkey (elg (nbits 4:2048)))"));
    checkError(gcry_pk_genkey(&keypair, params));
    *pub = gcry_sexp_find_token(keypair, "public-key", 0);
    *priv = gcry_sexp_find_token(keypair, "private-key", 0);
}

void LibgcryptDriver::encryptElGamal(gcry_sexp_t key, string message, gcry_sexp_t *cipher)
{
    gcry_sexp_t m;
    gcry_mpi_t mpi;
    const char *format = "(data (flags raw) (value %m))";

    checkError(gcry_mpi_scan(&mpi, GCRYMPI_FMT_USG, message.data(), message.length(), NULL));
    checkError(gcry_sexp_build(&m, NULL, format, mpi));
    checkError(gcry_pk_encrypt(cipher, m, key));
}

string LibgcryptDriver::decryptElGamal(gcry_sexp_t key, gcry_sexp_t cipher)
{
    gcry_sexp_t m;
    gcry_mpi_t mpi;
    const size_t bufsize = 10485760; // 10MB
    unsigned char *buffer = new unsigned char[bufsize];
    size_t bytesRead;

    checkError(gcry_pk_decrypt(&m, cipher, key));
    mpi = gcry_sexp_nth_mpi(m, 0, GCRYMPI_FMT_USG);
    gcry_mpi_print(GCRYMPI_FMT_USG, buffer, bufsize, &bytesRead, mpi);

    return string((const char *) buffer, bytesRead);
}

string LibgcryptDriver::hashSHA512(string message)
{
    unsigned int len = gcry_md_get_algo_dlen(GCRY_MD_SHA512);
    char *digest = new char[len];
    gcry_md_hash_buffer(GCRY_MD_SHA512, (void *)digest, message.data(), message.length());

    return btoh(digest, len);
}

string LibgcryptDriver::hashRIPEMD160(string message)
{
    unsigned int len = gcry_md_get_algo_dlen(GCRY_MD_RMD160);
    char *digest = new char[len];
    gcry_md_hash_buffer(GCRY_MD_RMD160, (void *)digest, message.data(), message.length());

    return btoh(digest, len);
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