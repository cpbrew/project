#include "OpenSSLDriver.h"
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

void checkErrors();

OpenSSLDriver::OpenSSLDriver()
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
}

OpenSSLDriver::~OpenSSLDriver()
{
    EVP_cleanup();
    ERR_free_strings();
}

string OpenSSLDriver::encryptAES256(string key, string message)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char buffer[message.length() * 2];
    int len, clen;
    const unsigned char *k = (const unsigned char *)key.data();
    const unsigned char *m = (const unsigned char *)message.data();

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        checkErrors();
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, k, NULL))
        checkErrors();
    if (1 != EVP_EncryptUpdate(ctx, buffer, &len, m, message.length()))
        checkErrors();
    clen = len;
    if(1 != EVP_EncryptFinal_ex(ctx, buffer + len, &len))
        checkErrors();
    clen += len;

    EVP_CIPHER_CTX_free(ctx);

    return string((char *)buffer, clen);
}

string OpenSSLDriver::decryptAES256(string key, string cipher)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char buffer[cipher.length() * 2];
    int len, mlen;
    const unsigned char *k = (const unsigned char *)key.data();
    const unsigned char *c = (const unsigned char *)cipher.data();

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        checkErrors();
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, k, NULL))
        checkErrors();
    if (1 != EVP_DecryptUpdate(ctx, buffer, &len, c, cipher.length()))
        checkErrors();
    mlen = len;
    if(1 != EVP_DecryptFinal_ex(ctx, buffer + len, &len))
        checkErrors();
    mlen += len;

    EVP_CIPHER_CTX_free(ctx);

    return string((char *)buffer, mlen);
}

string OpenSSLDriver::encryptBlowfish(string key, string message)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char buffer[message.length() * 2];
    int len, clen;
    const unsigned char *k = (const unsigned char *)key.data();
    const unsigned char *m = (const unsigned char *)message.data();

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        checkErrors();
    if (1 != EVP_EncryptInit_ex(ctx, EVP_bf_ecb(), NULL, k, NULL))
        checkErrors();
    if (1 != EVP_EncryptUpdate(ctx, buffer, &len, m, message.length()))
        checkErrors();
    clen = len;
    if(1 != EVP_EncryptFinal_ex(ctx, buffer + len, &len))
        checkErrors();
    clen += len;

    EVP_CIPHER_CTX_free(ctx);

    return string((char *)buffer, clen);
}

string OpenSSLDriver::decryptBlowfish(string key, string cipher)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char buffer[cipher.length() * 2];
    int len, mlen;
    const unsigned char *k = (const unsigned char *)key.data();
    const unsigned char *c = (const unsigned char *)cipher.data();

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        checkErrors();
    if (1 != EVP_DecryptInit_ex(ctx, EVP_bf_ecb(), NULL, k, NULL))
        checkErrors();
    if (1 != EVP_DecryptUpdate(ctx, buffer, &len, c, cipher.length()))
        checkErrors();
    mlen = len;
    if(1 != EVP_DecryptFinal_ex(ctx, buffer + len, &len))
        checkErrors();
    mlen += len;

    EVP_CIPHER_CTX_free(ctx);

    return string((char *)buffer, mlen);
}

string OpenSSLDriver::encryptArc4(string key, string message)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char buffer[message.length() * 2];
    int len, clen;
    const unsigned char *k = (const unsigned char *)key.data();
    const unsigned char *m = (const unsigned char *)message.data();

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        checkErrors();
    if (1 != EVP_EncryptInit_ex(ctx, EVP_rc4(), NULL, k, NULL))
        checkErrors();
    if (1 != EVP_EncryptUpdate(ctx, buffer, &len, m, message.length()))
        checkErrors();
    clen = len;
    if(1 != EVP_EncryptFinal_ex(ctx, buffer + len, &len))
        checkErrors();
    clen += len;

    EVP_CIPHER_CTX_free(ctx);

    return string((char *)buffer, clen);
}

string OpenSSLDriver::decryptArc4(string key, string cipher)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char buffer[cipher.length() * 2];
    int len, mlen;
    const unsigned char *k = (const unsigned char *)key.data();
    const unsigned char *c = (const unsigned char *)cipher.data();

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        checkErrors();
    if (1 != EVP_DecryptInit_ex(ctx, EVP_rc4(), NULL, k, NULL))
        checkErrors();
    if (1 != EVP_DecryptUpdate(ctx, buffer, &len, c, cipher.length()))
        checkErrors();
    mlen = len;
    if(1 != EVP_DecryptFinal_ex(ctx, buffer + len, &len))
        checkErrors();
    mlen += len;

    EVP_CIPHER_CTX_free(ctx);

    return string((char *)buffer, mlen);
}

void checkErrors()
{
    ERR_print_errors_fp(stderr);
    abort();
}