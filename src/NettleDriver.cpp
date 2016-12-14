#include "NettleDriver.h"
#include "utils.h"
#include <nettle/aes.h>
#include <nettle/blowfish.h>
#include <nettle/salsa20.h>
#include <nettle/arcfour.h>
#include <nettle/yarrow.h>
#include <nettle/sha2.h>
#include <nettle/ripemd160.h>

NettleDriver::NettleDriver()
{

}

NettleDriver::~NettleDriver()
{

}

string NettleDriver::encryptAES256(string key, string message)
{
    addPadding(message, AES_BLOCK_SIZE);

    struct aes256_ctx ctx;
    const uint8_t *k = (const uint8_t *)key.data();
    const uint8_t *m = (const uint8_t *)message.data();
    uint8_t *c = new uint8_t[message.length()];

    aes256_set_encrypt_key(&ctx, k);
    aes256_encrypt(&ctx, message.length(), c, m);

    return string((char *)c, message.length());
}

string NettleDriver::decryptAES256(string key, string cipher)
{
    struct aes256_ctx ctx;
    const uint8_t *k = (const uint8_t *)key.data();
    const uint8_t *c = (const uint8_t *)cipher.data();
    uint8_t *m = new uint8_t[cipher.length()];

    aes256_set_decrypt_key(&ctx, k);
    aes256_decrypt(&ctx, cipher.length(), m, c);

    return removePadding(string((char *)m, cipher.length()));
}

string NettleDriver::encryptBlowfish(string key, string message)
{
    addPadding(message, BLOWFISH_BLOCK_SIZE);

    struct blowfish_ctx ctx;
    const uint8_t *k = (const uint8_t *)key.data();
    const uint8_t *m = (const uint8_t *)message.data();
    uint8_t *c = new uint8_t[message.length()];

    blowfish_set_key(&ctx, key.length(), k);
    blowfish_encrypt(&ctx, message.length(), c, m);

    return string((char *)c, message.length());
}

string NettleDriver::decryptBlowfish(string key, string cipher)
{
    struct blowfish_ctx ctx;
    const uint8_t *k = (const uint8_t *)key.data();
    const uint8_t *c = (const uint8_t *)cipher.data();
    uint8_t *m = new uint8_t[cipher.length()];

    blowfish_set_key(&ctx, key.length(), k);
    blowfish_decrypt(&ctx, cipher.length(), m, c);

    return removePadding(string((char *)m, cipher.length()));
}

string NettleDriver::processSalsa20(string key, string iv, string message)
{
    struct salsa20_ctx ctx;
    const uint8_t *k = (const uint8_t *)key.data();
    const uint8_t *i = (const uint8_t *)iv.data();
    const uint8_t *m = (const uint8_t *)message.data();
    uint8_t *c = new uint8_t[message.length()];

    salsa20_256_set_key(&ctx, k);
    salsa20_set_nonce(&ctx, i);
    salsa20_crypt(&ctx, message.length(), c, m);

    return string((char *)c, message.length());
}

string NettleDriver::processArc4(string key, string message)
{
    struct arcfour_ctx ctx;
    const uint8_t *k = (const uint8_t *)key.data();
    const uint8_t *m = (const uint8_t *)message.data();
    uint8_t *c = new uint8_t[message.length()];

    arcfour_set_key(&ctx, key.length(), k);
    arcfour_crypt(&ctx, message.length(), c, m);

    return string((char *)c, message.length());
}

void NettleDriver::generateRSAKeypair(struct rsa_public_key *pub, struct rsa_private_key *priv)
{
    struct yarrow256_ctx ctx;
    string seed("seed me!");

    yarrow256_init(&ctx, 0, NULL);
    yarrow256_seed(&ctx, seed.length(), (const uint8_t *)seed.data());

    rsa_public_key_init(pub);
    rsa_private_key_init(priv);

    rsa_generate_keypair(pub, priv,
        &ctx, (nettle_random_func *)yarrow256_random,
        NULL, NULL, 2048, 17);
}

mpz_t *NettleDriver::encryptRSA(struct rsa_public_key key, string message)
{
    mpz_t *c = new mpz_t[1];
    mpz_init(*c);

    struct yarrow256_ctx ctx;
    string seed("seed me!");

    yarrow256_init(&ctx, 0, NULL);
    yarrow256_seed(&ctx, seed.length(), (const uint8_t *)seed.data());

    if (!rsa_encrypt(&key, &ctx, (nettle_random_func *)yarrow256_random,
        message.length(), (const uint8_t *)message.data(), *c))
        abort();

    return c;
}

string NettleDriver::decryptRSA(struct rsa_private_key key, mpz_t *cipher)
{
    size_t len = 10485760; // 10MB
    uint8_t *m = new uint8_t[len];
    if (!rsa_decrypt(&key, &len, m, *cipher))
        abort();

    return string((char *)m, len);
}

string NettleDriver::hashSHA512(string message)
{
    struct sha512_ctx ctx;
    uint8_t *d = new uint8_t[SHA512_DIGEST_SIZE];

    sha512_init(&ctx);
    sha512_update(&ctx, message.length(), (const uint8_t *)message.data());
    sha512_digest(&ctx, SHA512_DIGEST_SIZE, d);

    return btoh((char *)d, SHA512_DIGEST_SIZE);
}

string NettleDriver::hashRIPEMD160(string message)
{
    struct ripemd160_ctx ctx;
    uint8_t *d = new uint8_t[RIPEMD160_DIGEST_SIZE];

    ripemd160_init(&ctx);
    ripemd160_update(&ctx, message.length(), (const uint8_t *)message.data());
    ripemd160_digest(&ctx, RIPEMD160_DIGEST_SIZE, d);

    return btoh((char *)d, RIPEMD160_DIGEST_SIZE);
}