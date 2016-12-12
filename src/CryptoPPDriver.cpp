#include "CryptoPPDriver.h"

#include <crypto++/osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <crypto++/aes.h>
#include <crypto++/blowfish.h>
#include <crypto++/salsa.h>
#include <crypto++/arc4.h>
#include <crypto++/sha.h>
#include <crypto++/ripemd.h>

#include <crypto++/filters.h>
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;
using CryptoPP::HashFilter;

#include <crypto++/modes.h>

#include <crypto++/hex.h>
using CryptoPP::HexEncoder;

using namespace std;

CryptoPPDriver::CryptoPPDriver()
{
    
}

CryptoPPDriver::~CryptoPPDriver()
{
    
}

string CryptoPPDriver::encryptAES256(string key, string message)
{
    string ciphertext;

    CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption e;
    e.SetKey((const unsigned char *)key.data(), 32);

    StringSource(message, true,
        new StreamTransformationFilter(e,
            new StringSink(ciphertext)
        ) // StreamTransformationFilter
    ); // StringSource

    return ciphertext;
}

string CryptoPPDriver::decryptAES256(string key, string ciphertext)
{
    string message;

    CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption d;
    d.SetKey((const unsigned char *)key.data(), 32);

    StringSource(ciphertext, true, 
        new StreamTransformationFilter(d,
            new StringSink(message)
        ) // StreamTransformationFilter
    ); // StringSource

    return message;
}

string CryptoPPDriver::encryptBlowfish(string key, string message)
{
    string ciphertext;

    CryptoPP::ECB_Mode<CryptoPP::Blowfish>::Encryption e;
    e.SetKey((const unsigned char *)key.data(), 16);

    StringSource(message, true,
        new StreamTransformationFilter(e,
            new StringSink(ciphertext)
        ) // StreamTransformationFilter
    ); // StringSource

    return ciphertext;
}

string CryptoPPDriver::decryptBlowfish(string key, string ciphertext)
{
    string message;

    CryptoPP::ECB_Mode<CryptoPP::Blowfish>::Decryption d;
    d.SetKey((const unsigned char *)key.data(), 16);

    StringSource(ciphertext, true, 
        new StreamTransformationFilter(d,
            new StringSink(message)
        ) // StreamTransformationFilter
    ); // StringSource

    return message;
}

string CryptoPPDriver::processSalsa20(string key, string iv, string message)
{
    string ciphertext;
    uint8_t *buffer = new uint8_t[message.length()];

    CryptoPP::Salsa20::Encryption salsa;
    salsa.SetKeyWithIV((const unsigned char *)key.data(), 32, (const unsigned char *)iv.data());
    salsa.ProcessData(buffer, (const byte *)message.data(), message.length());
    ciphertext.assign((const char *)buffer, message.length());

    return ciphertext;
}

string CryptoPPDriver::processArc4(string key, string message)
{
    CryptoPP::ARC4 arc4((const unsigned char *)key.data(), key.length());
    arc4.ProcessData((unsigned char *)message.data(),
        (const unsigned char *)message.data(),
        message.length());

    return message;
}

void CryptoPPDriver::generateRSAKeypair(CryptoPP::RSA::PublicKey **pub, CryptoPP::RSA::PrivateKey **priv)
{
    AutoSeededRandomPool prng;

    CryptoPP::InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(prng, 2048);

    *pub = new CryptoPP::RSA::PublicKey(params);
    *priv = new CryptoPP::RSA::PrivateKey(params);
}

string CryptoPPDriver::encryptRSA(CryptoPP::RSA::PublicKey key, string message)
{
    string ciphertext("");
    AutoSeededRandomPool prng;

    CryptoPP::RSAES_OAEP_SHA_Encryptor e(key);
    for (int i = 0; i < message.length(); i += e.FixedMaxPlaintextLength())
    {
        int len = e.FixedMaxPlaintextLength();
        string blockIn(message, i, len), blockOut;
        StringSource(blockIn, true,
            new PK_EncryptorFilter(prng, e,
                new StringSink(blockOut)
            ) // PK_EncryptorFilter
        ); // StringSource
        ciphertext.append(blockOut);
    }

    return ciphertext;
}

string CryptoPPDriver::decryptRSA(CryptoPP::RSA::PrivateKey key, string ciphertext)
{
    string message("");
    AutoSeededRandomPool prng;

    CryptoPP::RSAES_OAEP_SHA_Decryptor d(key);
    for (int i = 0; i < ciphertext.length(); i+= d.FixedCiphertextLength())
    {
        int len = d.FixedCiphertextLength();
        string blockIn(ciphertext, i, len), blockOut;
        StringSource(blockIn, true,
            new PK_DecryptorFilter(prng, d,
                new StringSink(blockOut)
            ) // PK_DecryptorFilter
        ); // StringSource
        message.append(blockOut);
    }
    
    return message;
}

void CryptoPPDriver::generateElGamalKeypair(CryptoPP::ElGamalKeys::PublicKey **pub, CryptoPP::ElGamalKeys::PrivateKey **priv)
{
    AutoSeededRandomPool prng;

    *priv = new CryptoPP::ElGamalKeys::PrivateKey();
    (**priv).GenerateRandomWithKeySize(prng, 2048);

    *pub = new CryptoPP::ElGamalKeys::PublicKey();
    (**priv).MakePublicKey(**pub);
}

string CryptoPPDriver::encryptElGamal(CryptoPP::ElGamalKeys::PublicKey key, string message)
{
    string ciphertext("");
    AutoSeededRandomPool prng;

    CryptoPP::ElGamal::Encryptor e(key);
    for (int i = 0; i < message.length(); i += e.FixedMaxPlaintextLength())
    {
        int len = e.FixedMaxPlaintextLength();
        string blockIn(message, i, len), blockOut;
        StringSource(blockIn, true,
            new PK_EncryptorFilter(prng, e,
                new StringSink(blockOut)
            ) // PK_EncryptorFilter
        ); // StringSource
        ciphertext.append(blockOut);
    }

    return ciphertext;
}

string CryptoPPDriver::decryptElGamal(CryptoPP::ElGamalKeys::PrivateKey key, string ciphertext)
{
    string message("");
    AutoSeededRandomPool prng;

    CryptoPP::ElGamal::Decryptor d(key);
    for (int i = 0; i < ciphertext.length(); i += d.FixedCiphertextLength())
    {
        int len = d.FixedCiphertextLength();
        string blockIn(ciphertext, i, len), blockOut;
        StringSource(blockIn, true,
            new PK_DecryptorFilter(prng, d,
                new StringSink(blockOut)
            ) // PK_DecryptorFilter
        ); // StringSource
        message.append(blockOut);
    }

    return message;
}

string CryptoPPDriver::hashSHA512(string message)
{
    CryptoPP::SHA512 hash;
    string digest;

    StringSource(message, true,
        new HashFilter(hash,
            new HexEncoder(
                new StringSink(digest)
            ) // HexEncoder
        ) // HashFilter
    ); // StringSource

    return digest;
}

string CryptoPPDriver::hashRIPEMD160(string message)
{
    CryptoPP::RIPEMD160 hash;
    string digest;

    StringSource(message, true,
        new HashFilter(hash,
            new HexEncoder(
                new StringSink(digest)
            ) // HexEncoder
        ) // HashFilter
    ); // StringSource

    return digest;
}