#include "CryptoPPDriver.h"
#include <crypto++/osrng.h>
#include <crypto++/aes.h>
#include <crypto++/blowfish.h>
#include <crypto++/salsa.h>
#include <crypto++/arc4.h>
#include <crypto++/filters.h>
#include <crypto++/modes.h>
#include <crypto++/sha.h>
#include <crypto++/ripemd.h>
#include <crypto++/hex.h>
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
    e.SetKey((const unsigned char *)key.c_str(), 32);

    CryptoPP::StringSource(message, true,
        new CryptoPP::StreamTransformationFilter(e,
            new CryptoPP::StringSink(ciphertext)
        ) // StreamTransformationFilter
    ); // StringSource

    return ciphertext;
}

string CryptoPPDriver::decryptAES256(string key, string ciphertext)
{
    string message;

    CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption d;
    d.SetKey((const unsigned char *)key.c_str(), 32);

    CryptoPP::StringSource(ciphertext, true, 
        new CryptoPP::StreamTransformationFilter(d,
            new CryptoPP::StringSink(message)
        ) // StreamTransformationFilter
    ); // StringSource

    return message;
}

string CryptoPPDriver::encryptBlowfish(string key, string message)
{
    string ciphertext;

    CryptoPP::ECB_Mode<CryptoPP::Blowfish>::Encryption e;
    e.SetKey((const unsigned char *)key.c_str(), 16);

    CryptoPP::StringSource(message, true,
        new CryptoPP::StreamTransformationFilter(e,
            new CryptoPP::StringSink(ciphertext)
        ) // StreamTransformationFilter
    ); // StringSource

    return ciphertext;
}

string CryptoPPDriver::decryptBlowfish(string key, string ciphertext)
{
    string message;

    CryptoPP::ECB_Mode<CryptoPP::Blowfish>::Decryption d;
    d.SetKey((const unsigned char *)key.c_str(), 16);

    CryptoPP::StringSource(ciphertext, true, 
        new CryptoPP::StreamTransformationFilter(d,
            new CryptoPP::StringSink(message)
        ) // StreamTransformationFilter
    ); // StringSource

    return message;
}

        // Stream Ciphers
string CryptoPPDriver::processSalsa20(string key, string iv, string message)
{
    string ciphertext;
    uint8_t *buffer = new uint8_t[message.length()];

    CryptoPP::Salsa20::Encryption salsa;
    salsa.SetKeyWithIV((const unsigned char *)key.c_str(), 32, (const unsigned char *)iv.c_str());
    salsa.ProcessData(buffer, (const byte *)message.c_str(), message.length());
    ciphertext.assign((const char *)buffer, message.length());

    return ciphertext;
}

string CryptoPPDriver::processArc4(string key, string message)
{
    CryptoPP::ARC4 arc4((const unsigned char *)key.c_str(), key.length());
    arc4.ProcessData((unsigned char *)message.c_str(),
        (const unsigned char *)message.c_str(),
        message.length());

    return message;
}

void CryptoPPDriver::generateRSAKeypair(CryptoPP::RSA::PublicKey **pub, CryptoPP::RSA::PrivateKey **priv)
{
    CryptoPP::AutoSeededRandomPool prng;

    CryptoPP::InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(prng, 2048);

    *pub = new CryptoPP::RSA::PublicKey(params);
    *priv = new CryptoPP::RSA::PrivateKey(params);
}

string CryptoPPDriver::encryptRSA(CryptoPP::RSA::PublicKey key, string message)
{
    string ciphertext("");
    CryptoPP::AutoSeededRandomPool prng;

    CryptoPP::RSAES_OAEP_SHA_Encryptor e(key);
    for (int i = 0; i < message.length(); i += e.FixedMaxPlaintextLength())
    {
        int len = e.FixedMaxPlaintextLength();
        string blockIn(message, i, len), blockOut;
        CryptoPP::StringSource(blockIn, true,
            new CryptoPP::PK_EncryptorFilter(prng, e,
                new CryptoPP::StringSink(blockOut)
            ) // PK_EncryptorFilter
        ); // StringSource
        ciphertext.append(blockOut);
    }

    return ciphertext;
}

string CryptoPPDriver::decryptRSA(CryptoPP::RSA::PrivateKey key, string ciphertext)
{
    string message("");
    CryptoPP::AutoSeededRandomPool prng;

    CryptoPP::RSAES_OAEP_SHA_Decryptor d(key);
    for (int i = 0; i < ciphertext.length(); i+= d.FixedCiphertextLength())
    {
        int len = d.FixedCiphertextLength();
        string blockIn(ciphertext, i, len), blockOut;
        CryptoPP::StringSource(blockIn, true,
            new CryptoPP::PK_DecryptorFilter(prng, d,
                new CryptoPP::StringSink(blockOut)
            ) // PK_DecryptorFilter
        ); // StringSource
        message.append(blockOut);
    }
    
    return message;
}

void CryptoPPDriver::generateElGamalKeypair(CryptoPP::ElGamalKeys::PublicKey **pub, CryptoPP::ElGamalKeys::PrivateKey **priv)
{
    CryptoPP::AutoSeededRandomPool prng;

    *priv = new CryptoPP::ElGamalKeys::PrivateKey();
    (**priv).GenerateRandomWithKeySize(prng, 2048);

    *pub = new CryptoPP::ElGamalKeys::PublicKey();
    (**priv).MakePublicKey(**pub);
}

string CryptoPPDriver::encryptElGamal(CryptoPP::ElGamalKeys::PublicKey key, string message)
{
    string ciphertext("");
    CryptoPP::AutoSeededRandomPool prng;

    CryptoPP::ElGamal::Encryptor e(key);
    for (int i = 0; i < message.length(); i += e.FixedMaxPlaintextLength())
    {
        int len = e.FixedMaxPlaintextLength();
        string blockIn(message, i, len), blockOut;
        CryptoPP::StringSource(blockIn, true,
            new CryptoPP::PK_EncryptorFilter(prng, e,
                new CryptoPP::StringSink(blockOut)
            ) // PK_EncryptorFilter
        ); // StringSource
        ciphertext.append(blockOut);
    }

    return ciphertext;
}

string CryptoPPDriver::decryptElGamal(CryptoPP::ElGamalKeys::PrivateKey key, string ciphertext)
{
    string message("");
    CryptoPP::AutoSeededRandomPool prng;

    CryptoPP::ElGamal::Decryptor d(key);
    for (int i = 0; i < ciphertext.length(); i += d.FixedCiphertextLength())
    {
        int len = d.FixedCiphertextLength();
        string blockIn(ciphertext, i, len), blockOut;
        CryptoPP::StringSource(blockIn, true,
            new CryptoPP::PK_DecryptorFilter(prng, d,
                new CryptoPP::StringSink(blockOut)
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

    CryptoPP::StringSource s(message, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(digest)
            ) // HexEncoder
        ) // HashFilter
    ); // StringSource

    return digest;
}

string CryptoPPDriver::hashRIPEMD160(string message)
{
    CryptoPP::RIPEMD160 hash;
    string digest;

    CryptoPP::StringSource s(message, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(digest)
            ) // HexEncoder
        ) // HashFilter
    ); // StringSource

    return digest;
}