#include <string>
using std::string;

#include <crypto++/rsa.h>
using CryptoPP::RSA;

#include <crypto++/elgamal.h>
using CryptoPP::ElGamalKeys;

class CryptoPPDriver
{
    public:
        CryptoPPDriver();
        ~CryptoPPDriver();

        // Block Ciphers
        string encryptAES256(string, string);
        string decryptAES256(string, string);
        string encryptBlowfish(string, string);
        string decryptBlowfish(string, string);

        // Stream Ciphers
        string processSalsa20(string, string, string);
        string processArc4(string, string);

        // Asymmetric Key
        void generateRSAKeypair(RSA::PublicKey **, RSA::PrivateKey **);
        string encryptRSA(RSA::PublicKey, string);
        string decryptRSA(RSA::PrivateKey, string);
        void generateElGamalKeypair(ElGamalKeys::PublicKey **, ElGamalKeys::PrivateKey **);
        string encryptElGamal(ElGamalKeys::PublicKey, string);
        string decryptElGamal(ElGamalKeys::PrivateKey, string);

        // Hash Functions
        string hashSHA512(string);
        string hashRIPEMD160(string);
};