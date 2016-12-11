#include <string>
#include <crypto++/rsa.h>
#include <crypto++/elgamal.h>

class IDriver
{
    public:
        virtual ~IDriver() {}

        // Block Ciphers
        virtual std::string encryptAES256(std::string, std::string) = 0;
        virtual std::string decryptAES256(std::string, std::string) = 0;
        virtual std::string encryptBlowfish(std::string, std::string) = 0;
        virtual std::string decryptBlowfish(std::string, std::string) = 0;

        // Stream Ciphers
        virtual std::string processSalsa20(std::string, std::string, std::string) = 0;
        virtual std::string processArc4(std::string, std::string) = 0;

        // Asymmetric Key
        virtual void generateRSAKeypair(CryptoPP::RSA::PublicKey **, CryptoPP::RSA::PrivateKey **) = 0;
        virtual std::string encryptRSA(CryptoPP::RSA::PublicKey, std::string) = 0;
        virtual std::string decryptRSA(CryptoPP::RSA::PrivateKey, std::string) = 0;
        virtual void generateElGamalKeypair(CryptoPP::ElGamalKeys::PublicKey **, CryptoPP::ElGamalKeys::PrivateKey **) = 0;
        virtual std::string encryptElGamal(CryptoPP::ElGamalKeys::PublicKey, std::string) = 0;
        virtual std::string decryptElGamal(CryptoPP::ElGamalKeys::PrivateKey, std::string) = 0;

        // // Hash Functions
        virtual std::string hashSHA512(std::string) = 0;
        virtual std::string hashRIPEMD160(std::string) = 0;
};