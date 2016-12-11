#include "IDriver.h"

class CryptoPPDriver : public IDriver
{
    public:
        CryptoPPDriver();
        ~CryptoPPDriver();

        std::string encryptAES256(std::string, std::string);
        std::string decryptAES256(std::string, std::string);
        std::string encryptBlowfish(std::string, std::string);
        std::string decryptBlowfish(std::string, std::string);

        std::string processSalsa20(std::string, std::string, std::string);
        std::string processArc4(std::string, std::string);

        void generateRSAKeypair(CryptoPP::RSA::PublicKey **, CryptoPP::RSA::PrivateKey **);
        std::string encryptRSA(CryptoPP::RSA::PublicKey, std::string);
        std::string decryptRSA(CryptoPP::RSA::PrivateKey, std::string);
        void generateElGamalKeypair(CryptoPP::ElGamalKeys::PublicKey **, CryptoPP::ElGamalKeys::PrivateKey **);
        std::string encryptElGamal(CryptoPP::ElGamalKeys::PublicKey, std::string);
        std::string decryptElGamal(CryptoPP::ElGamalKeys::PrivateKey, std::string);

        std::string hashSHA512(std::string);
        std::string hashRIPEMD160(std::string);
};