#include <string>
using std::string;

#include <nettle/rsa.h>

class NettleDriver
{
    public:
        NettleDriver();
        ~NettleDriver();

        // Block Ciphers
        string encryptAES256(string, string);
        string decryptAES256(string, string);
        string encryptBlowfish(string, string);
        string decryptBlowfish(string, string);

        // Stream Ciphers
        string processSalsa20(string, string, string);
        string processArc4(string, string);

        // // Asymmetric Key
        void generateRSAKeypair(struct rsa_public_key *, struct rsa_private_key *);
        mpz_t *encryptRSA(struct rsa_public_key, string);
        string decryptRSA(struct rsa_private_key, mpz_t *);

        // // Hash Functions
        string hashSHA512(string);
        string hashRIPEMD160(string);
};