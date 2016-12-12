#include <string>
using std::string;

#include <gcrypt.h>

class LibgcryptDriver
{
    public:
        LibgcryptDriver();
        ~LibgcryptDriver();

        // Block Ciphers
        string encryptAES256(string, string);
        string decryptAES256(string, string);
        string encryptBlowfish(string, string);
        string decryptBlowfish(string, string);

        // Stream Ciphers
        string processSalsa20(string, string, string);
        string processArc4(string, string);

        // Asymmetric Key
        void generateRSAKeypair(gcry_sexp_t *);
        string encryptRSA(gcry_sexp_t, string);
        string decryptRSA(gcry_sexp_t, string);
        // void generateElGamalKeypair(ElGamalKeys::PublicKey **, ElGamalKeys::PrivateKey **);
        // string encryptElGamal(ElGamalKeys::PublicKey, string);
        // string decryptElGamal(ElGamalKeys::PrivateKey, string);
};