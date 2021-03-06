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
        void generateRSAKeypair(gcry_sexp_t *, gcry_sexp_t *);
        void encryptRSA(gcry_sexp_t, string, gcry_sexp_t *);
        string decryptRSA(gcry_sexp_t, gcry_sexp_t);
        void generateElGamalKeypair(gcry_sexp_t *, gcry_sexp_t *);
        void encryptElGamal(gcry_sexp_t, string, gcry_sexp_t *);
        string decryptElGamal(gcry_sexp_t, gcry_sexp_t);

        // Hash Functions
        string hashSHA512(string);
        string hashRIPEMD160(string);
};