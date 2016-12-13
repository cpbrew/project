#include <iostream>
#include <fstream>
#include <ctime>
#include "CryptoPPDriver.h"
#include "LibgcryptDriver.h"

using namespace std;

// #define INPUT_FILE string("Snake_River.jpg")
#define INPUT_FILE string("mytest.txt")

void testCryptoPP(string);
void testLibgcrypt(string);

int main(int argc, char *argv[])
{
    ifstream f;
    streamsize message_s;
    char *buffer;

    // Read the message file
    f.open(INPUT_FILE, ios::in | ios::binary | ios::ate);
    message_s = f.tellg();
    buffer = new char[message_s];
    f.seekg(0, ios::beg);
    f.read(buffer, message_s);
    f.close();
    string m(buffer, message_s);

    // testCryptoPP(m);
    testLibgcrypt(m);

    return 0;
}

void testCryptoPP(string m)
{
    CryptoPPDriver driver;
    ofstream f;
    clock_t t;
    char key[32], IV[8];
    for (int i = 0; i < 32; i++)
    {
        key[i] = i;
        if (i < 8) IV[i] = i;
    }
    string c, k(key, 32), iv(IV, 8);

    cout << "Running Crypto++: AES256..." << endl;
    t = clock();
    c = driver.encryptAES256(k, m);
    m = driver.decryptAES256(k, c);
    cout << "Elapsed time: " << (clock() - t) / (CLOCKS_PER_SEC / 1000) << endl;
    f.open("bin/" + INPUT_FILE + ".cpp.aes256", ios::out | ios::binary);
    f.write(m.data(), m.length());
    f.close();

    cout << "Running Crypto++: Blowfish... " << endl;
    t = clock();
    c = driver.encryptBlowfish(k, m);
    m = driver.decryptBlowfish(k, c);
    cout << "Elapsed time: " << (clock() - t) / (CLOCKS_PER_SEC / 1000) << endl;
    f.open("bin/" + INPUT_FILE + ".cpp.blowfish", ios::out | ios::binary);
    f.write(m.data(), m.length());
    f.close();

    cout << "Running Crypto++: Salsa20..." << endl;
    t = clock();
    c = driver.processSalsa20(k, iv, m);
    m = driver.processSalsa20(k, iv, c);
    cout << "Elapsed time: " << (clock() - t) / (CLOCKS_PER_SEC / 1000) << endl;
    f.open("bin/" + INPUT_FILE + ".cpp.salsa20", ios::out | ios::binary);
    f.write(m.data(), m.length());
    f.close();

    cout << "Running Crypto++: ARC4..." << endl;
    t = clock();
    c = driver.processArc4(k, m);
    m = driver.processArc4(k, c);
    cout << "Elapsed time: " << (clock() - t) / (CLOCKS_PER_SEC / 1000) << endl;
    f.open("bin/" + INPUT_FILE + ".cpp.arc4", ios::out | ios::binary);
    f.write(m.data(), m.length());
    f.close();

    cout << "Generating RSA keys..." << endl;
    CryptoPP::RSA::PublicKey *pubRSA;
    CryptoPP::RSA::PrivateKey *privRSA;
    driver.generateRSAKeypair(&pubRSA, &privRSA);
    cout << "Running Crypto++: RSA..." << endl;
    t = clock();
    c = driver.encryptRSA(*pubRSA, m);
    m = driver.decryptRSA(*privRSA, c);
    cout << "Elapsed time: " << (clock() - t) / (CLOCKS_PER_SEC / 1000) << endl;
    f.open("bin/" + INPUT_FILE + ".cpp.rsa", ios::out | ios::binary);
    f.write(m.data(), m.length());
    f.close();

    cout << "Generating ElGamal keys..." << endl;
    CryptoPP::ElGamalKeys::PublicKey *pubElGamal;
    CryptoPP::ElGamalKeys::PrivateKey *privElGamal;
    driver.generateElGamalKeypair(&pubElGamal, &privElGamal);
    cout << "Running Crypto++: ElGamal..." << endl;
    t = clock();
    c = driver.encryptElGamal(*pubElGamal, m);
    m = driver.decryptElGamal(*privElGamal, c);
    cout << "Elapsed time: " << (clock() - t) / (CLOCKS_PER_SEC / 1000) << endl;
    f.open("bin/" + INPUT_FILE + ".cpp.elgamal", ios::out | ios::binary);
    f.write(m.data(), m.length());
    f.close();

    cout << "Running Crypto++: SHA512..." << endl;
    t = clock();
    c = driver.hashSHA512(m);
    cout << "Elapsed time: " << (clock() - t) / (CLOCKS_PER_SEC / 1000) << endl;
    f.open("bin/" + INPUT_FILE + ".cpp.sha512", ios::out);
    f.write(c.data(), c.length());
    f.close();

    cout << "Running Crypto++: RIPEMD160..." << endl;
    t = clock();
    c = driver.hashRIPEMD160(m);
    cout << "Elapsed time: " << (clock() - t) / (CLOCKS_PER_SEC / 1000) << endl;
    f.open("bin/" + INPUT_FILE + ".cpp.ripemd160", ios::out);
    f.write(c.data(), c.length());
    f.close();
}

void testLibgcrypt(string m)
{
    LibgcryptDriver driver;
    ofstream f;
    clock_t t;
    char key[32], IV[8];
    for (int i = 0; i < 32; i++)
    {
        key[i] = i;
        if (i < 8) IV[i] = i;
    }
    string c, k(key, 32), iv(IV, 8);

    cout << "Running Libgcrypt: AES256..." << endl;
    t = clock();
    c = driver.encryptAES256(k, m);
    m = driver.decryptAES256(k, c);
    cout << "Elapsed time: " << (clock() - t) / (CLOCKS_PER_SEC / 1000) << endl;
    f.open("bin/" + INPUT_FILE + ".gcry.aes256", ios::out | ios::binary);
    f.write(m.data(), m.length());
    f.close();

    cout << "Running Libgcrypt: Blowfish..." << endl;
    t = clock();
    c = driver.encryptBlowfish(k.substr(0, 16), m);
    m = driver.decryptBlowfish(k.substr(0, 16), c);
    cout << "Elapsed time: " << (clock() - t) / (CLOCKS_PER_SEC / 1000) << endl;
    f.open("bin/" + INPUT_FILE + ".gcry.blowfish", ios::out | ios::binary);
    f.write(m.data(), m.length());
    f.close();

    cout << "Running Libgcrypt: Salsa20..." << endl;
    t = clock();
    c = driver.processSalsa20(k, iv, m);
    m = driver.processSalsa20(k, iv, c);
    cout << "Elapsed time: " << (clock() - t) / (CLOCKS_PER_SEC / 1000) << endl;
    f.open("bin/" + INPUT_FILE + ".gcry.salsa20", ios::out | ios::binary);
    f.write(m.data(), m.length());
    f.close();

    cout << "Running Libgcrypt: ARC4..." << endl;
    t = clock();
    c = driver.processArc4(k, m);
    m = driver.processArc4(k, c);
    cout << "Elapsed time: " << (clock() - t) / (CLOCKS_PER_SEC / 1000) << endl;
    f.open("bin/" + INPUT_FILE + ".gcry.arc4", ios::out | ios::binary);
    f.write(m.data(), m.length());
    f.close();

    cout << "Generating RSA keys..." << endl;
    gcry_sexp_t pubRSA, privRSA;
    driver.generateRSAKeypair(&pubRSA, &privRSA);
    cout << "Running Libgcrypt: RSA..." << endl;
    t = clock();
    gcry_sexp_t cRSA;
    driver.encryptRSA(pubRSA, m, &cRSA);
    m = driver.decryptRSA(privRSA, cRSA);
    cout << "Elapsed time: " << (clock() - t) / (CLOCKS_PER_SEC / 1000) << endl;
    f.open("bin/" + INPUT_FILE + ".gcry.rsa", ios::out | ios::binary);
    f.write(m.data(), m.length());
    f.close();

    cout << "Generating ElGamal keys..." << endl;
    gcry_sexp_t pubElGamal, privElGamal;
    driver.generateElGamalKeypair(&pubElGamal, &privElGamal);
    cout << "Running Libgcrypt: ElGamal..." << endl;
    t = clock();
    gcry_sexp_t cElGamal;
    driver.encryptElGamal(pubElGamal, m, &cElGamal);
    m = driver.decryptElGamal(privElGamal, cElGamal);
    cout << "Elapsed time: " << (clock() - t) / (CLOCKS_PER_SEC / 1000) << endl;
    f.open("bin/" + INPUT_FILE + ".gcry.elgamal", ios::out | ios::binary);
    f.write(m.data(), m.length());
    f.close();

    cout << "Running Libgcrypt: SHA512..." << endl;
    t = clock();
    c = driver.hashSHA512(m);
    cout << "Elapsed time: " << (clock() - t) / (CLOCKS_PER_SEC / 1000) << endl;
    f.open("bin/" + INPUT_FILE + ".gcry.sha512", ios::out);
    f.write(c.data(), c.length());
    f.close();

    cout << "Running Libgcrypt: RIPEMD160..." << endl;
    t = clock();
    c = driver.hashRIPEMD160(m);
    cout << "Elapsed time: " << (clock() - t) / (CLOCKS_PER_SEC / 1000) << endl;
    f.open("bin/" + INPUT_FILE + ".gcry.ripemd160", ios::out);
    f.write(c.data(), c.length());
    f.close();
}