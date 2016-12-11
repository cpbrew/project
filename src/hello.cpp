#include "CryptoPPDriver.h"
#include <iostream>
#include <fstream>
#include <ctime>
using namespace std;

#define FILE_EXT string("jpg")
#define INPUT_FILE "Snake_River." + FILE_EXT
// #define INPUT_FILE "mytest." + FILE_EXT

int main(int argc, char *argv[])
{
    fstream f;
    streamsize message_s;
    clock_t t;

    char *buffer;
    CryptoPPDriver cppdriver;
    char key[32], IV[8];
    for (int i = 0; i < 32; i++)
    {
        key[i] = i;
        if (i < 8) IV[i] = i;
    }
    string c, k(key, 32), iv(IV, 8);

    // Read the message file
    f.open(INPUT_FILE, ios::in | ios::binary | ios::ate);
    message_s = f.tellg();
    buffer = new char[message_s];
    f.seekg(0, ios::beg);
    f.read(buffer, message_s);
    f.close();
    string m(buffer, message_s);

    cout << "Running AES..." << endl;
    t = clock();
    c = cppdriver.encryptAES256(k, m);
    m = cppdriver.decryptAES256(k, c);
    cout << "Elapsed time: " << (clock() - t) / (CLOCKS_PER_SEC / 1000) << endl;
    f.open("aes." + FILE_EXT, ios::out | ios::binary);
    f.write(m.c_str(), m.length());
    f.close();

    cout << "Running Blowfish... " << endl;
    t = clock();
    c = cppdriver.encryptBlowfish(k, m);
    m = cppdriver.decryptBlowfish(k, c);
    cout << "Elapsed time: " << (clock() - t) / (CLOCKS_PER_SEC / 1000) << endl;
    f.open("blowfish." + FILE_EXT, ios::out | ios::binary);
    f.write(m.c_str(), m.length());
    f.close();

    cout << "Running Salsa20..." << endl;
    t = clock();
    c = cppdriver.processSalsa20(k, iv, m);
    m = cppdriver.processSalsa20(k, iv, c);
    cout << "Elapsed time: " << (clock() - t) / (CLOCKS_PER_SEC / 1000) << endl;
    f.open("salsa20." + FILE_EXT, ios::out | ios::binary);
    f.write(m.c_str(), m.length());
    f.close();

    cout << "Running RC4..." << endl;
    t = clock();
    c = cppdriver.processArc4(k, m);
    m = cppdriver.processArc4(k, c);
    cout << "Elapsed time: " << (clock() - t) / (CLOCKS_PER_SEC / 1000) << endl;
    f.open("arc4." + FILE_EXT, ios::out | ios::binary);
    f.write(m.c_str(), m.length());
    f.close();

    cout << "Generating RSA keys..." << endl;
    CryptoPP::RSA::PublicKey *pubRSA;
    CryptoPP::RSA::PrivateKey *privRSA;
    cppdriver.generateRSAKeypair(&pubRSA, &privRSA);
    cout << "Running RSA..." << endl;
    t = clock();
    c = cppdriver.encryptRSA(*pubRSA, m);
    m = cppdriver.decryptRSA(*privRSA, c);
    cout << "Elapsed time: " << (clock() - t) / (CLOCKS_PER_SEC / 1000) << endl;
    f.open("rsa." + FILE_EXT, ios::out | ios::binary);
    f.write(m.c_str(), m.length());
    f.close();

    cout << "Generating ElGamal keys..." << endl;
    CryptoPP::ElGamalKeys::PublicKey *pubElGamal;
    CryptoPP::ElGamalKeys::PrivateKey *privElGamal;
    cppdriver.generateElGamalKeypair(&pubElGamal, &privElGamal);
    cout << "Running ElGamal..." << endl;
    t = clock();
    c = cppdriver.encryptElGamal(*pubElGamal, m);
    m = cppdriver.decryptElGamal(*privElGamal, c);
    cout << "Elapsed time: " << (clock() - t) / (CLOCKS_PER_SEC / 1000) << endl;
    f.open("elgamal." + FILE_EXT, ios::out | ios::binary);
    f.write(m.c_str(), m.length());
    f.close();

    cout << "Running SHA512..." << endl;
    t = clock();
    c = cppdriver.hashSHA512(m);
    cout << "Elapsed time: " << (clock() - t) / (CLOCKS_PER_SEC / 1000) << endl;
    f.open("sha." + FILE_EXT, ios::out);
    f.write(c.c_str(), c.length());
    f.close();

    cout << "Running RIPEMD160..." << endl;
    t = clock();
    c = cppdriver.hashRIPEMD160(m);
    cout << "Elapsed time: " << (clock() - t) / (CLOCKS_PER_SEC / 1000) << endl;
    f.open("ripe." + FILE_EXT, ios::out);
    f.write(c.c_str(), c.length());
    f.close();

    return 0;
}
