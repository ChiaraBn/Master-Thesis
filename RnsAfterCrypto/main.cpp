/**
 * @file main.cpp
 * @author Chiara Boni
 * @brief 
 * @version 0.1
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include "palisade.h"
#include "helpers.h"

// serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "pubkeylp-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"

using namespace lbcrypto;

// It takes the current directory
// char buff[1024];
// string DATAFOLDER = string(getcwd(buff, 1024));

const string DATAFOLDER = "demoData";

template <typename T>
bool serializeToFile (const std::string& filename, const T& obj, 
                      const SerType::SERBINARY& sertype) {
  
  if (!Serial::SerializeToFile(filename, obj, sertype)) {
    cerr << "Error writing serialization to " << filename << endl;
    return false;
  }
  return true;
}

template <typename T>
bool deserializeFromFile(const std::string& filename, T& obj, 
                        const SerType::SERBINARY& sertype) {
  
  if (!Serial::DeserializeFromFile(filename, obj, sertype)) {
    cerr << "Could not read " << filename << endl;
    return false;
  }
  return true;
}

/**
 * @brief Create the cryptocontext
 * n = 65,536
 * p = plaintext Modulus
 * sigma - distribution parameter for error distribution
 */
CryptoContext<DCRTPoly> setup () {
  int plaintextModulus = 65537;
  double sigma = 3.2;
  SecurityLevel securityLevel = HEStd_128_classic;
  uint32_t depth = 2;

  CryptoContext<DCRTPoly> cc;
  cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrns(
          depth, plaintextModulus, securityLevel, sigma, depth, OPTIMIZED, BV);

  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);
  cc->Enable(LEVELEDSHE);
  
  if (!serializeToFile(DATAFOLDER + cryptoLocation, cc, SerType::BINARY)) return 0;
  return cc;
}

bool serializeKeys (LPKeyPair<DCRTPoly> keyPair, CryptoContext<DCRTPoly> &cc) {
  if (!serializeToFile(DATAFOLDER + keyPubLocation,keyPair.publicKey, SerType::BINARY)) return false;
 
  if (!serializeToFile(DATAFOLDER + keyPriLocation,keyPair.secretKey, SerType::BINARY)) return false;

  cc->EvalMultKeyGen(keyPair.secretKey);

  ofstream emkeyfile(DATAFOLDER + keyMultLocation, ios::out | ios::binary);
  if (emkeyfile.is_open()) {
    if (cc->SerializeEvalMultKey(emkeyfile, SerType::BINARY) == false) {
      cerr << "Error writing serialization of the eval mult keys to "
                   "key-eval-mult.txt"
                << endl;
      return false;
    }
    emkeyfile.close();
  } 
  else {
    cerr << "Error serializing eval mult keys" << endl;
    return false;
  }

  // Generate the rotation evaluation keys
  cc->EvalAtIndexKeyGen(keyPair.secretKey, {1, 2, -1, -2});
  
  ofstream erkeyfile(DATAFOLDER + keyRotLocation, ios::out | ios::binary);
  if (erkeyfile.is_open()) {
    if (cc->SerializeEvalAutomorphismKey(erkeyfile, SerType::BINARY) == false) {
      cerr << "Error writing serialization of the eval rotation keys to "
                   "key-eval-rot.txt"
                << endl;
      return false;
    }
    erkeyfile.close();
  } 
  else {
    cerr << "Error serializing eval rotation keys" << endl;
    return false;
  }
  return true;
}

bool deserializeKeys (CryptoContext<DCRTPoly> &cc, string location,
                      int64_t filter) {
  ifstream keys(location, ios::in | ios::binary);
  if (!keys.is_open()) {
    cerr << "I cannot read serialization from "
         << location << endl;
    return false ;
  }

  if (filter == 1) {
    if (cc->DeserializeEvalMultKey(keys, SerType::BINARY) == false) {
      cerr << "Could not deserialize the mult key file" << endl;
      return false;
    }
  }
  else {
    if (cc->DeserializeEvalAutomorphismKey(keys, SerType::BINARY) == false) {
      cerr << "Could not deserialize the eval rotation key file"
                << endl;
      return false;
    }
  }
  return true;
}

Ciphertext<DCRTPoly> makeCipher (LPKeyPair<DCRTPoly> keyPair, CryptoContext<DCRTPoly> &cc,
                                vector<int64_t> v, string filename) {
  
  Plaintext plain = cc->MakePackedPlaintext(v);

  auto cipher = cc->Encrypt(keyPair.publicKey, plain);
  cipher = cc->Compress(cipher, 2U);

  if (!serializeToFile(DATAFOLDER + filename, cipher, SerType::BINARY)) {
    return 0;
  }

  return cipher;
}

void palisade (CryptoContext<DCRTPoly> &cc, vector<int64_t> v1, vector<int64_t> v2) {

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();
  if (!serializeKeys(keyPair, cc)) return;

  // Creates and serializes the ciphers
  auto ciphertext1 = makeCipher(keyPair, cc, v1, ciphertextName(1));
  auto ciphertext2 = makeCipher(keyPair, cc, v2, ciphertextName(2));

  if (ciphertext1 && ciphertext2) {

    // Must clear out any PALISADE data objects when deserialize
    cc->ClearEvalMultKeys();
    cc->ClearEvalAutomorphismKeys();
    lbcrypto::CryptoContextFactory<lbcrypto::DCRTPoly>::ReleaseAllContexts();

    // DESERIALIZATION //
    CryptoContext<DCRTPoly> cc_ser;
    if (!deserializeFromFile(DATAFOLDER + cryptoLocation, cc_ser,SerType::BINARY)) {
      return;
    }

    LPPublicKey<DCRTPoly> pk;
    if (!deserializeFromFile(DATAFOLDER + keyPubLocation, pk,SerType::BINARY)) {
      return;
    }

    if (!deserializeKeys(cc_ser, DATAFOLDER+keyMultLocation, 1)) return;
    if (!deserializeKeys(cc_ser, DATAFOLDER+keyRotLocation, 2)) return;

    Ciphertext<DCRTPoly> ct1, ct2;
    if (!deserializeFromFile(DATAFOLDER + ciphertextName(1), ct1, SerType::BINARY)) {
      return;
    }

    if (!deserializeFromFile(DATAFOLDER + ciphertextName(2), ct2, SerType::BINARY)) {
      return;
    }

    auto sum12  = cc_ser->EvalAdd(ct1, ct2);
    auto mult12 = cc_ser->EvalMult(ct1, ct2);

    LPPrivateKey<DCRTPoly> sk;
    if (!deserializeFromFile(DATAFOLDER + keyPriLocation, sk,SerType::BINARY)) {
      return;
    }

    Plaintext plainSum12, plainMult12;
    cc_ser->Decrypt(sk, sum12, &plainSum12);
    cc_ser->Decrypt(sk, mult12, &plainMult12);

    cout << "\n > Results Palisade\n" 
        << "Sum: " << plainSum12 << endl
        << "Mult: " << plainMult12 << endl;
  }
}

// Reading the binary file into a vector
vector<int> readBinFile (string filename) {
  ifstream file;
  vector<int> vec;
  
  file.open(filename,  ios::in | ios::binary);
  file.seekg(0, ios::end);
  size_t filesize = file.tellg();
  file.seekg(0, ios::beg);

  vec.resize(filesize/sizeof(int));
  file.read(reinterpret_cast<char*>(vec.data()), filesize); 

  file.close();

  return vec;
}

void palisadeRNS (CryptoContext<DCRTPoly> &cc, 
                  vector<int64_t> v1, vector<int64_t> v2) {
  
  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();
  if (!serializeKeys(keyPair, cc)) return;

  // Creates and serializes the ciphers
  auto ciphertext1 = makeCipher(keyPair, cc, v1, ciphertextName(1));
  auto ciphertext2 = makeCipher(keyPair, cc, v2, ciphertextName(2));

  vector<int> vec1 = readBinFile(DATAFOLDER+ciphertextName(1));
  vector<int> vec2 = readBinFile(DATAFOLDER+ciphertextName(2));
  cout << "size of a vector: " << vec1.size() << endl;
}

int main() {

  vector<int64_t> a1 = {28};
  vector<int64_t> a2 = {13};
    
  // Serialization without RNS
  CryptoContext<DCRTPoly> cc = setup();
  if (cc) {
    palisade (cc, a1, a2);
  }
  
  // Serialization with RNS after the encryption
  CryptoContext<DCRTPoly> cc2 = setup();
  if (cc2) {    
    palisadeRNS (cc2, a1, a2);
  }

  return 0;
}