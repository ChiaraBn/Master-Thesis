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
const string DISTANCEINT = "../../Data/dataInt.txt";

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
  uint32_t depth = 2;
  SecurityLevel securityLevel = HEStd_128_classic;

  CryptoContext<DCRTPoly> cc;
  cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrns(
          depth, plaintextModulus, securityLevel, sigma, depth, RLWE, BV);

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

  /* Reduces the size of ciphertext modulus to minimize the
   * communication cost before sending the encrypted result for decryption
   */
  cipher = cc->Compress(cipher, 2U);

  if (!serializeToFile(DATAFOLDER + filename, cipher, SerType::BINARY)) {
    return 0;
  }

  return cipher;
}

void serverProcess (CryptoContext<DCRTPoly> &cc, 
                    vector<vector<int64_t>> v) {

  cc->ClearEvalMultKeys();
  cc->ClearEvalAutomorphismKeys();
  lbcrypto::CryptoContextFactory<lbcrypto::DCRTPoly>::ReleaseAllContexts();

  // KEYS DESERIALIZATION //
  CryptoContext<DCRTPoly> cc_ser;
  if (!deserializeFromFile(DATAFOLDER + cryptoLocation, cc_ser,SerType::BINARY)) {
    return;
  }

  LPPublicKey<DCRTPoly> pk;
  if (!deserializeFromFile(DATAFOLDER + keyPubLocation, pk, SerType::BINARY)) {
    return;
  }

  LPPrivateKey<DCRTPoly> sk;
  if (!deserializeFromFile(DATAFOLDER + keyPriLocation, sk,SerType::BINARY)) {
    return;
  }

  if (!deserializeKeys(cc_ser, DATAFOLDER+keyMultLocation, 1)) return;
  if (!deserializeKeys(cc_ser, DATAFOLDER+keyRotLocation, 2)) return;

  // CIPHERTEXTS DESERIALIZATION //
  for (long unsigned int i = 0; i < v.size()-1; i+=2) {    
    Ciphertext<DCRTPoly> ct1, ct2;
    if (!deserializeFromFile(DATAFOLDER + ciphertextName(i), ct1, SerType::BINARY)) {
      return;
    }

    if (!deserializeFromFile(DATAFOLDER + ciphertextName(i+1), ct2, SerType::BINARY)) {
      return;
    }

    auto sum  = cc_ser->EvalAdd(ct1, ct2);

    // Final check for operations 
    Plaintext plainSum;
    cc_ser->Decrypt(sk, sum, &plainSum);

    cout << "\n > Results Palisade\n" 
        << "Sum: " << plainSum << endl;
  } 
}

// Reading the binary file into a  INT vector
vector<int64_t> readCiphers (string filename) {
  ifstream file;
  
  file.open(filename,  ios::in | ios::binary);
  file.seekg(0, ios::end);
  size_t filesize = file.tellg();
  file.seekg(0, ios::beg);

  vector<int64_t> vec(filesize/sizeof(int64_t));
  file.read(reinterpret_cast<char*>(vec.data()), filesize); 
  file.close();

  return vec;
}

vector<vector<int64_t>> encoding (vector<vector<int64_t>> v) {
  // Data to send
  vector<vector<int64_t>> residues;

  // TODO prova su due cifrari -> espandere su tutti
  auto v1 = readCiphers(ciphertextName(0));
  auto v2 = readCiphers(ciphertextName(1));

  // RNS encoding
  

  return residues;
}

void palisade (CryptoContext<DCRTPoly> &cc, vector<vector<int64_t>> v,
              bool FLAGRNS) {

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();
  if (!serializeKeys(keyPair, cc)) return;

  // Creates and serializes the ciphers
  for (long unsigned int i = 0; i < v.size()-1; i+=2) {
    auto cipher1 = makeCipher(keyPair, cc, v[i], ciphertextName(i));
    auto cipher2 = makeCipher(keyPair, cc, v[i+1], ciphertextName(i+1));
  }

  /* --- SENDING ---
   * If the RNS encoding is active,
   * before sending the data must be reduced to its residues.
   */
  if (FLAGRNS) {
    vector<vector<int64_t>> residues = encoding (v);
  }

  /* --- RECEVEING AGGREGATOR SIDE --- */
  if (FLAGRNS) {
    // decoding();
  }

  serverProcess(cc, v);
}

vector<vector<int64_t>> readDataset () {
  ifstream file;
  file.open(DISTANCEINT);

  file.seekg(0, ios::end);
  file.seekg(0, ios::beg);

  int64_t value;
  vector<int64_t> values;

  if (file) {
    while ( file >> value ) {
      values.push_back(value);
    }
  }
  file.close();

  // Splitting values into mulitple arrays
  int bunch_size = 1000;
  vector<vector<int64_t>> splits;

  for(size_t i = 0; i < values.size(); i += bunch_size) {
    auto last = min(values.size(), i + bunch_size);
    splits.emplace_back(values.begin() + i, values.begin() + last);
  }

  return splits;
}

int main() {

  // Flag that decides whether to activate RNS or not
  bool FLAGRNS = false;
  
  vector<vector<int64_t>> values = readDataset();
    
  CryptoContext<DCRTPoly> cc = setup(); 
  palisade (cc, values, FLAGRNS);

  return 0;
}