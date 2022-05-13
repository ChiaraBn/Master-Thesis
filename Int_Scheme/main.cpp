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
const string AGGREGATORDATA = "aggregatorData";

/* Representability: 7420738134810
 * Prime numbers between 0 and 20: {2, 3, 5, 7, 11, 13, 17, 19}
 * Four redundant residues {23, 29, 31, 37}
 */
const vector<int> base = RNSBase(0, 40);

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
 * p = plaintext Modulus
 * depth = multiplicative depth (it changes the ciphertext size)
 * m = 16384 cyclotomic order
 * sigma - distribution parameter for error distribution
 */
CryptoContext<DCRTPoly> setup () {
  // int plaintextModulus = 65537;
  int plaintextModulus = 49153;
  double sigma = 3.2;
  uint32_t depth = 1;
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

void serverProcess(CryptoContext<DCRTPoly> &cc, int size, bool FLAGRNS) {

  cc->ClearEvalMultKeys();
  cc->ClearEvalAutomorphismKeys();
  lbcrypto::CryptoContextFactory<lbcrypto::DCRTPoly>::ReleaseAllContexts();

  // KEYS DESERIALIZATION //
  CryptoContext<DCRTPoly> cc_ser;
  if (!deserializeFromFile(DATAFOLDER + cryptoLocation, cc_ser, SerType::BINARY)) {
    return;
  }

  LPPublicKey<DCRTPoly> pk;
  if (!deserializeFromFile(DATAFOLDER + keyPubLocation, pk, SerType::BINARY)) {
    return;
  }

  LPPrivateKey<DCRTPoly> sk;
  if (!deserializeFromFile(DATAFOLDER + keyPriLocation, sk, SerType::BINARY)) {
    return;
  }

  if (!deserializeKeys(cc_ser, DATAFOLDER+keyMultLocation, 1)) return;
  if (!deserializeKeys(cc_ser, DATAFOLDER+keyRotLocation, 2)) return;

  // CIPHERTEXTS DESERIALIZATION //
  for (int i = 0; i < size-1; i+=2) { 

    Ciphertext<DCRTPoly> ct1, ct2;
    if (FLAGRNS) {
      if (!deserializeFromFile(AGGREGATORDATA + aggregatorFileName(i), ct1, SerType::BINARY)) {
        return;
      }

      if (!deserializeFromFile(AGGREGATORDATA + aggregatorFileName(i+1), ct2, SerType::BINARY)) {
        return;
      }
    }
    else {
      if (!deserializeFromFile(DATAFOLDER + ciphertextName(i), ct1, SerType::BINARY)) {
        return;
      }

      if (!deserializeFromFile(DATAFOLDER + ciphertextName(i+1), ct2, SerType::BINARY)) {
        return;
      }
    }

    auto sum = cc_ser->EvalAdd(ct1, ct2);
  
    Plaintext plainSum;
    cc_ser->Decrypt(sk, sum, &plainSum);

    cout << "\n > Results Palisade\n" 
        << "Sum: " << plainSum << endl;
  } 
}

// Reading the binary file into a INT vectors
vector<uint8_t> readCiphers (string filename) {
  ifstream file;
  
  file.open(filename,  ios::in | ios::binary);
  file.seekg(0, ios::end);
  size_t filesize = file.tellg();
  file.seekg(0, ios::beg);

  vector<uint8_t> vec(filesize/sizeof(uint8_t));
  file.read(reinterpret_cast<char*>(vec.data()), filesize); 
  file.close();

  return vec;
}

void writeAggregation (vector<uint8_t> v, string filename) {
  ofstream fout(filename, ios::out | ios::binary);
  fout.write((char*)&v[0], v.size() * sizeof(uint8_t));
  fout.close();
}

vector<vector<int>> encoding (long unsigned int i) {
  vector<vector<int>> residues;
  vector<uint8_t> vplain = readCiphers(DATAFOLDER+ciphertextName(i));

  // RNS encoding
  for (long unsigned int i = 0; i < vplain.size(); i++) {
    vector<int> ri = RNS(vplain[i], base);
    residues.push_back(ri);
  }

  return residues;
}

vector<vector<uint8_t>> decoding (map<int, vector<vector<int>>> dataset) {
  vector<vector<uint8_t>> dataset_decoding;
  vector<uint8_t> chuck_decoding;

  map<int, vector<vector<int>>>::iterator it;
  for (it = dataset.begin(); it != dataset.end(); it++) {
    for (long unsigned int i = 0; i < it->second.size(); i++) {
      int tmp = CRT(base, it->second[i]);
      chuck_decoding.push_back(tmp);
    }
    
    dataset_decoding.push_back(chuck_decoding);
    chuck_decoding.clear();
  }
  return dataset_decoding;
}

void palisade (CryptoContext<DCRTPoly> &cc, vector<vector<int64_t>> v,
              bool FLAGRNS) {
  
  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();
  if (!serializeKeys(keyPair, cc)) return;

  /* v[i] represents a chuck of the samplings */
  for (long unsigned int i = 0; i < v.size(); i++) {
    makeCipher(keyPair, cc, v[i], ciphertextName(i));
  }

  /* --- SENDING ---
   * If the RNS encoding is active,
   * before sending, the data must be reduced to its residues.
   */
  if (FLAGRNS) { 
    
    map<int, vector<vector<int>>> dataset;
  
    // ENCODING FOR SENDING // 
    for (long unsigned int i = 0; i < v.size(); i++) {
      vector<vector<int>> residues = encoding (i);
      dataset.insert(make_pair(i, residues));
    }  

    // DECODING FOR RECEVEING //
    vector<vector<uint8_t>> dec = decoding(dataset);
    for (long unsigned int i = 0; i < dec.size(); i++) {
      writeAggregation(dec[i], AGGREGATORDATA+aggregatorFileName(i));
    }
    
    serverProcess(cc, dec.size(), FLAGRNS);
  }
  else {
    serverProcess(cc, v.size(), FLAGRNS);
  }  
}

vector<vector<int64_t>> readDataset (bool FLAG) {
  ifstream file;
  file.open(DISTANCEINT);

  file.seekg(0, ios::end);
  file.seekg(0, ios::beg);

  int64_t value;
  vector<int64_t> values;

  // Reading 765041 distances
  if (file) {
    while ( file >> value ) {
      values.push_back(value);
    }
  }
  file.close();

  // Splitting values into mulitple arrays
  int64_t chunk_size = 1000;
  vector<vector<int64_t>> splits;

  long unsigned int index = values.size()/2;
  if (FLAG) {
    for(size_t i = 0; i < index; i += chunk_size) {
      auto last = min(values.size(), i + chunk_size);
      splits.emplace_back(values.begin() + i, values.begin() + last);
    }
  }

  return splits;
}

int main() {
  ios_base::sync_with_stdio(0);

  // Flag that decides whether to activate RNS or not
  bool FLAGRNS = true;

  vector<vector<int64_t>> values = readDataset(true);
  CryptoContext<DCRTPoly> cc = setup(); 

  palisade (cc, values, FLAGRNS);

  return 0;
}