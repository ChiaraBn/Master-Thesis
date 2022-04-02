/**
 * @file main.cpp
 * @author Chiara Boni
 * @brief FIRST approach of combining homomorphic encryption with
 * redudant RNS.
 * In this scenario, first the value from the sensor is converted into its rns representation,
 * and then each residue is encrypted and sent.
 * Comparison with encryption only and palisade with rns is present. 
 * @version 0.1
 * 
 * @copyright Copyright (c) 2022
 */

/* TO DISCUSS
 * Inserting serialization to reduce the size of the ciphers?
 */

#include "palisade.h"
#include "helpers.h"
using namespace lbcrypto;

CryptoContext<DCRTPoly> cc;

/**
 * @brief Create the cryptocontext
 * n = 65,536
 * p = plaintext Modulus
 * sigma - distribution parameter for error distribution
 */
void setup () {
  int plaintextModulus = 65537;
  double sigma = 3.2;
  SecurityLevel securityLevel = HEStd_128_classic;
  uint32_t depth = 2;

  cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrns(
          depth, plaintextModulus, securityLevel, sigma, depth, OPTIMIZED, BV);

  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);
  cc->Enable(LEVELEDSHE);  
}

Ciphertext<DCRTPoly> makeCipher (LPKeyPair<DCRTPoly> keyPair, vector<int64_t> v1) {
  cc->EvalMultKeyGen(keyPair.secretKey);
  cc->EvalAtIndexKeyGen(keyPair.secretKey, {1, 2, -1, -2});
  
  Plaintext plain = cc->MakePackedPlaintext(v1);
  auto cipher = cc->Encrypt(keyPair.publicKey, plain);
  cipher = cc->Compress(cipher, 2U);

  return cipher;
}

void palisade (vector<int64_t> v1, vector<int64_t> v2) {
  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();

  auto c1 = makeCipher(keyPair, v1);
  auto c2 = makeCipher(keyPair, v2);

  // Operations
  auto sum12 = cc->EvalAdd(c1, c2);
  auto mult12 = cc->EvalMult(c1, c2);

  Plaintext plainSum12, plainMult12;
  cc->Decrypt(keyPair.secretKey, sum12, &plainSum12);
  cc->Decrypt(keyPair.secretKey, mult12, &plainMult12);
  plainSum12->SetLength(v1.size());
  plainMult12->SetLength(v1.size());
  
  vector<int64_t> valueSum  = plainSum12->GetPackedValue();
  vector<int64_t> valueMult = plainMult12->GetPackedValue();

  cout << " > Results Palisade \n" 
       << "Sum: " << valueSum << endl
       << "Mult: " << valueMult << endl;
}

int64_t convertPlaintext (Plaintext p) {
  vector<int64_t> values = p->GetPackedValue();
  return values[0];
}

void fillCiphers (vector<int64_t> v, 
                  vector<Ciphertext<DCRTPoly>> &ciphers, LPKeyPair<DCRTPoly> keyPair) {

  vector<int64_t> tmp;
  Ciphertext<DCRTPoly> c;

  for (long unsigned int i = 0; i < v.size(); i++) {
    tmp.push_back(v[i]);
    c = makeCipher(keyPair, tmp);
    ciphers.push_back(c);
    tmp.clear();
  } 
}

void palisadeRNS (vector<int64_t> base, vector<int64_t> v1, vector<int64_t> v2) {
  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();

  vector<Ciphertext<DCRTPoly>> ciphers_v1;
  vector<Ciphertext<DCRTPoly>> ciphers_v2;

  // Encryption of each residue
  fillCiphers(v1, ciphers_v1, keyPair);
  fillCiphers(v2, ciphers_v2, keyPair);

  // Operations
  vector<Ciphertext<DCRTPoly>> cipherAdd, cipherMult;
  for (long unsigned int i = 0; i < ciphers_v1.size(); i++) {
    cipherAdd.push_back(cc->EvalAdd(ciphers_v1[i], ciphers_v2[i]));
    cipherMult.push_back(cc->EvalMult(ciphers_v1[i], ciphers_v2[i]));
  }

  // Decryption of each residue
  Plaintext p;
  vector<Plaintext> plainSum, plainMult;
  for (long unsigned int i = 0; i < cipherAdd.size(); i++) {
    cc->Decrypt(keyPair.secretKey, cipherAdd[i], &p);
    plainSum.push_back(p);

    cc->Decrypt(keyPair.secretKey, cipherMult[i], &p);
    plainMult.push_back(p);
  }

  // Conversion from RNS to positional
  vector<int64_t> resAdd, resMult;
  for (long unsigned int i = 0; i < plainSum.size(); i++) {
    resAdd.push_back(convertPlaintext(plainSum[i]));
    resMult.push_back(convertPlaintext(plainMult[i]));
  }

  reBase(resAdd, base);
  reBase(resMult, base);

  cout << "\n > Results Palisade RNS \n" 
       << "base: ";
  printVector(base);
  cout << "Sum: " << convertRNS(base, resAdd) << endl
       << "Mult: "<< convertRNS(base, resMult) << endl;
}

int main() {
  setup();

  vector<int64_t> a1 = {28};
  vector<int64_t> a2 = {13};

  // Results without RNS
  palisade (a1, a2);
  
  /* 
   * Rappresentability up to: 9699690 
   * 8 legitimate residues
   */
  vector<int64_t> base = chooseRNSBase(1, 20);

  vector<int64_t> v1 = representRNS(28, base);
  vector<int64_t> v2 = representRNS(13, base);

  // Results with RNS
  palisadeRNS (base, v1, v2);

  return 0;
}