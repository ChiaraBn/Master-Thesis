/**
 * @file helpers.cpp
 * @author Chiara Boni
 * @brief 
 * 
 * @copyright Copyright (c) 2022
 */
#include "helpers.h"

/**
 * @brief Returns the ciphertext location for the serialization
 * 
 * @param num 
 * @return string 
 */
string ciphertextName(int num) {
  string name = "/ciphertext" + to_string(num) + ".txt";
  return name;
}

/**
 * @brief Helper function to print the vector passed as parameter
 * 
 * @param v 
 */
void printVector (vector<int64_t> v) {
  for (long unsigned int i = 0; i < v.size(); i++) {
    cout<<v[i]<< " ";
  }
  cout << endl;
}

/**
 * @brief It returns the prime numbers between the range
 * 
 * @param low 
 * @param high 
 * @return vector<int64_t> 
 */
vector<int64_t> chooseRNSBase (int64_t low, int64_t high) {
  vector<int64_t> m;
  bool is_prime = true;
  int i = 0;

  while (low < high) {
    is_prime = true;

    if (low == 0 || low == 1) {
      is_prime = false;
    }
 
    for (i = 2; i <= low/2; ++i) {
      if (low % i == 0) {
        is_prime = false;
        break;
      }
    }
        
    if (is_prime)
      m.push_back(low);

    ++low;
  }

  return m;
}

/**
 * @brief Given a number and the moduli base, it returns the vector of remainders
 * 
 * @param n 
 * @param base 
 * @return * It 
 */
vector<int64_t> representRNS (int64_t n, vector<int64_t> base) {
  vector<int64_t> remainders;

  for (long unsigned int k = 0; k < base.size(); k++) {
    int64_t r = n % base[k];
    remainders.push_back(r);
  }

  return remainders;
}

/**
 * @brief Implements the Remainder Chinese Theoreom for the conversion
 * into the positional system
 * 
 * @param base 
 * @param rem 
 * @return int64_t 
 */
int64_t convertRNS(vector<int64_t> base, vector<int64_t> rem) {
    int64_t x = 1; 
    
    while (true) {
      long unsigned int j;
        for (j = 0; j < base.size(); j++ )
            if (x % base[j] != rem[j])
               break;
 
        if (j == base.size())
            return x;
 
        x++;
    }
 
    return x;
}

/**
 * @brief It sets the vector of values into the modulo base
 * 
 * @param value 
 * @param base 
 */
void reBase (vector<int64_t> &value, vector<int64_t> base) {
  for (long unsigned int i = 0; i < base.size(); i++) {
    value[i] = value[i] % base[i];
  }
}