#include "helpers.h"

/**
 * @brief Returns the ciphertext location for the serialization
 * 
 * @param num 
 * @return string 
 */
string ciphertextName(int num) {
  string name = "/ciphertexts/ciphertext" + to_string(num) + ".txt";
  return name;
}

/**
 * @brief Returns the aggregator file location for the serialization
 * 
 * @param num 
 * @return string 
 */
string aggregatorFileName(int num) {
  string name = "/file" + to_string(num) + ".txt";
  return name;
}

/**
 * @brief Helper function to print the vector passed as parameter
 * 
 * @param v 
 */
void printVector (vector<int> v) {
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
 */
vector<int> RNSBase (int low, int high) {
  vector<int> m;
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
 * @return
 */
vector<int> RNS (int n, vector<int> base) {
  vector<int> remainders(base.size());

  for (long unsigned int i = 0; i < base.size(); i++) {
    remainders[i] = n % base[i];
  }

  return remainders;
}

int inv(int a, int m) {
    int m0 = m, t, q;
    int x0 = 0, x1 = 1;
 
    if (m == 1)
        return 0;
 
    // Apply extended Euclid Algorithm
    while (a > 1) {
        // q is quotient
        q = a / m;
 
        t = m;
 
        // m is remainder now, process same as
        // euclid's algo
        m = a % m, a = t;
 
        t = x0;
 
        x0 = x1 - q * x0;
 
        x1 = t;
    }
 
    // Make x1 positive
    if (x1 < 0)
        x1 += m0;
 
    return x1;
}
 
int CRT(vector<int> base, vector<int> rem) {

  int k = sizeof(base) / sizeof(base[0]);

  int prod = 1;
  for (int i = 0; i < k; i++)
      prod *= base[i];

  int result = 0;
  for (int i = 0; i < k; i++) {
      int pp = prod / base[i];
      result += rem[i] * inv(pp, base[i]) * pp;
  }

  return result % prod;
}