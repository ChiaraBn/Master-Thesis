#include <bits/stdc++.h>
#include <execution>
using namespace std;

const string cryptoLocation = "/cryptocontext.txt";
const string keyPubLocation = "/key-public.txt";
const string keyPriLocation = "/key-private.txt";
const string keyMultLocation = "/key-eval-mult.txt";
const string keyRotLocation = "/key-eval-rot.txt";

string ciphertextName(int num);

string aggregatorFileName(int num);

void printVector (vector<int64_t> v);

vector<int> RNSBase (int low, int high);

vector<int64_t> RNS (int n, vector<int> base);

int inv(int a, int m);

int64_t CRT(vector<int> base, vector<int64_t> rem);