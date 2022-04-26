#include <bits/stdc++.h>
using namespace std;

const string cryptoLocation = "/cryptocontext.txt";
const string keyPubLocation = "/key-public.txt";
const string keyPriLocation = "/key-private.txt";
const string keyMultLocation = "/key-eval-mult.txt";
const string keyRotLocation = "/key-eval-rot.txt";

string ciphertextName(int num);

void printVector (vector<int64_t> v);

vector<int64_t> chooseRNSBase (int64_t low, int64_t high);

vector<int64_t> representRNS (int64_t n, vector<int64_t> base);

int64_t convertRNS(vector<int64_t> base, vector<int64_t> rem);

void reBase (vector<int64_t> &value, vector<int64_t> base);
