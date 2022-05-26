/**
 * @file comparing.cpp
 * @author Chiara Boni
 * @brief This script allows one to take two input files and compare their contents.
 * It was used to demonstrate that calculations with and without RNS encoding are equivalent.
 * 
 * @version 0.1
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include <bits/stdc++.h>
using namespace std;

/**
 * @brief Browses the contents of files using iterators
 * 
 * @param first1 
 * @param last1 
 * @param first2 
 * @param last2 
 * @return true 
 * @return false 
 */
template<typename InputIterator1, typename InputIterator2>
bool range_equal(InputIterator1 first1, InputIterator1 last1,
        InputIterator2 first2, InputIterator2 last2) {

    while(first1 != last1 && first2 != last2) {
        if(*first1 != *first2) return false;
        ++first1;
        ++first2;
    }
    return (first1 == last1) && (first2 == last2);
}

/**
 * @brief Converts the two files to iterators on char elements
 * 
 * @param filename1 
 * @param filename2 
 * @return true 
 * @return false 
 */
bool compare_files(const string& filename1, const string& filename2) {
    ifstream file1(filename1);
    ifstream file2(filename2);

    istreambuf_iterator<char> begin1(file1);
    istreambuf_iterator<char> begin2(file2);

    istreambuf_iterator<char> end;

    return range_equal(begin1, end, begin2, end);
}

int main () {

    string test = "./Int_Scheme/build/test.txt";
    string test_rns = "./Int_Scheme/build/test_rns.txt";

    if (compare_files(test, test_rns)) {
        cout << "Files are equal\n";
    }
    else {
        cout << "Files are NOT equal\n";
    }

    return 0;
}