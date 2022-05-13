# Use of RRNS in Exact Integer Arithmetic (BGV scheme)

## Approach
This scenario was introduced in order to try to include **redundancy** within the structures of ciphers, through the use of RNS encoding.<p>

[**Serialization**](https://palisade-crypto.org/wp-content/uploads/2021/08/PALISADE-12-11-20-Serialization-Applications.pdf) is introduced, supported in PALISADE, to convert the ciphertexts into a **sequence of bytes** and then represent them into **redundant** RNS.

## Draft
<img src="../Imgs/cryptoScheme.png"><p>
<img src="../Imgs/scheme2.png"><p>

[main.cpp](https://github.com/ChiaraBn/Master-Thesis/blob/main/Int_Scheme/main.cpp) contains the development for this first brief example.<br>
The use case is about a **sum** between two int numbers, which represents the integer approximation of the distance between GPS coordinates. <br>
It is also present a **comparison** between the presented approach and the one with the **serialization** usually used **without** the use of (R)RNS.<br>

Cryptographic scheme used: **BGV**, due to the usage of int numbers.

## Conclusions
It was therefore possible to interpret the various ciphers as sequences of integers, then encode them in a redundant RNS form and simulate sending them to an aggregator.<br>
The latter is able to remove the RNS encoding and reinterpret the contents as a cipher and then continue with the arithmetic operations.<br>
Simulations with and without RNS encoding are equivalent.

## Observations
- For a decentralized architecture is necessary to **send** the cryptocontext along with the keys (RSA).