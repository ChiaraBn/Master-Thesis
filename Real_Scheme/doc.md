# Use of RRNS in Approximate Arithmetic (CKKS scheme)

## Approach
The one presented is the main usage scenario for the concrete case study, which concerns the total path calculation by manipulating GPS coordinates.<br>
The dataset data are kept in **floating point**, which is easy to adapt to the approximate arithmetic scheme as **CKKS** is.<br>
**Redundancy** is inserted into the ciphers, when sending to the aggregator, by using the redundant encoding of RNS.

[**Serialization**](https://palisade-crypto.org/wp-content/uploads/2021/08/PALISADE-12-11-20-Serialization-Applications.pdf) is introduced, supported in PALISADE, to convert the ciphertexts into a **sequence of bytes** and then represent them into **redundant** RNS.

## Draft
<img src="../Imgs/cryptoScheme.png"><p>
<img src="../Imgs/scheme2.png"><p>

[main.cpp](https://github.com/ChiaraBn/Master-Thesis/blob/main/Real_Scheme/main.cpp) contains the development for this case study.<br>
The use case is about a **sum** between two floating point numbers, representing the distance between GPS coordinates.<br>
It is also present a **comparison** between the presented approach and the one with the **serialization** usually used **without** the use of RNS.<br>

Cryptographic scheme used: **CKKS**, due to the usage of floating point numbers.

## Conclusions
It was therefore possible to interpret the various ciphers as sequences of integers, then encode them in a redundant RNS form and simulate sending them to an aggregator.<br>
The latter is able to remove the RNS encoding and reinterpret the contents as a cipher and then continue with the arithmetic operations.<br>
Simulations with and without RNS encoding are equivalent.

## Observations
- For a decentralized architecture is necessary to **send** the cryptocontext along with the keys (RSA).