# Use of RRNS before encryption

## Approach
The approach involves sampling an integer data from a sensor, then transforming it into its RRNS representation and **encrypting each residue**.<p>

## First Draft
<img src="../Imgs/cryptoScheme.png"><p>
<img src="../Imgs/scheme1.png"><p>

[PALISADE](https://palisade-crypto.org/) takes each residue and, in first action, trasforms them into a **polynomial Plaintext**, still representing the input text.<br>
Then, each residue is transformed into a **ciphertext**, which is actually a **pair** of **polynomials**.<p>

[main.cpp](https://github.com/ChiaraBn/Master-Thesis/blob/main/RnsBeforeCrypto/main.cpp) contains the development for this first brief example.<br>
The use case is about a **sum** between two int numbers.<br>
It is also present a **comparison** between the presented approach and the one usually used **without** the use of RNS.<br>
The results are the **same**, concluding that the submitted approach **does not introduce errors** into the computation.<p>

Cryptographic scheme used: **BGV**, due to the usage of int numbers.

## TODO

- Adapt it to the concrete scenario with GPS coordinates
- For a decentralized architecture is necessary to **send** the cryptocontext along with the keys (RSA).