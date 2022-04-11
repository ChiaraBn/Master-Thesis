# Master-Thesis

## Overview
This project aims to combine the advantages of **homomorphic encryption**, thus allowing secure data aggregation operations, with the use of **redundant RNS**, which provides robustness in an **MCS context**.<p>
The **goal** of this study is to demonstrate that if the **aggregator** receives at least the number of **legitimate** residues, the overall arithmetic operations are still running.<br>
Having **more** data than necessary prepared for sending, in case of architecture failures, means that there is the possibility to **recover** lost data.<p>


The use of **redundant RNS** is analyzed by comparing the performances of the cryptographic schemes, where the RNS can be applied both **before** or **after** the scheme itself.<br>

Documentation [Rns Before Cryptography](https://github.com/ChiaraBn/Master-Thesis/tree/main/RnsBeforeCrypto/doc.md).<br>
Documentation [Rns After Cryptography](https://github.com/ChiaraBn/Master-Thesis/tree/main/RnsAfterCrypto/doc.md).<br>

## Project Directory

    ├── README.md
    ├── RnsAfterCrypto
        ├── a.out
        ├── build
            ├── CMakeFiles
               ├── ...
            ├── DemoData
            ├── cmake_install.cmake
            ├── CMakeCache.txt
            └── Makefile
        ├── doc.md
        ├── CMakeLists.txt
        ├── helpers.cpp
        ├── helpers.h
        └── main.cpp

    └── RnsBeforeCrypto
        ├── a.out
        ├── build
            ├── CMakeFiles
               ├── ...
            ├── cmake_install.cmake
            ├── CMakeCache.txt
            └── Makefile
        ├── doc.md
        ├── CMakeLists.txt
        ├── helpers.cpp
        ├── helpers.h
        └── main.cpp

## Build
This project relies on **PALISADE**, which is an open-source library that provides efficient implementations of lattice cryptography building blocks and leading homomorphic encryption schemes.<br>

Therefore **before** building any source code, it is necessary to have installed [PALISADE](https://gitlab.com/palisade/palisade-development/-/tree/release-v1.11.2). <p>

Subsequently:
```
$ Master-Thesis

cd RnsBeforeCrypto [RnsAfterCrypto]
cd build
make
```

To **run** the compiled code:
```
$ Master-Thesis/RnsBeforeCrypto/build

./run
```

After the testing, remove the files created by the compiler:
```
$ Master-Thesis/RnsBeforeCrypto/build

make clean
```

## Keywords
- Homomorphic encryption
- Lattice cryptography
- RRNS
- MCS
- Data Aggregation