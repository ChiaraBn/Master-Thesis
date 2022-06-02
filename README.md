# Data aggregation using Homomorphic Encryption in Mobile CrowdSensing context

## Overview
This project aims to combine the advantages of **homomorphic encryption**, thus allowing secure data aggregation operations, with the use of **redundant RNS**, which provides robustness in an **MCS context**.<p>
The **goal** of this study is to demonstrate that if the **aggregator** receives at least the number of **legitimate** residues, the overall arithmetic operations are still running.<br>
Having **more** data than necessary prepared for sending, in case of architecture failures, means that there is the possibility to **recover** lost data.<p>

The use of **redundant RNS** is analyzed by comparing the performances of the cryptographic **schemes**, where the RNS can be applied **after** the scheme itself.<p>

The experiments were performed on the [**GeoLife**](https://www.microsoft.com/en-us/download/details.aspx?id=52367) dataset, which has a set of geographical coordinates that have been pre-processed in order to calculate the **distance** between points.<br>
Having the possibility to implement multiple encryption schemes, the **exact integer** arithmetic encryption scheme (BGV/BFV) is compared with the **approximate arithmetic** one (CKKS).

Documentation [Approximate Arithmetic](https://github.com/ChiaraBn/Master-Thesis/tree/main/Real_Scheme/doc.md) (CKKS).<br>
Documentation [Exact Int Arithmetic](https://github.com/ChiaraBn/Master-Thesis/tree/main/Int_Scheme/doc.md) (BGV).<br>

## Project Directory

    ├── README.md
    ├── py_requirements.txt
    ├── comparing.cpp

    ├── Data
        ├── geolife_example.csv
        ├── pre-processing.py
        ├── dataFloat.txt
        ├── dataInt.txt

    ├── Real_Scheme
        ├── a.out
        ├── build
            ├── CMakeFiles
               ├── ...
            ├── demoData
            ├── aggregatorData
            ├── cmake_install.cmake
            ├── CMakeCache.txt
            └── Makefile
        ├── doc.md
        ├── CMakeLists.txt
        ├── helpers.cpp
        ├── helpers.h
        └── main.cpp

    └── Int_Scheme
        ├── a.out
        ├── build
            ├── CMakeFiles
               ├── ...
            ├── demoData
            ├── aggregatorData
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

Therefore **before** building any source code, it is necessary to have **installed** [PALISADE](https://gitlab.com/palisade/palisade-development/-/tree/release-v1.11.2). <p>

Subsequently:
```
$ Master-Thesis

cd Real_Scheme [Int_Scheme]
cd build
make
```

To **run** the compiled code:
```
$ Master-Thesis/Real_Scheme/build

./run
```

After the testing, remove the files created by the compiler:
```
$ Master-Thesis/Real_Scheme/build

make clean
```

## On the dataset
It has been used the dataset [**GeoLife**](https://www.microsoft.com/en-us/download/details.aspx?id=52367), which stores a set of **GPS** **trajectories**.<br>
A trajectory is represented by a sequence of time-stamped points, each of which contains the information of latitude, longitude and altitude. <br>
This dataset contains **17,621 trajectories** with a total distance of about 1.2 million kilometers and a total duration of 48,000+ hours.<br>
This collection contains data of **182 users** in a period of over three years (from April 2007 to August 2012).<p>

For the purpose of the project, these trajectories are important in order to be able to do the **total sum** of distances, using homomorphic encryption. <br>
About **765.041 distances** have been collected.

To calculate the distance between GPS coordinates, using **Python**, it is necessary to use [**geopy**](https://geopy.readthedocs.io/en/stable/).<br>
```
pip install geopy

# Calculate the distance
distance = geodesic(coordinate1, coordinate2).km
```

In order to pre-process and elaborate the dataset, it has been used [**Pandas**](https://pandas.pydata.org/), an open source **data analysis** and manipulation tool in **Python**.

```
pip install pandas
```

## Keywords
- Homomorphic encryption
- Lattice cryptography
- Data Aggregation
- RRNS
- MCS
