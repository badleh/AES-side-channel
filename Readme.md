# Secure AES-128 Implementation in C++

This project provides a functional implementation of the **AES-128 (Advanced Encryption Standard)** algorithm written in C++.

The primary focus of this implementation is to demonstrate the fundamental steps of the AES algorithm while incorporating countermeasures against **cache-based side-channel attacks**.



## Features

* **AES-128 Encryption:** Supports encryption of 16-byte blocks.
* **Key Expansion:** Generates round keys from a 128-bit master key.
* **Cache-Secure `SubBytes`:** Replaces standard table-lookup `SubByte` operations with mathematical calculations ($GF(2^8)$ inversion + Affine Transformation) to prevent timing attacks.

## Prerequisites

* A C++ compiler supporting C++11 or higher (e.g., `g++` or `clang`).

## Usage

### Compilation
Compile the code using `g++` with optimization flags for best performance:

```bash
g++ -O3 aes.cpp -o aes 
