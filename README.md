# Cryptography-Projects
# Cryptography Project

A collection of Python scripts demonstrating core cryptographic techniques, including RSA encryption, digital signatures, and custom hashing. This project is designed for educational purposes and showcases how these cryptographic primitives work under the hood.

---

## Table of Contents

- [Overview](#overview)
- [Tools & Scripts](#tools--scripts)
  - [Rsa.py](#rsapy)
  - [Rsav2.py](#rsav2py)
  - [DigitalSignature.py](#digitalsignaturepy)
  - [hash.py](#hashpy)
- [Requirements](#requirements)
- [Usage](#usage)
- [License](#license)

---

## Overview

This project implements fundamental cryptographic operations from scratch, including:

- RSA key generation, encryption, and decryption
- Secure exchange of symmetric keys using RSA
- Digital signature creation and verification
- Custom hash function for message integrity

Each script is self-contained and demonstrates a specific cryptographic concept.

---

## Tools & Scripts

### `Rsa.py`

Implements the RSA public-key cryptosystem, including:

- **Key Generation:** Generates large prime numbers, computes modulus, public and private exponents.
- **Encryption:** Converts a plaintext message to an integer, encrypts it using the public key.
- **Decryption:** Decrypts the ciphertext using the private key and converts it back to a string.
- **Demo:** Shows the process of generating keys, encrypting a symmetric key, and decrypting it to verify correctness.

**Use case:** Learn how RSA works for secure key exchange and message confidentiality.

---

### `Rsav2.py`

An alternative implementation of RSA with a focus on:

- **Byte-wise Encryption/Decryption:** Encrypts and decrypts messages byte by byte, demonstrating a different approach to handling data.
- **Key Generation:** Similar to `Rsa.py`, but with slight variations in implementation.
- **Demo:** Walks through key generation, encryption of a symmetric key, and decryption for verification.

**Use case:** Compare different approaches to RSA encryption and understand byte-level operations.

---

### `DigitalSignature.py`

Demonstrates digital signature creation and verification using RSA and a custom hash function:

- **Custom Hash Function:** Provides a simple, educational hash for message digest creation.
- **Signature Generation:** Signs a message digest with the RSA private key.
- **Signature Verification:** Verifies the signature using the RSA public key.
- **Tampering Demo:** Shows how signature verification fails if the message is altered.

**Use case:** Understand the principles of digital signatures and message integrity.

---

### `hash.py`

Implements a custom hash function for educational purposes:

- **Custom Hash:** Processes input strings with bitwise operations and produces a fixed-length hexadecimal digest.
- **Sensitivity Demo:** Shows how small changes in the input message produce drastically different hashes.

**Use case:** Learn about hash functions and their importance in cryptography.

---

## Requirements

- Python 3.x

No external dependencies are required.

---

## Usage

1. **Clone the repository:**
 

2. **Run any script directly:**
   ```sh
   python Rsa.py
   python Rsav2.py
   python DigitalSignature.py
   python hash.py
   ```

3. **Explore and modify the code** to experiment with cryptographic concepts.

---

## License

This project is licensed under the MIT License.
