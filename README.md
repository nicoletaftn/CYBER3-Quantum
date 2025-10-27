# Hybrid Quantum-Classical Secure Communication System

A practical implementation of a hybrid cryptographic protocol combining Quantum Key Distribution (QKD), Post-Quantum Cryptography (PQC), and classical symmetric encryption for secure communication.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Protocol Flow](#protocol-flow)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)

---

## 🔍 Overview

This project demonstrates a **future-proof secure communication system** that combines three complementary cryptographic approaches:

1. **QKD (Quantum Key Distribution)** - BB84 protocol for generating symmetric keys with information-theoretic security
2. **PQC (Post-Quantum Cryptography)** - ML-DSA-65 (NIST FIPS 204, formerly Dilithium) for quantum-resistant authentication
3. **AES-256-GCM** - Symmetric encryption using QKD-derived keys

The system provides end-to-end encrypted communication between two parties over a network, protecting against both classical and quantum adversaries.

---

## Features

- BB84 Quantum Key Distribution protocol (simulated via [QuNetSim](https://github.com/tqsd/QuNetSim))
- ML-DSA-65 post-quantum digital signatures
- AES-256-GCM authenticated encryption
- Network-based two-terminal communication
- Interactive command-line interface
- Real-time encrypted messaging

### Security Properties
- **Confidentiality**: Messages encrypted with QKD-derived keys
- **Authentication**: Digital signatures prevent impersonation
- **Integrity**: AES-GCM detects tampering
- **Non-repudiation**: ML-DSA-65 signatures are unforgeable
- **Forward secrecy**: Keys derived from QKD protocol

---

## 🏗️ Architecture

### System Components
```bash
┌─────────────────────────────────────────────────────────┐
│                    Secure Terminal                      │
│  ┌───────────────────────────────────────────────────┐  │
│  │           Interactive CLI Interface               │  │
│  └───────────────────────────────────────────────────┘  │
│                          ↓                              │
│  ┌───────────────────────────────────────────────────┐  │
│  │         Hybrid Protocol Manager                   │  │
│  │  ┌─────────────┐ ┌──────────────┐ ┌───────────┐   │  │
│  │  │ QKD Module  │ │  PQC Module  │ │AES Module │   │  │
│  │  │   (BB84)    │ │  (ML-DSA-65) │ │(AES-256)  │   │  │
│  │  └─────────────┘ └──────────────┘ └───────────┘   │  │
│  └───────────────────────────────────────────────────┘  │
│                          ↓                              │
│  ┌───────────────────────────────────────────────────┐  │
│  │          Network Communication Layer              │  │
│  │              (Socket-based)                       │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

### Communication Flow
```bash
Alice                                            Bob
│                                               │
├─────────► 1. ML-DSA-65 Public Key ───────────►│
│◄────────── 2. ML-DSA-65 Public Key ───────────┤
│                                               │
├─────────► 3. QKD BB84 Key Generation ────────►│
│           (Quantum channel simulation)        │
│                                               │
├─────────► 4. Encrypted Message ──────────────►│
│           (AES-256 + ML-DSA-65 signature)     │
│◄────────── 5. Encrypted Response ─────────────┤
│                                               │
```
---

## Protocol Flow
Cryptographic Exchange Between Alice and Bob

**Authentication Setup**
1. Alice generates ML-DSA-65 keypair → (Public Key A, Private Key A)
2. Bob generates ML-DSA-65 keypair → (Public Key B, Private Key B)

**Public Key Exchange**

4. Alice → Bob: Public Key A
5. Bob → Alice: Public Key B

**Quantum Key Distribution (BB84)**

6. Alice generates QKD key via BB84
- Prepares random qubits
- Sends qubits to Bob over quantum channel
- Bob measures qubits
- Basis reconciliation
- Error detection
- Result: 128-bit symmetric key (K_QKD)
7. Alice → Bob: K_QKD (over TCP)
  
**Secure Message Exchange**

8. Alice encrypts message → AES-256-GCM(message, K_QKD) → (nonce, tag, ciphertext)
9. Alice signs encrypted package → ML-DSA-65.Sign(encrypted_package, Private Key A) → signature
10. Alice → Bob: encrypted_package + signature
11. Bob verifies signature → ML-DSA-65.Verify(encrypted_package, signature, Public Key A)
12. Bob decrypts message → AES-256-GCM.Decrypt(encrypted_package, K_QKD) → plaintext

## 🛠️ Installation

### Windows Installation (Using WSL)

The easiest way to run this project on Windows is using **Windows Subsystem for Linux (WSL)**, which provides a Linux environment.

Open **PowerShell as Administrator** (Right-click → "Run as Administrator"):
```powershell
wsl --install
```
Restart computer when prompted then open elevated powershell and install ubuntu
```powershell
wsl.exe --install ubuntu
```
Create a username and password when prompted then run the following commands
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install required dependencies
sudo apt install -y python3 python3-pip python3-venv git cmake ninja-build libssl-dev

# Clone liboqs repository
cd ~
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs

# Build liboqs with shared libraries
mkdir build && cd build
cmake -GNinja -DBUILD_SHARED_LIBS=ON ..
ninja

# Install system-wide
sudo ninja install
sudo ldconfig

cd ~
git clone https://github.com/philipbilbo/hybrid-quantum-communication.git
cd hybrid-quantum-communication

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

#Verify installation
python test_setup.py
```
Expected output:
```bash
Testing Environment Setup...
------------------------------
✓ QuNetSim
✓ liboqs (ML-DSA-65)
✓ PyCryptodome (AES-256)
------------------------------
✓ Ready to start development!
```
---

### MacOS Installation (Homebrew)

Install dependecies
```bash
# Install Python 3.11+, cmake and Ninja
brew install python@3.11 cmake ninja

# Verify installations
python3 --version
cmake --version
```
Build and Install liboqs with Shared Libraries
```bash
# Clone liboqs repository
cd ~
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs

# Build liboqs with shared libraries
mkdir build && cd build
cmake -GNinja -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/opt/homebrew/opt/liboqs ..
ninja

# Install system-wide
sudo ninja install

# Verify shared library was created
ls /opt/homebrew/opt/liboqs/lib/liboqs.dylib
```
Clone the project and setup Python
```bash
# Clone the project
cd ~/Desktop  # or your preferred location
git clone https://github.com/philipbilbo/hybrid-quantum-communication.git
cd hybrid-quantum-communication

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install Python dependencies
pip install -r requirements.txt

# Verify installation
python test_setup.py
```
Expected output:
```bash
Testing Environment Setup...
------------------------------
✓ QuNetSim
✓ liboqs (ML-DSA-65)
✓ PyCryptodome (AES-256)
------------------------------
✓ Ready to start development!
```
---

## 🚀 Usage
Running the Secure Terminals
The system requires two terminal windows - one for each party (Alice and Bob).

**Terminal 1: Start Alice (Server)**
```bash
cd src/terminal
python secure_terminal.py --name Alice --role server --peer Bob
```
Alice will:
1. Start listening on port 9999
2. Wait for Bob to connect
3. Generate ML-DSA-65 keypair
4. Exchange public keys
5. Generate QKD key (takes ~1-2 minutes)
6. Enter interactive mode


**Terminal 2: Start Bob (Client)**
```bash
cd src/terminal
python secure_terminal.py --name Bob --role client --peer Alice
```
Bob will: 
1. Connect to Alice
2. Generate ML-DSA-65 keypair
3. Exchange public keys
4. Receive QKD key from Alice
5. Enter interactive mode

Interactive Commands
Once both terminals show "INTERACTIVE MODE - Ready to communicate!", you can:
bash# Send a message (just type and press Enter)
Alice> Hello Bob! This is quantum-safe!

### Check connection status
```bash
Alice> /status
```

### View message history
```bash
Alice> /history
```
### Get help
```bash
Alice> /help
```
### Exit
```bash
Alice> /quit
```
## Advanced Usage
### Use custom host and port
```bash
python secure_terminal.py --name Alice --role server --peer Bob --host 0.0.0.0 --port 8888
```

### Connect to remote server
```bash
python secure_terminal.py --name Bob --role client --peer Alice --host 192.168.1.100 --port 8888
```
---
## 📁 Project Structure
```bash
hybrid-quantum-crypto/
├── src/
│   ├── qkd/
│   │   └── bb84.py                 # BB84 QKD implementation
│   ├── pqc/
│   │   └── ml_dsa_auth.py          # ML-DSA-65 authentication
│   ├── crypto/
│   │   └── aes_cipher.py           # AES-256-GCM encryption
│   ├── protocol/
│   │   └── hybrid_protocol.py      # Hybrid protocol manager
│   ├── network/
│   │   └── socket_comm.py          # Network communication
│   └── terminal/
│       └── secure_terminal.py      # User interface
├── tests/
├── test_setup.py                   # Environment verification
├── requirements.txt                # Python dependencies
└── README.md
```
          
