# EncDec Studio Pro (v5.1.0) — Military-Grade Cryptography & Vault Suite

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Web Crypto: Native](https://img.shields.io/badge/Web_Crypto_API-AEAD-green.svg)](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
[![Cipher: AES-256-GCM](https://img.shields.io/badge/Cipher-AES--256--GCM-blueviolet.svg)](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
[![KDF: Scrypt / Argon2id](https://img.shields.io/badge/KDF-Scrypt_%2F_Argon2id-red.svg)](https://en.wikipedia.org/wiki/Scrypt)

**EncDec Studio Pro** is an open-source, quantum-resistant cryptography suite and file vault engineered for extreme security. Designed to withstand brute-force attacks from massive GPU clusters and supercomputers, it combines **Memory-Hard Key Derivation Functions (Scrypt & Argon2id)**, authenticated **AES-256-GCM** encryption, optional **Two-Factor Hardware Keyfiles**, high-entropy **Diceware Passphrase generation**, and a live **QR Code Studio & Scanner**.

---

## 🌟 Key Features

1. **Memory-Hard Key Derivation (Scrypt & Argon2id):**
   - Allocates between **16 MB and 512 MB of fast RAM** per key derivation across 10 security tiers (`Key 1` to `Key 10`).
   - High memory requirements throttle and neutralize parallel GPU/ASIC brute-force farms.

2. **Quantum-Resistant Authenticated Symmetric Cipher (AES-256-GCM AEAD):**
   - 256-bit key length provides full resistance against Grover's quantum search algorithm (128 bits post-quantum security margin).
   - 128-bit Galois Authentication Tag ensures tamper-proof integrity and guards against bit-flipping attacks.

3. **Two-Factor Keyfile Authentication:**
   - Attach an optional 256-bit binary token file (e.g. on a USB drive). Key derivation binds password entropy with the physical keyfile hash.

4. **Diceware Passphrase & High-Entropy Engine:**
   - Generates memorable, high-entropy passphrases (6 to 8 words, $\ge 80\text{–}120$ bits of true entropy).
   - Real-time Shannon entropy meter and crack time estimator calibrated for supercomputing clusters.

5. **Self-Describing Formats & Backward Compatibility:**
   - **Text Envelope (`ENC5:`):** Automatically identifies key profile and KDF.
   - **Binary Container (`ENC5F\x02`):** Embedded JSON metadata for streaming and large file vaults.
   - **Legacy Support:** Automatically detects and decrypts legacy `ENC4:` and `ENC4F\x01` (Fernet AES-128 / PBKDF2) data.

6. **Cross-Platform Multi-Mode Execution:**
   - **Single-File Standalone (`encdec_standalone.html`):** Runs 100% offline in any modern browser using the Web Crypto API with zero dependencies.
   - **Desktop GUI Launcher (`EncDec_WebView.py`):** Frameless app window mode or PyWebView.
   - **Command Line Tool (`EncDec_CLI.py`):** Full-featured CLI for scripting and automation.
   - **FastAPI Server (`server.py`):** High-throughput REST API with OpenCV camera/image QR scanning.
   - **Android Studio App:** Native mobile WebView integration with hardware acceleration.

---

## 🔒 10-Tier Cryptographic Profiles Matrix

| Profile | Memory Requirement | KDF Parameters (Scrypt) | Symmetric Cipher | Security Rating | Recommended Use Case |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Key 1 (Fast)** | **16 MB RAM** | $N=16384, r=8, p=1$ | AES-256-GCM | Fast Memory-Hard | Rapid text messaging & temporary tokens |
| **Key 2 (Standard)** | **32 MB RAM** | $N=32768, r=8, p=1$ | AES-256-GCM | Standard Memory-Hard | General daily secure communications |
| **Key 3 (Enhanced)** | **48 MB RAM** | $N=32768, r=12, p=1$ | AES-256-GCM | Enhanced Security | Personal records and sensitive text |
| **Key 4 (High)** | **64 MB RAM** | $N=65536, r=8, p=1$ | AES-256-GCM | High Security (AEAD) | **Default System Profile** |
| **Key 5 (High+)** | **96 MB RAM** | $N=65536, r=12, p=1$ | AES-256-GCM | High+ Vault Grade | Financial documents & stored credentials |
| **Key 6 (Strong)** | **128 MB RAM** | $N=131072, r=8, p=1$ | AES-256-GCM | Strong Vault Grade | Long-term confidential archives |
| **Key 7 (Very Strong)**| **160 MB RAM** | $N=131072, r=10, p=1$ | AES-256-GCM | Very Strong Vault | High GPU-threat environments |
| **Key 8 (Ultra)** | **192 MB RAM** | $N=131072, r=12, p=1$ | AES-256-GCM | Supercomputer-Proof | Critical backups & mission-critical files |
| **Key 9 (Extreme)** | **256 MB RAM** | $N=262144, r=8, p=1$ | AES-256-GCM | Military Vault Grade | Government & enterprise vault storage |
| **Key 10 (Paranoid)**| **512 MB RAM** | $N=524288, r=8, p=1$ | AES-256-GCM | Quantum / ASIC Proof | Maximum physical & thermodynamic resistance |

---

## 🚀 Installation & Quick Start

### 1. Requirements & Setup
```bash
git clone https://github.com/your-username/EncDec-Studio-Pro.git
cd EncDec-Studio-Pro
pip install -r requirements.txt
```

### 2. Desktop GUI Launcher
```bash
python EncDec_WebView.py
```

### 3. Command Line Interface (CLI)
```bash
# Encrypt Text
python EncDec_CLI.py encrypt-text -t "Secret Payload" -p "MasterPassphrase" -k "Key 4"

# Decrypt Text
python EncDec_CLI.py decrypt-text -t "ENC5:Key 4:scrypt:..." -p "MasterPassphrase"

# Encrypt File with 2FA Keyfile
python EncDec_CLI.py encrypt-file document.pdf -p "MasterPassphrase" -k "Key 8" --keyfile secret.key

# Decrypt File
python EncDec_CLI.py decrypt-file document.pdf.enc -p "MasterPassphrase" --keyfile secret.key

# Generate Diceware Passphrase
python EncDec_CLI.py gen-pass --words 6

# Run Cryptographic Benchmark Suite
python EncDec_CLI.py benchmark
```

### 4. FastAPI REST Server
```bash
python server.py
# or
uvicorn server:app --host 127.0.0.1 --port 8080 --reload
```

### 5. Zero-Setup Offline Browser App
Double-click or open `encdec_standalone.html` in Chrome, Firefox, Edge, or Safari.

---

## 📱 Android Studio Integration
The repository includes a ready-to-build Android Studio project. Simply open it in Android Studio and build the APK.

---

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
