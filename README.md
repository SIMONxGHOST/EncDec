# EncDec — Encryption, Decryption, File Security & QR Suite

**EncDec** is a cryptography and file security suite designed for authenticated text encryption, binary file protection, compressed QR code generation/scanning, and real-time password entropy analysis.

Available as both a responsive desktop interface and an enhanced web application.

## 🔒 Overview

EncDec provides end-to-end symmetric encryption powered by standard cryptographic primitives. It utilizes **Fernet (AES-128-CBC with HMAC-SHA256 authentication)** combined with **PBKDF2-HMAC-SHA256** key derivation, offering configurable iteration counts (100k up to 2.0M) and salt lengths (16 to 256 bytes).

---

## ✨ Key Features

* **Text Encryption & Decryption**: Dual-pane workflow with live character/word counters, clipboard integration, and file import/export.
* **Self-Describing Envelopes (`ENC4:`)**: Ciphertexts include key tier metadata, allowing automated security tier detection during decryption.
* **Binary File Security**: Encrypt any file type (`.pdf`, `.docx`, `.zip`, images, binaries) with atomic temporary writes and tamper verification.
* **High-Density QR Engine**: Utilizes `zlib` (level 9 compression) + URL-safe Base64 encoding to compress encrypted payloads for QR rendering and scanning.
* **QR Scanner**: Decode QR codes from image files via OpenCV or webcam scanning.
* **Password Entropy & Strength Analyzer**: Real-time evaluation of character pool entropy, pattern penalties, and bit strength.
* **Password Generator**: Cryptographically secure pseudo-random generator (CSPRNG) for high-entropy master passphrases.
* **Dual-Theme GUI / Web View**: Dark and Light themes with responsive layouts and real-time status telemetry.

---

## 🛡️ Cryptographic Specifications

| Component | Implementation | Description |
| --- | --- | --- |
| **Cipher** | Fernet (AES-128 in CBC mode) | PKCS7 padding, 128-bit IV |
| **Integrity / MAC** | HMAC-SHA256 | Authenticated encryption (ciphertext integrity verification) |
| **Key Derivation** | PBKDF2-HMAC-SHA256 | Derives a 256-bit encryption/authentication key |
| **Salt Generation** | `os.urandom` / CSPRNG | 16 to 256 bytes depending on key tier |
| **Data Compression** | `zlib` (Deflate level 9) | Payload size reduction for QR code transmission |

---

## ⚙️ Security Profiles & Key Tiers

EncDec allows selecting PBKDF2 iteration tiers based on security requirements:

| Profile | Alias | PBKDF2 Iterations | Salt Length | Typical Use Case |
| --- | --- | --- | --- | --- |
| **Key 1 (Fast)** | `Key 1` | 100,000 | 16 bytes | High-throughput / Low-latency |
| **Key 2 (Standard)** | `Key 2` | 200,000 | 32 bytes | **Default** balanced configuration |
| **Key 3 (Enhanced)** | `Key 3` | 300,000 | 32 bytes | General secure messaging |
| **Key 4 (High)** | `Key 4` | 400,000 | 32 bytes | Sensitive personal records |
| **Key 5 (High+)** | `Key 5` | 500,000 | 32 bytes | Enterprise document security |
| **Key 6 (Strong)** | `Key 6` | 800,000 | 64 bytes | Long-term archival |
| **Key 7 (Very Strong)** | `Key 7` | 1,000,000 | 64 bytes | OWASP / NIST recommended high baseline |
| **Key 8 (Ultra)** | `Key 8` | 1,200,000 | 64 bytes | Critical sensitive data storage |
| **Key 9 (Extreme)** | `Key 9` | 1,500,000 | 128 bytes | Maximum brute-force defense |
| **Key 10 (Paranoid)** | `Key 10` | 2,000,000 | 256 bytes | Highest key hardening tier |

---

## 📦 Envelope & Container Specifications

### 1. Self-Describing Text Envelope (`ENC4`)

Ciphertexts created with envelope formatting use a structured string representation:

```text
ENC4:<key_alias>:<salt_base64>:<ciphertext_base64>

```

*Example:*

```text
ENC4:Key 2:9dF2...==:gAAAAABn...==

```

### 2. Encrypted File Container (`ENC4F`)

Encrypted files (`.enc`) are saved using an atomic binary format:

```text
[MAGIC: 5 bytes ("ENC4F\x01")]
[ALIAS_LEN: 2 bytes (big-endian uint16)]
[ALIAS_BYTES: UTF-8 encoded key tier name]
[SALT_LEN: 2 bytes (big-endian uint16)]
[SALT_BYTES: Cryptographic salt]
[ENCRYPTED_PAYLOAD: Authenticated Fernet ciphertext]

```

---

## 🚀 Installation & Setup

### Prerequisites

* Python 3.8 or higher
* `pip` package manager

### Clone Repository

```bash
git clone https://github.com/SIMONxGHOST/EncDec.git
cd EncDec

```

### Install Dependencies

```bash
pip install cryptography pillow qrcode[pil] opencv-python

```

*(Optional dependencies for alternative QR backends: `pip install segno`)*

---

## 🖥️ Usage Guide

### Launching the Application

Run the Python application:

```bash
python3 EncDec5.py

```

### 1. Text Encryption & Decryption

1. Enter a **Master Password** in the top panel (or click **⚡ Generate** for a secure 32-character key).
2. Select the desired **Key Tier** from the dropdown.
3. Type or paste text into the **Plaintext** pane.
4. Click **🔒 Encrypt ➡️** to produce the ciphertext.
5. To decrypt, paste the ciphertext into the **Encrypted** pane and click **⬅️ Decrypt 🔓**.

### 2. File Security Hub

1. Navigate to the **📁 File Security** tab.
2. Click **📂 Browse...** to select any source file.
3. Enter the encryption password (or click **🔗 Copy from Main**).
4. Click **🔒 Encrypt File (.enc)** to create a protected archive.
5. To restore the file, select the `.enc` file, provide the password, and click **🔓 Decrypt File**.

### 3. QR Code Suite

* **Generate QR**: Click **📱 Show QR** from the text encryption tab to generate a compressed QR image of your ciphertext, with an option to save as PNG.
* **Scan QR**: Click **📷 Scan QR Image** to import an image containing a QR code directly into the encrypted text field.

### 4. Password Entropy & Generator

* The password strength indicator computes entropy in bits and categorizes strength into:
* `Very Weak` (< 35 bits)
* `Weak` (35–54 bits)
* `Moderate` (55–74 bits)
* `Strong` (75–94 bits)
* `Very Strong` (≥ 95 bits)



---

## 📂 Repository Structure

```text
EncDec/
├── EncDec5.py          # Main application source code
├── README.md           # Project documentation and specifications
└── requirements.txt    # Python package dependencies


```

---

## ⚠️ Security Considerations

* **Password Safety**: EncDec does not store your master password. If a master password is lost, data cannot be recovered.
* **Authenticated Encryption**: Fernet ensures ciphertext integrity. Any modification or corruption of ciphertext or encrypted files will cause decryption to fail safely rather than outputting corrupted data.
* **QR Code Density**: For very large payloads (> 2 KB), standard QR scanning may require higher image resolution or closer camera focus.

---

## 📄 License

This project is open-source as it can gets.
