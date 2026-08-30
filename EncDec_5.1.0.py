#!/usr/bin/env python3
"""
EncDec Pro (v5.1.0) — Military-Grade Encryption, Decryption, File Vault & QR Suite
==================================================================================
A secure, responsive desktop encryption application built with Python, Tkinter,
AES-256-GCM AEAD, Memory-Hard KDF (Scrypt / Argon2id), 2FA Keyfile support,
Diceware Passphrase Engine, and OpenCV QR Scanner.

Dependencies:
    pip install cryptography pillow qrcode[pil] opencv-python argon2-cffi
"""

import os
import io
import sys
import json
import math
import struct
import base64
import zlib
import re
import secrets
import string
import hashlib
import threading
import time
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, List

# Cryptography & Imaging
from PIL import Image
try:
    from PIL import ImageGrab
except ImportError:
    ImageGrab = None

try:
    from PIL import ImageTk
except ImportError:
    ImageTk = None

# Cryptography primitives
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# Optional Argon2
try:
    import argon2
    from argon2.low_level import hash_secret_raw, Type as ArgonType
    HAS_ARGON2 = True
except ImportError:
    HAS_ARGON2 = False

# GUI Imports
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog, font as tkfont
    from tkinter import scrolledtext
    HAS_TKINTER = True
except ImportError:
    HAS_TKINTER = False
    tk = None
    ttk = None
    messagebox = None
    filedialog = None
    tkfont = None
    scrolledtext = None

# QR Generation Backends
_qrcode = None
_segno = None
HAS_QRCODE = False
HAS_SEGNO = False

try:
    import qrcode as _qrcode
    HAS_QRCODE = hasattr(_qrcode, "QRCode") and hasattr(_qrcode, "constants")
except Exception:
    _qrcode = None
    HAS_QRCODE = False

try:
    import segno as _segno
    HAS_SEGNO = True
except Exception:
    _segno = None
    HAS_SEGNO = False

# QR Scanning Backend (OpenCV)
HAS_CV2 = False
try:
    import cv2
    import numpy as np
    HAS_CV2 = hasattr(cv2, "QRCodeDetector")
except Exception:
    HAS_CV2 = False


# =============================================================================
# Security Configurations & 10-Tier Profiles
# =============================================================================
KEY_CONFIGS: Dict[str, Dict[str, Any]] = {
    "Key 1 (Fast - 16MB Scrypt)": {
        "kdf": "argon2id" if HAS_ARGON2 else "scrypt",
        "cipher": "AES-256-GCM",
        "salt_length": 32,
        "scrypt_n": 16384,
        "scrypt_r": 8,
        "scrypt_p": 1,
        "argon_m": 16384,
        "argon_t": 2,
        "argon_p": 1,
        "mem_mb": 16,
        "alias": "Key 1",
        "rating": "Fast Memory-Hard"
    },
    "Key 2 (Standard - 32MB Scrypt)": {
        "kdf": "argon2id" if HAS_ARGON2 else "scrypt",
        "cipher": "AES-256-GCM",
        "salt_length": 32,
        "scrypt_n": 32768,
        "scrypt_r": 8,
        "scrypt_p": 1,
        "argon_m": 32768,
        "argon_t": 2,
        "argon_p": 1,
        "mem_mb": 32,
        "alias": "Key 2",
        "rating": "Standard Memory-Hard"
    },
    "Key 3 (Enhanced - 48MB Scrypt)": {
        "kdf": "argon2id" if HAS_ARGON2 else "scrypt",
        "cipher": "AES-256-GCM",
        "salt_length": 32,
        "scrypt_n": 32768,
        "scrypt_r": 12,
        "scrypt_p": 1,
        "argon_m": 49152,
        "argon_t": 2,
        "argon_p": 2,
        "mem_mb": 48,
        "alias": "Key 3",
        "rating": "Enhanced Security"
    },
    "Key 4 (High - 64MB Scrypt)": {
        "kdf": "argon2id" if HAS_ARGON2 else "scrypt",
        "cipher": "AES-256-GCM",
        "salt_length": 32,
        "scrypt_n": 65536,
        "scrypt_r": 8,
        "scrypt_p": 1,
        "argon_m": 65536,
        "argon_t": 2,
        "argon_p": 2,
        "mem_mb": 64,
        "alias": "Key 4",
        "rating": "High Security (AEAD)"
    },
    "Key 5 (High+ - 96MB Scrypt)": {
        "kdf": "argon2id" if HAS_ARGON2 else "scrypt",
        "cipher": "AES-256-GCM",
        "salt_length": 32,
        "scrypt_n": 65536,
        "scrypt_r": 12,
        "scrypt_p": 1,
        "argon_m": 98304,
        "argon_t": 3,
        "argon_p": 2,
        "mem_mb": 96,
        "alias": "Key 5",
        "rating": "High+ Vault Grade"
    },
    "Key 6 (Strong - 128MB Scrypt)": {
        "kdf": "argon2id" if HAS_ARGON2 else "scrypt",
        "cipher": "AES-256-GCM",
        "salt_length": 32,
        "scrypt_n": 131072,
        "scrypt_r": 8,
        "scrypt_p": 1,
        "argon_m": 131072,
        "argon_t": 3,
        "argon_p": 2,
        "mem_mb": 128,
        "alias": "Key 6",
        "rating": "Strong Vault Grade"
    },
    "Key 7 (Very Strong - 160MB Scrypt)": {
        "kdf": "argon2id" if HAS_ARGON2 else "scrypt",
        "cipher": "AES-256-GCM",
        "salt_length": 32,
        "scrypt_n": 131072,
        "scrypt_r": 10,
        "scrypt_p": 1,
        "argon_m": 163840,
        "argon_t": 3,
        "argon_p": 4,
        "mem_mb": 160,
        "alias": "Key 7",
        "rating": "Very Strong Vault"
    },
    "Key 8 (Ultra - 192MB Scrypt)": {
        "kdf": "argon2id" if HAS_ARGON2 else "scrypt",
        "cipher": "AES-256-GCM",
        "salt_length": 32,
        "scrypt_n": 131072,
        "scrypt_r": 12,
        "scrypt_p": 1,
        "argon_m": 196608,
        "argon_t": 4,
        "argon_p": 4,
        "mem_mb": 192,
        "alias": "Key 8",
        "rating": "Supercomputer-Proof"
    },
    "Key 9 (Extreme - 256MB Scrypt)": {
        "kdf": "argon2id" if HAS_ARGON2 else "scrypt",
        "cipher": "AES-256-GCM",
        "salt_length": 32,
        "scrypt_n": 262144,
        "scrypt_r": 8,
        "scrypt_p": 1,
        "argon_m": 262144,
        "argon_t": 4,
        "argon_p": 4,
        "mem_mb": 256,
        "alias": "Key 9",
        "rating": "Military Vault Grade"
    },
    "Key 10 (Paranoid - 512MB Scrypt)": {
        "kdf": "argon2id" if HAS_ARGON2 else "scrypt",
        "cipher": "AES-256-GCM",
        "salt_length": 32,
        "scrypt_n": 524288,
        "scrypt_r": 8,
        "scrypt_p": 1,
        "argon_m": 524288,
        "argon_t": 4,
        "argon_p": 4,
        "mem_mb": 512,
        "alias": "Key 10",
        "rating": "Quantum / ASIC Proof"
    }
}

LEGACY_PBKDF2_MAP = {
    "Key 1": 100000, "Key 2": 200000, "Key 3": 300000, "Key 4": 400000, "Key 5": 500000,
    "Key 6": 800000, "Key 7": 1000000, "Key 8": 1200000, "Key 9": 1500000, "Key 10": 2000000
}

ALIAS_TO_CONFIG: Dict[str, Dict[str, Any]] = {}
for k, v in KEY_CONFIGS.items():
    ALIAS_TO_CONFIG[k] = v
    ALIAS_TO_CONFIG[v["alias"]] = v

DEFAULT_KEY_PROFILE = "Key 4 (High - 64MB Scrypt)"

DICEWARE_WORDS = [
    "quantum", "cipher", "matrix", "falcon", "beacon", "galaxy", "nebula", "aurora",
    "shield", "vertex", "vector", "orbital", "stellar", "photon", "pulsar", "cosmos",
    "crypto", "zenith", "vortex", "plasma", "shadow", "silver", "golden", "glacier",
    "castle", "island", "forest", "timber", "canyon", "desert", "stream", "summit",
    "thunder", "blizzard", "tornado", "typhoon", "volcano", "horizon", "eclipse", "comet",
    "bastion", "citadel", "fortress", "paladin", "sentinel", "guardian", "titan", "phoenix",
    "dragon", "hydra", "chimera", "pegasus", "kraken", "griffin", "sphinx", "valkyrie",
    "diamond", "emerald", "sapphire", "obsidian", "crystal", "granite", "basalt", "quartz",
    "anchor", "compass", "voyage", "odyssey", "pioneer", "explorer", "journey", "passage",
    "whisper", "echo", "harmony", "symphony", "melody", "rhythm", "tempo", "chorus",
    "radiant", "luminous", "brilliant", "infinite", "eternal", "serene", "tranquil", "valiant"
]


def get_key_config(key_name: str) -> Dict[str, Any]:
    """Retrieve key profile config with safe fallback."""
    if key_name in ALIAS_TO_CONFIG:
        return ALIAS_TO_CONFIG[key_name]
    return KEY_CONFIGS[DEFAULT_KEY_PROFILE]


# =============================================================================
# Cryptography Core Engine (AES-256-GCM + Scrypt + 2FA Keyfile)
# =============================================================================
class CryptoEngine:
    MAGIC_HEADER_V5 = "ENC5:"
    MAGIC_HEADER_V4 = "ENC4:"
    FILE_MAGIC_V5 = b"ENC5F\x02"
    FILE_MAGIC_V4 = b"ENC4F\x01"

    @staticmethod
    def prepare_key_material(password: str, keyfile_bytes: Optional[bytes] = None) -> bytes:
        material = password.encode('utf-8')
        if keyfile_bytes:
            kf_hash = hashlib.sha256(keyfile_bytes).digest()
            material = material + b"::KEYFILE::" + kf_hash
        return material

    @classmethod
    def derive_symmetric_key(cls, material: bytes, salt: bytes, config: Dict[str, Any], length: int = 32) -> bytes:
        kdf_type = config.get("kdf", "scrypt")
        if kdf_type == "argon2id" and HAS_ARGON2:
            m = config.get("argon_m", 65536)
            t = config.get("argon_t", 2)
            p = config.get("argon_p", 2)
            return hash_secret_raw(
                secret=material,
                salt=salt,
                time_cost=t,
                memory_cost=m,
                parallelism=p,
                hash_len=length,
                type=ArgonType.ID
            )
        elif kdf_type in ("scrypt", "argon2id"):
            n = config.get("scrypt_n", 65536)
            r = config.get("scrypt_r", 8)
            p = config.get("scrypt_p", 1)
            maxmem = max(1024 * 1024 * 1024, (n * r * 128 * 2))
            return hashlib.scrypt(material, salt=salt, n=n, r=r, p=p, maxmem=maxmem, dklen=length)
        else:
            iters = config.get("iterations", 200000)
            return hashlib.pbkdf2_hmac('sha256', material, salt, iters, length)

    @classmethod
    def derive_legacy_pbkdf2(cls, password: str, salt: bytes, iterations: int) -> bytes:
        return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, 32)

    @classmethod
    def encrypt_text(cls, plain_text: str, password: str, key_type: str, use_envelope: bool = True,
                     keyfile_bytes: Optional[bytes] = None) -> str:
        """Encrypt plaintext into self-describing ENC5 or raw AES-256-GCM base64."""
        if not plain_text or not password:
            return ""
        config = get_key_config(key_type)
        salt = os.urandom(config["salt_length"])
        material = cls.prepare_key_material(password, keyfile_bytes)
        key = cls.derive_symmetric_key(material, salt, config, length=32)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plain_text.encode('utf-8'), None)

        if use_envelope:
            salt_b64 = cls.safe_b64encode(salt)
            nonce_b64 = cls.safe_b64encode(nonce)
            cipher_b64 = cls.safe_b64encode(ciphertext)
            alias = config["alias"]
            return f"{cls.MAGIC_HEADER_V5}{alias}:scrypt:{salt_b64}:{nonce_b64}:{cipher_b64}"
        else:
            return cls.safe_b64encode(salt + nonce + ciphertext)

    @classmethod
    def decrypt_text(cls, encrypted_text: str, password: str, key_type: str = "Key 4",
                     keyfile_bytes: Optional[bytes] = None) -> Tuple[bool, str, str]:
        """
        Decrypt encrypted text with automatic detection of ENC5, ENC4, and raw AEAD.
        Returns: (success: bool, decrypted_text: str, detected_key_alias: str)
        """
        if not encrypted_text or not password:
            return False, "", ""

        s = encrypted_text.strip()
        material = cls.prepare_key_material(password, keyfile_bytes)

        # 1. ENC5: Next-Gen AES-256-GCM envelope
        if s.startswith(cls.MAGIC_HEADER_V5):
            try:
                parts = s.split(":", 5)
                if len(parts) == 6:
                    _, alias, kdf_tag, salt_b64, nonce_b64, cipher_b64 = parts
                    salt = cls.safe_b64decode(salt_b64)
                    nonce = cls.safe_b64decode(nonce_b64)
                    ciphertext = cls.safe_b64decode(cipher_b64)
                    config = get_key_config(alias)
                    key = cls.derive_symmetric_key(material, salt, config, length=32)
                    decrypted = AESGCM(key).decrypt(nonce, ciphertext, None).decode('utf-8')
                    return True, decrypted, f"{alias} (AES-256-GCM)"
            except Exception:
                pass

        # 2. ENC4: Legacy Fernet envelope
        if s.startswith(cls.MAGIC_HEADER_V4):
            try:
                parts = s.split(":", 3)
                if len(parts) == 4:
                    _, alias, salt_b64, cipher_b64 = parts
                    salt = cls.safe_b64decode(salt_b64)
                    iters = LEGACY_PBKDF2_MAP.get(alias, 200000)
                    legacy_key = cls.derive_legacy_pbkdf2(password, salt, iters)
                    fernet_key = base64.urlsafe_b64encode(legacy_key)
                    decrypted = Fernet(fernet_key).decrypt(cipher_b64.encode('ascii')).decode('utf-8')
                    return True, decrypted, f"{alias} (Legacy Fernet)"
            except Exception:
                pass

        # 3. Probe all 10 V5 Memory-Hard configurations
        for alias, config in KEY_CONFIGS.items():
            try:
                raw_bytes = cls.safe_b64decode(s)
                salt_length = config["salt_length"]
                if len(raw_bytes) > salt_length + 12 + 16:
                    salt = raw_bytes[:salt_length]
                    nonce = raw_bytes[salt_length:salt_length+12]
                    ciphertext = raw_bytes[salt_length+12:]
                    key = cls.derive_symmetric_key(material, salt, config, length=32)
                    decrypted = AESGCM(key).decrypt(nonce, ciphertext, None).decode('utf-8')
                    return True, decrypted, f"{config['alias']} (AES-256-GCM)"
            except Exception:
                continue

        # 4. Probe Legacy PBKDF2 configurations
        for alias, iters in LEGACY_PBKDF2_MAP.items():
            try:
                raw_bytes = cls.safe_b64decode(s)
                salt_len = 16 if alias == "Key 1" else 32
                if len(raw_bytes) > salt_len + 57:
                    salt = raw_bytes[:salt_len]
                    cipher_bytes = raw_bytes[salt_len:]
                    legacy_key = cls.derive_legacy_pbkdf2(password, salt, iters)
                    fernet_key = base64.urlsafe_b64encode(legacy_key)
                    decrypted = Fernet(fernet_key).decrypt(cipher_bytes).decode('utf-8')
                    return True, decrypted, f"{alias} (Legacy Fernet)"
            except Exception:
                continue

        return False, "", ""

    @staticmethod
    def safe_b64encode(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).decode('ascii')

    @staticmethod
    def safe_b64decode(s: str) -> bytes:
        s = s.strip()
        missing_padding = len(s) % 4
        if missing_padding:
            s += '=' * (4 - missing_padding)
        return base64.urlsafe_b64decode(s.encode('ascii'))

    @classmethod
    def encrypt_file(cls, in_path: str, out_path: str, password: str, key_type: str,
                     keyfile_bytes: Optional[bytes] = None, progress_cb=None) -> None:
        """Encrypt file into Next-Gen ENC5F container with AES-256-GCM."""
        config = get_key_config(key_type)
        salt = os.urandom(config["salt_length"])
        material = cls.prepare_key_material(password, keyfile_bytes)

        if progress_cb:
            progress_cb(15, "Deriving memory-hard key...")

        key = cls.derive_symmetric_key(material, salt, config, 32)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)

        if progress_cb:
            progress_cb(40, "Encrypting file data with AES-256-GCM AEAD...")

        with open(in_path, "rb") as fin:
            data = fin.read()

        ciphertext = aesgcm.encrypt(nonce, data, None)

        if progress_cb:
            progress_cb(80, "Writing ENC5F secure container...")

        metadata = {
            "v": 2,
            "kdf": "scrypt",
            "cipher": "AES-256-GCM",
            "alias": config["alias"],
            "salt": cls.safe_b64encode(salt),
            "nonce": cls.safe_b64encode(nonce),
            "has_keyfile": bool(keyfile_bytes),
            "orig_name": os.path.basename(in_path),
            "size": len(data)
        }
        meta_bytes = json.dumps(metadata).encode('utf-8')

        tmp_out = out_path + ".tmp"
        with open(tmp_out, "wb") as fout:
            fout.write(cls.FILE_MAGIC_V5)
            fout.write(struct.pack(">I", len(meta_bytes)))
            fout.write(meta_bytes)
            fout.write(ciphertext)

        if os.path.exists(out_path):
            os.remove(out_path)
        os.rename(tmp_out, out_path)

        if progress_cb:
            progress_cb(100, "File encryption complete!")

    @classmethod
    def decrypt_file(cls, in_path: str, out_path: str, password: str, fallback_key: str = DEFAULT_KEY_PROFILE,
                     keyfile_bytes: Optional[bytes] = None, progress_cb=None) -> str:
        """Decrypt file (handles ENC5F and legacy ENC4F containers)."""
        if progress_cb:
            progress_cb(10, "Inspecting container header...")

        with open(in_path, "rb") as fin:
            header_magic = fin.read(6)

            # 1. Next-Gen ENC5F Container
            if header_magic == cls.FILE_MAGIC_V5:
                meta_len = struct.unpack(">I", fin.read(4))[0]
                meta_bytes = fin.read(meta_len)
                metadata = json.loads(meta_bytes.decode('utf-8'))
                ciphertext = fin.read()

                if metadata.get("has_keyfile") and not keyfile_bytes:
                    raise ValueError("This file was protected with a 2FA Keyfile. Please attach the Keyfile.")

                config = get_key_config(metadata.get("alias", "Key 4"))
                salt = cls.safe_b64decode(metadata["salt"])
                nonce = cls.safe_b64decode(metadata["nonce"])

                if progress_cb:
                    progress_cb(45, f"Computing memory-hard key ({config['alias']})...")

                material = cls.prepare_key_material(password, keyfile_bytes)
                key = cls.derive_symmetric_key(material, salt, config, 32)
                aesgcm = AESGCM(key)

                if progress_cb:
                    progress_cb(75, "Authenticating AEAD payload...")

                decrypted = aesgcm.decrypt(nonce, ciphertext, None)
                used_key = f"{config['alias']} (AES-256-GCM)"

            # 2. Legacy ENC4F Container
            elif header_magic == cls.FILE_MAGIC_V4:
                alias_len = struct.unpack(">H", fin.read(2))[0]
                alias = fin.read(alias_len).decode("utf-8", errors="ignore")
                salt_len = struct.unpack(">H", fin.read(2))[0]
                salt = fin.read(salt_len)
                encrypted_payload = fin.read()

                iters = LEGACY_PBKDF2_MAP.get(alias, 200000)
                if progress_cb:
                    progress_cb(45, f"Deriving legacy key ({alias})...")

                legacy_key = cls.derive_legacy_pbkdf2(password, salt, iters)
                fernet_key = base64.urlsafe_b64encode(legacy_key)
                cipher = Fernet(fernet_key)
                decrypted = cipher.decrypt(encrypted_payload)
                used_key = f"{alias} (Legacy Fernet)"

            else:
                raise ValueError("Unrecognized file format or corrupted EncDec container.")

        if progress_cb:
            progress_cb(90, "Writing decrypted file...")

        tmp_out = out_path + ".tmp"
        with open(tmp_out, "wb") as fout:
            fout.write(decrypted)

        if os.path.exists(out_path):
            os.remove(out_path)
        os.rename(tmp_out, out_path)

        if progress_cb:
            progress_cb(100, "File decryption complete!")

        return used_key


# =============================================================================
# QR Code Engine (Generation & Decoding)
# =============================================================================
class QRManager:
    @staticmethod
    def compress_for_qr(text: str) -> str:
        """Compress text with zlib level 9 and encode as URL-safe base64."""
        compressed = zlib.compress(text.encode('utf-8'), level=9)
        return base64.urlsafe_b64encode(compressed).decode('ascii')

    @staticmethod
    def decompress_from_qr(scanned_str: str) -> str:
        """Normalize scanned QR string, unwrapping zlib compression if present."""
        s = scanned_str.strip()
        if not s:
            return s
        try:
            raw = CryptoEngine.safe_b64decode(s)
            decompressed = zlib.decompress(raw).decode('utf-8')
            return decompressed
        except Exception:
            return s

    @staticmethod
    def generate_qr_image(data: str, box_size: int = 6, border: int = 4) -> Image.Image:
        """Generate a PIL Image for QR data using qrcode or segno backend."""
        if HAS_QRCODE:
            qr = _qrcode.QRCode(
                version=None,
                error_correction=_qrcode.constants.ERROR_CORRECT_L,
                box_size=box_size,
                border=border,
            )
            qr.add_data(data.encode('utf-8'))
            qr.make(fit=True)
            return qr.make_image(fill_color="black", back_color="white").convert("RGB")

        if HAS_SEGNO:
            qr = _segno.make(data, error='l', micro=False)
            bio = io.BytesIO()
            qr.save(bio, kind="png", scale=box_size, border=border)
            bio.seek(0)
            return Image.open(bio).convert("RGB")

        raise RuntimeError(
            "No QR generation backend installed.\nPlease install 'qrcode' or 'segno':\npip install qrcode[pil]")

    @staticmethod
    def decode_qr_from_image(pil_image: Image.Image) -> Optional[str]:
        """Decode QR code text from a PIL image using OpenCV."""
        if not HAS_CV2:
            raise RuntimeError("OpenCV is not available for QR scanning. Install opencv-python.")

        cv_img = np.array(pil_image.convert('RGB'))
        cv_img = cv_img[:, :, ::-1].copy()

        detector = cv2.QRCodeDetector()
        data, points, _ = detector.detectAndDecode(cv_img)
        return data if data else None


# =============================================================================
# Password Analysis & Diceware Engine
# =============================================================================
def calculate_password_entropy(password: str) -> Dict[str, Any]:
    """Calculate entropy score, rating, color, and brute-force resistance."""
    if not password:
        return {"score": 0, "label": "None", "entropy": 0.0, "color": "#64748b", "percent": 0, "crack_time": "Instant"}

    is_diceware = any(sep in password for sep in ["-", "_", " ", "."])
    words = re.split(r'[-_ .]', password)

    if is_diceware and len(words) >= 3:
        entropy = len(words) * 12.9
    else:
        length = len(password)
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_symbol = bool(re.search(r'[^a-zA-Z0-9]', password))

        pool_size = 0
        if has_lower: pool_size += 26
        if has_upper: pool_size += 26
        if has_digit: pool_size += 10
        if has_symbol: pool_size += 33
        if pool_size == 0: pool_size = 1

        entropy = length * math.log2(pool_size)

        if re.search(r'(.)\1{2,}', password):
            entropy -= 12
        if re.search(r'^[0-9]+$', password) or re.search(r'^[a-zA-Z]+$', password):
            entropy -= 10

    entropy = max(0.0, round(entropy, 1))

    # GPU cluster crack time (with memory-hard Scrypt)
    combinations = 2.0 ** entropy
    seconds = combinations / 2e4

    if seconds < 1: crack_time = "Instant (< 1 sec)"
    elif seconds < 60: crack_time = f"{int(seconds)} seconds"
    elif seconds < 3600: crack_time = f"{int(seconds / 60)} minutes"
    elif seconds < 86400: crack_time = f"{int(seconds / 3600)} hours"
    elif seconds < 31536000: crack_time = f"{int(seconds / 86400)} days"
    elif seconds < 31536000 * 100: crack_time = f"{int(seconds / 31536000)} years"
    elif seconds < 31536000 * 1e6: crack_time = f"{int(seconds / (31536000 * 1000))} Millennia"
    else: crack_time = "Billions of Years (Quantum-Proof)"

    if entropy < 40:
        return {"score": 1, "label": "Weak", "entropy": entropy, "color": "#ef4444", "percent": 25, "crack_time": crack_time}
    elif entropy < 65:
        return {"score": 2, "label": "Moderate", "entropy": entropy, "color": "#f97316", "percent": 50, "crack_time": crack_time}
    elif entropy < 90:
        return {"score": 3, "label": "Strong", "entropy": entropy, "color": "#eab308", "percent": 75, "crack_time": crack_time}
    elif entropy < 120:
        return {"score": 4, "label": "Very Strong", "entropy": entropy, "color": "#22c55e", "percent": 90, "crack_time": crack_time}
    else:
        return {"score": 5, "label": "Vault Grade", "entropy": entropy, "color": "#06b6d4", "percent": 100, "crack_time": crack_time}


def generate_diceware_passphrase(words: int = 6, sep: str = "-") -> str:
    """Generate high-entropy Diceware passphrase."""
    chosen = [secrets.choice(DICEWARE_WORDS) for _ in range(words)]
    return sep.join(chosen)


def generate_secure_password(length: int = 32, include_symbols: bool = True) -> str:
    """Generate cryptographically strong random password."""
    chars = string.ascii_letters + string.digits
    if include_symbols:
        chars += "!@#$%^&*()-_=+[]{}|;:,.<>?"
    return ''.join(secrets.choice(chars) for _ in range(length))


def format_file_size(num_bytes: int) -> str:
    """Format byte size into human readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if num_bytes < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


# =============================================================================
# Modern Tkinter GUI Application (v5.0.0)
# =============================================================================
class EncDecProApp:
    THEMES = {
        "dark": {
            "bg": "#0f172a",
            "panel_bg": "#1e293b",
            "border": "#334155",
            "fg": "#f8fafc",
            "fg_muted": "#94a3b8",
            "accent": "#38bdf8",
            "btn_bg": "#334155",
            "btn_hover": "#475569",
            "btn_fg": "#f8fafc",
            "btn_primary_bg": "#0284c7",
            "btn_primary_fg": "#ffffff",
            "entry_bg": "#0b1329",
            "entry_fg": "#f8fafc",
            "success": "#10b981",
            "error": "#ef4444",
            "warning": "#f59e0b",
            "info": "#38bdf8",
        },
        "light": {
            "bg": "#f1f5f9",
            "panel_bg": "#ffffff",
            "border": "#cbd5e1",
            "fg": "#0f172a",
            "fg_muted": "#64748b",
            "accent": "#0284c7",
            "btn_bg": "#e2e8f0",
            "btn_hover": "#cbd5e1",
            "btn_fg": "#0f172a",
            "btn_primary_bg": "#0284c7",
            "btn_primary_fg": "#ffffff",
            "entry_bg": "#f8fafc",
            "entry_fg": "#0f172a",
            "success": "#16a34a",
            "error": "#dc2626",
            "warning": "#d97706",
            "info": "#0284c7",
        }
    }

    def __init__(self, root: Any):
        if not HAS_TKINTER:
            raise RuntimeError("Tkinter is required to run the GUI interface.")

        self.root = root
        self.root.title("EncDec Studio Pro (v5.0.0) — Military-Grade Cryptography")
        self.root.geometry("1020x760")
        self.root.minsize(840, 640)

        self.current_theme = "dark"
        self.colors = self.THEMES[self.current_theme]

        self.auto_sync_var = tk.BooleanVar(value=False)
        self.use_envelope_var = tk.BooleanVar(value=True)
        self.debounce_timer: Optional[threading.Timer] = None

        self.loaded_keyfile_bytes: Optional[bytes] = None
        self.loaded_keyfile_name: str = ""

        self._init_fonts()
        self._setup_ui()
        self.apply_theme()
        self.set_status("EncDec Studio Pro v5.1.0 (AES-256-GCM & Memory-Hard Scrypt) Ready", "info")

    def _init_fonts(self):
        self.font_title = tkfont.Font(family="Helvetica", size=14, weight="bold")
        self.font_subtitle = tkfont.Font(family="Helvetica", size=10, weight="bold")
        self.font_body = tkfont.Font(family="Helvetica", size=10)
        self.font_mono = tkfont.Font(family="Courier", size=10)
        self.font_status = tkfont.Font(family="Helvetica", size=9)

    def _setup_ui(self):
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        # Header Bar
        self.header_frame = tk.Frame(self.root, bg=self.colors["bg"])
        self.header_frame.grid(row=0, column=0, sticky="ew", padx=16, pady=(12, 6))
        self.header_frame.grid_columnconfigure(1, weight=1)

        title_box = tk.Frame(self.header_frame, bg=self.colors["bg"])
        title_box.grid(row=0, column=0, sticky="w")

        title_label = tk.Label(
            title_box, text="🔒 EncDec Studio Pro", font=self.font_title,
            bg=self.colors["bg"], fg=self.colors["accent"]
        )
        title_label.pack(side="left")

        badge_lbl = tk.Label(
            title_box, text=" v5.1.0 • AES-256-GCM ", font=self.font_status,
            bg=self.colors["panel_bg"], fg=self.colors["accent"], relief="solid", bd=1
        )
        badge_lbl.pack(side="left", padx=8)

        mode_frame = tk.Frame(self.header_frame, bg=self.colors["bg"])
        mode_frame.grid(row=0, column=2, sticky="e")

        self.theme_btn = tk.Button(
            mode_frame, text="🌓 Toggle Theme", font=self.font_status,
            command=self.toggle_theme, relief="flat", padx=8, pady=3, cursor="hand2"
        )
        self.theme_btn.pack(side="right", padx=4)

        # Tabbed Notebook
        style = ttk.Style()
        style.theme_use("default")
        self.notebook = ttk.Notebook(self.root)
        self.notebook.grid(row=1, column=0, sticky="nsew", padx=16, pady=6)

        self.text_tab = tk.Frame(self.notebook, bg=self.colors["bg"])
        self.notebook.add(self.text_tab, text=" 📝 Text Cryptography ")

        self.file_tab = tk.Frame(self.notebook, bg=self.colors["bg"])
        self.notebook.add(self.file_tab, text=" 📁 File Security Vault ")

        self.benchmark_tab = tk.Frame(self.notebook, bg=self.colors["bg"])
        self.notebook.add(self.benchmark_tab, text=" ⚡ Security & Benchmarks ")

        self._build_text_tab()
        self._build_file_tab()
        self._build_benchmark_tab()

        # Bottom Status Bar
        self.status_frame = tk.Frame(self.root, bg=self.colors["panel_bg"], height=28)
        self.status_frame.grid(row=2, column=0, sticky="ew", padx=0, pady=0)
        self.status_frame.grid_columnconfigure(0, weight=1)

        self.status_label = tk.Label(
            self.status_frame, text="Ready", font=self.font_status,
            bg=self.colors["panel_bg"], fg=self.colors["fg_muted"], anchor="w", padx=12
        )
        self.status_label.grid(row=0, column=0, sticky="w")

        self.key_status_label = tk.Label(
            self.status_frame, text="Active: Key 4 (64MB Scrypt)", font=self.font_status,
            bg=self.colors["panel_bg"], fg=self.colors["accent"], anchor="e", padx=12
        )
        self.key_status_label.grid(row=0, column=1, sticky="e")

    def _build_text_tab(self):
        self.text_tab.grid_rowconfigure(2, weight=1)
        self.text_tab.grid_columnconfigure(0, weight=1)
        self.text_tab.grid_columnconfigure(1, weight=1)

        # Password & Key Panel
        pwd_panel = tk.Frame(self.text_tab, bg=self.colors["panel_bg"], bd=1, relief="solid")
        pwd_panel.grid(row=0, column=0, columnspan=2, sticky="ew", padx=8, pady=(8, 4), ipady=6)
        pwd_panel.grid_columnconfigure(1, weight=1)

        pwd_lbl = tk.Label(pwd_panel, text="Master Passphrase:", font=self.font_subtitle, bg=self.colors["panel_bg"])
        pwd_lbl.grid(row=0, column=0, padx=(12, 6), pady=4, sticky="w")

        self.password_entry = tk.Entry(
            pwd_panel, show="*", font=self.font_mono,
            bg=self.colors["entry_bg"], fg=self.colors["entry_fg"],
            insertbackground=self.colors["fg"], relief="flat", bd=4
        )
        self.password_entry.grid(row=0, column=1, padx=6, pady=4, sticky="ew")
        self.password_entry.bind("<KeyRelease>", self._on_password_input_change)

        self.show_pwd_btn = tk.Button(
            pwd_panel, text="👁️ Show", font=self.font_status,
            command=self.toggle_password_visibility, relief="flat", padx=6, pady=2, cursor="hand2"
        )
        self.show_pwd_btn.grid(row=0, column=2, padx=3, pady=4)

        self.gen_dice_btn = tk.Button(
            pwd_panel, text="🎲 Diceware", font=self.font_status,
            command=self.on_generate_diceware, relief="flat", padx=6, pady=2, cursor="hand2"
        )
        self.gen_dice_btn.grid(row=0, column=3, padx=3, pady=4)

        self.gen_pwd_btn = tk.Button(
            pwd_panel, text="⚡ Random (32ch)", font=self.font_status,
            command=self.on_generate_password, relief="flat", padx=6, pady=2, cursor="hand2"
        )
        self.gen_pwd_btn.grid(row=0, column=4, padx=3, pady=4)

        key_lbl = tk.Label(pwd_panel, text="Security Profile:", font=self.font_subtitle, bg=self.colors["panel_bg"])
        key_lbl.grid(row=0, column=5, padx=(8, 4), pady=4, sticky="w")

        self.key_choice_var = tk.StringVar(value=DEFAULT_KEY_PROFILE)
        self.key_dropdown = ttk.Combobox(
            pwd_panel, textvariable=self.key_choice_var, values=list(KEY_CONFIGS.keys()),
            state="readonly", width=28, font=self.font_body
        )
        self.key_dropdown.grid(row=0, column=6, padx=(4, 12), pady=4)
        self.key_dropdown.bind("<<ComboboxSelected>>", self._on_key_choice_change)

        # 2FA Keyfile & Strength Bar Row
        extra_bar_frame = tk.Frame(pwd_panel, bg=self.colors["panel_bg"])
        extra_bar_frame.grid(row=1, column=1, columnspan=6, sticky="ew", padx=6, pady=(2, 4))
        extra_bar_frame.grid_columnconfigure(0, weight=1)

        self.strength_canvas = tk.Canvas(extra_bar_frame, height=6, bg=self.colors["border"], highlightthickness=0)
        self.strength_canvas.grid(row=0, column=0, sticky="ew", padx=(0, 8), pady=4)

        self.strength_label = tk.Label(
            extra_bar_frame, text="Strength: None (0 bits)", font=self.font_status,
            bg=self.colors["panel_bg"], fg=self.colors["fg_muted"]
        )
        self.strength_label.grid(row=0, column=1, sticky="e", padx=(0, 8))

        # Keyfile Button
        self.keyfile_btn = tk.Button(
            extra_bar_frame, text="🔑 Add 2FA Keyfile", font=self.font_status,
            command=self.on_attach_keyfile, relief="flat", padx=6, pady=2, cursor="hand2"
        )
        self.keyfile_btn.grid(row=0, column=2, padx=(4, 12))

        # Controls Action Strip
        actions_frame = tk.Frame(self.text_tab, bg=self.colors["bg"])
        actions_frame.grid(row=1, column=0, columnspan=2, sticky="ew", padx=8, pady=4)
        actions_frame.grid_columnconfigure(2, weight=1)

        self.encrypt_btn = tk.Button(
            actions_frame, text="🔒 Encrypt (AES-256-GCM) ➡️", font=self.font_subtitle,
            command=self.action_encrypt, relief="flat", padx=14, pady=5, cursor="hand2"
        )
        self.encrypt_btn.pack(side="left", padx=4)

        self.decrypt_btn = tk.Button(
            actions_frame, text="⬅️ Decrypt 🔓", font=self.font_subtitle,
            command=self.action_decrypt, relief="flat", padx=14, pady=5, cursor="hand2"
        )
        self.decrypt_btn.pack(side="left", padx=4)

        self.qr_gen_btn = tk.Button(
            actions_frame, text="📱 Show QR Code", font=self.font_body,
            command=self.show_qr_popup, relief="flat", padx=10, pady=5, cursor="hand2"
        )
        self.qr_gen_btn.pack(side="left", padx=4)

        self.qr_scan_btn = tk.Button(
            actions_frame, text="📷 Scan QR Image", font=self.font_body,
            command=self.action_scan_qr_file, relief="flat", padx=10, pady=5, cursor="hand2"
        )
        self.qr_scan_btn.pack(side="left", padx=4)

        self.auto_sync_chk = tk.Checkbutton(
            actions_frame, text="Live Auto-Sync", variable=self.auto_sync_var,
            font=self.font_status, bg=self.colors["bg"], fg=self.colors["fg"],
            selectcolor=self.colors["panel_bg"], activebackground=self.colors["bg"]
        )
        self.auto_sync_chk.pack(side="right", padx=8)

        # Dual Text Panes
        left_pane = tk.Frame(self.text_tab, bg=self.colors["panel_bg"], bd=1, relief="solid")
        left_pane.grid(row=2, column=0, sticky="nsew", padx=(8, 4), pady=4)
        left_pane.grid_rowconfigure(1, weight=1)
        left_pane.grid_columnconfigure(0, weight=1)

        left_header = tk.Frame(left_pane, bg=self.colors["panel_bg"])
        left_header.grid(row=0, column=0, sticky="ew", padx=8, pady=4)
        left_header.grid_columnconfigure(0, weight=1)

        tk.Label(left_header, text="📄 Decrypted / Plaintext:", font=self.font_subtitle,
                 bg=self.colors["panel_bg"]).grid(row=0, column=0, sticky="w")
        self.plain_counter_lbl = tk.Label(left_header, text="0 chars | 0 words", font=self.font_status,
                                          bg=self.colors["panel_bg"], fg=self.colors["fg_muted"])
        self.plain_counter_lbl.grid(row=0, column=1, sticky="e", padx=4)

        self.decrypted_text_entry = scrolledtext.ScrolledText(
            left_pane, font=self.font_body, wrap="word",
            bg=self.colors["entry_bg"], fg=self.colors["entry_fg"],
            insertbackground=self.colors["fg"], relief="flat", bd=4
        )
        self.decrypted_text_entry.grid(row=1, column=0, sticky="nsew", padx=8, pady=4)
        self.decrypted_text_entry.bind("<KeyRelease>", self._on_plain_text_keystroke)

        left_toolbar = tk.Frame(left_pane, bg=self.colors["panel_bg"])
        left_toolbar.grid(row=2, column=0, sticky="ew", padx=8, pady=4)

        self.btn_copy_plain = tk.Button(left_toolbar, text="📋 Copy", font=self.font_status,
                                        command=lambda: self.copy_to_clipboard(self.decrypted_text_entry),
                                        relief="flat", padx=6, pady=2)
        self.btn_copy_plain.pack(side="left", padx=2)
        self.btn_paste_plain = tk.Button(left_toolbar, text="📥 Paste", font=self.font_status,
                                         command=lambda: self.paste_from_clipboard(self.decrypted_text_entry),
                                         relief="flat", padx=6, pady=2)
        self.btn_paste_plain.pack(side="left", padx=2)
        self.btn_clear_plain = tk.Button(left_toolbar, text="🗑️ Clear", font=self.font_status,
                                         command=lambda: self.clear_text_box(self.decrypted_text_entry), relief="flat",
                                         padx=6, pady=2)
        self.btn_clear_plain.pack(side="left", padx=2)
        self.btn_load_plain = tk.Button(left_toolbar, text="📂 Load File", font=self.font_status,
                                        command=lambda: self.load_text_file(self.decrypted_text_entry), relief="flat",
                                        padx=6, pady=2)
        self.btn_load_plain.pack(side="right", padx=2)

        right_pane = tk.Frame(self.text_tab, bg=self.colors["panel_bg"], bd=1, relief="solid")
        right_pane.grid(row=2, column=1, sticky="nsew", padx=(4, 8), pady=4)
        right_pane.grid_rowconfigure(1, weight=1)
        right_pane.grid_columnconfigure(0, weight=1)

        right_header = tk.Frame(right_pane, bg=self.colors["panel_bg"])
        right_header.grid(row=0, column=0, sticky="ew", padx=8, pady=4)
        right_header.grid_columnconfigure(0, weight=1)

        tk.Label(right_header, text="🔐 Encrypted / Ciphertext (ENC5):", font=self.font_subtitle,
                 bg=self.colors["panel_bg"]).grid(row=0, column=0, sticky="w")
        self.cipher_counter_lbl = tk.Label(right_header, text="0 chars", font=self.font_status,
                                           bg=self.colors["panel_bg"], fg=self.colors["fg_muted"])
        self.cipher_counter_lbl.grid(row=0, column=1, sticky="e", padx=4)

        self.encrypted_text_entry = scrolledtext.ScrolledText(
            right_pane, font=self.font_mono, wrap="char",
            bg=self.colors["entry_bg"], fg=self.colors["entry_fg"],
            insertbackground=self.colors["fg"], relief="flat", bd=4
        )
        self.encrypted_text_entry.grid(row=1, column=0, sticky="nsew", padx=8, pady=4)
        self.encrypted_text_entry.bind("<KeyRelease>", self._on_cipher_text_keystroke)

        right_toolbar = tk.Frame(right_pane, bg=self.colors["panel_bg"])
        right_toolbar.grid(row=2, column=0, sticky="ew", padx=8, pady=4)

        self.btn_copy_cipher = tk.Button(right_toolbar, text="📋 Copy", font=self.font_status,
                                         command=lambda: self.copy_to_clipboard(self.encrypted_text_entry),
                                         relief="flat", padx=6, pady=2)
        self.btn_copy_cipher.pack(side="left", padx=2)
        self.btn_paste_cipher = tk.Button(right_toolbar, text="📥 Paste", font=self.font_status,
                                          command=lambda: self.paste_from_clipboard(self.encrypted_text_entry),
                                          relief="flat", padx=6, pady=2)
        self.btn_paste_cipher.pack(side="left", padx=2)
        self.btn_clear_cipher = tk.Button(right_toolbar, text="🗑️ Clear", font=self.font_status,
                                          command=lambda: self.clear_text_box(self.encrypted_text_entry), relief="flat",
                                          padx=6, pady=2)
        self.btn_clear_cipher.pack(side="left", padx=2)
        self.btn_save_cipher = tk.Button(right_toolbar, text="💾 Save to File", font=self.font_status,
                                         command=lambda: self.save_text_file(self.encrypted_text_entry), relief="flat",
                                         padx=6, pady=2)
        self.btn_save_cipher.pack(side="right", padx=2)

    def _build_file_tab(self):
        self.file_tab.grid_columnconfigure(0, weight=1)

        card = tk.Frame(self.file_tab, bg=self.colors["panel_bg"], bd=1, relief="solid")
        card.grid(row=0, column=0, sticky="nsew", padx=16, pady=16, ipady=12)
        card.grid_columnconfigure(1, weight=1)

        tk.Label(card, text="📁 Military-Grade File Security Vault (ENC5F)", font=self.font_title, bg=self.colors["panel_bg"],
                 fg=self.colors["accent"]).grid(row=0, column=0, columnspan=3, sticky="w", padx=16, pady=12)

        tk.Label(card, text="Source File:", font=self.font_subtitle, bg=self.colors["panel_bg"]).grid(row=1, column=0,
                                                                                                      sticky="w",
                                                                                                      padx=16, pady=6)
        self.file_path_var = tk.StringVar(value="No file selected")
        self.file_path_entry = tk.Entry(card, textvariable=self.file_path_var, state="readonly", font=self.font_body,
                                        bg=self.colors["entry_bg"], fg=self.colors["entry_fg"], relief="flat", bd=4)
        self.file_path_entry.grid(row=1, column=1, sticky="ew", padx=8, pady=6)

        self.btn_browse_file = tk.Button(card, text="📂 Browse...", font=self.font_body, command=self.on_browse_file,
                                         relief="flat", padx=12, pady=4, cursor="hand2")
        self.btn_browse_file.grid(row=1, column=2, padx=16, pady=6)

        self.file_info_lbl = tk.Label(card, text="Size: — | Status: Waiting for selection", font=self.font_status,
                                      bg=self.colors["panel_bg"], fg=self.colors["fg_muted"])
        self.file_info_lbl.grid(row=2, column=1, columnspan=2, sticky="w", padx=8, pady=2)

        tk.Label(card, text="File Password:", font=self.font_subtitle, bg=self.colors["panel_bg"]).grid(row=3, column=0,
                                                                                                        sticky="w",
                                                                                                        padx=16, pady=6)
        self.file_pwd_entry = tk.Entry(card, show="*", font=self.font_mono, bg=self.colors["entry_bg"],
                                       fg=self.colors["entry_fg"], relief="flat", bd=4)
        self.file_pwd_entry.grid(row=3, column=1, sticky="ew", padx=8, pady=6)

        self.btn_use_main_pwd = tk.Button(card, text="🔗 Copy from Main", font=self.font_status,
                                          command=self.on_copy_main_password_to_file, relief="flat", padx=8, pady=2)
        self.btn_use_main_pwd.grid(row=3, column=2, padx=16, pady=6)

        self.file_progress = ttk.Progressbar(card, orient="horizontal", mode="determinate")
        self.file_progress.grid(row=4, column=0, columnspan=3, sticky="ew", padx=16, pady=(16, 4))

        self.file_progress_lbl = tk.Label(card, text="Ready", font=self.font_status, bg=self.colors["panel_bg"],
                                          fg=self.colors["fg_muted"])
        self.file_progress_lbl.grid(row=5, column=0, columnspan=3, sticky="w", padx=16, pady=2)

        btn_box = tk.Frame(card, bg=self.colors["panel_bg"])
        btn_box.grid(row=6, column=0, columnspan=3, pady=16)

        self.btn_encrypt_file = tk.Button(btn_box, text="🔒 Encrypt File (.enc)", font=self.font_subtitle,
                                          command=self.action_encrypt_file, relief="flat", padx=16, pady=6,
                                          cursor="hand2")
        self.btn_encrypt_file.pack(side="left", padx=8)

        self.btn_decrypt_file = tk.Button(btn_box, text="🔓 Decrypt File", font=self.font_subtitle,
                                          command=self.action_decrypt_file, relief="flat", padx=16, pady=6,
                                          cursor="hand2")
        self.btn_decrypt_file.pack(side="left", padx=8)

    def _build_benchmark_tab(self):
        self.benchmark_tab.grid_columnconfigure(0, weight=1)

        card = tk.Frame(self.benchmark_tab, bg=self.colors["panel_bg"], bd=1, relief="solid")
        card.grid(row=0, column=0, sticky="nsew", padx=16, pady=16, ipady=12)
        card.grid_columnconfigure(0, weight=1)

        header_row = tk.Frame(card, bg=self.colors["panel_bg"])
        header_row.pack(fill="x", padx=16, pady=8)

        tk.Label(header_row, text="⚡ Cryptographic Specifications & Benchmarks", font=self.font_title,
                 bg=self.colors["panel_bg"], fg=self.colors["accent"]).pack(side="left")

        self.btn_run_bench = tk.Button(header_row, text="⚡ Run Benchmark", font=self.font_body,
                                       command=self.action_run_benchmark, relief="flat", padx=10, pady=3, cursor="hand2")
        self.btn_run_bench.pack(side="right")

        self.bench_text = scrolledtext.ScrolledText(
            card, font=self.font_mono, height=18,
            bg=self.colors["entry_bg"], fg=self.colors["entry_fg"], relief="flat", bd=4
        )
        self.bench_text.pack(fill="both", expand=True, padx=16, pady=8)

        spec_info = (
            "======================================================================\n"
            "  EncDec Studio Pro (v5.1.0) Security Architecture\n"
            "======================================================================\n"
            "• Symmetric Cipher : AES-256-GCM AEAD (256-bit Key, 96-bit Nonce, 128-bit Tag)\n"
            "• Memory-Hard KDF  : Scrypt (RFC 7914) & Argon2id (16MB to 512MB RAM)\n"
            "• 2FA Token        : SHA-256 Keyfile Integration\n"
            "• QR Engine        : Zlib Level 9 Deflate + Base64URL\n"
            "• Backward Support : Automatic Decryption of ENC4 Envelopes & Fernet Tokens\n"
            "======================================================================\n"
            "Click 'Run Benchmark' to measure hardware execution speed across all 10 tiers.\n"
        )
        self.bench_text.insert(tk.END, spec_info)

    def toggle_theme(self):
        self.current_theme = "light" if self.current_theme == "dark" else "dark"
        self.colors = self.THEMES[self.current_theme]
        self.apply_theme()
        self.set_status(f"Theme switched to {self.current_theme.capitalize()} mode", "info")

    def apply_theme(self):
        c = self.colors
        self.root.configure(bg=c["bg"])
        self.header_frame.configure(bg=c["bg"])
        self.text_tab.configure(bg=c["bg"])
        self.file_tab.configure(bg=c["bg"])
        self.benchmark_tab.configure(bg=c["bg"])
        self.status_frame.configure(bg=c["panel_bg"])

        for widget in [self.password_entry, self.decrypted_text_entry, self.encrypted_text_entry,
                       self.file_path_entry, self.file_pwd_entry, self.bench_text]:
            widget.configure(bg=c["entry_bg"], fg=c["entry_fg"], insertbackground=c["fg"])

        for btn in [self.theme_btn, self.show_pwd_btn, self.gen_pwd_btn, self.gen_dice_btn, self.keyfile_btn,
                    self.btn_copy_plain, self.btn_paste_plain, self.btn_clear_plain, self.btn_load_plain,
                    self.btn_copy_cipher, self.btn_paste_cipher, self.btn_clear_cipher, self.btn_save_cipher,
                    self.btn_browse_file, self.btn_use_main_pwd, self.qr_gen_btn, self.qr_scan_btn, self.btn_run_bench]:
            btn.configure(bg=c["btn_bg"], fg=c["btn_fg"], activebackground=c["btn_hover"], activeforeground=c["btn_fg"])

        self.encrypt_btn.configure(bg=c["btn_primary_bg"], fg=c["btn_primary_fg"], activebackground=c["accent"])
        self.decrypt_btn.configure(bg=c["btn_primary_bg"], fg=c["btn_primary_fg"], activebackground=c["accent"])
        self.btn_encrypt_file.configure(bg=c["btn_primary_bg"], fg=c["btn_primary_fg"], activebackground=c["accent"])
        self.btn_decrypt_file.configure(bg=c["btn_primary_bg"], fg=c["btn_primary_fg"], activebackground=c["accent"])

        self.status_label.configure(bg=c["panel_bg"], fg=c["fg_muted"])
        self.key_status_label.configure(bg=c["panel_bg"], fg=c["accent"])

    def set_status(self, message: str, level: str = "info"):
        color_map = {
            "success": self.colors["success"],
            "error": self.colors["error"],
            "warning": self.colors["warning"],
            "info": self.colors["info"]
        }
        fg = color_map.get(level, self.colors["fg_muted"])
        self.status_label.config(text=f"● {message}", fg=fg)

    def on_attach_keyfile(self):
        if self.loaded_keyfile_bytes is not None:
            self.loaded_keyfile_bytes = None
            self.loaded_keyfile_name = ""
            self.keyfile_btn.config(text="🔑 Add 2FA Keyfile", bg=self.colors["btn_bg"])
            self.set_status("2FA Keyfile removed", "info")
            if self.auto_sync_var.get():
                self._schedule_auto_sync()
            return

        path = filedialog.askopenfilename(title="Select 2FA Keyfile (.key, .bin, or any token file)")
        if path:
            try:
                self.loaded_keyfile_bytes = Path(path).read_bytes()
                self.loaded_keyfile_name = os.path.basename(path)
                h = hashlib.sha256(self.loaded_keyfile_bytes).hexdigest()[:8]
                self.keyfile_btn.config(text=f"🔑 Keyfile: {self.loaded_keyfile_name[:10]} (SHA:{h}...) ✕", bg=self.colors["accent"])
                self.set_status(f"Attached 2FA Keyfile: {self.loaded_keyfile_name}", "success")
                if self.auto_sync_var.get():
                    self._schedule_auto_sync()
            except Exception as e:
                messagebox.showerror("Keyfile Error", f"Could not read keyfile: {e}")

    def _on_key_choice_change(self, event=None):
        conf = get_key_config(self.key_choice_var.get())
        self.key_status_label.config(text=f"Active: {conf['alias']} ({conf['mem_mb']}MB RAM)")
        if self.auto_sync_var.get():
            self._schedule_auto_sync()

    def _on_password_input_change(self, event=None):
        pwd = self.password_entry.get()
        strength = calculate_password_entropy(pwd)
        self.strength_label.config(
            text=f"Strength: {strength['label']} ({strength['entropy']} bits) | Crack: {strength['crack_time']}",
            fg=strength["color"]
        )
        self._draw_strength_bar(strength["percent"], strength["color"])

        if self.auto_sync_var.get():
            self._schedule_auto_sync()

    def _draw_strength_bar(self, percent: int, color: str):
        self.strength_canvas.delete("all")
        width = self.strength_canvas.winfo_width()
        if width <= 1:
            width = 300
        fill_width = int((percent / 100.0) * width)
        self.strength_canvas.create_rectangle(0, 0, fill_width, 6, fill=color, width=0)

    def _on_plain_text_keystroke(self, event=None):
        text = self.decrypted_text_entry.get("1.0", tk.END).strip()
        chars = len(text)
        words = len(text.split()) if text else 0
        self.plain_counter_lbl.config(text=f"{chars} chars | {words} words")
        if self.auto_sync_var.get():
            self._schedule_auto_sync(direction="encrypt")

    def _on_cipher_text_keystroke(self, event=None):
        text = self.encrypted_text_entry.get("1.0", tk.END).strip()
        self.cipher_counter_lbl.config(text=f"{len(text)} chars")
        if self.auto_sync_var.get():
            self._schedule_auto_sync(direction="decrypt")

    def _schedule_auto_sync(self, direction: str = "encrypt"):
        if self.debounce_timer:
            self.debounce_timer.cancel()
        if direction == "encrypt":
            self.debounce_timer = threading.Timer(0.35, self.action_encrypt)
        else:
            self.debounce_timer = threading.Timer(0.35, self.action_decrypt)
        self.debounce_timer.start()

    def toggle_password_visibility(self):
        if self.password_entry.cget('show') == '*':
            self.password_entry.config(show='')
            self.show_pwd_btn.config(text="🙈 Hide")
        else:
            self.password_entry.config(show='*')
            self.show_pwd_btn.config(text="👁️ Show")

    def on_generate_password(self):
        new_pwd = generate_secure_password(32)
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, new_pwd)
        self._on_password_input_change()
        self.set_status("Generated new 32-character random password", "success")

    def on_generate_diceware(self):
        new_pwd = generate_diceware_passphrase(6, "-")
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, new_pwd)
        self._on_password_input_change()
        self.set_status("Generated new 6-word Diceware passphrase", "success")

    def action_encrypt(self):
        plain_text = self.decrypted_text_entry.get("1.0", tk.END).strip()
        password = self.password_entry.get()
        key_type = self.key_choice_var.get()
        use_env = self.use_envelope_var.get()

        if not plain_text:
            self.set_status("Plaintext is empty", "warning")
            return
        if not password:
            self.set_status("Please enter a master passphrase to encrypt", "error")
            return

        def _worker():
            try:
                t0 = time.perf_counter()
                encrypted = CryptoEngine.encrypt_text(
                    plain_text, password, key_type,
                    use_envelope=use_env, keyfile_bytes=self.loaded_keyfile_bytes
                )
                elapsed = round((time.perf_counter() - t0) * 1000)
                self.root.after(0, lambda: self._apply_encryption_result(encrypted, elapsed))
            except Exception as e:
                self.root.after(0, lambda: self.set_status(f"Encryption failed: {e}", "error"))

        threading.Thread(target=_worker, daemon=True).start()

    def _apply_encryption_result(self, encrypted: str, elapsed_ms: int):
        self.encrypted_text_entry.delete("1.0", tk.END)
        self.encrypted_text_entry.insert(tk.END, encrypted)
        self.cipher_counter_lbl.config(text=f"{len(encrypted)} chars")
        self.set_status(f"Text encrypted in {elapsed_ms}ms (AES-256-GCM + Scrypt)", "success")

    def action_decrypt(self):
        raw_cipher = self.encrypted_text_entry.get("1.0", tk.END).strip()
        normalized_cipher = QRManager.decompress_from_qr(raw_cipher)
        password = self.password_entry.get()
        key_type = self.key_choice_var.get()

        if not normalized_cipher:
            self.set_status("Ciphertext box is empty", "warning")
            return
        if not password:
            self.set_status("Please enter a master passphrase to decrypt", "error")
            return

        def _worker():
            t0 = time.perf_counter()
            success, decrypted, key_alias = CryptoEngine.decrypt_text(
                normalized_cipher, password, key_type, keyfile_bytes=self.loaded_keyfile_bytes
            )
            elapsed = round((time.perf_counter() - t0) * 1000)
            self.root.after(0, lambda: self._apply_decryption_result(success, decrypted, key_alias, elapsed))

        threading.Thread(target=_worker, daemon=True).start()

    def _apply_decryption_result(self, success: bool, decrypted: str, key_alias: str, elapsed_ms: int):
        if success:
            self.decrypted_text_entry.delete("1.0", tk.END)
            self.decrypted_text_entry.insert(tk.END, decrypted)
            self._on_plain_text_keystroke()
            self.set_status(f"Decryption successful in {elapsed_ms}ms (Matched: {key_alias})", "success")
        else:
            self.set_status("Decryption failed: Incorrect password, keyfile, or corrupted ciphertext", "error")

    def show_qr_popup(self):
        text = self.encrypted_text_entry.get("1.0", tk.END).strip()
        if not text:
            self.set_status("No encrypted text available to generate QR", "warning")
            return

        try:
            canonical = QRManager.decompress_from_qr(text)
            qr_payload = QRManager.compress_for_qr(canonical)

            if len(qr_payload) > 2800:
                if not messagebox.askyesno("Large Payload Warning",
                                           "The encrypted text is large for a single QR code. Scanning may be difficult. Continue?"):
                    return

            pil_img = QRManager.generate_qr_image(qr_payload, box_size=5, border=3)

            top = tk.Toplevel(self.root)
            top.title("Encrypted QR Code (ENC5)")
            top.geometry("440x520")
            top.configure(bg=self.colors["bg"])
            top.transient(self.root)

            tk_img = ImageTk.PhotoImage(pil_img)
            img_lbl = tk.Label(top, image=tk_img, bg=self.colors["bg"])
            img_lbl.image = tk_img
            img_lbl.pack(padx=16, pady=16)

            info_lbl = tk.Label(
                top, text=f"Payload: {len(qr_payload)} bytes (Compressed Zlib Level 9 + Base64)",
                font=self.font_status, bg=self.colors["bg"], fg=self.colors["fg_muted"]
            )
            info_lbl.pack(pady=(0, 10))

            btn_frame = tk.Frame(top, bg=self.colors["bg"])
            btn_frame.pack(pady=8)

            def _save_qr_png():
                save_path = filedialog.asksaveasfilename(
                    defaultextension=".png", filetypes=[("PNG Image", "*.png"), ("All Files", "*.*")]
                )
                if save_path:
                    pil_img.save(save_path)
                    messagebox.showinfo("Saved", f"QR Code saved to:\n{save_path}")

            save_btn = tk.Button(btn_frame, text="💾 Save Image (PNG)", font=self.font_body, command=_save_qr_png,
                                 relief="flat", padx=10, pady=4)
            save_btn.pack(side="left", padx=6)

            close_btn = tk.Button(btn_frame, text="Close", font=self.font_body, command=top.destroy, relief="flat",
                                  padx=10, pady=4)
            close_btn.pack(side="left", padx=6)

            self.set_status("QR Code generated successfully", "success")

        except Exception as e:
            messagebox.showerror("QR Error", f"Could not generate QR code:\n{e}")
            self.set_status(f"QR generation error: {e}", "error")

    def action_scan_qr_file(self):
        if not HAS_CV2:
            messagebox.showerror("OpenCV Required",
                                 "QR Scanner requires opencv-python.\nPlease install it via:\npip install opencv-python")
            return

        file_path = filedialog.askopenfilename(
            filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp;*.webp"), ("All Files", "*.*")]
        )
        if not file_path:
            return

        try:
            pil_img = Image.open(file_path)
            raw_data = QRManager.decode_qr_from_image(pil_img)
            if not raw_data:
                messagebox.showwarning("Scan Failed", "No QR Code could be detected in the selected image.")
                return

            normalized = QRManager.decompress_from_qr(raw_data)
            self.encrypted_text_entry.delete("1.0", tk.END)
            self.encrypted_text_entry.insert(tk.END, normalized)
            self._on_cipher_text_keystroke()
            self.set_status("QR code scanned & imported into Encrypted Text box", "success")

            if self.password_entry.get().strip():
                self.action_decrypt()

        except Exception as e:
            messagebox.showerror("Scan Error", f"Failed to process image file:\n{e}")

    def on_browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path_var.set(file_path)
            size = os.path.getsize(file_path)
            self.file_info_lbl.config(
                text=f"Size: {format_file_size(size)} ({size} bytes) | File ready",
                fg=self.colors["fg"]
            )
            self.set_status(f"Selected file: {os.path.basename(file_path)}", "info")

    def on_copy_main_password_to_file(self):
        pwd = self.password_entry.get()
        self.file_pwd_entry.delete(0, tk.END)
        self.file_pwd_entry.insert(0, pwd)
        self.set_status("Copied passphrase from main panel to file password", "info")

    def action_encrypt_file(self):
        in_path = self.file_path_var.get()
        password = self.file_pwd_entry.get() or self.password_entry.get()
        key_type = self.key_choice_var.get()

        if not in_path or not os.path.isfile(in_path):
            messagebox.showwarning("File Missing", "Please select a valid source file to encrypt.")
            return
        if not password:
            messagebox.showwarning("Password Missing", "Please provide a password for file encryption.")
            return

        out_path = filedialog.asksaveasfilename(
            initialfile=os.path.basename(in_path) + ".enc",
            defaultextension=".enc",
            filetypes=[("Encrypted Vault Containers", "*.enc"), ("All Files", "*.*")]
        )
        if not out_path:
            return

        def _update_progress(pct, msg):
            self.root.after(0, lambda: self.file_progress.configure(value=pct))
            self.root.after(0, lambda: self.file_progress_lbl.configure(text=f"{pct}% - {msg}"))

        def _worker():
            try:
                CryptoEngine.encrypt_file(
                    in_path, out_path, password, key_type,
                    keyfile_bytes=self.loaded_keyfile_bytes, progress_cb=_update_progress
                )
                self.root.after(0, lambda: messagebox.showinfo("Success",
                                                               f"File encrypted successfully into ENC5F container!\nSaved to:\n{out_path}"))
                self.root.after(0, lambda: self.set_status(f"File encrypted: {os.path.basename(out_path)}", "success"))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Encryption Error", f"File encryption failed:\n{e}"))
                self.root.after(0, lambda: self.set_status(f"File encryption failed: {e}", "error"))

        threading.Thread(target=_worker, daemon=True).start()

    def action_decrypt_file(self):
        in_path = self.file_path_var.get()
        password = self.file_pwd_entry.get() or self.password_entry.get()
        key_type = self.key_choice_var.get()

        if not in_path or not os.path.isfile(in_path):
            messagebox.showwarning("File Missing", "Please select a valid source file to decrypt.")
            return
        if not password:
            messagebox.showwarning("Password Missing", "Please provide a password for file decryption.")
            return

        suggested_name = os.path.basename(in_path)
        if suggested_name.endswith(".enc"):
            suggested_name = suggested_name[:-4]
        else:
            suggested_name += ".dec"

        out_path = filedialog.asksaveasfilename(
            initialfile=suggested_name,
            filetypes=[("All Files", "*.*")]
        )
        if not out_path:
            return

        def _update_progress(pct, msg):
            self.root.after(0, lambda: self.file_progress.configure(value=pct))
            self.root.after(0, lambda: self.file_progress_lbl.configure(text=f"{pct}% - {msg}"))

        def _worker():
            try:
                used_key = CryptoEngine.decrypt_file(
                    in_path, out_path, password, fallback_key=key_type,
                    keyfile_bytes=self.loaded_keyfile_bytes, progress_cb=_update_progress
                )
                self.root.after(0, lambda: messagebox.showinfo("Success",
                                                               f"File decrypted successfully!\nMatched Engine: {used_key}\nSaved to:\n{out_path}"))
                self.root.after(0, lambda: self.set_status(f"File decrypted: {os.path.basename(out_path)}", "success"))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Decryption Error",
                                                                f"File decryption failed. Invalid password, missing keyfile, or corrupted file.\nDetails: {e}"))
                self.root.after(0, lambda: self.set_status("File decryption failed", "error"))

        threading.Thread(target=_worker, daemon=True).start()

    def action_run_benchmark(self):
        self.btn_run_bench.config(state="disabled", text="⏳ Running...")
        self.bench_text.delete("1.0", tk.END)
        self.bench_text.insert(tk.END, "Running cryptographic benchmark across all 10 tiers...\n\n")

        def _bench_worker():
            pwd = "BenchmarkPassword123!".encode('utf-8')
            lines = []
            for name, conf in KEY_CONFIGS.items():
                salt = os.urandom(32)
                t0 = time.perf_counter()
                key = CryptoEngine.derive_symmetric_key(pwd, salt, conf, 32)
                AESGCM(key).encrypt(os.urandom(12), b"Benchmark payload", None)
                elapsed = round((time.perf_counter() - t0) * 1000)
                lines.append(f"  {conf['alias']:7} | RAM: {conf['mem_mb']:3} MB | Rating: {conf['rating']:22} | Speed: {elapsed} ms\n")
            
            def _done():
                for line in lines:
                    self.bench_text.insert(tk.END, line)
                self.bench_text.insert(tk.END, "\n[✓] Benchmark completed successfully!\n")
                self.btn_run_bench.config(state="normal", text="⚡ Run Benchmark")
                self.set_status("Cryptographic benchmark completed", "success")

            self.root.after(0, _done)

        threading.Thread(target=_bench_worker, daemon=True).start()

    def copy_to_clipboard(self, text_widget):
        content = text_widget.get("1.0", tk.END).strip()
        if content:
            self.root.clipboard_clear()
            self.root.clipboard_append(content)
            self.set_status("Copied text to system clipboard", "info")

    def paste_from_clipboard(self, text_widget):
        # 1. Try text from clipboard
        try:
            content = self.root.clipboard_get()
            if content and content.strip():
                if text_widget is self.encrypted_text_entry:
                    content = QRManager.decompress_from_qr(content)
                text_widget.delete("1.0", tk.END)
                text_widget.insert(tk.END, content)
                if text_widget is self.decrypted_text_entry:
                    self._on_plain_text_keystroke()
                else:
                    self._on_cipher_text_keystroke()
                self.set_status("Pasted text from clipboard", "info")
                return
        except Exception:
            pass

        # 2. Try Image from clipboard (Ctrl+V / Paste QR Image)
        if ImageGrab and HAS_CV2:
            try:
                img = ImageGrab.grabclipboard()
                if isinstance(img, Image.Image):
                    raw_data = QRManager.decode_qr_from_image(img)
                    if raw_data:
                        normalized = QRManager.decompress_from_qr(raw_data)
                        self.encrypted_text_entry.delete("1.0", tk.END)
                        self.encrypted_text_entry.insert(tk.END, normalized)
                        self._on_cipher_text_keystroke()
                        self.set_status("QR Code image scanned & imported from clipboard!", "success")
                        if self.password_entry.get().strip():
                            self.action_decrypt()
                        return
                    else:
                        self.set_status("Pasted image contains no readable QR code", "warning")
                        return
            except Exception as e:
                pass

        self.set_status("No valid text or QR code image found in clipboard", "warning")

    def clear_text_box(self, text_widget):
        text_widget.delete("1.0", tk.END)
        if text_widget is self.decrypted_text_entry:
            self._on_plain_text_keystroke()
        else:
            self._on_cipher_text_keystroke()
        self.set_status("Cleared text box", "info")

    def load_text_file(self, text_widget):
        path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if path:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            text_widget.delete("1.0", tk.END)
            text_widget.insert(tk.END, content)
            self._on_plain_text_keystroke()
            self.set_status(f"Loaded text from: {os.path.basename(path)}", "info")

    def save_text_file(self, text_widget):
        content = text_widget.get("1.0", tk.END).strip()
        if not content:
            self.set_status("Text box is empty, nothing to save", "warning")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt",
                                            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            self.set_status(f"Saved text to: {os.path.basename(path)}", "success")


# =============================================================================
# Application Entry Point
# =============================================================================
def main():
    if not HAS_TKINTER:
        print("Error: Tkinter is required to run the EncDec Pro GUI.")
        print("Please install python3-tk on Linux or run with standard Python.")
        sys.exit(1)

    root = tk.Tk()
    app = EncDecProApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
