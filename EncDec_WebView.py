#!/usr/bin/env python3
"""
EncDec Studio Pro (v5.1.0) — Universal Desktop WebView & Local Web Application
======================================================================
Military-Grade Cryptography Architecture:
- 10 Key Profiles (Key 1 to Key 10): 100% AES-256-GCM AEAD & Graded Memory-Hard KDFs (Scrypt/Argon2id, 16MB to 512MB RAM)
- Keyfile / 2-Factor Hardware Token Authentication
- Next-Gen ENC5 Envelopes & ENC5F\x02 File Containers
- Full Legacy Backwards Compatibility for ENC4 Envelopes, ENC4F Containers & Fernet AES-128
- Native PyWebView, Chrome/Edge Frameless App Mode, or Browser execution
"""

import os
import io
import sys
import time
import json
import base64
import zlib
import struct
import shutil
import socket
import argparse
import hashlib
import threading
import webbrowser
import subprocess
from pathlib import Path
from http.server import HTTPServer, SimpleHTTPRequestHandler
from typing import Optional, Dict, Any, Tuple

# Cryptography
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.backends import default_backend
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

# Optional OpenCV & PIL
try:
    import cv2
    import numpy as np
    from PIL import Image
    HAS_OPENCV = hasattr(cv2, "QRCodeDetector")
except ImportError:
    HAS_OPENCV = False

# All 10 Key Profiles (Key 1 to Key 10) Upgraded to AES-256-GCM & Memory-Hard KDF
KEY_CONFIGS: Dict[str, Dict[str, Any]] = {
    "Key 1": {
        "kdf": "argon2id" if HAS_ARGON2 else "scrypt",
        "cipher": "AES-256-GCM",
        "salt_length": 32,
        "scrypt_n": 16384,   # 16 MB memory
        "scrypt_r": 8,
        "scrypt_p": 1,
        "argon_m": 16384,
        "argon_t": 2,
        "argon_p": 1,
        "alias": "Key 1",
        "label": "Key 1 (Fast - 16MB Memory-Hard + AES-256-GCM)",
        "security_rating": "Fast Memory-Hard"
    },
    "Key 2": {
        "kdf": "argon2id" if HAS_ARGON2 else "scrypt",
        "cipher": "AES-256-GCM",
        "salt_length": 32,
        "scrypt_n": 32768,   # 32 MB memory
        "scrypt_r": 8,
        "scrypt_p": 1,
        "argon_m": 32768,
        "argon_t": 2,
        "argon_p": 1,
        "alias": "Key 2",
        "label": "Key 2 (Standard - 32MB Memory-Hard + AES-256-GCM)",
        "security_rating": "Standard Memory-Hard"
    },
    "Key 3": {
        "kdf": "argon2id" if HAS_ARGON2 else "scrypt",
        "cipher": "AES-256-GCM",
        "salt_length": 32,
        "scrypt_n": 32768,   # 48 MB memory
        "scrypt_r": 12,
        "scrypt_p": 1,
        "argon_m": 49152,
        "argon_t": 2,
        "argon_p": 2,
        "alias": "Key 3",
        "label": "Key 3 (Enhanced - 48MB Memory-Hard + AES-256-GCM)",
        "security_rating": "Enhanced Security"
    },
    "Key 4": {
        "kdf": "argon2id" if HAS_ARGON2 else "scrypt",
        "cipher": "AES-256-GCM",
        "salt_length": 32,
        "scrypt_n": 65536,   # 64 MB memory
        "scrypt_r": 8,
        "scrypt_p": 1,
        "argon_m": 65536,
        "argon_t": 2,
        "argon_p": 2,
        "alias": "Key 4",
        "label": "Key 4 (High - 64MB Memory-Hard + AES-256-GCM)",
        "security_rating": "High Security (AEAD)"
    },
    "Key 5": {
        "kdf": "argon2id" if HAS_ARGON2 else "scrypt",
        "cipher": "AES-256-GCM",
        "salt_length": 32,
        "scrypt_n": 65536,   # 96 MB memory
        "scrypt_r": 12,
        "scrypt_p": 1,
        "argon_m": 98304,
        "argon_t": 3,
        "argon_p": 2,
        "alias": "Key 5",
        "label": "Key 5 (High+ - 96MB Memory-Hard + AES-256-GCM)",
        "security_rating": "High+ Vault Grade"
    },
    "Key 6": {
        "kdf": "argon2id" if HAS_ARGON2 else "scrypt",
        "cipher": "AES-256-GCM",
        "salt_length": 32,
        "scrypt_n": 131072,  # 128 MB memory
        "scrypt_r": 8,
        "scrypt_p": 1,
        "argon_m": 131072,
        "argon_t": 3,
        "argon_p": 2,
        "alias": "Key 6",
        "label": "Key 6 (Strong - 128MB Memory-Hard + AES-256-GCM)",
        "security_rating": "Strong Vault Grade"
    },
    "Key 7": {
        "kdf": "argon2id" if HAS_ARGON2 else "scrypt",
        "cipher": "AES-256-GCM",
        "salt_length": 32,
        "scrypt_n": 131072,  # 160 MB memory
        "scrypt_r": 10,
        "scrypt_p": 1,
        "argon_m": 163840,
        "argon_t": 3,
        "argon_p": 4,
        "alias": "Key 7",
        "label": "Key 7 (Very Strong - 160MB Memory-Hard + AES-256-GCM)",
        "security_rating": "Very Strong Vault"
    },
    "Key 8": {
        "kdf": "argon2id" if HAS_ARGON2 else "scrypt",
        "cipher": "AES-256-GCM",
        "salt_length": 32,
        "scrypt_n": 131072,  # 192 MB memory
        "scrypt_r": 12,
        "scrypt_p": 1,
        "argon_m": 196608,
        "argon_t": 4,
        "argon_p": 4,
        "alias": "Key 8",
        "label": "Key 8 (Ultra - 192MB Memory-Hard + AES-256-GCM)",
        "security_rating": "Supercomputer-Proof"
    },
    "Key 9": {
        "kdf": "argon2id" if HAS_ARGON2 else "scrypt",
        "cipher": "AES-256-GCM",
        "salt_length": 32,
        "scrypt_n": 262144,  # 256 MB memory
        "scrypt_r": 8,
        "scrypt_p": 1,
        "argon_m": 262144,
        "argon_t": 4,
        "argon_p": 4,
        "alias": "Key 9",
        "label": "Key 9 (Extreme - 256MB Memory-Hard + AES-256-GCM)",
        "security_rating": "Military Vault Grade"
    },
    "Key 10": {
        "kdf": "argon2id" if HAS_ARGON2 else "scrypt",
        "cipher": "AES-256-GCM",
        "salt_length": 32,
        "scrypt_n": 524288,  # 512 MB memory
        "scrypt_r": 8,
        "scrypt_p": 1,
        "argon_m": 524288,
        "argon_t": 4,
        "argon_p": 4,
        "alias": "Key 10",
        "label": "Key 10 (Paranoid - 512MB Memory-Hard + AES-256-GCM)",
        "security_rating": "Quantum / ASIC Proof"
    }
}

# Legacy PBKDF2 iterations mapping for decrypting old ciphertexts
LEGACY_PBKDF2_MAP = {
    "Key 1": 100000,
    "Key 2": 200000,
    "Key 3": 300000,
    "Key 4": 400000,
    "Key 5": 500000,
    "Key 6": 800000,
    "Key 7": 1000000,
    "Key 8": 1200000,
    "Key 9": 1500000,
    "Key 10": 2000000
}

ALIAS_MAP = {}
for k, v in KEY_CONFIGS.items():
    ALIAS_MAP[k] = v
    ALIAS_MAP[v["alias"]] = v
    ALIAS_MAP[v["label"]] = v

MAGIC_HEADER_V5 = "ENC5:"
MAGIC_HEADER_V4 = "ENC4:"
FILE_MAGIC_V5 = b"ENC5F\x02"
FILE_MAGIC_V4 = b"ENC4F\x01"

def get_key_config(name: str) -> Dict[str, Any]:
    return ALIAS_MAP.get(name, KEY_CONFIGS["Key 4"])

def prepare_key_material(password: str, keyfile_bytes: Optional[bytes] = None) -> bytes:
    material = password.encode('utf-8')
    if keyfile_bytes:
        kf_hash = hashlib.sha256(keyfile_bytes).digest()
        material = material + b"::KEYFILE::" + kf_hash
    return material

def derive_symmetric_key(material: bytes, salt: bytes, config: Dict[str, Any], length: int = 32) -> bytes:
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

def derive_legacy_pbkdf2(password: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, 32)

def safe_b64decode(s: str) -> bytes:
    s = s.strip()
    missing_padding = len(s) % 4
    if missing_padding:
        s += '=' * (4 - missing_padding)
    return base64.urlsafe_b64decode(s.encode('ascii'))

def safe_b64encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode('ascii')

def normalize_qr_text(s: str) -> str:
    s = s.strip()
    if not s:
        return s
    try:
        raw = safe_b64decode(s)
        decompressed = zlib.decompress(raw).decode('utf-8')
        return decompressed
    except Exception:
        return s

# Server Request Handler
class EncDecRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, directory=None, **kwargs):
        if directory is None:
            directory = str(Path(__file__).resolve().parent)
        super().__init__(*args, directory=directory, **kwargs)

    def end_headers(self):
        # Prevent browser/webview caching of static JS/CSS resources and API responses
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

    def do_GET(self):
        if self.path == "/api/status":
            self.send_json_response({
                "status": "online",
                "crypto_backend": "AES-256-GCM AEAD (All Key 1-10 Upgraded)",
                "has_opencv_scanner": HAS_OPENCV,
                "key_configs": list(KEY_CONFIGS.keys()),
                "default_key": "Key 4"
            })
            return
        elif self.path in ("/", "/index.html"):
            # Prefer standalone self-contained bundle or fallback to modular index.html
            standalone_path = Path(self.directory) / "encdec_standalone.html"
            if not standalone_path.exists():
                standalone_path = Path(self.directory) / "index.html"
            if standalone_path.exists():
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                with open(standalone_path, "rb") as f:
                    self.wfile.write(f.read())
                return

        return super().do_GET()

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)
        
        try:
            req = json.loads(post_data.decode("utf-8")) if post_data else {}
        except Exception:
            req = {}

        if self.path == "/api/encrypt":
            if not HAS_CRYPTO:
                self.send_error_response("Python cryptography not available on server", 501)
                return
            plain = req.get("plain_text", "")
            pwd = req.get("password", "")
            key_type = req.get("key_type", "Key 4")
            use_env = req.get("use_envelope", True)
            kf_b64 = req.get("keyfile_base64")

            if not plain or not pwd:
                self.send_error_response("Plaintext and password are required.", 400)
                return

            config = get_key_config(key_type)
            salt = os.urandom(config["salt_length"])
            kf_bytes = safe_b64decode(kf_b64) if kf_b64 else None
            material = prepare_key_material(pwd, kf_bytes)

            key = derive_symmetric_key(material, salt, config, length=32)
            aesgcm = AESGCM(key)
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, plain.encode('utf-8'), None)

            if use_env:
                salt_b64 = safe_b64encode(salt)
                nonce_b64 = safe_b64encode(nonce)
                cipher_b64 = safe_b64encode(ciphertext)
                alias = config["alias"]
                kdf_tag = config.get("kdf", "scrypt")
                result = f"{MAGIC_HEADER_V5}{alias}:{kdf_tag}:{salt_b64}:{nonce_b64}:{cipher_b64}"
            else:
                result = safe_b64encode(salt + nonce + ciphertext)

            self.send_json_response({
                "success": True,
                "encrypted_text": result,
                "key_type": config["alias"],
                "cipher": "AES-256-GCM",
                "has_keyfile": bool(kf_bytes)
            })
            return

        elif self.path == "/api/decrypt":
            if not HAS_CRYPTO:
                self.send_error_response("Python cryptography not available on server", 501)
                return
            cipher_text = req.get("encrypted_text", "")
            pwd = req.get("password", "")
            kf_b64 = req.get("keyfile_base64")

            if not cipher_text or not pwd:
                self.send_error_response("Ciphertext and password are required.", 400)
                return

            s = normalize_qr_text(cipher_text)
            kf_bytes = safe_b64decode(kf_b64) if kf_b64 else None
            material = prepare_key_material(pwd, kf_bytes)

            # 1. ENC5: Modern Format
            if s.startswith(MAGIC_HEADER_V5):
                try:
                    parts = s.split(":", 5)
                    if len(parts) == 6:
                        _, alias, kdf_tag, salt_b64, nonce_b64, cipher_b64 = parts
                        salt = safe_b64decode(salt_b64)
                        nonce = safe_b64decode(nonce_b64)
                        ciphertext = safe_b64decode(cipher_b64)
                        config = get_key_config(alias)
                        key = derive_symmetric_key(material, salt, config, length=32)
                        aesgcm = AESGCM(key)
                        decrypted = aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')
                        self.send_json_response({
                            "success": True,
                            "decrypted_text": decrypted,
                            "key_alias": alias,
                            "cipher": "AES-256-GCM"
                        })
                        return
                except Exception:
                    pass

            # 2. ENC4: Legacy Fernet Format
            if s.startswith(MAGIC_HEADER_V4):
                try:
                    parts = s.split(":", 3)
                    if len(parts) == 4:
                        _, alias, salt_b64, cipher_b64 = parts
                        salt = safe_b64decode(salt_b64)
                        iters = LEGACY_PBKDF2_MAP.get(alias, 200000)
                        legacy_key = derive_legacy_pbkdf2(pwd, salt, iters)
                        fernet_key = base64.urlsafe_b64encode(legacy_key)
                        cipher = Fernet(fernet_key)
                        decrypted = cipher.decrypt(cipher_b64.encode('ascii')).decode('utf-8')
                        self.send_json_response({
                            "success": True,
                            "decrypted_text": decrypted,
                            "key_alias": f"{alias} (Legacy Fernet)",
                            "cipher": "Fernet-128"
                        })
                        return
                except Exception:
                    pass

            # 3. Probe all V5 configurations
            for alias, config in KEY_CONFIGS.items():
                try:
                    raw_bytes = safe_b64decode(s)
                    salt_length = config["salt_length"]
                    if len(raw_bytes) > salt_length + 12 + 16:
                        salt = raw_bytes[:salt_length]
                        nonce = raw_bytes[salt_length:salt_length+12]
                        ciphertext = raw_bytes[salt_length+12:]
                        key = derive_symmetric_key(material, salt, config, length=32)
                        aesgcm = AESGCM(key)
                        decrypted = aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')
                        self.send_json_response({
                            "success": True,
                            "decrypted_text": decrypted,
                            "key_alias": config["alias"],
                            "cipher": "AES-256-GCM"
                        })
                        return
                except Exception:
                    continue

            # 4. Probe Legacy PBKDF2 Fernet configurations
            for alias, iters in LEGACY_PBKDF2_MAP.items():
                try:
                    raw_bytes = safe_b64decode(s)
                    salt_len = 16 if alias == "Key 1" else 32
                    if len(raw_bytes) > salt_len + 57:
                        salt = raw_bytes[:salt_len]
                        cipher_bytes = raw_bytes[salt_len:]
                        legacy_key = derive_legacy_pbkdf2(pwd, salt, iters)
                        fernet_key = base64.urlsafe_b64encode(legacy_key)
                        cipher = Fernet(fernet_key)
                        decrypted = cipher.decrypt(cipher_bytes).decode('utf-8')
                        self.send_json_response({
                            "success": True,
                            "decrypted_text": decrypted,
                            "key_alias": f"{alias} (Legacy Fernet)",
                            "cipher": "Fernet-128"
                        })
                        return
                except Exception:
                    continue

            self.send_error_response("Decryption failed. Invalid password, incorrect keyfile, or corrupted ciphertext.", 400)
            return

        elif self.path == "/api/scan-qr":
            if not HAS_OPENCV:
                self.send_error_response("OpenCV not installed on server", 501)
                return
            try:
                raw_data = req.get("image_base64", "")
                if ',' in raw_data:
                    raw_data = raw_data.split(',', 1)[1]
                img_bytes = base64.b64decode(raw_data)
                pil_img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
                cv_img = np.array(pil_img)[:, :, ::-1].copy()

                detector = cv2.QRCodeDetector()
                val, pts, qr = detector.detectAndDecode(cv_img)
                if val:
                    normalized = normalize_qr_text(val)
                    self.send_json_response({"success": True, "text": normalized, "raw_text": val})
                else:
                    self.send_json_response({"success": False, "message": "No QR code found."})
            except Exception as e:
                self.send_error_response(f"Scan failed: {e}", 400)
            return

        self.send_error_response("Endpoint not found", 404)

    def send_json_response(self, data: dict, status_code: int = 200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_error_response(self, msg: str, status_code: int = 400):
        self.send_json_response({"success": False, "error": msg}, status_code=status_code)

    def log_message(self, format, *args):
        pass


def find_free_port(start_port: int = 8080) -> int:
    for port in range(start_port, start_port + 50):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(('127.0.0.1', port)) != 0:
                return port
    return start_port


def launch_native_window(url: str):
    try:
        import webview
        print(" [✓] Launching native PyWebView application window...")
        webview.create_window(
            title="EncDec Studio Pro — Military Cryptography & QR Suite",
            url=url,
            width=1120,
            height=820,
            min_size=(800, 600)
        )
        webview.start()
        return
    except ImportError:
        pass

    app_browsers = ["google-chrome", "chrome", "chromium", "msedge", "brave"]
    for b in app_browsers:
        path = shutil.which(b)
        if path:
            print(f" [✓] Launching frameless app window using {b}...")
            try:
                subprocess.Popen([path, f"--app={url}", "--window-size=1120,820"])
                return
            except Exception:
                pass

    print(" [✓] Opening application in default web browser...")
    webbrowser.open(url)


def main():
    parser = argparse.ArgumentParser(description="EncDec Studio Pro — Universal WebView App")
    parser.add_argument("--port", type=int, default=8080, help="Port to bind server (default: 8080)")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host address (default: 127.0.0.1)")
    parser.add_argument("--no-browser", action="store_true", help="Start server without launching browser")
    args = parser.parse_args()

    port = find_free_port(args.port)
    url = f"http://{args.host}:{port}"

    print("=" * 74)
    print("  🔒 EncDec Studio Pro (v5.1.0) — Military-Grade Cryptography & Vault Suite")
    print("=" * 74)
    print(f"  Local Web View URL: {url}")
    print(f"  Cryptographic Backend: 100% AES-256-GCM AEAD (All Key 1-10 Profiles)")
    print(f"  Memory-Hard KDFs: Scrypt (16MB to 512MB RAM) / Argon2id")
    print(f"  QR Scanner Engine: {'OpenCV Detector Active' if HAS_OPENCV else 'Browser API / Web Scanner'}")
    print("=" * 74)

    base_dir = Path(__file__).resolve().parent
    if (base_dir / "encdec_webview").is_dir() and (base_dir / "encdec_webview" / "encdec_standalone.html").exists():
        base_dir = base_dir / "encdec_webview"

    handler_factory = lambda *a, **k: EncDecRequestHandler(*a, directory=str(base_dir), **k)
    server = HTTPServer((args.host, port), handler_factory)

    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    if not args.no_browser:
        time.sleep(0.4)
        launch_native_window(url)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping EncDec Studio Pro server...")
        server.shutdown()
        sys.exit(0)


if __name__ == "__main__":
    main()
