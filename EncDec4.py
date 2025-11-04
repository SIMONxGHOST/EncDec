# EncDec4.py (PC version) — with QR popup
"""
QR Code Support: Generate and scan QR codes for quick sharing of encrypted messages between devices.
This version adds a resilient QR generator that works with either `qrcode` or `segno` if available.
If neither is installed or the wrong module is imported, the app shows a helpful error.
"""

import base64
import io
import os
import re
import secrets
import string
import zlib
import tkinter as tk
import tkinter.filedialog as filedialog
from tkinter import font as tkfont
from tkinter import messagebox
from tkinter import scrolledtext, messagebox
from PIL import Image, ImageTk
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- Try preferred QR libraries (robust against wrong/shadowed modules) ---
_qrcode = None
_segno = None
HAS_QRCODE = False
HAS_SEGNO = False

try:
    import qrcode as _qrcode  # may be shadowed; we verify attributes
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


KEY_CONFIGS = {
    "Key 1": {"salt_length": 16, "iterations": 100000},
    "Key 2": {"salt_length": 32, "iterations": 200000},
    "Key 3": {"salt_length": 32, "iterations": 300000},
    "Key 4": {"salt_length": 32, "iterations": 400000},
    "Key 5": {"salt_length": 32, "iterations": 500000},
    "Key 6": {"salt_length": 64, "iterations": 800000},
    "Key 7": {"salt_length": 64, "iterations": 1000000},
    "Key 8": {"salt_length": 64, "iterations": 1200000},
    "Key 9": {"salt_length": 128, "iterations": 1500000},
    "Key 10": {"salt_length": 256, "iterations": 2000000},
}

def derive_key(password: str, salt: bytes, key_type: str) -> bytes:
    """Derive key from password and salt using PBKDF2HMAC; parameters depend on key_type."""
    config = KEY_CONFIGS[key_type]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=config['iterations'],
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_text(plain_text: str, password: str, key_type: str) -> str:
    """Encrypt plain text using provided password and key_type."""
    config = KEY_CONFIGS[key_type]
    salt = os.urandom(config['salt_length'])
    key = derive_key(password, salt, key_type)
    cipher = Fernet(key)
    encrypted_text = cipher.encrypt(plain_text.encode())
    return base64.urlsafe_b64encode(salt + encrypted_text).decode()


# simple base64-ish pattern for quick plausibility checks
_B64_RE = re.compile(r'^[A-Za-z0-9\-_]+=*$')

def _looks_like_base64(s: str) -> bool:
    """Quick check whether a string could be URL-safe base64."""
    s = s.strip()
    return bool(_B64_RE.match(s))

def normalize_scanned_encrypted_text(s: str) -> str:
    """
    If s is our QR wrapper (urlsafe_b64(zlib.compress(original_aes_base64))),
    return the inner original AES base64 string.
    Otherwise return s unchanged.
    This function is permissive and will fall back to returning the original
    string if any decoding step fails.
    """
    s = s.strip()
    if not s:
        return s

    # Quick heuristic: if it doesn't even look like base64, bail out early.
    if not _looks_like_base64(s):
        return s

    # Try to decode and decompress (the wrapper). If it works and yields UTF-8,
    # assume it's our wrapper and return the inner text.
    try:
        decoded = base64.urlsafe_b64decode(s.encode('ascii'))
        decompressed = zlib.decompress(decoded)
        inner = decompressed.decode('utf-8')
        # final sanity: inner should look like base64 too (EncDec produces base64)
        if _looks_like_base64(inner):
            return inner
    except Exception:
        pass

    # Not our wrapper — return original (likely already EncDec AES base64)
    return s

def make_qr_payload_from_encdec(encdec_base64: str) -> str:
    """
    Take the EncDec AES base64 text and return a safe ASCII payload suitable
    for QR: urlsafe_base64(zlib.compress(encdec_base64_bytes)).
    """
    compressed = zlib.compress(encdec_base64.encode('utf-8'), level=9)
    return base64.urlsafe_b64encode(compressed).decode('ascii')

def decrypt_text(encrypted_text: str, password: str, key_type: str) -> str:
    """Decrypt encrypted text using provided password and key_type."""
    try:
        encrypted_text_bytes = base64.urlsafe_b64decode(encrypted_text.encode())
        config = KEY_CONFIGS[key_type]
        salt_length = config['salt_length']
        salt = encrypted_text_bytes[:salt_length]
        encrypted_text = encrypted_text_bytes[salt_length:]
        key = derive_key(password, salt, key_type)
        cipher = Fernet(key)
        decrypted_text = cipher.decrypt(encrypted_text)
        update_password_indicator(True)
        update_status("Decryption Successful", "green")
        return decrypted_text.decode()
    except Exception:
        update_password_indicator(False)
        update_status("Decryption Failed", "red")
        return ""

def update_password_indicator(is_valid: bool):
    color = 'green' if is_valid else 'red'
    password_indicator.itemconfig(password_indicator_circle, fill=color)

def update_status(message, color="green"):
    status_label.config(text=message, fg=color)
    root.after(3000, clear_status)

def clear_status():
    status_label.config(text="")

def on_encrypted_text_change(event=None):
    raw = encrypted_text_entry.get("1.0", tk.END).strip()
    encrypted_text = normalize_scanned_encrypted_text(raw)
    password = password_entry.get()
    if encrypted_text and password:
        key_type = key_choice.get()
        decrypted_text = decrypt_text(encrypted_text, password, key_type)
        if decrypted_text:
            decrypted_text_entry.delete("1.0", tk.END)
            decrypted_text_entry.insert(tk.END, decrypted_text)

def on_decrypted_text_change(event=None):
    """
    Called when the decrypted-text box changes. If there is plaintext and a password,
    produce the EncDec base64 ciphertext and insert it into the Encrypted Text box.
    """
    decrypted_text = decrypted_text_entry.get("1.0", tk.END).strip()
    password = password_entry.get()
    if decrypted_text and password:
        key_type = key_choice.get()
        encrypted_text = encrypt_text(decrypted_text, password, key_type)
        encrypted_text_entry.delete("1.0", tk.END)
        encrypted_text_entry.insert(tk.END, encrypted_text)
        update_status("Encryption Successful", "green")

def on_password_change(event=None):
    if encrypted_text_entry.get("1.0", tk.END).strip():
        on_encrypted_text_change()
    if decrypted_text_entry.get("1.0", tk.END).strip():
        on_decrypted_text_change()


def generate_random_password():
    # Use letters, digits, and punctuation for a strong character set
    characters = string.ascii_letters + string.digits + string.punctuation

    # Generate a secure 32-character password
    password = ''.join(secrets.choice(characters) for _ in range(32))

    # Insert into the Tkinter entry widget
    password_entry.delete(0, tk.END)
    password_entry.insert(0, password)


def copy_to_clipboard(text_widget):
    root.clipboard_clear()
    root.clipboard_append(text_widget.get("1.0", tk.END).strip())
    update_status("Copied to clipboard", "blue")

def paste_from_clipboard(text_widget):
    scanned = root.clipboard_get()
    # If pasting into the Encrypted Text box, normalize (detect QR wrapper).
    if text_widget is encrypted_text_entry:
        scanned = normalize_scanned_encrypted_text(scanned)
    text_widget.delete("1.0", tk.END)
    text_widget.insert(tk.END, scanned)
    update_status("Pasted from clipboard", "blue")

def toggle_password_visibility():
    if password_entry.cget('show') == '*':
        password_entry.config(show='')
        update_status("Password visible", "blue")
    else:
        password_entry.config(show='*')
        update_status("Password hidden", "blue")

def adjust_to_screen_size():
    screen_width = root.winfo_screenwidth()
    if screen_width > 800:
        text_box_width = 70
        text_box_height = 10
        button_font_size = 12
    else:
        text_box_width = 40
        text_box_height = 5
        button_font_size = 10
    custom_font.configure(size=button_font_size)
    encrypted_text_entry.config(height=text_box_height, width=text_box_width)
    decrypted_text_entry.config(height=text_box_height, width=text_box_width)

def encrypt_file(file_path, password, key_type):
    config = KEY_CONFIGS[key_type]
    salt = os.urandom(config['salt_length'])
    with open(file_path, "rb") as f:
        data = f.read()
    key = derive_key(password, salt, key_type)
    cipher = Fernet(key)
    encrypted_data = cipher.encrypt(data)
    with open(file_path + ".enc", "wb") as f:
        f.write(salt + encrypted_data)
    update_status("File encryption successful", "green")

def decrypt_file(file_path, password, key_type):
    try:
        with open(file_path, "rb") as f:
            encrypted_data = f.read()
        config = KEY_CONFIGS[key_type]
        salt_length = config['salt_length']
        salt = encrypted_data[:salt_length]
        encrypted_data = encrypted_data[salt_length:]
        key = derive_key(password, salt, key_type)
        cipher = Fernet(key)
        decrypted_data = cipher.decrypt(encrypted_data)
        with open(file_path.replace(".enc", ""), "wb") as f:
            f.write(decrypted_data)
        update_status("File decryption successful", "green")
    except Exception:
        update_status("File decryption failed", "red")

def choose_file_to_encrypt():
    file_path = filedialog.askopenfilename()
    if file_path:
        encrypt_file(file_path, password_entry.get(), key_choice.get())

def choose_file_to_decrypt():
    file_path = filedialog.askopenfilename()
    if file_path:
        decrypt_file(file_path, password_entry.get(), key_choice.get())

# --- QR helpers: pick a working backend and render a PIL Image ---


def make_qr_image(data: str, box_size: int = 4, border: int = 4) -> Image.Image:
    if HAS_QRCODE:
        qr = _qrcode.QRCode(
            version=None,
            error_correction=_qrcode.constants.ERROR_CORRECT_L,  # lower ECC → more capacity
            box_size=box_size,
            border=border,
        )
        # Prefer binary when possible
        if isinstance(data, bytes):
            qr.add_data(data)
        else:
            qr.add_data(data.encode('utf-8'))  # force bytes to avoid mode issues
        qr.make(fit=True)
        return qr.make_image(fill_color="black", back_color="white").convert("RGB")

    if HAS_SEGNO:
        qr = _segno.make(data, error='l', micro=False)  # 'l' = lowest ECC
        bio = io.BytesIO()
        qr.save(bio, kind="png", scale=box_size, border=border)
        bio.seek(0)
        return Image.open(bio)

    messagebox.showerror("QR Code Error", "No working QR backend found.\n\nInstall one of:\n  pip install qrcode[pil]\n  pip install segno")
    raise RuntimeError("No QR backend available")

def chunk_bytes(b: bytes, size: int):
    for i in range(0, len(b), size):
        yield i // size, b[i:i+size]

def show_qr_code():
    text = encrypted_text_entry.get("1.0", tk.END).strip()
    if not text:
        update_status("No encrypted text to generate QR", "red")
        return
    try:
        # Normalize in case the field already contains a QR wrapper (or plain EncDec)
        canonical = normalize_scanned_encrypted_text(text)
        # Wrap (compress + urlsafe-base64) for scanner-safe ASCII payload
        qr_payload = make_qr_payload_from_encdec(canonical)

        qr_img = make_qr_image(qr_payload, box_size=4, border=4)

        top = tk.Toplevel(root)
        top.title("QR Code")
        tk_img = ImageTk.PhotoImage(qr_img)
        lbl = tk.Label(top, image=tk_img)
        lbl.image = tk_img
        lbl.pack(padx=20, pady=20)

        update_status("QR Code generated (compressed + base64)", "green")
    except Exception as e:
        update_status(f"QR generation failed: {e}", "red")

def show_qr_code():
    text = encrypted_text_entry.get("1.0", tk.END).strip()
    if not text:
        update_status("No encrypted text to generate QR", "red")
        return
    try:
        # Ensure we operate on the canonical EncDec base64 form first.
        canonical = normalize_scanned_encrypted_text(text)
        # Wrap (compress + base64) so QR payload is ASCII-safe and scanner-friendly
        qr_payload = make_qr_payload_from_encdec(canonical)

        qr_img = make_qr_image(qr_payload, box_size=4, border=4)

        top = tk.Toplevel(root)
        top.title("QR Code")
        tk_img = ImageTk.PhotoImage(qr_img)
        lbl = tk.Label(top, image=tk_img)
        lbl.image = tk_img
        lbl.pack(padx=20, pady=20)

        update_status("QR Code generated (compressed + base64)", "green")
    except Exception as e:
        update_status(f"QR generation failed: {e}", "red")

# ---------------- Main Application Setup ----------------
root = tk.Tk()
root.title("Encryption App")
root.geometry("800x600")

custom_font = tkfont.Font(size=12)

dark_bg = "#333"
dark_fg = "#FFF"
button_bg = "#555"
button_fg = "#FFF"

root.configure(bg=dark_bg)

# Password Entry
password_label = tk.Label(root, text="Password:", bg=dark_bg, fg=dark_fg)
password_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")

password_entry = tk.Entry(root, show="*", bg=dark_bg, fg=dark_fg, insertbackground=dark_fg)
password_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
password_entry.bind("<KeyRelease>", on_password_change)

toggle_password_button = tk.Button(root, text="Show", command=toggle_password_visibility, bg=button_bg, fg=button_fg)
toggle_password_button.grid(row=0, column=2, padx=10, pady=10, sticky="ew")

generate_password_button = tk.Button(root, text="Generate", command=generate_random_password, bg=button_bg, fg=button_fg)
generate_password_button.grid(row=0, column=3, padx=10, pady=10, sticky="ew")

# Key Choice Dropdown
key_label = tk.Label(root, text="Key Type:", bg=dark_bg, fg=dark_fg)
key_label.grid(row=0, column=4, padx=10, pady=10, sticky="w")

key_choice = tk.StringVar(value="Choose Key")
key_menu = tk.OptionMenu(root, key_choice, *KEY_CONFIGS.keys())
key_menu.config(bg=button_bg, fg=button_fg)
key_menu.grid(row=0, column=5, padx=10, pady=10, sticky="ew")

# Encrypted Text Box
encrypted_label = tk.Label(root, text="Encrypted Text:", bg=dark_bg, fg=dark_fg)
encrypted_label.grid(row=1, column=0, padx=10, pady=10, sticky="nw")

encrypted_text_entry = scrolledtext.ScrolledText(root, height=10, width=70, bg=dark_bg, fg=dark_fg, insertbackground=dark_fg)
encrypted_text_entry.grid(row=1, column=1, columnspan=2, padx=10, pady=10, sticky="nsew")
encrypted_text_entry.bind("<KeyRelease>", on_encrypted_text_change)

copy_encrypted_button = tk.Button(root, text="Copy", command=lambda: copy_to_clipboard(encrypted_text_entry), bg=button_bg, fg=button_fg)
copy_encrypted_button.grid(row=1, column=3, padx=10, pady=10, sticky="ew")

paste_encrypted_button = tk.Button(root, text="Paste", command=lambda: paste_from_clipboard(encrypted_text_entry), bg=button_bg, fg=button_fg)
paste_encrypted_button.grid(row=1, column=4, padx=10, pady=10, sticky="ew")

qr_button = tk.Button(root, text="QR Code", command=show_qr_code, bg=button_bg, fg=button_fg)
qr_button.grid(row=1, column=5, padx=10, pady=10, sticky="ew")

# Decrypted Text Box
decrypted_label = tk.Label(root, text="Decrypted Text:", bg=dark_bg, fg=dark_fg)
decrypted_label.grid(row=2, column=0, padx=10, pady=10, sticky="nw")

decrypted_text_entry = scrolledtext.ScrolledText(root, height=10, width=70, bg=dark_bg, fg=dark_fg, insertbackground=dark_fg)
decrypted_text_entry.grid(row=2, column=1, columnspan=2, padx=10, pady=10, sticky="nsew")
decrypted_text_entry.bind("<KeyRelease>", on_decrypted_text_change)

copy_decrypted_button = tk.Button(root, text="Copy", command=lambda: copy_to_clipboard(decrypted_text_entry), bg=button_bg, fg=button_fg)
copy_decrypted_button.grid(row=2, column=3, padx=10, pady=10, sticky="ew")

paste_decrypted_button = tk.Button(root, text="Paste", command=lambda: paste_from_clipboard(decrypted_text_entry), bg=button_bg, fg=button_fg)
paste_decrypted_button.grid(row=2, column=4, padx=10, pady=10, sticky="ew")

# Password Validity Indicator
password_indicator = tk.Canvas(root, width=20, height=20, bg=dark_bg, highlightthickness=0)
password_indicator_circle = password_indicator.create_oval(5, 5, 15, 15, fill="red")
password_indicator.grid(row=0, column=6, padx=10, pady=10)

# Encrypt/Decrypt File Buttons
encrypt_file_button = tk.Button(root, text="Encrypt File", command=choose_file_to_encrypt, bg=button_bg, fg=button_fg)
encrypt_file_button.grid(row=3, column=1, padx=10, pady=10, sticky="ew")

decrypt_file_button = tk.Button(root, text="Decrypt File", command=choose_file_to_decrypt, bg=button_bg, fg=button_fg)
decrypt_file_button.grid(row=3, column=2, padx=10, pady=10, sticky="ew")

# Status Label
status_label = tk.Label(root, text="", bg=dark_bg, fg=dark_fg, font=custom_font)
status_label.grid(row=4, column=0, columnspan=6, padx=10, pady=10, sticky="ew")

# Adjust size to screen
adjust_to_screen_size()

root.mainloop()
