# this version can only work on PC
""" i need to do these :

QR Code Support: Generate and scan QR codes for quick sharing of encrypted messages between devices."""


import tkinter as tk
from tkinter import font as tkfont
from tkinter import scrolledtext, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import os
import secrets
import tkinter.filedialog as filedialog


KEY_CONFIGS = {
    "Key 1": {"salt_length": 16, "iterations": 100000},
    "Key 2 (EncDec 2,3)": {"salt_length": 32, "iterations": 200000},
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
    """ Derives a key from the given password and salt using PBKDF2HMAC, adjusted by key_type. """
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
    """ Encrypts the given plain text using the provided password and key_type. """
    config = KEY_CONFIGS[key_type]
    salt = os.urandom(config['salt_length'])  # Use the specified salt length
    key = derive_key(password, salt, key_type)
    cipher = Fernet(key)
    encrypted_text = cipher.encrypt(plain_text.encode())
    return base64.urlsafe_b64encode(salt + encrypted_text).decode()

def decrypt_text(encrypted_text: str, password: str, key_type: str) -> str:
    """ Decrypts the given encrypted text using the provided password and key_type. """
    try:
        encrypted_text_bytes = base64.urlsafe_b64decode(encrypted_text.encode())
        config = KEY_CONFIGS[key_type]
        salt_length = config['salt_length']
        salt = encrypted_text_bytes[:salt_length]
        encrypted_text = encrypted_text_bytes[salt_length:]
        key = derive_key(password, salt, key_type)
        cipher = Fernet(key)
        decrypted_text = cipher.decrypt(encrypted_text)
        update_password_indicator(True)  # Password is correct
        update_status("Decryption Successful", "green")  # Status message
        return decrypted_text.decode()
    except Exception:
        update_password_indicator(False)  # Password is incorrect
        update_status("Decryption Failed", "red")  # Status message
        return ""  # Return an empty string but do not clear the text

def update_password_indicator(is_valid: bool):
    """ Updates the color of the password validation indicator. """
    color = 'green' if is_valid else 'red'
    password_indicator.itemconfig(password_indicator_circle, fill=color)

def update_status(message, color="green"):
    """ Updates the status label with a message and color. """
    status_label.config(text=message, fg=color)
    root.after(3000, clear_status)  # Clear the status after 3 seconds

def clear_status():
    """ Clears the status message. """
    status_label.config(text="")

def on_encrypted_text_change(event=None):
    """ Called when the encrypted text changes. """
    encrypted_text = encrypted_text_entry.get("1.0", tk.END).strip()
    password = password_entry.get()
    if encrypted_text and password:
        key_type = key_choice.get()  # Get the selected key type
        decrypted_text = decrypt_text(encrypted_text, password, key_type)
        if decrypted_text:  # Only update if decryption was successful
            decrypted_text_entry.delete("1.0", tk.END)
            decrypted_text_entry.insert(tk.END, decrypted_text)

def on_decrypted_text_change(event=None):
    """ Called when the decrypted text changes. """
    decrypted_text = decrypted_text_entry.get("1.0", tk.END).strip()
    password = password_entry.get()
    if decrypted_text and password:
        key_type = key_choice.get()  # Get the selected key type
        encrypted_text = encrypt_text(decrypted_text, password, key_type)
        encrypted_text_entry.delete("1.0", tk.END)
        encrypted_text_entry.insert(tk.END, encrypted_text)
        update_status("Encryption Successful", "green")  # Status message

def on_password_change(event=None):
    """ Called when the password changes. Reprocess the text in both boxes if possible. """
    if encrypted_text_entry.get("1.0", tk.END).strip():
        on_encrypted_text_change()
    if decrypted_text_entry.get("1.0", tk.END).strip():
        on_decrypted_text_change()

def generate_random_password():
    """Generates a random memorable password with a 6-digit number."""
    words = ["apple", "orange", "banana", "hello", "pencil", "data", "python", "#", "?", "@", "$", "+"]
    random_number = secrets.randbelow(1000000)  # Generate a random 6-digit number
    password = '-'.join(secrets.choice(words) for _ in range(3)) + f"-{random_number:06d}"  # Memorable format with number
    password_entry.delete(0, tk.END)
    password_entry.insert(0, password)

def copy_to_clipboard(text_widget):
    """ Copy the content of the text widget to the clipboard. """
    root.clipboard_clear()
    root.clipboard_append(text_widget.get("1.0", tk.END).strip())
    update_status("Copied to clipboard", "blue")  # Status message

def paste_from_clipboard(text_widget):
    """ Paste the content from the clipboard into the text widget. """
    text_widget.delete("1.0", tk.END)
    text_widget.insert(tk.END, root.clipboard_get())
    update_status("Pasted from clipboard", "blue")  # Status message

def toggle_password_visibility():
    """ Toggles the visibility of the password entry. """
    if password_entry.cget('show') == '*':
        password_entry.config(show='')
        update_status("Password visible", "blue")
    else:
        password_entry.config(show='*')
        update_status("Password hidden", "blue")

def adjust_to_screen_size():
    """ Adjusts the size of widgets according to the screen size. """
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()

    if screen_width > 800:  # Large screen (PC)
        text_box_width = 70
        text_box_height = 10
        button_font_size = 12
    else:  # Small screen (Phone)
        text_box_width = 40
        text_box_height = 5
        button_font_size = 10

    custom_font.configure(size=button_font_size)
    encrypted_text_entry.config(height=text_box_height, width=text_box_width)
    decrypted_text_entry.config(height=text_box_height, width=text_box_width)

def encrypt_file(file_path, password, key_type):
    """ Encrypts a file using the provided password and key_type. """
    config = KEY_CONFIGS[key_type]
    salt = os.urandom(config['salt_length'])
    with open(file_path, "rb") as f:
        data = f.read()

    key = derive_key(password, salt, key_type)
    cipher = Fernet(key)
    encrypted_data = cipher.encrypt(data)

    with open(file_path + ".enc", "wb") as f:
        f.write(salt + encrypted_data)

    update_status("File encryption successful", "green")  # Status message

def decrypt_file(file_path, password, key_type):
    """ Decrypts a file using the provided password and key_type. """
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

        update_status("File decryption successful", "green")  # Status message
    except Exception:
        update_status("File decryption failed", "red")  # Status message

def choose_file_to_encrypt():
    """ Opens a file dialog to choose a file for encryption. """
    file_path = filedialog.askopenfilename()
    if file_path:
        encrypt_file(file_path, password_entry.get(), key_choice.get())

def choose_file_to_decrypt():
    """ Opens a file dialog to choose a file for decryption. """
    file_path = filedialog.askopenfilename()
    if file_path:
        decrypt_file(file_path, password_entry.get(), key_choice.get())

# Main Application Setup
root = tk.Tk()
root.title("Encryption App")
root.geometry("800x600")

# Custom font
custom_font = tkfont.Font(size=12)

# Background and foreground colors
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

# Status Label (added for non-intrusive notifications)
status_label = tk.Label(root, text="", bg=dark_bg, fg=dark_fg, font=custom_font)
status_label.grid(row=4, column=0, columnspan=6, padx=10, pady=10, sticky="ew")

# Adjust size to screen
adjust_to_screen_size()

root.mainloop()
