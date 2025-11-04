import tkinter as tk
from tkinter import font as tkfont
from tkinter import scrolledtext
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import os
import secrets
import string
from datetime import datetime

def derive_key(password: str, salt: bytes) -> bytes:
    """ Derives a key from the given password and salt using PBKDF2HMAC. """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_text(plain_text: str, password: str) -> str:
    """ Encrypts the given plain text using the provided password. """
    salt = os.urandom(32)  # Use a 256-bit salt
    key = derive_key(password, salt)
    cipher = Fernet(key)
    encrypted_text = cipher.encrypt(plain_text.encode())
    return base64.urlsafe_b64encode(salt + encrypted_text).decode()

def decrypt_text(encrypted_text: str, password: str) -> str:
    """ Decrypts the given encrypted text using the provided password. """
    try:
        encrypted_text_bytes = base64.urlsafe_b64decode(encrypted_text.encode())
        salt = encrypted_text_bytes[:32]
        encrypted_text = encrypted_text_bytes[32:]
        key = derive_key(password, salt)
        cipher = Fernet(key)
        decrypted_text = cipher.decrypt(encrypted_text)
        update_password_indicator(True)  # Password is correct
        return decrypted_text.decode()
    except Exception:
        update_password_indicator(False)  # Password is incorrect
        return ""  # Return an empty string but do not clear the text

def update_password_indicator(is_valid: bool):
    """ Updates the color of the password validation indicator. """
    color = 'green' if is_valid else 'red'
    password_indicator.itemconfig(password_indicator_circle, fill=color)

def on_encrypted_text_change(event=None):
    """ Called when the encrypted text changes. """
    encrypted_text = encrypted_text_entry.get("1.0", tk.END).strip()
    password = password_entry.get()
    if encrypted_text and password:
        decrypted_text = decrypt_text(encrypted_text, password)
        if decrypted_text:  # Only update if decryption was successful
            decrypted_text_entry.delete("1.0", tk.END)
            decrypted_text_entry.insert(tk.END, decrypted_text)

def on_decrypted_text_change(event=None):
    """ Called when the decrypted text changes. """
    decrypted_text = decrypted_text_entry.get("1.0", tk.END).strip()
    password = password_entry.get()
    if decrypted_text and password:
        encrypted_text = encrypt_text(decrypted_text, password)
        encrypted_text_entry.delete("1.0", tk.END)
        encrypted_text_entry.insert(tk.END, encrypted_text)

def on_password_change(event=None):
    """ Called when the password changes. Reprocess the text in both boxes if possible. """
    if encrypted_text_entry.get("1.0", tk.END).strip():
        on_encrypted_text_change()
    if decrypted_text_entry.get("1.0", tk.END).strip():
        on_decrypted_text_change()

def generate_random_password(length=16):
    """ Generates a strong random password using the secret's module. """
    characters = string.ascii_letters + string.digits + string.punctuation
    random_seed = datetime.now().strftime('%Y%m%d%H%M%S%f')
    secrets_generator = secrets.SystemRandom(random_seed)
    password = ''.join(secrets_generator.choice(characters) for i in range(length))
    password_entry.delete(0, tk.END)
    password_entry.insert(0, password)
    on_password_change()

def copy_to_clipboard(text_widget):
    """ Copy the content of the text widget to the clipboard. """
    root.clipboard_clear()
    root.clipboard_append(text_widget.get("1.0", tk.END).strip())

def paste_from_clipboard(text_widget):
    """ Paste the content from the clipboard into the text widget. """
    text_widget.delete("1.0", tk.END)
    text_widget.insert(tk.END, root.clipboard_get())

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

# Create the main window
root = tk.Tk()
root.title("Text Encryption/Decryption")

# Set dark gray theme colors
background_color = "#2E2E2E"  # Dark gray background
text_color = "#E0E0E0"        # Light gray text
button_color = "#4E4E4E"      # Medium gray button

# Apply the dark gray theme to the window
root.configure(bg=background_color)

# Create a custom font
custom_font = tkfont.Font(family="Helvetica", size=16)

# Create and place widgets
tk.Label(root, text="Encrypted Text:", bg=background_color, fg=text_color, font=custom_font).pack(pady=10)

encrypted_text_entry = scrolledtext.ScrolledText(root, height=10, width=50, bg="#3A3A3A", fg=text_color, font=custom_font, insertbackground='white')
encrypted_text_entry.pack(pady=5)
encrypted_text_entry.bind("<KeyRelease>", on_encrypted_text_change)  # Reprocess on text change

encrypted_buttons_frame = tk.Frame(root, bg=background_color)
encrypted_buttons_frame.pack(pady=5)

tk.Button(encrypted_buttons_frame, text="Copy", command=lambda: copy_to_clipboard(encrypted_text_entry), bg=button_color, fg=text_color, font=custom_font).pack(side=tk.LEFT, padx=5)
tk.Button(encrypted_buttons_frame, text="Paste", command=lambda: paste_from_clipboard(encrypted_text_entry), bg=button_color, fg=text_color, font=custom_font).pack(side=tk.LEFT, padx=5)

tk.Label(root, text="Decrypted Text:", bg=background_color, fg=text_color, font=custom_font).pack(pady=10)

decrypted_text_entry = scrolledtext.ScrolledText(root, height=10, width=50, bg="#3A3A3A", fg=text_color, font=custom_font, insertbackground='white')
decrypted_text_entry.pack(pady=5)
decrypted_text_entry.bind("<KeyRelease>", on_decrypted_text_change)  # Reprocess on text change

decrypted_buttons_frame = tk.Frame(root, bg=background_color)
decrypted_buttons_frame.pack(pady=5)

tk.Button(decrypted_buttons_frame, text="Copy", command=lambda: copy_to_clipboard(decrypted_text_entry), bg=button_color, fg=text_color, font=custom_font).pack(side=tk.LEFT, padx=5)
tk.Button(decrypted_buttons_frame, text="Paste", command=lambda: paste_from_clipboard(decrypted_text_entry), bg=button_color, fg=text_color, font=custom_font).pack(side=tk.LEFT, padx=5)

tk.Label(root, text="Password:", bg=background_color, fg=text_color, font=custom_font).pack(pady=10)

password_frame = tk.Frame(root, bg=background_color)
password_frame.pack(pady=10)

password_entry = tk.Entry(password_frame, bg="#3A3A3A", fg=text_color, font=custom_font)  # Password is visible
password_entry.pack(side=tk.LEFT, padx=(0, 10))
password_entry.bind("<KeyRelease>", on_password_change)  # Reprocess on password change

# Create a circle indicator next to the password entry
password_indicator = tk.Canvas(password_frame, width=20, height=20, bg=background_color, bd=0, highlightthickness=0)
password_indicator_circle = password_indicator.create_oval(0, 0, 20, 20, fill='red')
password_indicator.pack(side=tk.LEFT)

# Generate Password Button
generate_password_button = tk.Button(root, text="Generate Password", command=generate_random_password, bg=button_color, fg=text_color, font=custom_font)
generate_password_button.pack(pady=20)

# Adjust sizes based on screen size
adjust_to_screen_size()

# Run the application
root.mainloop()

# only this version is compatible with both PC and mobile phones
# this version uses stone key