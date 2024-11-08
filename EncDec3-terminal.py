import os
import base64
import random
import string
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import time

KEY_CONFIGS = {
    1: {"salt_length": 16, "iterations": 100000, "description": "Basic encryption, fast but less secure."},
    2: {"salt_length": 32, "iterations": 200000, "description": "Good for personal files, moderate security."},
    3: {"salt_length": 32, "iterations": 300000, "description": "Suitable for sensitive documents, strong security."},
    4: {"salt_length": 32, "iterations": 400000, "description": "High security, recommended for confidential data."},
    5: {"salt_length": 32, "iterations": 500000, "description": "Better for long-term secure storage."},
    6: {"salt_length": 64, "iterations": 800000, "description": "Best for highly sensitive information."},
    7: {"salt_length": 64, "iterations": 1000000, "description": "Excellent for critical data with top-level security."},
    8: {"salt_length": 64, "iterations": 1200000, "description": "Very high security, slower encryption."},
    9: {"salt_length": 128, "iterations": 1500000, "description": "Maximum security, slow but extremely secure."},
    10: {"salt_length": 256, "iterations": 2000000, "description": "Ultimate security, best for long-term encryption."},
}

def show_help():
    print("\nKey Strength Information:")
    for strength, config in KEY_CONFIGS.items():
        print(f"{strength}: {config['description']}")
    print("Choose the same key strength for both encryption and decryption.\n")

def generate_random_password(length: int = 12) -> str:
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for i in range(length))

def derive_key(password: str, salt: bytes, strength: int) -> bytes:
    config = KEY_CONFIGS[strength]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=config['iterations'],
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_text(plain_text: str, password: str, strength: int) -> str:
    config = KEY_CONFIGS[strength]
    salt = os.urandom(config['salt_length'])
    key = derive_key(password, salt, strength)
    cipher = Fernet(key)
    encrypted_text = cipher.encrypt(plain_text.encode())
    return base64.urlsafe_b64encode(salt + encrypted_text).decode()

def decrypt_text(encrypted_text: str, password: str, strength: int) -> str:
    try:
        encrypted_text_bytes = base64.urlsafe_b64decode(encrypted_text.encode())
        config = KEY_CONFIGS[strength]
        salt_length = config['salt_length']
        salt = encrypted_text_bytes[:salt_length]
        encrypted_text = encrypted_text_bytes[salt_length:]
        key = derive_key(password, salt, strength)
        cipher = Fernet(key)
        decrypted_text = cipher.decrypt(encrypted_text)
        return decrypted_text.decode()
    except Exception:
        return "Decryption failed. Please check the password and key strength."

def encrypt_file(file_path: str, password: str, strength: int):
    config = KEY_CONFIGS[strength]
    salt = os.urandom(config['salt_length'])
    with open(file_path, "rb") as f:
        data = f.read()

    key = derive_key(password, salt, strength)
    cipher = Fernet(key)
    encrypted_data = cipher.encrypt(data)

    with open(file_path + ".enc", "wb") as f:
        f.write(salt + encrypted_data)

    print("File encryption successful.")

def decrypt_file(file_path: str, password: str, strength: int):
    try:
        with open(file_path, "rb") as f:
            encrypted_data = f.read()

        config = KEY_CONFIGS[strength]
        salt_length = config['salt_length']
        salt = encrypted_data[:salt_length]
        encrypted_data = encrypted_data[salt_length:]

        key = derive_key(password, salt, strength)
        cipher = Fernet(key)
        decrypted_data = cipher.decrypt(encrypted_data)

        with open(file_path.replace(".enc", ""), "wb") as f:
            f.write(decrypted_data)

        print("File decryption successful.")
    except Exception:
        print("File decryption failed. Please check the password and key strength.")

def main():
    while True:
        print("\nChoose an option:")
        print("1. Encrypt a text")
        print("2. Decrypt a text")
        print("3. Encrypt a file")
        print("4. Decrypt a file")
        print("5. Exit")
        choice = input("Enter your choice (1-5): ")

        if choice == "5":
            print("Exiting...")
            break

        password_input = input("Enter password or 'r' for a random password: ")

        if password_input.lower() == 'r':
            password = generate_random_password()
            print(f"Randomly generated password: {password}")
        else:
            password = password_input

        # Ask for key strength
        print("\nChoose key strength between 1 to 10 (for more info enter 'help')")
        strength_input = input("Enter key strength: ")

        if strength_input.lower() == 'help':
            show_help()
            strength = int(input("Choose key strength (1-10): "))
        else:
            strength = int(strength_input)

        if choice == "1":
            plain_text = input("Enter the text to encrypt: ")
            start_time = time.time()
            encrypted = encrypt_text(plain_text, password, strength)
            end_time = time.time()
            print(f"Encrypted Text: {encrypted}")
            print(f"Encryption took {end_time - start_time:.2f} seconds.")
        elif choice == "2":
            encrypted_text = input("Enter the text to decrypt: ")
            start_time = time.time()
            decrypted = decrypt_text(encrypted_text, password, strength)
            end_time = time.time()
            print(f"Decrypted Text: {decrypted}")
            print(f"Decryption took {end_time - start_time:.2f} seconds.")
        elif choice == "3":
            file_path = input("Enter the file path to encrypt: ")
            start_time = time.time()
            encrypt_file(file_path, password, strength)
            end_time = time.time()
            print(f"File encryption took {end_time - start_time:.2f} seconds.")
        elif choice == "4":
            file_path = input("Enter the file path to decrypt: ")
            start_time = time.time()
            decrypt_file(file_path, password, strength)
            end_time = time.time()
            print(f"File decryption took {end_time - start_time:.2f} seconds.")
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()


""" to run trough terminal:
    python {your_script_name}.py
"""
