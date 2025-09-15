import os
import sys
import platform
from dotenv import load_dotenv
from supabase import create_client, Client
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import tkinter as tk
from tkinter import messagebox

# Load environment variables
load_dotenv()
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Generate key from password and salt
def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Get user ID (same logic as in encryption)
def get_user_id():
    id_file = os.path.expanduser("~/.user_id")
    if os.path.exists(id_file):
        with open(id_file, "r") as f:
            return f.read().strip()
    else:
        print("[ERROR] User ID file not found. You must run the encryption script first.")
        sys.exit(1)

# Get password from Supabase
def get_user_password(user_id: str) -> str:
    result = supabase.table("encryption_keys").select("*").eq("user_id", user_id).execute()
    if not result.data:
        print("[ERROR] No password found for this user in Supabase.")
        sys.exit(1)
    return result.data[0]["password"]

# Validate password using first file
def validate_password(file_path: str, password: str) -> bool:
    try:
        with open(file_path, 'rb') as f:
            salt = f.read(16)
            iv = f.read(16)
            encrypted_data = f.read()

        key = generate_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Try unpadding
        unpadder = padding.PKCS7(128).unpadder()
        _ = unpadder.update(decrypted_data) + unpadder.finalize()

        return True
    except Exception:
        return False

# Decrypt a single file
def decrypt_file(file_path: str, password: str):
    with open(file_path, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        encrypted_data = f.read()

    key = generate_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    original_data = unpadder.update(decrypted_data) + unpadder.finalize()

    with open(file_path, 'wb') as dec_file:
        dec_file.write(original_data)

# Recursively decrypt a folder
def decrypt_directory(directory_path: str, password: str):
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                decrypt_file(file_path, password)
                print(f"[✓] Decrypted: {file_path}")
            except Exception as e:
                print(f"[!] Failed to decrypt {file_path}: {e}")

# if __name__ == "__main__":
#     user_id = get_user_id()
#     print(f"Using User ID: {user_id}")
#     # If Automatic Supabase password extraction
#     # password = get_user_password(user_id)

#     # If password asking
#     password = input("Enter the decryption password: ").strip()
	

#     directory_to_decrypt = input("Enter the directory path to decrypt: ").strip()

#     # Pick first file to validate password
#     first_file = None
#     for root, _, files in os.walk(directory_to_decrypt):
#         if files:
#             first_file = os.path.join(root, files[0])
#             break

#     if not first_file:
#         print("No files found in the directory.")
#         sys.exit(1)

#     if not validate_password(first_file, password):
#         print("[ERROR] Decryption password is invalid.")
#         sys.exit(1)

#     decrypt_directory(directory_to_decrypt, password)
#     print("✅ Decryption complete.")


# ---------- Main Script ----------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("[ERROR] No password provided. Please provide a password to validate.")
        sys.exit(1)

    password = sys.argv[1]
    print(f"Validating password: {password}")

    # Validate the password by checking a sample file
    directory_to_decrypt = "personal_Fa0337"
    first_file = None
    for root, _, files in os.walk(directory_to_decrypt):
        if files:
            first_file = os.path.join(root, files[0])
            break
        if not first_file:
            print("[ERROR] No files found in the directory.")
            sys.exit(1)

        # Validate password by attempting to decrypt a file in the directory
        try:
            with open(first_file, 'rb') as f:
                salt = f.read(16)
                iv = f.read(16)
                encrypted_data = f.read()

            # Generate key from the provided password
            key = generate_key(password, salt)

            # Try to decrypt the file
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

            # Try unpadding
            unpadder = padding.PKCS7(128).unpadder()
            _ = unpadder.update(decrypted_data) + unpadder.finalize()

            # If it reaches here, the password is correct
            print("Password is valid. Starting decryption...")

            # Proceed with decrypting the entire directory
            decrypt_directory(directory_to_decrypt, password)
            print("✅ Decryption complete.")
        
        except Exception as e:
            print(f"[ERROR] Invalid password or decryption failed: {e}")
            sys.exit(1)