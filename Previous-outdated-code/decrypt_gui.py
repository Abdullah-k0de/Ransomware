import os
import tkinter as tk
from tkinter import messagebox
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv

# Load .env for Supabase (if needed)
load_dotenv()

# ---------- Crypto Helper ----------
def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

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

        unpadder = padding.PKCS7(128).unpadder()
        _ = unpadder.update(decrypted_data) + unpadder.finalize()
        return True
    except Exception:
        return False

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

def decrypt_directory(directory_path: str, password: str):
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                decrypt_file(file_path, password)
                print(f"[✓] Decrypted: {file_path}")
            except Exception as e:
                print(f"[!] Failed to decrypt {file_path}: {e}")

    encrypted_flag = os.path.join(directory_path, ".encrypted_flag")
    if os.path.exists(encrypted_flag):
        os.remove(encrypted_flag)
        print("[*] Encryption flag removed.")

def ask_for_password():
    user_password = None

    def on_submit():
        nonlocal user_password
        user_password = password_entry.get()
        window.destroy()

    window = tk.Tk()
    window.title("Enter Decryption Password")
    window.geometry("300x150")

    tk.Label(window, text="Enter Password:").pack(pady=10)
    password_entry = tk.Entry(window, show="*")
    password_entry.pack(pady=5)

    submit_button = tk.Button(window, text="Submit", command=on_submit)
    submit_button.pack(pady=20)

    window.mainloop()
    return user_password

# ---------- Main Script ----------
if __name__ == "__main__":
    # Search for personal_Fa0337 folder on Desktop
    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
    target_folder = None
    for root, dirs, _ in os.walk(desktop_path):
        if "personal_Fa0337" in dirs:
            target_folder = os.path.join(root, "personal_Fa0337")
            break

    if not target_folder:
        print("Folder 'personal_Fa0337' not found.")
        sys.exit(1)

    # Check if files are encrypted
    encrypted_flag_path = os.path.join(target_folder, ".encrypted_flag")
    if not os.path.exists(encrypted_flag_path):
        print("No encrypted files found in personal_Fa0337.")
        sys.exit(1)

    # Get password from user
    print("Password is required to decrypt the files.")
    user_password = ask_for_password()

    if not user_password:
        print("No password entered. Exiting...")
        sys.exit(1)

    print("Decryption password entered:", user_password)

    # Find first file to validate password
    first_file = None
    for root, _, files in os.walk(target_folder):
        if files:
            first_file = os.path.join(root, files[0])
            break

    if not first_file:
        print("[ERROR] No files found in the directory.")
        sys.exit(1)

    # Validate and decrypt
    if validate_password(first_file, user_password):
        decrypt_directory(target_folder, user_password)
        print("✅ Decryption complete.")
    else:
        print("[ERROR] Invalid password. Nice try.")
        sys.exit(1)