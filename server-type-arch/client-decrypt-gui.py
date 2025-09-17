import os
import sys
import requests
import tkinter as tk
import platform
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

SERVER_URL = "https://qlvtkhpjazvwfnqzoqjr.supabase.co/functions/v1/verify-password"

# ----- Crypto -----
def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=100000, backend=default_backend()
    )
    return kdf.derive(password.encode())

def decrypt_file(fp: str, password: str):
    with open(fp, "rb") as f:
        salt, iv, enc = f.read(16), f.read(16), f.read()
    key = generate_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor().update(enc) + cipher.decryptor().finalize()
    unpad = padding.PKCS7(128).unpadder()
    data = unpad.update(dec) + unpad.finalize()
    open(fp, "wb").write(data)

def decrypt_directory(path: str, password: str):
    for root, _, files in os.walk(path):
        for f in files:
            if f == ".encrypted_flag": continue
            try:
                decrypt_file(os.path.join(root, f), password)
                print(f"[✓] Decrypted: {f}")
            except Exception as e:
                print(f"[!] Failed {f}: {e}")
    flag = os.path.join(path, ".encrypted_flag")
    if os.path.exists(flag): os.remove(flag)

# ----- Tkinter password prompt -----
def ask_for_password():
    user_password = None
    def on_submit():
        nonlocal user_password
        user_password = entry.get()
        window.destroy()

    window = tk.Tk()
    window.title("Enter Decryption Password")
    tk.Label(window, text="Enter Password:").pack(pady=10)
    entry = tk.Entry(window, show="*"); entry.pack(pady=5)
    tk.Button(window, text="Submit", command=on_submit).pack(pady=20)
    window.mainloop()
    return user_password

# ----- Remote check -----
def verify_password(user_id: str, password: str) -> bool:
    r = requests.post(SERVER_URL, json={"user_id": user_id, "password": password})
    r.raise_for_status()
    return r.json().get("valid", False)

# ----- Main -----
if __name__ == "__main__":
    user_id = platform.nodename  # or use same `get_or_create_user_id` logic
    print(f"User ID: {user_id}")

    desktop = os.path.join(os.path.expanduser("~"), "Desktop")
    target_folder = os.path.join(desktop, "personal_Fa0337")
    if not os.path.exists(target_folder):
        print("Folder not found.")
        sys.exit(1)

    if not os.path.exists(os.path.join(target_folder, ".encrypted_flag")):
        print("No encrypted files found.")
        sys.exit(1)

    pw = ask_for_password()
    if not pw:
        print("No password entered.")
        sys.exit(1)

    print("Verifying password with server...")
    if verify_password(user_id, pw):
        decrypt_directory(target_folder, pw)
        print("✅ Decryption complete.")
    else:
        print("❌ Invalid password.")
        sys.exit(1)
