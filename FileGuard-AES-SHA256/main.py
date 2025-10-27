import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import os
import hashlib

# === CRYPTO & HASH FUNCTIONS ===
def load_key():
    if not os.path.exists("secret.key"):
        messagebox.showwarning("Missing Key", "No key file found! Please generate a new one.")
        return None
    return open("secret.key", "rb").read()

def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    messagebox.showinfo("Key Generated", "New encryption key saved as secret.key")

def compute_file_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def encrypt_file(file_path):
    key = load_key()
    if key is None:
        return
    fernet = Fernet(key)

    with open(file_path, "rb") as file:
        original = file.read()

    encrypted = fernet.encrypt(original)

    if not os.path.exists("encrypted"):
        os.makedirs("encrypted")

    enc_path = f"encrypted/{os.path.basename(file_path)}.enc"
    with open(enc_path, "wb") as encrypted_file:
        encrypted_file.write(encrypted)

    # Save original hash for verification
    hash_hex = compute_file_hash(file_path)
    hash_path = f"encrypted/{os.path.basename(file_path)}.sha256"
    with open(hash_path, "w") as hf:
        hf.write(hash_hex)

    messagebox.showinfo(
        "Encryption Complete",
        f"File encrypted successfully!\n\nEncrypted file:\n{enc_path}\n\nSHA256 saved:\n{hash_path}"
    )

def decrypt_file(enc_path):
    key = load_key()
    if key is None:
        return
    fernet = Fernet(key)

    with open(enc_path, "rb") as enc_file:
        encrypted = enc_file.read()

    decrypted = fernet.decrypt(encrypted)

    if not os.path.exists("decrypted"):
        os.makedirs("decrypted")

    dec_path = f"decrypted/{os.path.basename(enc_path).replace('.enc', '')}"
    with open(dec_path, "wb") as dec_file:
        dec_file.write(decrypted)

    # Integrity check
    saved_hash_path = f"encrypted/{os.path.basename(dec_path)}.sha256"
    result_msg = f"Decrypted file saved:\n{dec_path}\n\n"

    if os.path.exists(saved_hash_path):
        saved_hash = open(saved_hash_path, "r").read().strip()
        dec_hash = compute_file_hash(dec_path)
        if dec_hash == saved_hash:
            result_msg += "✅ Integrity Check: PASSED"
        else:
            result_msg += "❌ Integrity Check: FAILED"
    else:
        result_msg += "ℹ️ No saved hash found for verification"

    messagebox.showinfo("Decryption Complete", result_msg)

# === GUI FUNCTIONS ===
def browse_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        entry_path.delete(0, tk.END)
        entry_path.insert(0, file_path)

def handle_encrypt():
    path = entry_path.get()
    if path and os.path.exists(path):
        encrypt_file(path)
    else:
        messagebox.showwarning("Warning", "Please select a valid file first!")

def handle_decrypt():
    path = entry_path.get()
    if path and os.path.exists(path):
        decrypt_file(path)
    else:
        messagebox.showwarning("Warning", "Please select a valid .enc file!")

# === MAIN WINDOW ===
root = tk.Tk()
root.title("🔐 Secure File Storage System (AES + SHA256)")
root.geometry("650x320")
root.resizable(False, False)
root.configure(bg="#1e1e1e")

# Title
tk.Label(root, text="Secure File Storage System (AES + SHA256)",
         bg="#1e1e1e", fg="white", font=("Arial", 14, "bold")).pack(pady=10)

# File selection entry
entry_path = tk.Entry(root, width=60)
entry_path.pack(pady=10)
tk.Button(root, text="Browse File", command=browse_file,
          bg="#3a3a3a", fg="white").pack(pady=5)

# Action buttons
frame = tk.Frame(root, bg="#1e1e1e")
frame.pack(pady=20)

tk.Button(frame, text="Generate Key", command=generate_key,
          bg="#4169E1", fg="white", width=18).grid(row=0, column=0, padx=10)

tk.Button(frame, text="Encrypt File", command=handle_encrypt,
          bg="#2e8b57", fg="white", width=18).grid(row=0, column=1, padx=10)

tk.Button(frame, text="Decrypt File", command=handle_decrypt,
          bg="#b22222", fg="white", width=18).grid(row=0, column=2, padx=10)

# Footer
tk.Label(root,
         text="Built by DID | AES-256 Encryption + SHA-256 Integrity Verification",
         bg="#1e1e1e", fg="gray", font=("Arial", 9)).pack(side="bottom", pady=10)

root.mainloop()
