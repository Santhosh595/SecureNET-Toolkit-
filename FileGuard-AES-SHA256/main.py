"""FileGuard — Secure File Encryption & Integrity Verification.

Provides AES-256 encryption via Fernet and SHA-256 integrity checking
with a Tkinter GUI.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import string
from pathlib import Path
from typing import Optional

import tkinter as tk
from tkinter import filedialog, messagebox

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# --- Constants ---
KEY_DIR = Path("keys")
ENC_DIR = Path("encrypted")
DEC_DIR = Path("decrypted")
HASH_SUFFIX = ".sha256"
ITERATIONS = 480_000


# --- Key Management ---
def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a Fernet-compatible key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def generate_key(password: str) -> bytes:
    """Generate a new encryption key derived from a password.

    Returns the raw Fernet key. The salt is stored alongside the key file.
    """
    salt = secrets.token_bytes(16)
    key = _derive_key(password, salt)
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    key_file = KEY_DIR / "secret.key"
    salt_file = KEY_DIR / "secret.salt"
    key_file.write_bytes(key)
    salt_file.write_bytes(salt)
    return key


def load_key(password: str) -> Optional[bytes]:
    """Load and verify the encryption key using the provided password."""
    key_file = KEY_DIR / "secret.key"
    salt_file = KEY_DIR / "secret.salt"
    if not key_file.exists() or not salt_file.exists():
        return None
    salt = salt_file.read_bytes()
    return _derive_key(password, salt)


def key_exists() -> bool:
    """Check if a key file exists."""
    return (KEY_DIR / "secret.key").exists()


# --- Hashing ---
def compute_file_hash(file_path: str | Path) -> str:
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


# --- Encryption / Decryption ---
def encrypt_file(file_path: str | Path, password: str) -> Optional[Path]:
    """Encrypt a file and save it to the encrypted directory.

    Returns the path to the encrypted file, or None on failure.
    """
    file_path = Path(file_path)
    if not file_path.exists():
        messagebox.showerror("Error", f"File not found: {file_path}")
        return None

    key = load_key(password)
    if key is None:
        messagebox.showerror("Error", "Invalid password or no key found.")
        return None

    fernet = Fernet(key)
    data = file_path.read_bytes()

    try:
        encrypted = fernet.encrypt(data)
    except Exception as exc:
        messagebox.showerror("Error", f"Encryption failed: {exc}")
        return None

    ENC_DIR.mkdir(parents=True, exist_ok=True)
    enc_path = ENC_DIR / f"{file_path.name}.enc"
    enc_path.write_bytes(encrypted)

    # Save hash for integrity verification
    hash_hex = compute_file_hash(file_path)
    hash_path = ENC_DIR / f"{file_path.name}{HASH_SUFFIX}"
    hash_path.write_text(hash_hex)

    return enc_path


def decrypt_file(enc_path: str | Path, password: str) -> Optional[Path]:
    """Decrypt a file and verify its integrity.

    Returns the path to the decrypted file, or None on failure.
    """
    enc_path = Path(enc_path)
    if not enc_path.exists():
        messagebox.showerror("Error", f"File not found: {enc_path}")
        return None

    key = load_key(password)
    if key is None:
        messagebox.showerror("Error", "Invalid password or no key found.")
        return None

    fernet = Fernet(key)

    try:
        decrypted = fernet.decrypt(enc_path.read_bytes())
    except InvalidToken:
        messagebox.showerror("Error", "Decryption failed: invalid key or corrupted file.")
        return None
    except Exception as exc:
        messagebox.showerror("Error", f"Decryption failed: {exc}")
        return None

    DEC_DIR.mkdir(parents=True, exist_ok=True)
    original_name = enc_path.stem  # removes .enc
    dec_path = DEC_DIR / original_name
    dec_path.write_bytes(decrypted)

    # Integrity check
    hash_path = ENC_DIR / f"{original_name}{HASH_SUFFIX}"
    if hash_path.exists():
        saved_hash = hash_path.read_text().strip()
        actual_hash = compute_file_hash(dec_path)
        if actual_hash == saved_hash:
            integrity = "Integrity Check: PASSED"
        else:
            integrity = "Integrity Check: FAILED — file may have been tampered with"
    else:
        integrity = "No saved hash found for verification"

    messagebox.showinfo("Decryption Complete", f"Decrypted file: {dec_path}\n\n{integrity}")
    return dec_path


# --- GUI ---
class FileGuardApp:
    """Main application window for FileGuard."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("FileGuard — AES-256 + SHA-256")
        self.root.geometry("700x400")
        self.root.resizable(False, False)
        self.root.configure(bg="#0f172a")

        self._password: str = ""
        self._file_path: str = ""

        self._build_ui()

    def _build_ui(self) -> None:
        # Title
        tk.Label(
            self.root,
            text="FileGuard — Secure File Encryption",
            bg="#0f172a",
            fg="#e2e8f0",
            font=("Segoe UI", 16, "bold"),
        ).pack(pady=(20, 5))

        tk.Label(
            self.root,
            text="AES-256 Encryption + SHA-256 Integrity Verification",
            bg="#0f172a",
            fg="#64748b",
            font=("Segoe UI", 10),
        ).pack(pady=(0, 20))

        # Password frame
        pw_frame = tk.Frame(self.root, bg="#0f172a")
        pw_frame.pack(pady=5)
        tk.Label(
            pw_frame, text="Password:", bg="#0f172a", fg="#94a3b8",
            font=("Segoe UI", 10),
        ).pack(side="left", padx=5)
        self.pw_entry = tk.Entry(pw_frame, width=40, show="*", bg="#1e293b",
                                  fg="#e2e8f0", insertbackground="#e2e8f0",
                                  relief="flat", font=("Segoe UI", 10))
        self.pw_entry.pack(side="left", padx=5)

        # File selection frame
        file_frame = tk.Frame(self.root, bg="#0f172a")
        file_frame.pack(pady=10)
        tk.Label(
            file_frame, text="File:", bg="#0f172a", fg="#94a3b8",
            font=("Segoe UI", 10),
        ).pack(side="left", padx=5)
        self.path_entry = tk.Entry(file_frame, width=40, bg="#1e293b",
                                    fg="#e2e8f0", insertbackground="#e2e8f0",
                                    relief="flat", font=("Segoe UI", 10))
        self.path_entry.pack(side="left", padx=5)
        tk.Button(
            file_frame, text="Browse", command=self._browse_file,
            bg="#334155", fg="#e2e8f0", relief="flat",
            font=("Segoe UI", 9), padx=10,
        ).pack(side="left", padx=5)

        # Buttons frame
        btn_frame = tk.Frame(self.root, bg="#0f172a")
        btn_frame.pack(pady=25)

        buttons = [
            ("Generate Key", self._handle_generate_key, "#0ea5e9"),
            ("Encrypt File", self._handle_encrypt, "#10b981"),
            ("Decrypt File", self._handle_decrypt, "#f43f5e"),
        ]
        for text, command, color in buttons:
            tk.Button(
                btn_frame, text=text, command=command,
                bg=color, fg="#ffffff", width=16, relief="flat",
                font=("Segoe UI", 10, "bold"), pady=6,
            ).pack(side="left", padx=8)

        # Status
        self.status_label = tk.Label(
            self.root, text="", bg="#0f172a", fg="#64748b",
            font=("Segoe UI", 9),
        )
        self.status_label.pack(pady=10)

        # Footer
        tk.Label(
            self.root,
            text="FileGuard v2.0 | AES-256 + SHA-256 | MIT License",
            bg="#0f172a", fg="#475569", font=("Segoe UI", 8),
        ).pack(side="bottom", pady=10)

    def _get_password(self) -> Optional[str]:
        pw = self.pw_entry.get().strip()
        if not pw:
            messagebox.showwarning("Warning", "Please enter a password.")
            return None
        return pw

    def _browse_file(self) -> None:
        path = filedialog.askopenfilename()
        if path:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, path)

    def _handle_generate_key(self) -> None:
        pw = self._get_password()
        if pw is None:
            return
        generate_key(pw)
        self.status_label.configure(text="Key generated and saved to keys/secret.key")
        messagebox.showinfo("Key Generated",
                            "New encryption key derived and saved.\n"
                            "Store your password safely — it cannot be recovered.")

    def _handle_encrypt(self) -> None:
        pw = self._get_password()
        if pw is None:
            return
        path = self.path_entry.get().strip()
        if not path or not Path(path).exists():
            messagebox.showwarning("Warning", "Please select a valid file first.")
            return
        result = encrypt_file(path, pw)
        if result:
            self.status_label.configure(text=f"Encrypted: {result}")
            messagebox.showinfo("Encryption Complete",
                                f"File encrypted successfully.\n\nSaved to: {result}")

    def _handle_decrypt(self) -> None:
        pw = self._get_password()
        if pw is None:
            return
        path = self.path_entry.get().strip()
        if not path or not Path(path).exists():
            messagebox.showwarning("Warning", "Please select a valid .enc file.")
            return
        decrypt_file(path, pw)


# --- Entry Point ---
def main() -> None:
    root = tk.Tk()
    app = FileGuardApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
