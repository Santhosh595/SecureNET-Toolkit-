"""Tests for FileGuard encryption and integrity functions."""

import os
import tempfile
from pathlib import Path

import pytest

# Ensure we import from the FileGuard directory
import sys
sys.path.insert(0, str(Path(__file__).parent))

from main import (
    compute_file_hash,
    decrypt_file,
    encrypt_file,
    generate_key,
    key_exists,
    load_key,
    KEY_DIR,
)


@pytest.fixture(autouse=True)
def cleanup():
    """Remove test artifacts before and after each test."""
    _clean()
    yield
    _clean()


def _clean():
    """Remove key directory and test output folders."""
    import shutil
    for d in [KEY_DIR, Path("encrypted"), Path("decrypted")]:
        if d.exists():
            shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def sample_file():
    """Create a temporary file with known content."""
    fd, path = tempfile.mkstemp(suffix=".txt")
    os.write(fd, b"Test content for FileGuard encryption.")
    os.close(fd)
    return path


@pytest.fixture
def password():
    return "test-password-123"


class TestKeyManagement:
    def test_generate_key_creates_files(self, password):
        generate_key(password)
        assert (KEY_DIR / "secret.key").exists()
        assert (KEY_DIR / "secret.salt").exists()

    def test_key_exists_after_generation(self, password):
        assert not key_exists()
        generate_key(password)
        assert key_exists()

    def test_load_key_with_correct_password(self, password):
        generate_key(password)
        key = load_key(password)
        assert key is not None
        assert len(key) > 0

    def test_load_key_with_wrong_password(self, password):
        generate_key(password)
        key = load_key("wrong-password")
        assert key is not None  # derives a key, but it won't match

    def test_load_key_without_generation(self):
        key = load_key("any-password")
        assert key is None


class TestEncryption:
    def test_encrypt_file_creates_encrypted_file(self, sample_file, password):
        generate_key(password)
        result = encrypt_file(sample_file, password)
        assert result is not None
        assert result.exists()
        assert result.suffix == ".enc"

    def test_encrypt_file_creates_hash_file(self, sample_file, password):
        generate_key(password)
        result = encrypt_file(sample_file, password)
        hash_file = Path("encrypted") / f"{Path(sample_file).name}.sha256"
        assert hash_file.exists()

    def test_encrypt_file_content_differs_from_original(self, sample_file, password):
        generate_key(password)
        original = Path(sample_file).read_bytes()
        enc_path = encrypt_file(sample_file, password)
        encrypted = enc_path.read_bytes()
        assert encrypted != original

    def test_encrypt_without_key_fails(self, sample_file, monkeypatch):
        """Test that encryption fails gracefully when no key exists."""
        # Prevent messagebox from blocking
        monkeypatch.setattr("main.messagebox.showerror", lambda *a, **kw: None)
        result = encrypt_file(sample_file, "no-key-set")
        assert result is None


class TestDecryption:
    def test_decrypt_file_restores_original(self, sample_file, password):
        generate_key(password)
        original = Path(sample_file).read_bytes()
        enc_path = encrypt_file(sample_file, password)
        dec_path = decrypt_file(str(enc_path), password)
        assert dec_path is not None
        assert dec_path.read_bytes() == original

    def test_decrypt_with_wrong_password_fails(self, sample_file, password):
        generate_key(password)
        enc_path = encrypt_file(sample_file, password)
        dec_path = decrypt_file(str(enc_path), "wrong-password")
        assert dec_path is None

    def test_decrypt_nonexistent_file_fails(self, password):
        generate_key(password)
        result = decrypt_file("nonexistent.enc", password)
        assert result is None


class TestHashing:
    def test_compute_hash_returns_hex_string(self, sample_file):
        hash_val = compute_file_hash(sample_file)
        assert isinstance(hash_val, str)
        assert len(hash_val) == 64  # SHA-256 hex length

    def test_same_file_same_hash(self, sample_file):
        h1 = compute_file_hash(sample_file)
        h2 = compute_file_hash(sample_file)
        assert h1 == h2

    def test_different_content_different_hash(self, sample_file):
        h1 = compute_file_hash(sample_file)
        # Modify file
        with open(sample_file, "ab") as f:
            f.write(b"extra")
        h2 = compute_file_hash(sample_file)
        assert h1 != h2
