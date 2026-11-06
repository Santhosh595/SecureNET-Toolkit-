"""Tests for HashDetect detector. No network."""
import hashlib
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from detector import detect_hash, _is_hex, _is_base64

class TestPrimitives:
    def test_is_hex(self):
        assert _is_hex("deadbeef") and _is_hex("ABC123")
        assert not _is_hex("nothex!")
    def test_is_base64(self):
        assert _is_base64("aGVsbG8=")
        assert not _is_base64("ab")  # too short

class TestDetect:
    def test_empty(self):
        r = detect_hash("")
        assert r.error == "Empty input"
    def test_non_hex_error(self):
        r = detect_hash("not-a-hash!!!")
        assert r.error == "Input is not valid hex or base64"
    def test_md5(self):
        md5 = hashlib.md5(b"hello").hexdigest()  # 32 hex chars
        names = {m.name for m in detect_hash(md5).matches}
        assert "MD5" in names
    def test_sha256(self):
        sha = hashlib.sha256(b"hello").hexdigest()  # 64 hex chars
        names = {m.name for m in detect_hash(sha).matches}
        assert "SHA-256" in names
    def test_sha1(self):
        sha1 = hashlib.sha1(b"hello").hexdigest()  # 40 hex chars
        names = {m.name for m in detect_hash(sha1).matches}
        assert "SHA-1" in names
    def test_sha512(self):
        sha512 = hashlib.sha512(b"hello").hexdigest()  # 128 hex chars
        names = {m.name for m in detect_hash(sha512).matches}
        assert "SHA-512" in names
    def test_bcrypt(self):
        # Real bcrypt is 60 chars: $2b$12$ + 53 chars (22-char salt + 31-char hash)
        bc = "$2b$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ12345"
        assert len(bc) == 60
        r = detect_hash(bc)
        assert "bcrypt" in {m.name for m in r.matches}
