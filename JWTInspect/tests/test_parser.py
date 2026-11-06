"""Tests for JWTInspect parser. No network."""
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from parser import parse_jwt, forge_token, _base64url_decode, _base64url_encode, _normalize_token, format_timestamp, format_duration

def make_token(payload, header=None, **kw):
    h = header or {"alg": "HS256", "typ": "JWT"}
    return forge_token(h, payload, secret=kw.get("secret", "s3cr3t"), algorithm=kw.get("alg", "HS256"))

class TestBase64:
    def test_roundtrip(self):
        assert _base64url_decode(_base64url_encode(b"hi")) == b"hi"
    def test_strips_padding_equals(self):
        enc = _base64url_encode(b"hello")
        assert "=" not in enc
    def test_decode_unpadded(self):
        # "hi" -> aGk (unpadded) decodes back
        assert _base64url_decode("aGk") == b"hi"

class TestNormalize:
    def test_bearer_prefix(self):
        assert _normalize_token("Bearer abc.def.ghi") == "abc.def.ghi"
    def test_whitespace(self):
        assert _normalize_token("  abc  ") == "abc"

class TestParse:
    def test_valid_token(self):
        now = int(time.time())
        tok = make_token({"sub": "u1", "exp": now + 3600, "iat": now})
        p = parse_jwt(tok)
        assert p.errors == []
        assert p.algorithm == "HS256"
        assert p.claims.sub == "u1"
        assert p.is_expired is False
        assert p.is_valid_time is True
    def test_expired_token(self):
        now = int(time.time())
        tok = make_token({"sub": "u1", "exp": now - 10})
        p = parse_jwt(tok)
        assert p.is_expired is True
        assert p.is_valid_time is False
        assert p.expires_in is not None and p.expires_in < 0
    def test_alg_none(self):
        tok = forge_token({"alg": "none"}, {"sub": "u1"}, algorithm="none")
        p = parse_jwt(tok)
        assert p.algorithm == "none"
    def test_malformed_too_few_parts(self):
        p = parse_jwt("not-a-jwt")
        assert p.algorithm == "UNKNOWN"
        assert p.errors and "Invalid JWT format" in p.errors[0]
    def test_garbage_header_errors(self):
        p = parse_jwt("!!!.!!!.xxx")
        assert p.errors
    def test_bearer_prefix_parses(self):
        now = int(time.time())
        tok = make_token({"sub": "u2", "exp": now + 60})
        assert parse_jwt("Bearer " + tok).claims.sub == "u2"

class TestFormat:
    def test_timestamp_utc(self):
        s = format_timestamp(0)
        assert "1970-01-01" in s and "UTC" in s
    def test_duration(self):
        assert format_duration(None) == "N/A"
        assert format_duration(30) == "30s"
        assert format_duration(90) == "1.5m"
