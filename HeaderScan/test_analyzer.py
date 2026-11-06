"""Tests for HeaderScan pure checkers and scoring. No network."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from analyzer import (
    HEADER_WEIGHTS, TOTAL_WEIGHT, RiskLevel, Grade,
    _check_hsts, _check_csp, _check_x_frame_options,
    _check_x_content_type_options, _check_referrer_policy,
    _check_permissions_policy, _check_xss_protection,
    _check_cache_control, _check_set_cookie, _check_server_header,
    _normalize_url, _compute_grade,
)

class TestWeights:
    def test_weights_sum_100(self):
        assert TOTAL_WEIGHT == 100
        assert sum(HEADER_WEIGHTS.values()) == 100

class TestHSTS:
    def test_missing_is_critical(self):
        r = _check_hsts({})
        assert (r.present, r.risk) == (False, RiskLevel.CRITICAL.value)
    def test_short_max_age_warning(self):
        r = _check_hsts({"Strict-Transport-Security": "max-age=3600"})
        assert r.risk == RiskLevel.WARNING.value
    def test_long_max_age_safe(self):
        r = _check_hsts({"Strict-Transport-Security": "max-age=63072000; includeSubDomains"})
        assert r.risk == RiskLevel.SAFE.value

class TestCSP:
    def test_missing_critical(self):
        assert _check_csp({}).risk == RiskLevel.CRITICAL.value
    def test_unsafe_inline_warning(self):
        r = _check_csp({"Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'"})
        assert r.risk == RiskLevel.WARNING.value
    def test_strict_csp_safe(self):
        r = _check_csp({"Content-Security-Policy": "default-src 'self'"})
        assert r.risk == RiskLevel.SAFE.value

class TestFrameAndNosniffReferrer:
    def test_frame_deny_safe(self):
        assert _check_x_frame_options({"X-Frame-Options": "DENY"}).risk == RiskLevel.SAFE.value
    def test_frame_missing_critical(self):
        assert _check_x_frame_options({}).risk == RiskLevel.CRITICAL.value
    def test_nosniff_safe(self):
        assert _check_x_content_type_options({"X-Content-Type-Options": "nosniff"}).risk == RiskLevel.SAFE.value
    def test_nosniff_missing_warning(self):
        assert _check_x_content_type_options({}).risk == RiskLevel.WARNING.value
    def test_referrer_safe_values(self):
        for v in ["no-referrer", "strict-origin-when-cross-origin", "same-origin", "origin"]:
            assert _check_referrer_policy({"Referrer-Policy": v}).risk == RiskLevel.SAFE.value
    def test_permissions_missing_warning(self):
        assert _check_permissions_policy({}).risk == RiskLevel.WARNING.value
    def test_permissions_present_safe(self):
        r = _check_permissions_policy({"Permissions-Policy": "camera=(), microphone=()"})
        assert r.risk == RiskLevel.SAFE.value
    def test_xss_zero_safe(self):
        assert _check_xss_protection({"X-XSS-Protection": "0"}).risk == RiskLevel.SAFE.value

class TestCacheCookieServer:
    def test_cache_no_store_safe(self):
        assert _check_cache_control({"Cache-Control": "no-store"}).risk == RiskLevel.SAFE.value
    def test_cookie_missing_flags_critical(self):
        r = _check_set_cookie({"Set-Cookie": "sid=1"})
        assert r.risk == RiskLevel.CRITICAL.value
    def test_cookie_secure_safe(self):
        r = _check_set_cookie({"Set-Cookie": "sid=1; Secure; HttpOnly; SameSite=Strict"})
        assert r.risk == RiskLevel.SAFE.value
    def test_server_version_leak_warning(self):
        r = _check_server_header({"Server": "Apache/2.4.1"})
        assert r.risk == RiskLevel.WARNING.value
    def test_server_absent_safe(self):
        assert _check_server_header({}).risk == RiskLevel.SAFE.value

class TestGradeAndUrl:
    def test_grades(self):
        assert (_compute_grade(95), _compute_grade(80), _compute_grade(60), _compute_grade(10)) == (
            Grade.A, Grade.B, Grade.C, Grade.F)
    def test_boundary_grades(self):
        assert (_compute_grade(90), _compute_grade(75), _compute_grade(50), _compute_grade(49)) == (
            Grade.A, Grade.B, Grade.C, Grade.F)
    def test_normalize_url(self):
        assert _normalize_url("example.com") == "https://example.com"
        assert _normalize_url("https://example.com/x") == "https://example.com/x"
