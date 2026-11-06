"""Tests for DNSAudit scorer. No network."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from scorer import DNSScorer, score_audit, Grade, MAX_RAW_SCORE, NUM_CATEGORIES

class TestGrade:
    def test_boundaries(self):
        cases = {100: "A+", 95: "A+", 94: "A", 85: "A", 84: "B", 70: "B",
                 69: "C", 50: "C", 49: "D", 30: "D", 29: "F", 0: "F"}
        for pct, label in cases.items():
            assert Grade.from_percentage(pct).label == label
    def test_clamped(self):
        assert Grade.from_percentage(-5).label == "F"
        assert Grade.from_percentage(150).label == "A+"

class TestCategoryDeductions:
    def test_critical_deducts_4(self):
        s = DNSScorer("example.com")
        s.add_finding("SPF", "CRITICAL", "Bad SPF")
        assert s.categories["SPF"].final_score == 6.0
    def test_high_deducts_2(self):
        s = DNSScorer("example.com")
        s.add_finding("SPF", "HIGH", "Bad SPF")
        assert s.categories["SPF"].final_score == 8.0
    def test_low_deducts_0(self):
        s = DNSScorer("example.com")
        s.add_finding("SPF", "LOW", "Note")
        assert s.categories["SPF"].final_score == 10.0
    def test_unknown_category_raises(self):
        s = DNSScorer("example.com")
        try:
            s.add_finding("NOPE", "HIGH", "x")
            assert False, "should raise"
        except ValueError:
            pass

class TestCalculate:
    def test_clean_audit_a_plus(self):
        r = DNSScorer("example.com").calculate()
        assert r.grade == "A+" and r.raw_total == MAX_RAW_SCORE
        assert len(r.categories) == NUM_CATEGORIES
    def test_zone_transfer_cap_f(self):
        r = score_audit("example.com", {"Zone Transfer": [
            {"severity": "CRITICAL", "description": "Zone transfer is open"}]})
        assert r.grade == "F"
        assert any("Zone Transfer" in c for c in r.caps_applied)
    def test_no_email_auth_cap_d(self):
        r = score_audit("example.com", {
            "SPF": [{"severity": "HIGH", "description": "No SPF record"}],
            "DKIM": [{"severity": "HIGH", "description": "No DKIM record"}],
            "DMARC": [{"severity": "HIGH", "description": "No DMARC record"}]})
        assert r.grade == "D"
