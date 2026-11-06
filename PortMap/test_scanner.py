"""Tests for PortMap scanner maps. No sockets, no network."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from scanner import SERVICE_MAP, RISK_MAP, PORT_PROFILES, RiskLevel, get_service_name, get_risk, is_private_ip

class TestMaps:
    def test_known_services(self):
        assert get_service_name(22) == "SSH"
        assert get_service_name(80) == "HTTP"
        assert get_service_name(443) == "HTTPS"
    def test_unknown_service(self):
        assert get_service_name(59999) == "Unknown"
    def test_risk_high_ports(self):
        for p in [21, 23, 69, 445, 3306, 6379]:
            lvl, _ = get_risk(p)
            assert lvl == RiskLevel.HIGH
    def test_risk_low_ports(self):
        for p in [22, 53, 443]:
            lvl, _ = get_risk(p)
            assert lvl == RiskLevel.LOW
    def test_risk_unknown_port_medium(self):
        lvl, _ = get_risk(59999)
        assert lvl == RiskLevel.MEDIUM
    def test_profiles(self):
        assert 22 in PORT_PROFILES["quick"]
        assert PORT_PROFILES["full"] == list(range(1, 1025))

class TestPrivateIP:
    def test_private(self):
        assert is_private_ip("10.0.0.1") and is_private_ip("192.168.1.1")
    def test_public(self):
        assert not is_private_ip("8.8.8.8")
    def test_invalid(self):
        assert is_private_ip("not-an-ip") is False
