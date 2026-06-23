"""Tests for Network Sniffer database and detection modules."""

import os
import sqlite3
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import sys
sys.path.insert(0, str(Path(__file__).parent))

import db
import detector2


@pytest.fixture(autouse=True)
def cleanup():
    """Remove test database before and after each test."""
    _clean()
    yield
    _clean()


def _clean():
    if Path("packets.db").exists():
        os.remove("packets.db")
    if Path("logs").exists():
        import shutil
        shutil.rmtree("logs", ignore_errors=True)


class TestDatabase:
    def test_init_db_creates_tables(self):
        db.init_db()
        conn = sqlite3.connect("packets.db")
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cur.fetchall()}
        conn.close()
        assert "packets" in tables
        assert "alerts" in tables

    def test_insert_and_retrieve_packet(self):
        db.init_db()
        row_id = db.insert_packet(
            ts=time.time(), src="10.0.0.1", dst="10.0.0.2",
            proto="TCP", sport=12345, dport=80, length=64, flags="SYN"
        )
        assert row_id == 1

        packets = db.get_latest_packets(limit=10)
        assert len(packets) == 1
        assert packets[0]["src"] == "10.0.0.1"
        assert packets[0]["dport"] == 80

    def test_insert_and_retrieve_alert(self):
        db.init_db()
        row_id = db.insert_alert("PORT_SCAN", "10.0.0.1", '{"unique_ports": 15}')
        assert row_id == 1

        alerts = db.get_alerts(limit=10)
        assert len(alerts) == 1
        assert alerts[0]["rule"] == "PORT_SCAN"

    def test_count_packets(self):
        db.init_db()
        assert db.count_packets() == 0
        db.insert_packet(time.time(), "1.1.1.1", "2.2.2.2", "TCP", 80, 443, 64, "")
        db.insert_packet(time.time(), "1.1.1.1", "2.2.2.2", "UDP", 53, 53, 32, "")
        assert db.count_packets() == 2

    def test_count_alerts(self):
        db.init_db()
        assert db.count_alerts() == 0
        db.insert_alert("TEST", "1.1.1.1")
        assert db.count_alerts() == 1

    def test_get_recent_packets_filters_by_time(self):
        db.init_db()
        old_ts = time.time() - 30
        new_ts = time.time()
        db.insert_packet(old_ts, "1.1.1.1", "2.2.2.2", "TCP", 80, 443, 64, "")
        db.insert_packet(new_ts, "3.3.3.3", "4.4.4.4", "UDP", 53, 53, 32, "")

        recent = db.get_recent_packets(seconds=10)
        assert len(recent) == 1
        assert recent[0]["src"] == "3.3.3.3"

    def test_get_latest_packets_ordering(self):
        db.init_db()
        for i in range(5):
            db.insert_packet(time.time() + i, f"10.0.0.{i}", "dst", "TCP", 80, 443, 64, "")

        packets = db.get_latest_packets(limit=3)
        assert len(packets) == 3
        # Should be newest first
        assert packets[0]["src"] == "10.0.0.4"
        assert packets[2]["src"] == "10.0.0.2"


class TestDetector:
    def _make_db_mock(self, rows):
        mock = MagicMock()
        mock.get_recent_packets.return_value = rows
        return mock

    def test_no_alert_on_normal_traffic(self):
        rows = [
            (time.time(), "10.0.0.1", "10.0.0.2", "TCP", 12345, 80, 64, "SYN"),
            (time.time(), "10.0.0.1", "10.0.0.2", "TCP", 12346, 443, 64, "SYN"),
        ]
        mock_db = self._make_db_mock(rows)
        alerts = detector2.detect_port_scan(mock_db)
        assert len(alerts) == 0

    def test_port_scan_detected(self):
        rows = []
        for port in range(80, 95):
            rows.append((time.time(), "10.0.0.1", "10.0.0.2", "TCP", 12345, port, 64, "SYN"))
        mock_db = self._make_db_mock(rows)
        alerts = detector2.detect_port_scan(mock_db)
        assert len(alerts) == 1
        assert alerts[0][0] == "PORT_SCAN"
        assert alerts[0][1] == "10.0.0.1"

    def test_high_rate_detected(self):
        rows = []
        for i in range(60):
            rows.append((time.time(), "10.0.0.1", "10.0.0.2", "TCP", 12345 + i, 80, 64, "SYN"))
        mock_db = self._make_db_mock(rows)
        alerts = detector2.detect_high_rate(mock_db)
        assert len(alerts) == 1
        assert alerts[0][0] == "HIGH_RATE"

    def test_alert_cooldown_suppresses_duplicates(self):
        detector2.reset_cooldowns()
        rows = []
        for port in range(80, 95):
            rows.append((time.time(), "10.0.0.1", "10.0.0.2", "TCP", 12345, port, 64, "SYN"))
        mock_db = self._make_db_mock(rows)
        # First call should alert
        alerts1 = detector2.detect_port_scan(mock_db)
        assert len(alerts1) == 1
        # Second call should be suppressed by cooldown
        alerts2 = detector2.detect_port_scan(mock_db)
        assert len(alerts2) == 0
