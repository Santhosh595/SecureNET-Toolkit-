"""ARPWatch — ARP spoofing detection rules.

Implements 4 detection rules:
1. MAC Mismatch — known IP seen with different MAC
2. Gratuitous ARP — self-announcement from unknown MAC
3. ARP Flood — >50 packets from one MAC in 10s
4. Gateway Spoof — gateway IP seen with different MAC
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Alert:
    """Represents a detection alert."""
    timestamp: float
    alert_type: str       # MAC_MISMATCH / GRATUITOUS_ARP / ARP_FLOOD / GATEWAY_SPOOF
    severity: str         # INFO / WARNING / CRITICAL
    ip: str
    expected_mac: str
    seen_mac: str
    verdict: str          # SAFE / SUSPICIOUS / SPOOFED
    details: str = ""


@dataclass
class _PacketStats:
    """Track per-MAC packet counts for flood detection."""
    count: int = 0
    window_start: float = 0.0


class ARPDetector:
    """ARP spoofing detector with 4 detection rules."""

    # Flood threshold: packets per window
    FLOOD_THRESHOLD = 50
    FLOOD_WINDOW = 10.0  # seconds

    # Cooldown: suppress same alert type for same IP
    COOLDOWN = 60.0  # seconds

    def __init__(self, gateway_ip: Optional[str] = None):
        self.gateway_ip = gateway_ip
        self.baseline: dict[str, str] = {}  # ip -> mac
        self._mac_stats: dict[str, _PacketStats] = defaultdict(_PacketStats)
        self._last_alert: dict[str, float] = {}  # "type:ip" -> timestamp

    def set_baseline(self, baseline: dict[str, str]) -> None:
        """Set the trusted baseline."""
        self.baseline = baseline

    def set_gateway(self, gateway_ip: str) -> None:
        """Set the gateway IP for gateway spoof detection."""
        self.gateway_ip = gateway_ip

    def _is_cooldown(self, alert_type: str, ip: str) -> bool:
        """Check if an alert for this type+IP is in cooldown."""
        key = f"{alert_type}:{ip}"
        last = self._last_alert.get(key, 0)
        return (time.time() - last) < self.COOLDOWN

    def _record_alert(self, alert_type: str, ip: str) -> None:
        """Record an alert timestamp for cooldown."""
        key = f"{alert_type}:{ip}"
        self._last_alert[key] = time.time()

    def _check_mac_mismatch(self, src_ip: str, src_mac: str) -> Optional[Alert]:
        """Rule 1: Check if IP is known but MAC differs."""
        if src_ip in self.baseline:
            expected = self.baseline[src_ip]
            if src_mac != expected:
                if self._is_cooldown("MAC_MISMATCH", src_ip):
                    return None
                self._record_alert("MAC_MISMATCH", src_ip)
                return Alert(
                    timestamp=time.time(),
                    alert_type="MAC_MISMATCH",
                    severity="WARNING",
                    ip=src_ip,
                    expected_mac=expected,
                    seen_mac=src_mac,
                    verdict="SPOOFED",
                    details=f"IP {src_ip} changed from {expected} to {src_mac}",
                )
        return None

    def _check_gratuitous_arp(self, src_ip: str, src_mac: str,
                                dst_ip: str, op: int) -> Optional[Alert]:
        """Rule 2: Detect gratuitous ARP (sender IP = target IP, op=2 reply)."""
        # op=2 is reply, op=1 is request
        if op == 2 and src_ip == dst_ip:
            # Gratuitous ARP: only alert if MAC is not in baseline
            if src_ip not in self.baseline:
                if self._is_cooldown("GRATUITOUS_ARP", src_ip):
                    return None
                self._record_alert("GRATUITOUS_ARP", src_ip)
                return Alert(
                    timestamp=time.time(),
                    alert_type="GRATUITOUS_ARP",
                    severity="WARNING",
                    ip=src_ip,
                    expected_mac="N/A",
                    seen_mac=src_mac,
                    verdict="SUSPICIOUS",
                    details=f"Gratuitous ARP from unknown MAC for {src_ip}",
                )
        return None

    def _check_arp_flood(self, src_mac: str) -> Optional[Alert]:
        """Rule 3: Detect ARP flood (>50 packets from one MAC in 10s)."""
        now = time.time()
        stats = self._mac_stats[src_mac]

        # Reset window if expired
        if now - stats.window_start > self.FLOOD_WINDOW:
            stats.count = 0
            stats.window_start = now

        stats.count += 1

        if stats.count == self.FLOOD_THRESHOLD:
            if self._is_cooldown("ARP_FLOOD", src_mac):
                return None
            self._record_alert("ARP_FLOOD", src_mac)
            return Alert(
                timestamp=time.time(),
                alert_type="ARP_FLOOD",
                severity="WARNING",
                ip="multiple",
                expected_mac="N/A",
                seen_mac=src_mac,
                verdict="SUSPICIOUS",
                details=f"{stats.count} ARP packets from {src_mac} in {self.FLOOD_WINDOW}s",
            )
        return None

    def _check_gateway_spoof(self, src_ip: str, src_mac: str) -> Optional[Alert]:
        """Rule 4: Detect gateway IP being used by different MAC."""
        if self.gateway_ip and src_ip == self.gateway_ip:
            if src_ip in self.baseline:
                expected = self.baseline[src_ip]
                if src_mac != expected:
                    if self._is_cooldown("GATEWAY_SPOOF", src_ip):
                        return None
                    self._record_alert("GATEWAY_SPOOF", src_ip)
                    return Alert(
                        timestamp=time.time(),
                        alert_type="GATEWAY_SPOOF",
                        severity="CRITICAL",
                        ip=src_ip,
                        expected_mac=expected,
                        seen_mac=src_mac,
                        verdict="SPOOFED",
                        details=f"Gateway {src_ip} MAC changed from {expected} to {src_mac}",
                    )
        return None

    def analyze(self, src_ip: str, src_mac: str,
                dst_ip: str, op: int) -> list[Alert]:
        """Run all detection rules on an ARP packet.

        Args:
            src_ip: Sender IP (ARP protocol).
            src_mac: Sender MAC.
            dst_ip: Target IP.
            op: ARP operation (1=request, 2=reply).

        Returns:
            List of alerts (may be empty).
        """
        alerts: list[Alert] = []

        # Normalize MAC to lowercase
        src_mac = src_mac.lower()

        # Rule 4: Gateway spoof (highest priority)
        alert = self._check_gateway_spoof(src_ip, src_mac)
        if alert:
            alerts.append(alert)

        # Rule 1: MAC mismatch
        alert = self._check_mac_mismatch(src_ip, src_mac)
        if alert:
            alerts.append(alert)

        # Rule 2: Gratuitous ARP
        alert = self._check_gratuitous_arp(src_ip, src_mac, dst_ip, op)
        if alert:
            alerts.append(alert)

        # Rule 3: ARP flood
        alert = self._check_arp_flood(src_mac)
        if alert:
            alerts.append(alert)

        return alerts
