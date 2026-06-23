"""ARPWatch — Scapy ARP packet capture.

Sniffs ARP packets on the local network and feeds them to the detector.
"""

from __future__ import annotations

import threading
import time
from typing import Callable, Optional

from scapy.all import sniff, ARP, Ether, conf

from detector import ARPDetector, Alert


class ARPSniffer:
    """Captures ARP packets and runs them through the detector."""

    def __init__(
        self,
        detector: ARPDetector,
        iface: Optional[str] = None,
        on_alert: Optional[Callable[[Alert], None]] = None,
        on_packet: Optional[Callable[[str, str, str, int], None]] = None,
    ):
        """
        Args:
            detector: ARPDetector instance for analysis.
            iface: Network interface (None = auto-detect).
            on_alert: Callback when an alert is triggered.
            on_packet: Callback for every ARP packet (src_ip, src_mac, dst_ip, op).
        """
        self.detector = detector
        self.iface = iface
        self.on_alert = on_alert
        self.on_packet = on_packet
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._packet_count = 0
        self._alert_count = 0
        self._start_time: Optional[float] = None

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def packet_count(self) -> int:
        return self._packet_count

    @property
    def alert_count(self) -> int:
        return self._alert_count

    @property
    def uptime(self) -> float:
        if self._start_time is None:
            return 0.0
        return time.time() - self._start_time

    def _process_packet(self, pkt) -> None:
        """Process a single captured ARP packet."""
        if not pkt.haslayer(ARP):
            return

        arp = pkt[ARP]
        src_ip = arp.psrc
        src_mac = arp.hwsrc.lower()
        dst_ip = arp.pdst
        op = arp.op  # 1=request, 2=reply

        self._packet_count += 1

        # Callback for every packet
        if self.on_packet:
            self.on_packet(src_ip, src_mac, dst_ip, op)

        # Run detection
        alerts = self.detector.analyze(src_ip, src_mac, dst_ip, op)

        for alert in alerts:
            self._alert_count += 1
            if self.on_alert:
                self.on_alert(alert)

    def _sniff_loop(self) -> None:
        """Main sniffing loop (runs in thread)."""
        try:
            sniff(
                filter="arp",
                prn=self._process_packet,
                iface=self.iface,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except Exception as e:
            if self._running:
                print(f"[ARPWatch] Sniff error: {e}")

    def start(self) -> None:
        """Start sniffing in a background thread."""
        if self._running:
            return
        self._running = True
        self._start_time = time.time()
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop sniffing."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
