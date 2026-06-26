"""Background health monitor for SecureNET Control Panel tools."""

import threading
import time
import logging
import requests
from datetime import datetime, timedelta

import database
from process_manager import ProcessManager

logger = logging.getLogger(__name__)

# ponytail: constants at module level, no config object for values that don't change
HEALTH_CHECK_INTERVAL = 5
RESTART_THRESHOLD_MS = 30_000
RESTART_BACKOFF = 30
HISTORY_WINDOW_HOURS = 24
STATUS_URL = "http://127.0.0.1:{port}/status"


class HealthMonitor:
    """Pings all managed tools, logs health, auto-restarts dead ones."""

    def __init__(self, process_manager: ProcessManager | None = None):
        self.pm = process_manager or ProcessManager()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        # ponytail: dict of tool_name -> list of (timestamp, ok_bool); 24h window pruned on read
        self.health_history: dict[str, list[tuple[str, bool]]] = {}
        self._restart_timers: dict[str, float] = {}  # tool_name -> deadline timestamp
        self._lock = threading.Lock()

    def _record(self, tool_name: str, ok: bool):
        with self._lock:
            if tool_name not in self.health_history:
                self.health_history[tool_name] = []
            self.health_history[tool_name].append((datetime.utcnow().isoformat(), ok))

    def _prune_history(self):
        cutoff = (datetime.utcnow() - timedelta(hours=HISTORY_WINDOW_HOURS)).isoformat()
        with self._lock:
            for name in self.health_history:
                self.health_history[name] = [
                    (ts, ok) for ts, ok in self.health_history[name] if ts >= cutoff
                ]

    def _check_tool(self, name: str, port: int):
        url = STATUS_URL.format(port=port)
        start = time.monotonic()
        try:
            resp = requests.get(url, timeout=3)
            elapsed_ms = int((time.monotonic() - start) * 1000)
            ok = resp.status_code == 200
            database.log_health_alert(name, "ok" if ok else "error", response_time_ms=elapsed_ms)
            database.save_tool_status(name, "active" if ok else "error", port=port)
            self._record(name, ok)
            if not ok:
                logger.warning(f"{name} returned {resp.status_code} ({elapsed_ms}ms)")
        except requests.RequestException:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            database.log_health_alert(name, "critical", response_time_ms=elapsed_ms)
            database.save_tool_status(name, "down", port=port)
            self._record(name, False)
            logger.error(f"{name} unreachable (port {port})")
            self._schedule_restart(name)

    def _schedule_restart(self, name: str):
        with self._lock:
            if name in self._restart_timers:
                return  # already scheduled
            self._restart_timers[name] = time.monotonic() + RESTART_BACKOFF
            logger.info(f"Auto-restart scheduled for '{name}' in {RESTART_BACKOFF}s")

    def _process_restart_timers(self):
        now = time.monotonic()
        with self._lock:
            ready = [n for n, deadline in self._restart_timers.items() if now >= deadline]
        for name in ready:
            with self._lock:
                self._restart_timers.pop(name, None)
            logger.info(f"Auto-restarting '{name}'")
            self.pm.restart_tool(name)

    def _loop(self):
        while not self._stop_event.is_set():
            statuses = self.pm.get_all_statuses()
            for name, alive in statuses.items():
                if not alive:
                    continue
                info = getattr(self.pm, '_tool_info', {}).get(name)
                if not info:
                    continue
                self._check_tool(name, info['port'])
            self._process_restart_timers()
            self._prune_history()
            self._stop_event.wait(HEALTH_CHECK_INTERVAL)

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="health-monitor")
        self._thread.start()
        logger.info("Health monitor started")

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10)
            self._thread = None
        logger.info("Health monitor stopped")

    def get_uptime_percentage(self, tool_name: str) -> float:
        """Return uptime % over the last 24h window for a tool."""
        with self._lock:
            entries = self.health_history.get(tool_name, [])
        if not entries:
            return 0.0
        cutoff = (datetime.utcnow() - timedelta(hours=HISTORY_WINDOW_HOURS)).isoformat()
        window = [(ts, ok) for ts, ok in entries if ts >= cutoff]
        if not window:
            return 0.0
        up = sum(1 for _, ok in window if ok)
        return round((up / len(window)) * 100, 2)


# ponytail: minimal self-check, not a test framework
if __name__ == "__main__":
    database.init_db()
    pm = ProcessManager(log_dir="logs")
    monitor = HealthMonitor(pm)
    monitor.start()
    time.sleep(15)
    for name in pm.get_all_statuses():
        print(f"{name}: {monitor.get_uptime_percentage(name)}%")
    monitor.stop()
    print("OK")
