import subprocess
import sys
import threading
import logging
import os
import time

# ponytail: stdlib only, no psutil dependency for process management

class ProcessManager:
    def __init__(self, log_dir="logs"):
        self.processes = {}
        self._tool_info = {}
        self.lock = threading.Lock()
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        
        logging.basicConfig(
            filename=os.path.join(log_dir, "startup.log"),
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s"
        )
        self.logger = logging.getLogger(__name__)

    def start_tool(self, name, path, port):
        with self.lock:
            if name in self.processes and self.processes[name].poll() is None:
                self.logger.warning(f"Tool '{name}' already running (PID {self.processes[name].pid})")
                return False

            dashboard_path = os.path.join(path, "dashboard.py")
            if not os.path.exists(dashboard_path):
                self.logger.error(f"dashboard.py not found at {dashboard_path}")
                return False

            try:
                proc = subprocess.Popen(
                    [sys.executable, "dashboard.py"],
                    cwd=path,
                    env={**os.environ, "TOOL_PORT": str(port), "TOOL_NAME": name},
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                self.processes[name] = proc
                self._tool_info[name] = {"path": path, "port": port}
                self.logger.info(f"Started '{name}' (PID {proc.pid}) on port {port}")
                return True
            except Exception as e:
                self.logger.error(f"Failed to start '{name}': {e}")
                return False

    def stop_tool(self, name):
        with self.lock:
            proc = self.processes.get(name)
            if proc is None:
                self.logger.warning(f"Tool '{name}' not found in process list")
                return False
            if proc.poll() is not None:
                self.logger.info(f"Tool '{name}' already stopped")
                del self.processes[name]
                return True

            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
            del self.processes[name]
            self._tool_info.pop(name, None)
            self.logger.info(f"Stopped '{name}' (PID {proc.pid})")
            return True

    def restart_tool(self, name):
        with self.lock:
            proc = self.processes.get(name)
            if proc is None:
                self.logger.warning(f"Cannot restart '{name}': not running")
                return False
            # ponytail: we don't store path/port, caller must re-start with same args
            # For restart, we need to retrieve stored info - storing minimal metadata
            info = getattr(self, '_tool_info', {}).get(name)
            if not info:
                self.logger.error(f"Cannot restart '{name}': no stored path/port info")
                return False

        self.stop_tool(name)
        time.sleep(0.5)
        return self.start_tool(name, info['path'], info['port'])

    def get_status(self, name):
        with self.lock:
            proc = self.processes.get(name)
            if proc is None:
                return False
            return proc.poll() is None

    def get_all_statuses(self):
        with self.lock:
            return {name: proc.poll() is None for name, proc in self.processes.items()}

    def cleanup_all(self):
        with self.lock:
            names = list(self.processes.keys())
        for name in names:
            self.stop_tool(name)
        self.logger.info("All processes cleaned up")
