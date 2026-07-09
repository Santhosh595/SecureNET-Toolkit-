"""SecureNET Control Panel - Main Hub

Central orchestration hub for all SecureNET tools.
Run: python hub.py
"""

from __future__ import annotations

import atexit
import os
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

import yaml
from flask import Flask, jsonify, render_template, request

# Local imports
sys.path.insert(0, str(Path(__file__).parent))
from database import init_db, save_tool_status, log_health_alert, save_alert, save_scan_log
from database import get_recent_alerts, get_scan_history, get_stats, update_setting, get_all_settings
from process_manager import ProcessManager
from health_monitor import HealthMonitor
from alert_aggregator import AlertAggregator
from quick_scan import (quick_scan_headerscan, quick_scan_portmap, quick_scan_hashdetect,
                         quick_scan_tlscan, quick_scan_dnsaudit, quick_scan_subprobe,
                         quick_scan_jwtinspect, quick_scan_secretsniff, quick_scan_vulnprobe,
                         get_result)

# Load config
CONFIG_PATH = Path(__file__).parent / "securenet.yaml"
config = {}
if CONFIG_PATH.exists():
    with open(CONFIG_PATH) as f:
        config = yaml.safe_load(f)

settings = config.get("settings", {})
tools_config = config.get("tools", {})

app = Flask(__name__)
app.config["SECRET_KEY"] = "securenet-hub-" + datetime.now().strftime("%Y%m%d")

# Global managers
process_manager = ProcessManager(str(Path(__file__).parent / "logs"))
health_monitor = HealthMonitor(process_manager)
alert_aggregator = AlertAggregator()

# Track start time for uptime
START_TIME = time.time()


@app.before_request
def startup():
    """Initialize subsystems on first request (idempotent)."""
    if not getattr(app, '_initialized', False):
        try:
            init_db()
            save_tool_status("hub", "running", settings.get("hub_port", 5000))
            health_monitor.start()
            alert_aggregator.start()
            app._initialized = True
        except Exception as e:
            print(f"[WARN] Startup init failed: {e}")
        print("[OK] Control panel subsystems initialized")


@app.teardown_appcontext
def shutdown(exception=None):
    """Cleanup on shutdown."""
    pass


def cleanup_all():
    """Graceful shutdown of all subprocesses."""
    health_monitor.stop()
    alert_aggregator.stop()
    process_manager.cleanup_all()
    save_tool_status("hub", "stopped", settings.get("hub_port", 5000))


atexit.register(cleanup_all)


# === Page Routes ===

PAGE_TEMPLATES = {
    "command": "command_center.html",
    "analytics": "analytics.html",
    "alerts": "alerts.html",
    "history": "history.html",
    "tools": "tools_manager.html",
    "docs": "docs.html",
}


def render_page(template_name):
    return render_template(template_name, settings=settings, tools=tools_config)


@app.route("/")
def index():
    return render_page("command_center.html")


@app.route("/command")
def command_center():
    return render_page("command_center.html")


@app.route("/analytics")
def analytics():
    return render_page("analytics.html")


@app.route("/alerts")
def alerts():
    return render_page("alerts.html")


@app.route("/history")
def history():
    return render_page("history.html")


@app.route("/tools")
def tools_manager():
    return render_page("tools_manager.html")


@app.route("/docs")
def docs():
    return render_page("docs.html")


# === API Routes ===

@app.route("/api/status")
def api_status():
    """Get status of all tools."""
    statuses = process_manager.get_all_statuses()
    for tool_key, tool_config in tools_config.items():
        if tool_key not in statuses:
            port = tool_config.get("port", 0)
            statuses[tool_key] = {
                "name": tool_config.get("name", tool_key),
                "status": "STOPPED",
                "port": port,
                "color": tool_config.get("color", "#64748b"),
                "enabled": tool_config.get("enabled", True),
            }
    return jsonify({"tools": statuses, "hub_uptime": int(time.time() - START_TIME)})


@app.route("/api/status/<tool>")
def api_status_tool(tool):
    """Get status of a single tool."""
    status = process_manager.get_status(tool)
    if not status:
        return jsonify({"error": f"Unknown tool: {tool}"}), 404
    return jsonify(status)


@app.route("/api/start/<tool>", methods=["POST"])
def api_start(tool):
    """Start a tool subprocess."""
    result = process_manager.start_tool(tool)
    if result:
        save_tool_status(tool, "running", tools_config.get(tool, {}).get("port", 0))
        return jsonify({"status": "started", "tool": tool})
    return jsonify({"error": "Failed to start tool"}), 500


@app.route("/api/stop/<tool>", methods=["POST"])
def api_stop(tool):
    """Stop a tool subprocess."""
    result = process_manager.stop_tool(tool)
    if result:
        save_tool_status(tool, "stopped", tools_config.get(tool, {}).get("port", 0))
        return jsonify({"status": "stopped", "tool": tool})
    return jsonify({"error": "Failed to stop tool"}), 500


@app.route("/api/restart/<tool>", methods=["POST"])
def api_restart(tool):
    """Restart a tool subprocess."""
    result = process_manager.restart_tool(tool)
    if result:
        save_tool_status(tool, "running", tools_config.get(tool, {}).get("port", 0))
        return jsonify({"status": "restarted", "tool": tool})
    return jsonify({"error": "Failed to restart tool"}), 500


@app.route("/api/alerts")
def api_alerts():
    """Get unified alerts."""
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    severity = request.args.get("severity", None)
    tool = request.args.get("tool", None)

    alerts = alert_aggregator.get_unified_alerts()
    if severity:
        alerts = [a for a in alerts if a.get("severity") == severity]
    if tool:
        alerts = [a for a in alerts if a.get("tool") == tool]

    total = len(alerts)
    start = (page - 1) * per_page
    end = start + per_page
    alerts_paginated = alerts[start:end]

    return jsonify({"alerts": alerts_paginated, "total": total, "page": page, "per_page": per_page})


@app.route("/api/alerts/acknowledge", methods=["POST"])
def api_acknowledge_alerts():
    """Acknowledge alerts."""
    data = request.get_json()
    ids = data.get("ids", [])
    return jsonify({"acknowledged": len(ids)})


@app.route("/api/stats")
def api_stats():
    """Get global analytics data."""
    stats = get_stats()
    stats["active_scans"] = 0
    stats["alerts_today"] = len([a for a in alert_aggregator.get_unified_alerts()
                                  if a.get("timestamp", "").startswith(datetime.now().strftime("%Y-%m-%d"))])
    stats["running_tools"] = sum(1 for s in process_manager.get_all_statuses().values()
                                  if s.get("status") == "running")
    stats["total_tools"] = len(tools_config)
    return jsonify(stats)


@app.route("/api/history")
def api_history():
    """Get unified scan history."""
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    history = get_scan_history(limit=per_page, offset=(page - 1) * per_page)
    return jsonify({"history": history, "page": page, "per_page": per_page})


@app.route("/api/health")
def api_health():
    """Hub health check."""
    return jsonify({
        "status": "healthy",
        "uptime_seconds": int(time.time() - START_TIME),
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "timestamp": datetime.now().isoformat(),
    })


@app.route("/api/tools")
def api_tools():
    """Get tool configuration list."""
    return jsonify({"tools": tools_config, "settings": settings})


@app.route("/api/settings", methods=["POST"])
def api_settings():
    """Update settings."""
    data = request.get_json()
    for key, value in data.items():
        update_setting(key, str(value))
    return jsonify({"status": "updated", "settings": get_all_settings()})


@app.route("/api/logs/<tool>")
def api_logs(tool):
    """Get last 100 log lines for a tool."""
    log_path = Path(__file__).parent / "logs" / f"{tool}.log"
    if not log_path.exists():
        return jsonify({"logs": []})
    lines = log_path.read_text().split("\n")[-100:]
    return jsonify({"logs": lines})


# === Quick Scan API ===

@app.route("/api/quickscan/headerscan", methods=["POST"])
def quickscan_headerscan():
    data = request.get_json()
    url = data.get("url", "")
    job_id = quick_scan_headerscan(url)
    return jsonify({"job_id": job_id, "status": "pending"})


@app.route("/api/quickscan/portmap", methods=["POST"])
def quickscan_portmap():
    data = request.get_json()
    host = data.get("host", "")
    job_id = quick_scan_portmap(host)
    return jsonify({"job_id": job_id, "status": "pending"})


@app.route("/api/quickscan/hashdetect", methods=["POST"])
def quickscan_hashdetect():
    data = request.get_json()
    hash_str = data.get("hash", "")
    job_id = quick_scan_hashdetect(hash_str)
    return jsonify({"job_id": job_id, "status": "pending"})


@app.route("/api/quickscan/tlscan", methods=["POST"])
def quickscan_tlscan():
    data = request.get_json()
    domain = data.get("domain", "")
    job_id = quick_scan_tlscan(domain)
    return jsonify({"job_id": job_id, "status": "pending"})


@app.route("/api/quickscan/dnsaudit", methods=["POST"])
def quickscan_dnsaudit():
    data = request.get_json()
    domain = data.get("domain", "")
    job_id = quick_scan_dnsaudit(domain)
    return jsonify({"job_id": job_id, "status": "pending"})


@app.route("/api/quickscan/subprobe", methods=["POST"])
def quickscan_subprobe():
    data = request.get_json()
    domain = data.get("domain", "")
    job_id = quick_scan_subprobe(domain)
    return jsonify({"job_id": job_id, "status": "pending"})


@app.route("/api/quickscan/jwtinspect", methods=["POST"])
def quickscan_jwtinspect():
    data = request.get_json()
    token = data.get("token", "")
    job_id = quick_scan_jwtinspect(token)
    return jsonify({"job_id": job_id, "status": "pending"})


@app.route("/api/quickscan/secretsniff", methods=["POST"])
def quickscan_secretsniff():
    data = request.get_json()
    path = data.get("path", "")
    job_id = quick_scan_secretsniff(path)
    return jsonify({"job_id": job_id, "status": "pending"})


@app.route("/api/quickscan/vulnprobe", methods=["POST"])
def quickscan_vulnprobe():
    data = request.get_json()
    url = data.get("url", "")
    severity = data.get("severity", "HIGH,CRITICAL")
    job_id = quick_scan_vulnprobe(url, severity)
    return jsonify({"job_id": job_id, "status": "pending"})


@app.route("/api/quickscan/result/<job_id>")
def quickscan_result(job_id):
    result = get_result(job_id)
    return jsonify(result)


# === Proxy Route ===

@app.route("/proxy/<tool>/", defaults={"path": ""})
@app.route("/proxy/<tool>/<path:path>")
def proxy(tool, path):
    """Proxy requests to tool dashboards."""
    import requests as req
    tool_config = tools_config.get(tool)
    if not tool_config:
        return jsonify({"error": "Unknown tool"}), 404
    port = tool_config.get("port")
    url = f"http://127.0.0.1:{port}/{path}"
    try:
        resp = req.request(
            method=request.method,
            url=url,
            headers={k: v for k, v in request.headers if k.lower() != "host"},
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            timeout=30,
        )
        excluded_headers = ["content-encoding", "content-length", "transfer-encoding", "connection"]
        headers = [(k, v) for k, v in resp.raw.headers.items() if k.lower() not in excluded_headers]
        return resp.content, resp.status_code, headers
    except req.exceptions.ConnectionError:
        return jsonify({"error": f"{tool} is not running on port {port}"}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# === Main ===

def main():
    """Run the control panel."""
    hub_port = settings.get("hub_port", 5000)
    bind = settings.get("bind_address", "127.0.0.1")

    if bind != "127.0.0.1":
        print("[WARN] Binding to non-localhost is not recommended!")
        print("[WARN] Tool communication is localhost-only.")

    print("=" * 50)
    print("  SecureNET Control Panel")
    print(f"  http://{bind}:{hub_port}")
    print("=" * 50)

    # Initialize database
    init_db()

    app.run(host=bind, port=hub_port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
