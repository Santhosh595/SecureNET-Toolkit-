"""quick_scan.py — Programmatic async interface for SecureNET tools.

Each quick_scan_* function returns a job_id immediately and runs the tool
in a background thread. Use get_result(job_id) to poll status/results.
"""

import json
import os
import subprocess
import threading
import time
import uuid

# quick_scan.py lives in SecureNET-Control-Panel/, tools live in sibling dirs under the toolkit root
TOOLKIT_ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

TOOL_MODULES = {
    "headerscan": os.path.join(TOOLKIT_ROOT, "HeaderScan", "main.py"),
    "portmap": os.path.join(TOOLKIT_ROOT, "PortMap", "main.py"),
    "hashdetect": os.path.join(TOOLKIT_ROOT, "HashDetect", "main.py"),
    "tlscan": os.path.join(TOOLKIT_ROOT, "TLScan", "main.py"),
    "dnsaudit": os.path.join(TOOLKIT_ROOT, "DNSAudit", "main.py"),
    "subprobe": os.path.join(TOOLKIT_ROOT, "SubProbe", "main.py"),
    "jwtinspect": os.path.join(TOOLKIT_ROOT, "JWTInspect", "main.py"),
    "secretsniff": os.path.join(TOOLKIT_ROOT, "SecretSniff", "main.py"),
}

_jobs = {}
_jobs_lock = threading.Lock()


def _run_tool(job_id, tool_key, args):
    """Run a tool subprocess and store its output in the job dict."""
    script = os.path.normpath(TOOL_MODULES[tool_key])
    workdir = os.path.dirname(script)
    # Use list form + cwd to avoid shell-escaping issues on Windows
    cmd = ["python", script] + args

    with _jobs_lock:
        _jobs[job_id]["status"] = "running"

    try:
        proc = subprocess.run(
            cmd,
            cwd=workdir,
            capture_output=True,
            text=True,
            timeout=300,
            # Avoid inherited stdin/stderr handles that can trigger WinError 267
            stdin=subprocess.DEVNULL,
        )
        with _jobs_lock:
            _jobs[job_id]["status"] = "complete"
            _jobs[job_id]["returncode"] = proc.returncode
            _jobs[job_id]["stdout"] = proc.stdout
            _jobs[job_id]["stderr"] = proc.stderr
            _jobs[job_id]["completed_at"] = time.time()
    except subprocess.TimeoutExpired:
        with _jobs_lock:
            _jobs[job_id]["status"] = "complete"
            _jobs[job_id]["returncode"] = -1
            _jobs[job_id]["stdout"] = ""
            _jobs[job_id]["stderr"] = "Timed out after 300s"
            _jobs[job_id]["completed_at"] = time.time()
    except Exception as e:
        with _jobs_lock:
            _jobs[job_id]["status"] = "complete"
            _jobs[job_id]["returncode"] = -1
            _jobs[job_id]["stdout"] = ""
            _jobs[job_id]["stderr"] = str(e)
            _jobs[job_id]["completed_at"] = time.time()


def _start_job(tool_key, args):
    """Create a job entry and launch the tool in a background thread."""
    job_id = str(uuid.uuid4())[:12]
    with _jobs_lock:
        _jobs[job_id] = {
            "status": "pending",
            "tool": tool_key,
            "args": args,
            "created_at": time.time(),
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "completed_at": None,
        }
    t = threading.Thread(target=_run_tool, args=(job_id, tool_key, args), daemon=True)
    t.start()
    return job_id


def quick_scan_headerscan(url):
    """Start a HeaderScan on a URL. Returns job_id."""
    return _start_job("headerscan", [url, "--json"])


def quick_scan_portmap(host):
    """Start a PortMap scan on a host. Returns job_id."""
    return _start_job("portmap", [host, "--yes"])


def quick_scan_hashdetect(hash_str):
    """Start a HashDetect on a hash string. Returns job_id."""
    return _start_job("hashdetect", [hash_str])


def quick_scan_tlscan(domain):
    """Start a TLScan on a domain. Returns job_id."""
    return _start_job("tlscan", [domain, "--no-disclaimer", "--json"])


def quick_scan_dnsaudit(domain):
    """Start a DNSAudit on a domain. Returns job_id."""
    return _start_job("dnsaudit", [domain, "--json", "--no-disclaimer"])


def quick_scan_subprobe(domain):
    """Start a SubProbe on a domain. Returns job_id."""
    return _start_job("subprobe", [domain, "--no-disclaimer"])


def quick_scan_jwtinspect(token):
    """Start a JWTInspect on a JWT token. Returns job_id."""
    return _start_job("jwtinspect", [token, "--no-disclaimer"])


def quick_scan_secretsniff(path):
    """Start a SecretSniff scan on a path. Returns job_id."""
    return _start_job("secretsniff", ["scan", "--path", path])


def get_result(job_id):
    """Get the status/results for a job.

    Returns a dict with keys: status, tool, stdout, stderr, returncode, created_at, completed_at.
    Status is one of: pending, running, complete.
    """
    with _jobs_lock:
        job = _jobs.get(job_id)
    if job is None:
        return {"status": "not_found", "error": f"No job with id {job_id}"}
    return {
        "status": job["status"],
        "tool": job["tool"],
        "stdout": job["stdout"],
        "stderr": job["stderr"],
        "returncode": job["returncode"],
        "created_at": job["created_at"],
        "completed_at": job["completed_at"],
    }


def list_jobs():
    """Return a summary of all jobs."""
    with _jobs_lock:
        return {
            jid: {"status": j["status"], "tool": j["tool"], "created_at": j["created_at"]}
            for jid, j in _jobs.items()
        }


if __name__ == "__main__":
    # ponytail: minimal self-check, remove when wiring into the dashboard
    print("quick_scan.py — SecureNET async tool runner")
    print(f"Jobs store: {len(_jobs)} jobs")

    # Quick smoke test
    jid = quick_scan_headerscan("https://example.com")
    print(f"Started headerscan job: {jid}")

    for _ in range(30):
        r = get_result(jid)
        if r["status"] == "complete":
            print(f"Job complete. Return code: {r['returncode']}")
            print(r["stdout"][:500] if r["stdout"] else "(no output)")
            break
        time.sleep(1)
    else:
        print("Job did not complete in 30s")
