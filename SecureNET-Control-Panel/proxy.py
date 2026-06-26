from flask import Blueprint, request, Response
import requests

proxy_bp = Blueprint("proxy", __name__)

# ponytail: flat dict, add tools as needed
TOOL_PORTS = {
    "nmap": 4567,
    "wireshark": 4568,
    "snort": 4569,
    "nessus": 4570,
    "openvas": 4571,
    "metasploit": 4572,
    "burpsuite": 4573,
    "nikto": 4574,
    "clamav": 4575,
}


@proxy_bp.route("/proxy/<tool>/<path:path>", methods=["GET", "POST"])
def proxy(tool, path):
    port = TOOL_PORTS.get(tool)
    if port is None:
        return Response(f"Unknown tool: {tool}", status=404)

    url = f"http://127.0.0.1:{port}/{path}"
    headers = {k: v for k, v in request.headers if k.lower() != "host"}
    headers["X-Forwarded-For"] = request.remote_addr

    try:
        if request.method == "GET":
            resp = requests.get(url, headers=headers, params=request.args, timeout=5)
        else:
            resp = requests.post(url, headers=headers, data=request.get_data(), timeout=5)
    except requests.ConnectionError:
        return Response(f"{tool} is not running", status=502)
    except requests.Timeout:
        return Response(f"{tool} timed out", status=504)

    excluded = {"content-encoding", "transfer-encoding", "content-length"}
    resp_headers = {k: v for k, v in resp.headers.items() if k.lower() not in excluded}
    return Response(resp.content, status=resp.status_code, headers=resp_headers)
