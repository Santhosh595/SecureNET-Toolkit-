from flask import Flask, render_template, jsonify
import sqlite3
import time

app = Flask(__name__)

DB_PATH = "packets.db"

def get_latest_packets(limit=20):
    """Fetch latest packets from database."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM packets ORDER BY id DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    return rows

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/data")
def data():
    packets = get_latest_packets()
    data = []
    for pkt in packets:
        data.append({
            "id": pkt[0],
            "timestamp": pkt[1],
            "src": pkt[2],
            "dst": pkt[3],
            "proto": pkt[4],
            "length": pkt[5],
            "flags": pkt[6],
            "alert": pkt[7]
        })
    return jsonify(data)

if __name__ == "__main__":
    print("[+] Starting Flask Dashboard...")
    app.run(host="0.0.0.0", port=5000, debug=True)
