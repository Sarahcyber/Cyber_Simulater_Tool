"""
app.py — Flask Web Dashboard
Serves the UI, receives simulation requests, streams live logs via SSE,
and implements auto-block mitigation when thresholds are exceeded.
"""
import threading
import queue
import time
from flask import Flask, render_template, request, Response, jsonify
from simulator import run_port_scan, run_icmp_flood
app = Flask(__name__)

# ── Shared state ─────────────────────────────────────────────
# Queue used to pass log messages from simulator thread → SSE stream
log_queue = queue.Queue()

total_request_count = 0

REQUEST_THRESHOLD = 50

BLOCKED_IPS_FILE = "blocked_ips.txt"

# ── Mitigation: Auto-Block ────────────────────────────────────
def auto_block_ip(target_ip):
    """
    Simulated auto-block: writes the offending IP to blocked_ips.txt.

    """
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    block_entry = f"{timestamp} | BLOCKED: {target_ip}\n"

    with open(BLOCKED_IPS_FILE, "a") as blocked_file:
        blocked_file.write(block_entry)

    log_queue.put(f"[BLOCK] {target_ip} exceeded threshold — added to blocked_ips.txt")
    log_queue.put(f"[BLOCK] Entry: {block_entry.strip()}")

# ── SSE Stream ───────────────────────────────────────────────
def generate_log_stream():
    """
    Generator function for Server-Sent Events (SSE).
    Continuously reads from log_queue and yields each message
    to the browser in the SSE format: "data: <message>\n\n"
    """
    while True:
        try:
            log_message = log_queue.get(timeout=30)  
            yield f"data: {log_message}\n\n"  
        except queue.Empty:
            # send heartbeat to keep connection alive

            yield "data: [HEARTBEAT] Connection alive...\n\n"

# ── Flask Routes ─────────────────────────────────────────────
@app.route("/")
def index():
    """Serve the main dashboard page."""
    return render_template("index.html")

@app.route("/stream")
def stream():
    """SSE endpoint — browser connects here to receive live logs."""
    return Response(generate_log_stream(), mimetype="text/event-stream")

@app.route("/start_scan", methods=["POST"])
def start_scan():
    """
    Receive scan parameters from the dashboard form.
    Runs the port scan in a background thread so the UI stays responsive.
    """
    global total_request_count
 
    target_ip  = request.form.get("target_ip",  "127.0.0.1")
    start_port = int(request.form.get("start_port", 1))
    end_port   = int(request.form.get("end_port",   100))
 
    total_request_count += (end_port - start_port + 1)
 
   
    if total_request_count > REQUEST_THRESHOLD:
        auto_block_ip(target_ip)
        return jsonify({"status": "blocked", "ip": target_ip})
 
    
    scan_thread = threading.Thread(
        target=run_port_scan,
        args=(target_ip, start_port, end_port, log_queue),
        daemon=True
    )
    scan_thread.start()
 
    return jsonify({"status": "started", "target": target_ip})

@app.route("/start_flood", methods=["POST"])
def start_flood():
    """
    Receive flood parameters from the dashboard form.
    Runs the ICMP flood in a background thread.
    """
    global total_request_count
 
    target_ip    = request.form.get("target_ip", "127.0.0.1")
    packet_count = int(request.form.get("packet_count", 50))
 
    total_request_count += packet_count
 
    # Check threshold — auto-block if exceeded
    if total_request_count > REQUEST_THRESHOLD:
        auto_block_ip(target_ip)
        return jsonify({"status": "blocked", "ip": target_ip})
 
    flood_thread = threading.Thread(
        target=run_icmp_flood,
        args=(target_ip, packet_count, log_queue),
        daemon=True
    )
    flood_thread.start()
 
    return jsonify({"status": "started", "target": target_ip})
 


@app.route("/get_blocked")
def get_blocked():
    """Return the contents of blocked_ips.txt as JSON."""
    try:
        with open(BLOCKED_IPS_FILE, "r") as blocked_file:
            blocked_entries = blocked_file.readlines()
        return jsonify({"blocked": blocked_entries})
    except FileNotFoundError:
        return jsonify({"blocked": []})
 
 
if __name__ == "__main__":
    # debug=False is safer for threaded packet sending
    app.run(debug=False, threaded=True)

