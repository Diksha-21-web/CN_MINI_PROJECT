import os, csv, io, tempfile
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from packet_engine import engine, detect_alerts

app = Flask(__name__)
CORS(app)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.get("/api/health")
def health():
    return jsonify({"ok": True, "service": "NetWatch API", "mode": engine.mode})

@app.get("/api/interfaces")
def interfaces():
    try:
        from scapy.all import get_if_list
        return jsonify({"interfaces": get_if_list(), "capture_available": True})
    except Exception as exc:
        return jsonify({"interfaces": [], "capture_available": False, "error": str(exc)})

@app.post("/api/capture/start")
def start_capture():
    data = request.get_json(silent=True) or {}
    mode = data.get("mode", "demo")
    if mode == "live":
        interface = data.get("interface") or None
        engine.start_live(interface)
    else:
        engine.start_demo()
    return jsonify({"ok": True, "mode": engine.mode})

@app.post("/api/capture/stop")
def stop_capture():
    engine.stop()
    return jsonify({"ok": True, "mode": engine.mode})

@app.get("/api/packets")
def packets():
    rows = engine.snapshot()
    protocol = request.args.get("protocol", "all").lower()
    search = request.args.get("search", "").lower()
    try: limit = min(max(int(request.args.get("limit", 500)), 1), 5000)
    except ValueError: limit = 500
    if protocol != "all":
        rows = [p for p in rows if p["protocol"].lower() == protocol]
    if search:
        rows = [p for p in rows if search in " ".join(str(v) for v in p.values()).lower()]
    return jsonify({"packets": rows[-limit:][::-1], "count": len(rows)})

@app.get("/api/stats")
def stats():
    result = engine.stats()
    rows = engine.snapshot()
    result["alerts"] = detect_alerts(rows)
    return jsonify(result)

@app.post("/api/pcap/upload")
def upload_pcap():
    if "file" not in request.files:
        return jsonify({"error": "Choose a PCAP file first."}), 400
    f = request.files["file"]
    name = (f.filename or "").lower()
    if not (name.endswith(".pcap") or name.endswith(".pcapng")):
        return jsonify({"error": "Only .pcap and .pcapng files are supported."}), 400
    path = os.path.join(UPLOAD_DIR, "analysis_upload.pcap")
    f.save(path)
    try:
        count = engine.load_pcap(path)
        return jsonify({"ok": True, "packets_loaded": count})
    except Exception as exc:
        return jsonify({"error": f"Could not parse capture file: {exc}"}), 400
    finally:
        try: os.remove(path)
        except OSError: pass

@app.get("/api/export/csv")
def export_csv():
    rows = engine.snapshot()
    output = io.StringIO()
    fields = ["timestamp","source_ip","destination_ip","protocol","source_port","destination_port","length","direction","summary"]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    mem = io.BytesIO(output.getvalue().encode("utf-8"))
    mem.seek(0)
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name="netwatch_packets.csv")

@app.get("/api/export/pdf")
def export_pdf():
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
        from reportlab.lib import colors
        mem = io.BytesIO()
        c = canvas.Canvas(mem, pagesize=A4)
        width, height = A4
        stats = engine.stats()
        c.setFillColor(colors.HexColor("#10213c")); c.rect(0, height-105, width, 105, fill=1, stroke=0)
        c.setFillColor(colors.white); c.setFont("Helvetica-Bold", 22); c.drawString(42, height-55, "NetWatch")
        c.setFont("Helvetica", 10); c.drawString(42, height-76, "Network Packet Analysis Summary")
        c.setFillColor(colors.black); y = height-140
        c.setFont("Helvetica-Bold", 13); c.drawString(42,y,"Capture overview"); y -= 25
        c.setFont("Helvetica", 10)
        for label, value in [("Total packets",stats["total_packets"]),("Total bytes",stats["total_bytes"]),
                             ("Average packet size",stats["average_packet_size"]),("Capture mode",stats["mode"])]:
            c.drawString(48,y,f"{label}: {value}"); y -= 18
        y -= 12; c.setFont("Helvetica-Bold",13); c.drawString(42,y,"Protocol distribution"); y -= 23
        c.setFont("Helvetica",10)
        for item in stats["protocols"]:
            c.drawString(48,y,f'{item["name"]}: {item["value"]} packets'); y -= 17
        y -= 12; c.setFont("Helvetica-Bold",13); c.drawString(42,y,"Traffic alerts (heuristic)"); y -= 23
        c.setFont("Helvetica",9)
        for alert in detect_alerts(engine.snapshot())[:12]:
            c.drawString(48,y,f'{alert["severity"]} | {alert["category"]} | {alert["source_ip"]}'); y -= 15
            if y < 70:
                c.showPage(); y = height-60; c.setFont("Helvetica",9)
        c.setFont("Helvetica-Oblique",8); c.drawString(42,35,"Educational analysis only. Alerts are heuristics, not confirmed attacks.")
        c.save(); mem.seek(0)
        return send_file(mem, mimetype="application/pdf", as_attachment=True, download_name="netwatch_report.pdf")
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

@app.errorhandler(413)
def too_large(_):
    return jsonify({"error": "File exceeds the 50 MB upload limit."}), 413

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
