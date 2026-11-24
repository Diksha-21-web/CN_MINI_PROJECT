import random
import threading
import time
from datetime import datetime, timezone
from collections import Counter
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, DNS, ARP, Raw, get_if_list, rdpcap

class PacketEngine:
    def __init__(self):
        self.packets = []
        self.running = False
        self.mode = "idle"
        self.error = None
        self.thread = None
        self.lock = threading.Lock()
        self.started_at = None
        self.demo_thread = None

    def _decode(self, pkt):
        now = datetime.now(timezone.utc).astimezone().isoformat(timespec="milliseconds")
        row = {
            "timestamp": now, "protocol": "OTHER", "source_ip": "-", "destination_ip": "-",
            "source_port": "-", "destination_port": "-", "length": len(pkt),
            "direction": "Unknown", "summary": "Unclassified packet", "tcp_flags": "-",
            "source_mac": "-", "destination_mac": "-"
        }
        try:
            if pkt.haslayer(ARP):
                a = pkt[ARP]; row.update(protocol="ARP", source_ip=a.psrc or "-", destination_ip=a.pdst or "-",
                    source_mac=a.hwsrc or "-", destination_mac=a.hwdst or "-", summary=f"ARP operation {a.op}")
            if pkt.haslayer(IP):
                ip = pkt[IP]; row.update(source_ip=ip.src, destination_ip=ip.dst)
            elif pkt.haslayer(IPv6):
                ip = pkt[IPv6]; row.update(source_ip=ip.src, destination_ip=ip.dst)
            if pkt.haslayer(TCP):
                t = pkt[TCP]; row.update(protocol="TCP", source_port=t.sport, destination_port=t.dport,
                    tcp_flags=str(t.flags), summary=f"TCP {t.sport} → {t.dport}")
                if t.dport == 443 or t.sport == 443: row["protocol"] = "TLS/HTTPS"
                elif t.dport == 80 or t.sport == 80: row["protocol"] = "HTTP"
            elif pkt.haslayer(UDP):
                u = pkt[UDP]; row.update(protocol="UDP", source_port=u.sport, destination_port=u.dport,
                    summary=f"UDP {u.sport} → {u.dport}")
                if u.dport == 53 or u.sport == 53: row["protocol"] = "DNS"
                elif u.dport == 67 or u.sport == 67: row["protocol"] = "DHCP"
            elif pkt.haslayer(ICMP):
                row.update(protocol="ICMP", summary="ICMP network control message")
            if pkt.haslayer(DNS): row["protocol"] = "DNS"
            row["direction"] = "Outgoing" if row["source_ip"] not in ("-", "0.0.0.0", "::") else "Unknown"
            if pkt.haslayer(Raw):
                row["summary"] += " • payload present (not displayed)"
        except Exception as exc:
            row["summary"] = f"Packet decode warning: {exc}"
        return row

    def add_packet(self, row):
        with self.lock:
            self.packets.append(row)
            if len(self.packets) > 10000:
                self.packets = self.packets[-8000:]

    def start_demo(self):
        self.stop()
        self.mode, self.running, self.error = "demo", True, None
        self.started_at = time.time()
        self.demo_thread = threading.Thread(target=self._demo_loop, daemon=True)
        self.demo_thread.start()

    def _demo_loop(self):
        protocols = ["TCP", "TCP", "TLS/HTTPS", "UDP", "DNS", "ICMP", "ARP"]
        ips = ["192.168.1.12", "192.168.1.20", "192.168.1.34", "10.0.0.8"]
        while self.running and self.mode == "demo":
            src = random.choice(ips)
            proto = random.choice(protocols)
            dst_port = {"TCP": 8080, "TLS/HTTPS": 443, "UDP": 5353, "DNS": 53, "ICMP": "-", "ARP": "-"}.get(proto, "-")
            row = {
                "timestamp": datetime.now().astimezone().isoformat(timespec="milliseconds"),
                "protocol": proto, "source_ip": src, "destination_ip": random.choice(ips + ["8.8.8.8", "1.1.1.1"]),
                "source_port": random.randint(30000, 60000) if proto in ("TCP", "UDP", "TLS/HTTPS", "DNS") else "-",
                "destination_port": dst_port, "length": random.randint(64, 1450),
                "direction": random.choice(["Incoming", "Outgoing"]),
                "summary": f"{proto} demonstration packet", "tcp_flags": random.choice(["S", "A", "PA", "-"]),
                "source_mac": "-", "destination_mac": "-", "demo": True
            }
            self.add_packet(row)
            time.sleep(0.45)

    def start_live(self, interface=None):
        self.stop()
        self.mode, self.running, self.error = "live", True, None
        self.started_at = time.time()
        def worker():
            try:
                sniff(iface=interface or None, prn=lambda p: self.add_packet(self._decode(p)),
                      store=False, stop_filter=lambda _: not self.running)
            except Exception as exc:
                self.error = str(exc)
                self.running = False
        self.thread = threading.Thread(target=worker, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.mode != "idle":
            self.mode = "stopped"

    def load_pcap(self, path):
        parsed = []
        for pkt in rdpcap(path):
            parsed.append(self._decode(pkt))
            if len(parsed) >= 10000: break
        with self.lock:
            self.packets = parsed
        self.mode, self.running = "pcap", False
        return len(parsed)

    def snapshot(self):
        with self.lock:
            return list(self.packets)

    def stats(self):
        rows = self.snapshot()
        protocols = Counter(p["protocol"] for p in rows)
        sources = Counter(p["source_ip"] for p in rows if p["source_ip"] != "-")
        destinations = Counter(p["destination_ip"] for p in rows if p["destination_ip"] != "-")
        total_bytes = sum(p["length"] for p in rows)
        incoming = sum(p["length"] for p in rows if p["direction"] == "Incoming")
        outgoing = sum(p["length"] for p in rows if p["direction"] == "Outgoing")
        return {
            "total_packets": len(rows), "total_bytes": total_bytes, "incoming_bytes": incoming,
            "outgoing_bytes": outgoing, "protocols": [{"name": k, "value": v} for k,v in protocols.most_common()],
            "top_sources": [{"ip": k, "packets": v} for k,v in sources.most_common(7)],
            "top_destinations": [{"ip": k, "packets": v} for k,v in destinations.most_common(7)],
            "average_packet_size": round(total_bytes / len(rows), 1) if rows else 0,
            "mode": self.mode, "running": self.running, "error": self.error,
            "duration": round(time.time() - self.started_at, 1) if self.started_at and self.running else 0
        }

engine = PacketEngine()

def detect_alerts(rows):
    counts = Counter(p["source_ip"] for p in rows if p["source_ip"] != "-")
    alerts = []
    for ip, count in counts.most_common():
        if count >= 35:
            alerts.append({"severity": "High" if count >= 100 else "Medium", "category": "High packet volume",
                           "source_ip": ip, "count": count,
                           "reason": f"{count} packets observed from this source in the current capture."})
    port_attempts = {}
    for p in rows:
        if p["protocol"] in ("TCP", "HTTP", "TLS/HTTPS") and p["source_ip"] != "-":
            port_attempts.setdefault(p["source_ip"], set()).add(str(p["destination_port"]))
    for ip, ports in port_attempts.items():
        if len(ports) >= 8:
            alerts.append({"severity": "Medium", "category": "Possible port scanning pattern",
                           "source_ip": ip, "count": len(ports),
                           "reason": f"Traffic observed to {len(ports)} distinct destination ports."})
    return alerts[:30]
