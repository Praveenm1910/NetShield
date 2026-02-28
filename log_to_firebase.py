import time
import re
import firebase_admin
from firebase_admin import credentials, db
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

LOG_FILE = "/var/log/netshield_arp.log"

# ---------- Firebase ----------
cred = credentials.Certificate("firebase_key.json")
firebase_admin.initialize_app(
    cred,
    {
        "databaseURL": "https://netshield-idps-default-rtdb.asia-southeast1.firebasedatabase.app/"
    },
)

ref = db.reference("netshield_logs")

# ---------- Regex ----------
DDOS_RE = re.compile(
    r"\[(.*?)\]\s+\[DDOS\]\s+(\d+\.\d+\.\d+\.\d+)\s+SYN=(\d+)\s+TOTAL=(\d+)"
)

ARP_RE_1 = re.compile(
    r"\[(.*?)\]\s+\[ARP\]\s+(\d+\.\d+\.\d+\.\d+)\s+\((.*?)\)\s+->\s+(\d+\.\d+\.\d+\.\d+)\s+\((.*?)\)"
)

ARP_RE_2 = re.compile(
    r"\[(.*?)\]\s+ARP PACKET \| SRC (\d+\.\d+\.\d+\.\d+)\s+\((.*?)\)\s+->\s+DST\s+(\d+\.\d+\.\d+\.\d+)\s+\((.*?)\)"
)


# ---------- Parser ----------
def parse_log(line):
    line = line.strip()

    # ---- DDOS ----
    m = DDOS_RE.search(line)
    if m:
        syn = int(m.group(3))
        total = int(m.group(4))

        category = "normal"
        severity = "LOW"

        if total > 50 or syn > 10:
            category = "suspicious"
            severity = "MEDIUM"
        if total > 200 or syn > 30:
            category = "attack"
            severity = "HIGH"

        return {
            "type": "ddos",
            "timestamp": m.group(1),
            "src_ip": m.group(2),
            "syn": syn,
            "total": total,
            "category": category,
            "severity": severity,
        }

    # ---- ARP (format 1) ----
    m = ARP_RE_1.search(line)
    if not m:
        m = ARP_RE_2.search(line)

    if m:
        category = "normal"
        confidence = 10

        if m.group(5) == "00:00:00:00:00:00":
            category = "suspicious"
            confidence = 70

        return {
            "type": "arp",
            "timestamp": m.group(1),
            "src_ip": m.group(2),
            "src_mac": m.group(3),
            "dst_ip": m.group(4),
            "dst_mac": m.group(5),
            "category": category,
            "confidence": confidence,
        }

    return None


# ---------- Firebase Push ----------
def push_to_firebase(data):
    ref.child("traffic").child(data["type"]).push(data)

    if data.get("category") in ["attack", "suspicious"]:
        ref.child("alerts").child(data["type"]).push(data)


# ---------- Watchdog ----------
class LogHandler(FileSystemEventHandler):
    def __init__(self):
        self.fp = open(LOG_FILE, "r")
        self.fp.seek(0, 2)

    def on_modified(self, event):
        if event.src_path != LOG_FILE:
            return

        for line in self.fp.readlines():
            parsed = parse_log(line)
            if parsed:
                push_to_firebase(parsed)
                print(f"📤 {parsed['type'].upper()} pushed → {parsed.get('src_ip')}")


# ---------- Main ----------
if __name__ == "__main__":
    print("📡 NetShield Firebase Logger Started")
    observer = Observer()
    observer.schedule(LogHandler(), path="/var/log", recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()
