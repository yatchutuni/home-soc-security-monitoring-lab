from pathlib import Path
from datetime import datetime, timedelta
import csv
import random

random.seed(42)

OUT = Path(__file__).parent / "sample_logs" / "auth_log.csv"
OUT.parent.mkdir(exist_ok=True)

start = datetime(2026, 8, 18, 9, 0, 0)

events = []

def add_event(ts, host, user, source_ip, status, event_id, logon_type, message):
    events.append({
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "host": host,
        "username": user,
        "source_ip": source_ip,
        "status": status,
        "event_id": event_id,
        "logon_type": logon_type,
        "message": message,
    })

# Normal activity
normal_users = ["alex", "jamie", "morgan", "taylor"]
normal_ips = ["192.168.1.20", "192.168.1.21", "192.168.1.22", "192.168.1.23"]

for i in range(35):
    ts = start + timedelta(minutes=random.randint(0, 180), seconds=random.randint(0, 59))
    user = random.choice(normal_users)
    ip = normal_ips[normal_users.index(user)]
    if random.random() < 0.90:
        add_event(ts, "WIN11-LAB", user, ip, "SUCCESS", 4624, 2, "Successful interactive logon")
    else:
        add_event(ts, "WIN11-LAB", user, ip, "FAILURE", 4625, 2, "Failed logon - incorrect password")

# Simulated brute-force attack: repeated failures against administrator
attacker_ip = "10.10.10.55"
attack_start = start + timedelta(minutes=65)
for i in range(12):
    ts = attack_start + timedelta(seconds=i * 18)
    add_event(ts, "WIN11-LAB", "administrator", attacker_ip, "FAILURE", 4625, 3,
              "Failed network logon - bad username or password")

# Password spraying behavior: same IP targets multiple accounts
spray_ip = "172.16.5.99"
spray_start = start + timedelta(minutes=110)
for i, user in enumerate(["alex", "jamie", "morgan", "taylor", "administrator", "guest"]):
    ts = spray_start + timedelta(seconds=i * 25)
    add_event(ts, "WIN11-LAB", user, spray_ip, "FAILURE", 4625, 3,
              "Failed network logon - bad username or password")

# A success after many failed attempts from attacker IP
add_event(attack_start + timedelta(minutes=5), "WIN11-LAB", "administrator",
          attacker_ip, "SUCCESS", 4624, 3,
          "Successful network logon following repeated failures")

events.sort(key=lambda x: x["timestamp"])

with OUT.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=events[0].keys())
    writer.writeheader()
    writer.writerows(events)

print(f"Generated {len(events)} simulated authentication events")
print(f"Saved to: {OUT}")
