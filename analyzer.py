from pathlib import Path
from collections import defaultdict
from datetime import datetime, timedelta
import csv

BASE = Path(__file__).parent
INPUT = BASE / "sample_logs" / "auth_log.csv"
OUTPUT = BASE / "output"
OUTPUT.mkdir(exist_ok=True)

FAILURE_THRESHOLD = 5
WINDOW_MINUTES = 10
MULTI_USER_THRESHOLD = 4

def read_events():
    rows = []
    with INPUT.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            row["dt"] = datetime.strptime(row["timestamp"], "%Y-%m-%d %H:%M:%S")
            rows.append(row)
    return sorted(rows, key=lambda x: x["dt"])

def detect_bruteforce(events):
    findings = []
    grouped = defaultdict(list)

    for e in events:
        if e["status"] == "FAILURE":
            grouped[(e["source_ip"], e["username"])].append(e)

    for (ip, user), failed in grouped.items():
        for i in range(len(failed)):
            window_start = failed[i]["dt"]
            window_end = window_start + timedelta(minutes=WINDOW_MINUTES)
            window = [x for x in failed if window_start <= x["dt"] <= window_end]
            if len(window) >= FAILURE_THRESHOLD:
                findings.append({
                    "severity": "HIGH",
                    "detection": "Potential brute-force attack",
                    "source_ip": ip,
                    "username": user,
                    "event_count": len(window),
                    "first_seen": window[0]["timestamp"],
                    "last_seen": window[-1]["timestamp"],
                    "reason": f"{len(window)} failed logins within {WINDOW_MINUTES} minutes"
                })
                break
    return findings

def detect_password_spray(events):
    findings = []
    by_ip = defaultdict(list)

    for e in events:
        if e["status"] == "FAILURE":
            by_ip[e["source_ip"]].append(e)

    for ip, failed in by_ip.items():
        users = sorted(set(e["username"] for e in failed))
        if len(users) >= MULTI_USER_THRESHOLD:
            findings.append({
                "severity": "MEDIUM",
                "detection": "Possible password spraying",
                "source_ip": ip,
                "username": ",".join(users),
                "event_count": len(failed),
                "first_seen": failed[0]["timestamp"],
                "last_seen": failed[-1]["timestamp"],
                "reason": f"One source IP attempted authentication against {len(users)} usernames"
            })
    return findings

def detect_success_after_failures(events):
    findings = []
    failures_by_ip_user = defaultdict(list)

    for e in events:
        key = (e["source_ip"], e["username"])
        if e["status"] == "FAILURE":
            failures_by_ip_user[key].append(e)
        elif e["status"] == "SUCCESS":
            prior = [
                f for f in failures_by_ip_user[key]
                if timedelta(0) <= e["dt"] - f["dt"] <= timedelta(minutes=15)
            ]
            if len(prior) >= FAILURE_THRESHOLD:
                findings.append({
                    "severity": "CRITICAL",
                    "detection": "Successful login after repeated failures",
                    "source_ip": e["source_ip"],
                    "username": e["username"],
                    "event_count": len(prior),
                    "first_seen": prior[0]["timestamp"],
                    "last_seen": e["timestamp"],
                    "reason": f"Successful login followed {len(prior)} failures from the same IP/user"
                })
    return findings

def write_findings(findings):
    path = OUTPUT / "detection_results.csv"
    fields = ["severity", "detection", "source_ip", "username", "event_count",
              "first_seen", "last_seen", "reason"]
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(findings)
    return path

def write_ip_summary(events):
    stats = defaultdict(lambda: {"success": 0, "failure": 0, "users": set()})
    for e in events:
        s = stats[e["source_ip"]]
        s["success" if e["status"] == "SUCCESS" else "failure"] += 1
        s["users"].add(e["username"])

    path = OUTPUT / "ip_summary.csv"
    with path.open("w", newline="", encoding="utf-8") as f:
        fields = ["source_ip", "success_count", "failure_count", "unique_users"]
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for ip, s in sorted(stats.items()):
            w.writerow({
                "source_ip": ip,
                "success_count": s["success"],
                "failure_count": s["failure"],
                "unique_users": len(s["users"])
            })
    return path

def write_user_summary(events):
    stats = defaultdict(lambda: {"success": 0, "failure": 0, "ips": set()})
    for e in events:
        s = stats[e["username"]]
        s["success" if e["status"] == "SUCCESS" else "failure"] += 1
        s["ips"].add(e["source_ip"])

    path = OUTPUT / "user_summary.csv"
    with path.open("w", newline="", encoding="utf-8") as f:
        fields = ["username", "success_count", "failure_count", "unique_source_ips"]
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for user, s in sorted(stats.items()):
            w.writerow({
                "username": user,
                "success_count": s["success"],
                "failure_count": s["failure"],
                "unique_source_ips": len(s["ips"])
            })
    return path

def write_incident_summary(events, findings):
    critical = sum(1 for x in findings if x["severity"] == "CRITICAL")
    high = sum(1 for x in findings if x["severity"] == "HIGH")
    medium = sum(1 for x in findings if x["severity"] == "MEDIUM")
    failures = sum(1 for e in events if e["status"] == "FAILURE")
    successes = sum(1 for e in events if e["status"] == "SUCCESS")

    text = [
        "HOME SOC SECURITY MONITORING LAB - INCIDENT SUMMARY",
        "=" * 58,
        f"Total authentication events analyzed: {len(events)}",
        f"Successful logins: {successes}",
        f"Failed logins: {failures}",
        f"Detections: {len(findings)}",
        f"Critical: {critical} | High: {high} | Medium: {medium}",
        "",
        "FINDINGS",
        "-" * 58,
    ]

    for idx, f in enumerate(findings, 1):
        text.extend([
            f"{idx}. [{f['severity']}] {f['detection']}",
            f"   Source IP: {f['source_ip']}",
            f"   Username(s): {f['username']}",
            f"   First seen: {f['first_seen']}",
            f"   Last seen: {f['last_seen']}",
            f"   Reason: {f['reason']}",
            ""
        ])

    text.extend([
        "RECOMMENDED REMEDIATION",
        "-" * 58,
        "1. Investigate the source IPs and affected accounts.",
        "2. Reset credentials if compromise is suspected.",
        "3. Enable multi-factor authentication where available.",
        "4. Configure account lockout/rate limiting.",
        "5. Block or restrict malicious source IPs when appropriate.",
        "6. Continue monitoring for recurring authentication anomalies.",
        ""
    ])

    path = OUTPUT / "incident_summary.txt"
    path.write_text("\n".join(text), encoding="utf-8")
    return path

def main():
    if not INPUT.exists():
        print("Input log not found.")
        print("Run: python generate_sample_logs.py")
        return

    events = read_events()
    findings = []
    findings.extend(detect_bruteforce(events))
    findings.extend(detect_password_spray(events))
    findings.extend(detect_success_after_failures(events))

    detection_path = write_findings(findings)
    ip_path = write_ip_summary(events)
    user_path = write_user_summary(events)
    summary_path = write_incident_summary(events, findings)

    print("=" * 62)
    print("HOME SOC SECURITY MONITORING LAB")
    print("=" * 62)
    print(f"Events analyzed: {len(events)}")
    print(f"Detections found: {len(findings)}")
    for f in findings:
        print(f"[{f['severity']}] {f['detection']} | IP={f['source_ip']} | user={f['username']}")
    print()
    print("Output files:")
    print(f"- {detection_path}")
    print(f"- {summary_path}")
    print(f"- {ip_path}")
    print(f"- {user_path}")

if __name__ == "__main__":
    main()
