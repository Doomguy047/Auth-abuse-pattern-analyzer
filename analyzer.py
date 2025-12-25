import csv
import json
from collections import defaultdict
from datetime import datetime, timedelta


def load_logs(file_path):
    logs = []
    with open(file_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row["success"] = row["success"].lower() == "true"
            row["timestamp"] = datetime.strptime(
                row["timestamp"], "%Y-%m-%d %H:%M"
            )
            logs.append(row)
    return logs


def analyze_logs(logs, window_minutes=5):
    window = timedelta(minutes=window_minutes)

    ip_events = defaultdict(list)     
    user_events = defaultdict(list)   

    # Collect only failed authentication attempts
    for entry in logs:
        if not entry["success"]:
            ip_events[entry["source_ip"]].append(
                (entry["timestamp"], entry["username"])
            )
            user_events[entry["username"]].append(entry["timestamp"])

    findings = []

    # Password Spraying Detection
    
    for ip, events in ip_events.items():
        events.sort(key=lambda x: x[0])

        for i in range(len(events)):
            start_time = events[i][0]
            users = set()
            attempts = 0

            for j in range(i, len(events)):
                if events[j][0] - start_time <= window:
                    users.add(events[j][1])
                    attempts += 1
                else:
                    break

            if len(users) >= 3 and attempts >= 4:
                findings.append({
                    "attack_type": "Password Spraying",
                    "source_ip": ip,
                    "time_window_minutes": window_minutes,
                    "evidence": [
                        "Multiple user accounts targeted",
                        "Concentrated failures within short time window"
                    ],
                    "statistics": {
                        "unique_users": len(users),
                        "failed_attempts": attempts
                    }
                })
                break

    # Brute Force Detection
    
    for user, times in user_events.items():
        times.sort()

        for i in range(len(times)):
            start_time = times[i]
            attempts = 0

            for j in range(i, len(times)):
                if times[j] - start_time <= window:
                    attempts += 1
                else:
                    break

            if attempts >= 3:
                findings.append({
                    "attack_type": "Brute Force",
                    "target_user": user,
                    "time_window_minutes": window_minutes,
                    "evidence": [
                        "Repeated authentication failures on a single account",
                        "Failures clustered in a short time window"
                    ],
                    "statistics": {
                        "failed_attempts": attempts
                    }
                })
                break

    return findings


if __name__ == "__main__":
    logs = load_logs("auth_logs.csv")
    results = analyze_logs(logs, window_minutes=5)
    print(json.dumps(results, indent=2))
