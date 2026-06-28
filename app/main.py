import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from parser import open_logs, find_events
from detections.brute_force import ip_aggregation, ip_severity
from detections.spray import user_aggregation, user_severity

import argparse


DEFAULT_LOG = Path(__file__).resolve().parent.parent / "logs" / "traning_logs_auth.log"

parser = argparse.ArgumentParser()
parser.add_argument("--log", default=str(DEFAULT_LOG))
parser.add_argument("--output", choices=["print", "json", "csv"], default="print")
args = parser.parse_args()

LOG_PATH = Path(args.log).resolve()

def failed_events(events):
    return sum(
        1 for e in events
        if e["source"] != "pam_unix" and e["type"] in ("failed_login", "failed_root_login")
    )

def invalid_users(events):
    return sum(
        1 for e in events
        if e["source"] != "pam_unix" and e["type"] == "invalid_user"
    )

def accepted_logins(events):
    return sum(1 for e in events if e["type"] == "accepted_login")

def unique_ips(events):
    return len({e["ip"] for e in events if e["ip"] is not None})

def unique_users(events):
    return len({e["user"] for e in events if e["user"] is not None})

def summary_events(events):
    print("=" * 50)
    print(f"Failed logins   : {failed_events(events)}")
    print(f"Invalid user    : {invalid_users(events)}")
    print(f"Accepted logins : {accepted_logins(events)}")
    print(f"Unique IPs      : {unique_ips(events)}")
    print(f"Unique users    : {unique_users(events)}")

if __name__ == "__main__":
    log_lines = open_logs(LOG_PATH)
    events = find_events(log_lines)

    pot_brute_force_ip, sec_brute_force_ip = ip_aggregation(events)
    heavy_ips = {ip for entry in pot_brute_force_ip + sec_brute_force_ip for ip in entry}
    spray = user_aggregation(events, heavy_ips)

    pot_severity, sec_severity = ip_severity(pot_brute_force_ip, sec_brute_force_ip)
    spray_severity = user_severity(spray)

    results = {
        "summary": {
            "failed_logins"   : failed_events(events),
            "invalid_users"   : invalid_users(events),
            "accepted_logins" : accepted_logins(events),
            "unique_ips"      : unique_ips(events),
            "unique_users"    : unique_users(events),
        },
        "potential_brute_force" : pot_severity,
        "compromise"            : sec_severity,
        "spray"                 : spray_severity,
    }

    if args.output == "json":
        import json
        print(json.dumps(results, indent=2, default=str))

    elif args.output == "csv":
        import csv, sys
        writer = csv.writer(sys.stdout)
        writer.writerow(["type", "entity", "count", "severity"])
        for entry in pot_severity:
            for ip, data in entry.items():
                writer.writerow(["potential_brute_force", ip, data["count"], data["severity"]])
        for entry in sec_severity:
            for ip, data in entry.items():
                writer.writerow(["compromise", ip, data["count"], data["severity"]])
        for entry in spray_severity:
            for user, data in entry.items():
                writer.writerow(["spray", user, data["count"], data["severity"]])

    else:
        summary_events(events)
        print("\n--- Potential Brute Force from IPs ---")
        for entry in pot_severity:
            for ip, data in entry.items():
                print(f"  {ip} | count: {data['count']} | severity: {data['severity']}")
        print("\n--- Successful Brute Force from IPs (COMPROMISE) ---")
        for entry in sec_severity:
            for ip, data in entry.items():
                print(f"  {ip} | count: {data['count']} | severity: {data['severity']}")
        print("\n--- Password Spray on Users ---")
        for entry in spray_severity:
            for user, data in entry.items():
                print(f"  {user} | unique source IPs: {data['count']} | severity: {data['severity']}")