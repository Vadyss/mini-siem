from config import SPRAY_THRESHOLD
from detections.brute_force import get_severity

def user_aggregation(events, heavy_ips, spray_threshold=SPRAY_THRESHOLD):
    user_ips = {}

    for event in events:
        if event["source"] == "pam_unix":
            continue
        if event["type"] not in ("invalid_user", "failed_login", "failed_root_login"):
            continue
        if event["user"] is None or event["ip"] is None:
            continue

        user = event["user"]
        user_ips.setdefault(user, set()).add(event["ip"])

    spray = []

    for user, ips in user_ips.items():
        light_ips = {ip for ip in ips if ip not in heavy_ips}
        if len(light_ips) >= spray_threshold:
            spray.append({user: len(light_ips)})

    return spray

def user_severity(spray_alerts):
    spray_severity = []

    for entry in spray_alerts:
        for user, count in entry.items():
            sev = get_severity("spray", count)
            spray_severity.append({user: {"count": count, "severity": sev}})

    return spray_severity