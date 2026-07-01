from config import SPRAY_THRESHOLD
from detections.brute_force import get_severity

def user_aggregation(events, heavy_ips, spray_threshold=SPRAY_THRESHOLD):
    user_ips = {}
    user_events = {}

    for event in events:
        if event["source"] == "pam_unix":
            continue
        if event["type"] not in ("invalid_user", "failed_login", "failed_root_login"):
            continue
        if event["user"] is None or event["ip"] is None:
            continue

        user = event["user"]
        user_ips.setdefault(user, set()).add(event["ip"])
        user_events.setdefault(user, []).append(event)

    spray = []

    for user, ips in user_ips.items():
        light_ips = {ip for ip in ips if ip not in heavy_ips}
        if len(light_ips) >= spray_threshold:
            spray.append({user: {"count": len(light_ips), "events": user_events[user], "light_ips": light_ips}})

    return spray

def user_severity(spray_alerts):
    spray_severity = []

    for entry in spray_alerts:
        for user, data in entry.items():
            count = data["count"]
            light_ips = data["light_ips"]
            user_evts = [e for e in data["events"] if e["ip"] in light_ips]
            sev = get_severity("spray", count)
            times = [e["time"] for e in user_evts if e["time"] is not None]
            spray_severity.append({user: {
                "count": count,
                "severity": sev,
                "first_seen": str(min(times)) if times else None,
                "last_seen": str(max(times)) if times else None,
                "source_ips": sorted(data["light_ips"]),
                "sample_raw_logs": [e["raw"] for e in user_evts[:3]],
                "ports": sorted({e["port"] for e in user_evts if e["port"] is not None}),
            }})

    return spray_severity