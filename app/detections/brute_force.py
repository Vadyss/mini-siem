from config import WINDOW_MINUTES, BRUTE_FORCE_THRESHOLD

def get_severity(finding_type, count=0):
    if finding_type == "compromise":
        return "CRITICAL"
    if finding_type == "spray":
        return "HIGH"
    if finding_type == "brute_force":
        return "HIGH" if count >= 15 else "MED"
    if finding_type == "recon":
        return "LOW"
    return "LOW"

def has_window_trigger(timestamps, window_minutes=WINDOW_MINUTES, threshold=BRUTE_FORCE_THRESHOLD):
    timestamps = sorted(timestamps)
    start = 0
    for end in range(len(timestamps)):
        while (timestamps[end] - timestamps[start]).total_seconds() > window_minutes * 60:
            start += 1
        if (end - start + 1) >= threshold:
            return True
    return False

def ip_aggregation(events):
    fail_events = {}

    for event in events:
        if event["source"] == "pam_unix":
            continue
        if event["type"] not in ("invalid_user", "failed_login", "failed_root_login"):
            continue
        if event["ip"] is None or event["time"] is None:
            continue

        ip = event["ip"]
        fail_events.setdefault(ip, []).append(event)

    successful_ips = {
        event["ip"]
        for event in events
        if event["type"] == "accepted_login" and event["ip"] is not None
    }

    pot_brute_force = []
    sec_brute_force = []

    for ip, ip_events in fail_events.items():
        timestamps = [e["time"] for e in ip_events]
        if not has_window_trigger(timestamps):
            continue

        count = len(ip_events)

        if ip in successful_ips:
            sec_brute_force.append({ip: {"count": count, "events": ip_events}})
        else:
            pot_brute_force.append({ip: {"count": count, "events": ip_events}})

    return pot_brute_force, sec_brute_force

def _enrich(ip_events, finding_type, count):
    sev = get_severity(finding_type, count)
    times = [e["time"] for e in ip_events if e["time"] is not None]
    return {
        "count": count,
        "severity": sev,
        "first_seen": str(min(times)) if times else None,
        "last_seen": str(max(times)) if times else None,
        "usernames_tried": sorted({e["user"] for e in ip_events if e["user"] is not None}),
        "sample_raw_logs": [e["raw"] for e in ip_events[:3]],
        "ports": sorted({e["port"] for e in ip_events if e["port"] is not None}),
    }

def ip_severity(pot_brute_force_ip, sec_brute_force_ip):
    pot_severity = []
    sec_severity = []

    for entry in pot_brute_force_ip:
        for ip, data in entry.items():
            pot_severity.append({ip: _enrich(data["events"], "brute_force", data["count"])})

    for entry in sec_brute_force_ip:
        for ip, data in entry.items():
            sec_severity.append({ip: _enrich(data["events"], "compromise", data["count"])})

    return pot_severity, sec_severity