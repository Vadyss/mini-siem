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
    fail_timestamps = {}

    for event in events:
        if event["source"] == "pam_unix":
            continue
        if event["type"] not in ("invalid_user", "failed_login", "failed_root_login"):
            continue
        if event["ip"] is None or event["time"] is None:
            continue

        ip = event["ip"]
        fail_timestamps.setdefault(ip, []).append(event["time"])

    # O(1) fix — předpočítej successful IPs jednou
    successful_ips = {
        event["ip"]
        for event in events
        if event["type"] == "accepted_login" and event["ip"] is not None
    }

    pot_brute_force = []
    sec_brute_force = []

    for ip, timestamps in fail_timestamps.items():
        if not has_window_trigger(timestamps):
            continue

        count = len(timestamps)

        if ip in successful_ips:
            sec_brute_force.append({ip: count})
        else:
            pot_brute_force.append({ip: count})

    return pot_brute_force, sec_brute_force

def ip_severity(pot_brute_force_ip, sec_brute_force_ip):
    pot_severity = []
    sec_severity = []

    for entry in pot_brute_force_ip:
        for ip, count in entry.items():
            sev = get_severity("brute_force", count)
            pot_severity.append({ip: {"count": count, "severity": sev}})

    for entry in sec_brute_force_ip:
        for ip, count in entry.items():
            sev = get_severity("compromise", count)
            sec_severity.append({ip: {"count": count, "severity": sev}})

    return pot_severity, sec_severity