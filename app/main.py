import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import re
import ipaddress
from dateutil import parser as dateparser
from datetime import datetime
from collections import Counter

from assets.event_types_assets import EVENT_PATTERNS
from assets.get_user_assets import patterns

LOG_PATH = Path(__file__).resolve().parent.parent / "logs" / "traning_logs_auth.log"

ip_regex = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
ipv6_regex = re.compile(r'[0-9a-fA-F:]{2,39}')
port_regex = r"\bport\s+(\d+)\b"

ip = []

def open_logs():
    
    with LOG_PATH.open("r", encoding="utf-8") as file:
        return [line.strip() for line in file]

def is_valid_ip(log):
    
    match = re.search(ip_regex, log)
    
    if match: 
        try: 
            ipaddress.ip_address(match.group(0))
            ip.append(match.group(0))
            return match.group(0)
        except ValueError:
                pass
            
    for candidate in ipv6_regex.findall(log):
        try:
            valid = str(ipaddress.IPv6Address(candidate))
            ip.append(valid)
            return valid
        except ValueError:
            pass
    
    return None

def time_stamp(log):
    ts_patterns = [
        r'^\[([^\]]+)\]',                          
        r'^(\d{4}-\d{2}-\d{2}T[\d:.]+Z?)',         
        r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',
        r'^(\d{2}/\w{3}/\d{4}[: ][\d:+ ]+)',       
        r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})',
    ]
    
    for pattern in ts_patterns:
        match = re.search(pattern, log)
        if match:
            try:
                return dateparser.parse(
                    match.group(1),
                    default=datetime(datetime.now().year, 1, 1)
                )
            except (ValueError, OverflowError):
                continue
    return None

def get_user(log):
                
    for pattern in patterns:
        match = re.search(pattern, log, re.IGNORECASE)

        if match:
            return match.group("user")

    return None            

def get_event_type(log):
    
    log_lower = log.lower()

    for pattern, event_type in EVENT_PATTERNS:
        if pattern in log_lower:
            return event_type
    return None

def find_events(log_lines):
    events = []

    for log in log_lines:
        
        event_type = get_event_type(log)
        
        if event_type is None:
            continue
        
        port_match = re.search(port_regex, log)
        port = int(port_match.group(1)) if port_match else None

        event = {
            "time"   : time_stamp(log),
            "type"   : event_type,
            "ip"     : is_valid_ip(log),
            "user"   : get_user(log),
            "port"   : port,
            "raw"    : log,
            "source" : "pam_unix" if "pam_unix" in log else "sshd"  # ← přidej
        }
                
        events.append(event)
        
    return events

def failed_events(events):
    
    failed_logins_count = 0
    
    for event in events:
        if event["source"] == "pam_unix":
            continue

        if event["type"] in ("failed_login", "failed_root_login"):
            failed_logins_count += 1
    
    return failed_logins_count

def invalid_users(events):
    
    invalid_users_count = 0
    
    for event in events:
        if event["source"] == "pam_unix":
            continue
        
        if event["type"] == "invalid_user":
            invalid_users_count += 1

    return invalid_users_count

def accepted_logins(events):
    
    accepted_logins_count = 0
    
    for event in events:
        if event["type"] == "accepted_login":
            accepted_logins_count += 1
            
    return accepted_logins_count

def unique_ips(events):
    
    unique_ips_count = 0
    unique_ips = set()

    for event in events:
        ip = event["ip"]
        
        if ip is not None:
            unique_ips.add(ip)
            
    unique_ips_count = len(unique_ips)
    
    return unique_ips_count
    
def unique_users(events):
    
    unique_users = set()
    unique_users_count = 0
    
    for event in events:
        
        user = event["user"]
        
        if user is not None:
            unique_users.add(user)
    
    unique_users_count = len(unique_users)
    
    return unique_users_count

def has_window_trigger(timestamps, window_minutes=10, threshold=5):
    
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
        
        if ip not in fail_timestamps:
            fail_timestamps[ip] = []
            
        fail_timestamps[ip].append(event["time"])
    
    pot_brute_force = []
    sec_brute_force = []
    
    print("=" * 50)
    
    for ip, timestamps in fail_timestamps.items():
        
        if not has_window_trigger(timestamps):
            continue
        
        successful = any(
            event["ip"] == ip and event["type"] == "accepted_login"
            for event in events
        )
        
        count = len(timestamps)
        
        if successful:
            print(f"Potential successful brute force attack from this IP:")
            print(f"{ip} : {count}")
            sec_brute_force.append({ip: count})
        else:
            print(f"Potential brute force attack from this IP:")
            print(f"{ip} : {count}")
            pot_brute_force.append({ip: count})
    
    return pot_brute_force, sec_brute_force

def user_aggregation(events):
    
    fail_timestamps = {}
    
    for event in events:
        if event["source"] == "pam_unix":
            continue
        if event["type"] not in ("invalid_user", "failed_login", "failed_root_login"):
            continue
        if event["user"] is None or event["time"] is None:
            continue
        
        user = event["user"]
        
        if user not in fail_timestamps:
            fail_timestamps[user] = []
        
        fail_timestamps[user].append(event["time"]) 
    
    pot_brute_force_user = []
    sec_brute_force_user = []
    
    print("=" * 50)
    
    for user, timestamps in fail_timestamps.items():
        
        if not has_window_trigger(timestamps):
            continue
        
        successful = any(
            event["user"] == user and event["type"] == "accepted_login"
            for event in events
        )
        
        count = len(timestamps)

        if successful:
            print(f"Potential successful brute force attack on this user:")
            print(f"{user} : {count}")
            sec_brute_force_user.append({user: count})
        else:
            print(f"Potential brute force attack on this user:")
            print(f"{user} : {count}")
            pot_brute_force_user.append({user: count})
    
    return pot_brute_force_user, sec_brute_force_user

def ip_severity(pot_brute_force_user, sec_brute_force_user):
    return

def user_severity(pot_brute_force_user, sec_brute_force_user):
    return

def print_events(events):
    
    for event in events:
        print("=" * 50)
        print(f"TIME : {event['time']}")
        print(f"TYPE : {event['type']}")
        print(f"IP   : {event['ip']}")
        print(f"USER : {event['user']}")
        print(f"PORT : {event['port']}")
        print(f"RAW  : {event['raw']}")

def summary_events(events):
    
    print("=" * 50)
    print(f"Failed logins   : {failed_events(events)}")
    print(f"Invalid user    : {invalid_users(events)}")
    print(f"Accepted logins : {accepted_logins(events)}")
    print(f"Unique IPs      : {unique_ips(events)}")
    print(f"Unique users    : {unique_users(events)}")
    
def summary_pot_brute_force_ip(pot_brute_force_ip, sec_brute_force_ip):
    
    print("=" * 50)
    print(f"Potencional brute force attack from this ip: {pot_brute_force_ip}")
    print("=" * 50)
    print(f"Potencional successful brute force attack from this ip: {sec_brute_force_ip}")

def summary_pot_brute_force_user(pot_brute_force_user, sec_brute_force_user):
    
    print("=" * 50)
    print(f"Potencional brute force attack on this user: {pot_brute_force_user}")
    print("=" * 50)
    print(f"Potencional successful brute force attack on this user: {sec_brute_force_user}")

if __name__ == "__main__":
    log_lines = open_logs()
    events = find_events(log_lines)
    
    print_events(events)
    summary_events(events)
    
    pot_brute_force_ip, sec_brute_force_ip = ip_aggregation(events)
    pot_brute_force_user, sec_brute_force_user = user_aggregation(events)
    
    summary_pot_brute_force_ip(pot_brute_force_ip, sec_brute_force_ip)
    summary_pot_brute_force_user(pot_brute_force_user, sec_brute_force_user)