import sys
from pathlib import Path
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
print(sys.path)  # debug
print(Path(__file__).resolve().parent.parent)  # debug

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
            ipaddress.IPv6Address(candidate)
            ip.append(match.group(0))
            return str(ipaddress.IPv6Address(candidate))
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
            "time" : time_stamp(log),
            "type" : event_type,
            "ip" : is_valid_ip(log),
            "user" : get_user(log),
            "port" : port,
            "raw" : log
        }
                
        events.append(event)
        
    return events

def failed_events(events):
    
    failed_logins_count = 0
    
    for event in events:
        if event["type"] in ("failed_login", "failed_invalid_user"):
            failed_logins_count += 1
    
    return failed_logins_count

def invalid_users(events):
    
    invalid_users_count = 0
    
    for event in events:
        if event["type"] in ("invalid_user", "failed_invalid_user"):
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

def ip_aggregation(events, ip):
    
    pot_brute_force = []
    counts = Counter(ip)
    
    result = {k: v for k, v in counts.items() if v >= 2}
    
    if not result:
        pass
    if result:
        
        print("=" * 50)
        
        for ip, count in result.items():
            
            if count > 5 or count == 5:
                print("Potencional brute force attack from this IP:")
                print(f"{ip} : {count}")
                
                brute_foce_adress = {ip : count}
                
                return pot_brute_force.append(brute_foce_adress)
                
            elif count < 5:
                print(f"{ip} : {count}")
    
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
    
def summary_pot_brute_force(pot_brute_force):
    
    print("=" * 50)
    print(f"Potencional brute force attack: {pot_brute_force}")
    
if __name__ == "__main__":
    log_lines = open_logs()
    events = find_events(log_lines)
    
    print_events(events)
    summary_events(events)
    
    pot_brute_force = ip_aggregation(events, ip)
    summary_pot_brute_force(pot_brute_force)