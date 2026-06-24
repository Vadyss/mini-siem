from pathlib import Path
import re
import ipaddress

LOG_PATH = Path(__file__).resolve().parent.parent / "logs" / "traning_logs_auth.log"

ip_regex = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
port_regex = r"\bport\s+(\d+)\b"

def open_logs():
    
    with LOG_PATH.open("r", encoding="utf-8") as file:
        return [line.strip() for line in file]

def is_valid_ip(log):
    
    match = re.search(ip_regex, log)
                
    if not match:
        return None
                
    ip = match.group(0)
                
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        return None

def get_user(log):
    
    patterns = [
        r"Failed password for invalid user (?P<user>\S+)",
        r"Failed password for (?P<user>\S+)",
        r"Invalid user (?P<user>\S+)",
        r"Accepted password for (?P<user>\S+)",
    ]
                
    for pattern in patterns:
        match = re.search(pattern, log, re.IGNORECASE)

        if match:
            return match.group("user")

    return None
               

def get_event_type(log):
    
    log_lower = log.lower()

    if "failed password for invalid user" in log_lower:
        return "failed_invalid_user"
    elif "failed password" in log_lower:
        return "failed_login"
    elif "invalid user" in log_lower:
        return "invalid_user"
    elif "accepted password" in log_lower:
        return "accepted_login"
    else:
        return

def find_events(log_lines):
    events = []

    for log in log_lines:
        
        event_type = get_event_type(log)
        
        if event_type is None:
            continue
        
        port_match = re.search(port_regex, log)
        port = int(port_match.group(1)) if port_match else None
        
        event = {
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
        if event["type"] == "failed_login":
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
    
def print_events(events):
    
    for event in events:
        print("=" * 50)
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
    

if __name__ == "__main__":
    log_lines = open_logs()
    events = find_events(log_lines)
    
    print_events(events)
    summary_events(events)