from pathlib import Path
import re
import ipaddress

LOG_PATH = Path("logs/traning_logs_auth.log")

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
        
        if not match:
            return None
        
        user = match
        
        if user:
            return user.group("user")
               

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
        return "unknown"

def find_error(log_lines):
    events = []

    for log in log_lines:
        
        if "failed" not in log.lower():
            continue  
            
        port = re.search(port_regex, log)
            
        event = {
            "type" : get_event_type(log),
            "ip" : is_valid_ip(log),
            "user" : get_user(log),
            "port" : port,
            "raw" : log
        }
                
        events.append(event)
        
    return events

if __name__ == "__main__":
    log_lines = open_logs()
    events = find_error(log_lines)

    print(events)
else:
    print("Error. __name__ != __main__")