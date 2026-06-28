import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import re
import ipaddress
from dateutil import parser as dateparser
from datetime import datetime

from assets.event_types_assets import EVENT_PATTERNS
from assets.get_user_assets import patterns

ip_regex = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
ipv6_regex = re.compile(r'[0-9a-fA-F:]{2,39}')
port_regex = r"\bport\s+(\d+)\b"

def open_logs(log_path):
    with Path(log_path).open("r", encoding="utf-8") as file:
        return [line.strip() for line in file]

def is_valid_ip(log):
    match = re.search(ip_regex, log)
    if match:
        try:
            ipaddress.ip_address(match.group(0))
            return match.group(0)
        except ValueError:
            pass

    for candidate in ipv6_regex.findall(log):
        try:
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
            "time"   : time_stamp(log),
            "type"   : event_type,
            "ip"     : is_valid_ip(log),
            "user"   : get_user(log),
            "port"   : port,
            "raw"    : log,
            "source" : "pam_unix" if "pam_unix" in log else "sshd"
        }
        events.append(event)
    return events