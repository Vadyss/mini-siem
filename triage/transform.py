import json
import sys
import pathlib

data = json.load(sys.stdin)
events = []

for entery in data["potential_brute_force"]:
    for subject, details in entery.items():
        events.append({
            "event_id": f"bf_{subject}",
            "category": "potential_brute_force",
            "subject": subject,
            "subject_type": "ip",
            "count": details["count"],
            "severity_heuristic": details["severity"],
            "first_seen": details["first_seen"],
            "last_seen": details["last_seen"],
            "associated_values": details["usernames_tried"],
            "sample_raw_logs": details["sample_raw_logs"],
            "ports": details["ports"],
            "ground_truth_severity": None,
            "ground_truth_label": None
        })
        
for entery in data["compromise"]:
    for subject, details in entery.items():
        events.append({
            "event_id": f"comp_{subject}",
            "category": "compromise",
            "subject": subject,
            "subject_type": "ip",
            "count": details["count"],
            "severity_heuristic": details["severity"],
            "first_seen": details["first_seen"],
            "last_seen": details["last_seen"],
            "associated_values": details["usernames_tried"],
            "sample_raw_logs": details["sample_raw_logs"],
            "ports": details["ports"],
            "ground_truth_severity": None,
            "ground_truth_label": None
        })

for entery in data["spray"]:
    for subject, details in entery.items():
        events.append({
            "event_id": f"spray_{subject}",
            "category": "spray",
            "subject": subject,
            "subject_type": "username",
            "count": details["count"],
            "severity_heuristic": details["severity"],
            "first_seen": details["first_seen"],
            "last_seen": details["last_seen"],
            "associated_values": details["source_ips"],
            "sample_raw_logs": details["sample_raw_logs"],
            "ports": details["ports"],
            "ground_truth_severity": None,
            "ground_truth_label": None
        })

output_path = pathlib.Path(__file__).parent / "data" / "events.json"
output_path.parent.mkdir(exist_ok=True)

with open(output_path, "w") as f:
    json.dump(events, f, indent=2)
    
print(f"{len(events)} events write → {output_path}")