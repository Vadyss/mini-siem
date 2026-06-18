from pathlib import Path

def open_logs():
    logs = Path("logs/traning_logs_auth.log")
    log_lines = []

    with logs.open("r", encoding="utf-8") as file:
        for line in file:
            log_lines.append(line.strip())
            
    return log_lines

def find_error(log_lines):
    events = []

    for log in log_lines:
        if "Failed" in log or "failed" in log:
            
            words = log.split()
            words_length = len(words)
            
            if "failed" in words:
                failed_position = words.index("failed")
                if failed_position + 1 < words_length:
                    fail = f"{words[failed_position]} {words[failed_position + 1]}"
                else:
                    fail = words[failed_position]
            elif "Failed" in words:
                failed_position = words.index("Failed")
                if failed_position + 1 < words_length:
                    fail = f"{words[failed_position]} {words[failed_position + 1]}"
                else:
                    fail = words[failed_position]
            else:
                fail = None
            
            if "from" in words:
                ip_position = words.index("from")
                if ip_position + 1 < words_length:
                    error_ip = words[ip_position + 1]
                else:
                    error_ip = None
            else:
                error_ip = None
                
            if "for" in words:
                user_position = words.index("for")
                
                if user_position + 1 < words_length:
                    first_error_user = words[user_position + 1]
                    
                    if first_error_user == "invalid":
                        if user_position + 3 < words_length:
                            error_user = words[user_position + 3]
                        else:
                            error_user = None
                    else:
                        error_user = first_error_user
                else: error_user = None
            else:
                error_user = None
            
            if "port" in words:
                port_position = words.index("port")
                if port_position + 1 < words_length:
                    error_port = words[port_position + 1]
                else: 
                    error_port = None
            else:
                error_port = None
            
            if fail == "Failed password":
                event_type = "failed_login"
            else:
                event_type = "unknown"
            
            event = {
                "type" : event_type,
                "message" : fail,
                "ip" : error_ip,
                "user" : error_user,
                "port" : error_port,
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