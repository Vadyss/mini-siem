patterns = [
    # --- Authentication failures ---
    r"Failed password for invalid user (?P<user>\S+)",
    r"Failed password for (?P<user>\S+)",
    r"Failed publickey for invalid user (?P<user>\S+)",
    r"Failed publickey for (?P<user>\S+)",
    r"Failed keyboard-interactive/pam for invalid user (?P<user>\S+)",
    r"Failed keyboard-interactive/pam for (?P<user>\S+)",
    r"Failed none for (?P<user>\S+)",
    r"authentication failure.*user=(?P<user>\S+)",
    r"PAM: Authentication failure for (?:illegal user )?(?P<user>\S+)",
    r"pam_unix.*authentication failure.*user=(?P<user>\S+)",
    r"Maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S+)",

    # --- Invalid / unknown users ---
    r"Invalid user (?P<user>\S+)",
    r"User (?P<user>\S+) from .+ not allowed because not listed in AllowUsers",
    r"User (?P<user>\S+) not allowed because account is locked",
    r"User (?P<user>\S+) not allowed because shell \S+ is not executable",
    r"Illegal user (?P<user>\S+)",

    # --- Successful authentication ---
    r"Accepted password for (?P<user>\S+)",
    r"Accepted publickey for (?P<user>\S+)",
    r"Accepted keyboard-interactive/pam for (?P<user>\S+)",
    r"Accepted gssapi-with-mic for (?P<user>\S+)",
    r"Accepted hostbased for (?P<user>\S+)",
    r"PAM: Accepted for (?P<user>\S+)",

    # --- Session lifecycle ---
    r"session (?:opened|closed) for user (?P<user>\S+)",
    r"pam_unix\(sshd:session\): session (?:opened|closed) for user (?P<user>\S+)",
    r"Starting session: \S+ for (?P<user>\S+)",
    r"Close session: user (?P<user>\S+)",

    # --- Disconnects ---
    r"Disconnected from user (?P<user>\S+)",
    r"Disconnected from invalid user (?P<user>\S+)",
    r"Received disconnect from .+ port \d+:\d+: .+ \[preauth\].*user (?P<user>\S+)",
    r"Connection closed by invalid user (?P<user>\S+)",
    r"Connection closed by user (?P<user>\S+)",
    r"Connection reset by invalid user (?P<user>\S+)",
    r"Connection reset by user (?P<user>\S+)",

    # --- Privilege escalation / sudo / su ---
    r"sudo:.*USER=(?P<user>\S+)",
    r"sudo:.*user=(?P<user>\S+)",
    r"su\[.*\]: \S+ to (?P<user>\S+)",
    r"su\[.*\]: pam_unix.*; user (?P<user>\S+)",
    r"pam_unix\(su(?:-l)?:auth\): authentication failure.*user=(?P<user>\S+)",

    # --- Brute-force / blocking signals ---
    r"error: maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S+)",
    r"Postponed \S+ for (?:invalid user )?(?P<user>\S+)",
    r"Did not receive identification string from .+.*user (?P<user>\S+)",

    # --- Misc / other relevant patterns ---
    r"User (?P<user>\S+) authenticated",
    r"Received disconnect for (?P<user>\S+) from",
    r"subsystem request for sftp by user (?P<user>\S+)",
    r"command=.* by user (?P<user>\S+)",
    r"Forced command .* for user (?P<user>\S+)",
    r"Changed uid to (?:\d+) \((?P<user>\S+)\)",
]