EVENT_PATTERNS = [

    # === FAILED LOGIN ===
    ("failed password for invalid user",        "failed_invalid_user"),
    ("failed password for root",                "failed_root_login"),
    ("failed password",                         "failed_login"),
    ("failure; logname=",                       "pam_login_failure"),
    ("authentication failure",                  "auth_failure"),
    ("authorization failure",                   "auth_failure"),

    # === INVALID / UNKNOWN USER ===
    ("invalid user",                            "invalid_user"),
    ("user unknown",                            "user_unknown"),
    ("unknown user",                            "unknown_user"),
    ("illegal user",                            "illegal_user"),

    # === SUCCESSFUL LOGIN ===
    ("accepted password",                       "accepted_login"),
    ("accepted publickey for",                  "accepted_publickey"),
    ("accepted keyboard-interactive",           "accepted_keyboard_interactive"),
    ("accepted hostbased",                      "accepted_hostbased"),
    ("accepted gssapi-with-mic",                "accepted_gssapi"),

    # === PUBLICKEY / CERTIFICATE ===
    ("invalid public key from",                 "invalid_publickey"),
    ("invalid public key type",                 "invalid_publickey_type"),
    ("certificate invalid",                     "certificate_invalid"),
    ("certificate expired",                     "certificate_expired"),
    ("certificate revoked",                     "certificate_revoked"),
    ("key_load_public: invalid format",         "publickey_invalid_format"),
    ("userauth_pubkey: certificate signature",  "publickey_cert_sig_error"),
    ("temporarily denied connection for",       "temporarily_denied"),

    # === MAX ATTEMPTS / BRUTE FORCE ===
    ("maximum authentication attempts exceeded","max_auth_attempts"),
    ("too many authentication failures",        "max_auth_attempts"),
    ("repeated login failures",                 "repeated_login_failures"),
    ("blocked by tcp wrappers",                 "blocked_tcp_wrappers"),

    # === CONNECTION EVENTS ===
    ("connection closed by authenticating user","connection_closed_during_auth"),
    ("connection closed by invalid user",       "connection_closed_invalid_user"),
    ("connection closed by",                    "connection_closed"),
    ("connection reset by",                     "connection_reset"),
    ("connection from",                         "connection_from"),
    ("connection refused",                      "connection_refused"),
    ("refused connect from",                    "connection_refused_by_tcp_wrapper"),
    ("did not receive identification string from", "no_identification_string"),
    ("bad protocol version identification",     "bad_protocol_version"),
    ("protocol version mismatch",               "protocol_version_mismatch"),
    ("client sent invalid protocol identifier", "invalid_protocol_identifier"),
    ("no route to host",                        "no_route_to_host"),

    # === DISCONNECT ===
    ("received disconnect from",                "received_disconnect"),
    ("disconnected from invalid user",          "disconnected_invalid_user"),
    ("disconnected from authenticating user",   "disconnected_during_auth"),
    ("disconnected from",                       "disconnected"),
    ("client_loop: send disconnect: broken pipe","client_broken_pipe"),
    ("timeout, client not responding",          "client_timeout"),
    ("connection timed out",                    "connection_timeout"),

    # === SESSION ===
    ("session opened for user root",            "root_session_opened"),
    ("session opened for",                      "session_opened"),
    ("session closed for user root",            "root_session_closed"),
    ("session closed for",                      "session_closed"),

    # === REVERSE DNS / MAPPING ===
    ("reverse mapping checking getaddrinfo for","reverse_mapping_fail"),
    ("possible break-in attempt",               "possible_breakin_attempt"),
    ("address maps to",                         "dns_forward_mismatch"),
    ("cannot determine your domain name",       "dns_domain_unresolvable"),

    # === KEX / NEGOTIATION ===
    ("unable to negotiate with",                "kex_negotiation_failed"),
    ("no matching key exchange method found",   "kex_no_matching_method"),
    ("no matching cipher found",                "kex_no_matching_cipher"),
    ("no matching mac found",                   "kex_no_matching_mac"),
    ("no matching compression found",           "kex_no_matching_compression"),
    ("no supported authentication methods available", "no_auth_methods_available"),
    ("no hostkey alg",                          "no_hostkey_algorithm"),
    ("diffie-hellman group exchange failed",    "kex_dh_group_exchange_failed"),

    # === PORT FORWARDING / TUNNELING ===
    ("port forwarding",                         "port_forwarding"),
    ("open failed: administratively prohibited","tunnel_admin_prohibited"),
    ("direct-tcpip request from",               "direct_tcpip_request"),
    ("tcpip-forward request from",              "tcpip_forward_request"),
    ("forwarding failed",                       "forwarding_failed"),
    ("x11 forwarding request failed",           "x11_forwarding_failed"),
    ("x11 connection from",                     "x11_connection"),

    # === SFTP / SCP ===
    ("subsystem request for sftp",              "sftp_subsystem_request"),
    ("sftp-server: read",                       "sftp_read"),
    ("sftp-server: write",                      "sftp_write"),
    ("sftp-server: open",                       "sftp_open"),
    ("sftp-server: remove",                     "sftp_remove"),
    ("sftp-server: rename",                     "sftp_rename"),
    ("sftp-server: sent status no such file",   "sftp_no_such_file"),

    # === PAM ===
    ("pam_unix(sshd:auth): check pass",         "pam_check_pass"),
    ("pam_unix(sshd:auth): authentication failure", "pam_auth_failure"),
    ("pam_unix(sshd:session): session opened",  "pam_session_opened"),
    ("pam_unix(sshd:session): session closed",  "pam_session_closed"),
    ("pam_unix(su:session): session opened",    "pam_su_session_opened"),
    ("pam_unix(su:session): session closed",    "pam_su_session_closed"),
    ("pam_unix(sudo:session): session opened",  "pam_sudo_session_opened"),
    ("pam_unix(sudo:session): session closed",  "pam_sudo_session_closed"),
    ("pam_unix(cron:session): session opened",  "pam_cron_session_opened"),
    ("pam_unix(cron:session): session closed",  "pam_cron_session_closed"),
    ("pam_tally2",                              "pam_tally2"),
    ("pam_tally",                               "pam_tally_lockout"),
    ("pam_faillock",                            "pam_faillock"),
    ("pam_limits",                              "pam_limits"),
    ("pam_env",                                 "pam_env"),
    ("pam_systemd",                             "pam_systemd"),
    ("pam_keyinit",                             "pam_keyinit"),
    ("account is locked",                       "account_locked"),
    ("account has been locked",                 "account_locked"),
    ("user not allowed because account is locked","account_locked"),
    ("account expired",                         "account_expired"),
    ("password expired",                        "password_expired"),
    ("must change password",                    "password_must_change"),
    ("password change required",                "password_change_required"),

    # === SUDO ===
    ("sudo: pam_unix(sudo:auth): authentication failure", "sudo_auth_failure"),
    ("sudo: pam_unix",                          "sudo_pam_event"),
    ("sudo:session",                            "sudo_session"),
    ("incorrect password attempt",              "sudo_wrong_password"),
    ("command not allowed",                     "sudo_command_not_allowed"),
    ("user not in sudoers",                     "sudo_not_in_sudoers"),
    ("is not allowed to run sudo",              "sudo_not_allowed"),
    ("sudo: command not found",                 "sudo_command_not_found"),
    ("a root shell is not allowed",             "sudo_root_shell_denied"),
    ("sorry, you must have a tty",              "sudo_no_tty"),
    ("sorry, try again",                        "sudo_wrong_password"),
    ("3 incorrect password attempts",           "sudo_max_attempts"),
    ("sudo: refreshing credentials",            "sudo_credentials_refresh"),

    # === USER / GROUP MANAGEMENT ===
    ("new user:",                               "user_created"),
    ("new group:",                              "group_created"),
    ("delete user",                             "user_deleted"),
    ("removed group",                           "group_deleted"),
    ("usermod",                                 "user_modified"),
    ("add member to group",                     "group_member_added"),
    ("remove member from group",                "group_member_removed"),
    ("passwd: password changed for",            "password_changed"),
    ("password changed for root",               "root_password_changed"),
    ("chage:",                                  "password_aging_changed"),
    ("useradd:",                                "useradd"),
    ("userdel:",                                "userdel"),
    ("groupadd:",                               "groupadd"),
    ("groupdel:",                               "groupdel"),

    # === FILE / KEY PERMISSIONS ===
    ("bad ownership or modes for file",         "bad_file_permissions"),
    ("bad ownership or modes for directory",    "bad_directory_permissions"),
    ("bad file modes for",                      "bad_file_modes"),
    ("authentication refused: bad ownership",   "auth_refused_bad_ownership"),
    ("authorized_keys",                         "authorized_keys_event"),

    # === HOST KEY / KNOWN HOSTS ===
    ("warning: remote host identification has changed", "host_key_changed"),
    ("host key verification failed",            "host_key_verification_failed"),
    ("offending key in",                        "offending_key"),
    ("added to the list of known hosts",        "host_added_known_hosts"),

    # === SSHD DAEMON ===
    ("server listening on",                     "sshd_listening"),
    ("reloading",                               "sshd_reload"),
    ("received signal 15",                      "sshd_sigterm"),
    ("received signal 1",                       "sshd_sighup"),
    ("exiting on signal",                       "sshd_exit_signal"),
    ("could not load host key",                 "sshd_missing_host_key"),
    ("error loading protocol",                  "sshd_protocol_load_error"),
    ("sshd: fatal:",                            "sshd_fatal_error"),
    ("sshd: error:",                            "sshd_error"),

    # === CRON ===
    ("cron[",                                   "cron_event"),
    ("cmd (",                                   "cron_command"),
    ("cron: pam_unix",                          "cron_pam_event"),

    # === SU ===
    ("successful su for",                       "su_success"),
    ("su: authentication failure",              "su_auth_failure"),
    ("su: pam_unix",                            "su_pam_event"),
    ("bad su",                                  "su_bad"),
    ("su: no passwd entry for",                 "su_no_passwd_entry"),
]