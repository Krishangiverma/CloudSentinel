FAILED_KEYWORDS = [
    "failed",
    "authentication failure",
    "invalid user"
]


def detect_suspicious_event(log_line):
    log_line = log_line.lower()

    for keyword in FAILED_KEYWORDS:
        if keyword in log_line:
            return True

    return False


if __name__ == "__main__":
    test_log = "Failed password for invalid user admin"

    if detect_suspicious_event(test_log):
        print("🚨 ALERT: Suspicious authentication event detected!")
    else:
        print("Normal event")
