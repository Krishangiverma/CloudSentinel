FAILED_KEYWORDS = [
    "failed",
    "authentication failure",
    "invalid user"
]


def detect_brute_force(logs, threshold=3):
    failed_count = 0

    for log in logs:
        log = log.lower()

        for keyword in FAILED_KEYWORDS:
            if keyword in log:
                failed_count += 1
                break

    if failed_count >= threshold:
        return True, failed_count

    return False, failed_count
