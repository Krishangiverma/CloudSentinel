import subprocess
from detector import detect_suspicious_event
from brute_force import detect_brute_force

LOG_FILE = "/var/log/auth.log"


def collect_logs():
    result = subprocess.run(
        ["sudo", "tail", "-n", "20", LOG_FILE],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("Error reading security logs.")
        return []

    return result.stdout.splitlines()


def main():
    print("=== CloudSentinel Security Monitor ===")

    logs = collect_logs()

    print("\n--- Event Analysis ---")

    for log in logs:
        if detect_suspicious_event(log):
            print("🚨 SUSPICIOUS:", log)

    brute_force, failed_count = detect_brute_force(logs)

    print("\n--- Brute-Force Analysis ---")

    if brute_force:
        print(
            f"🚨 ALERT: Possible brute-force attack detected! "
            f"Failed attempts: {failed_count}"
        )
    else:
        print(
            f"Normal: Failed authentication attempts: {failed_count}"
        )


if __name__ == "__main__":
    main()
