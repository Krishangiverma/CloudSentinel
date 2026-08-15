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

    print("\n--- Security Events ---")

    events = []

    for log in logs:
        event = detect_suspicious_event(log)

        if event:
            events.append(event)
            event.display()

    brute_force_event = detect_brute_force(logs)

    if brute_force_event:
        events.append(brute_force_event)
        brute_force_event.display()

    print(f"\nTotal security events detected: {len(events)}")


if __name__ == "__main__":
    main()
