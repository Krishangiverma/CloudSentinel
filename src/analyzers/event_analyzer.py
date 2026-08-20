from src.data.database import get_all_events


def analyze_events():
    """
    Analyze security events stored in the database.
    """

    events = get_all_events()

    if not events:
        print("No security events found.")
        return

    total_events = len(events)

    severity_count = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    event_type_count = {}

    for event in events:
        severity = event[3]
        event_type = event[2]

        # Count severity
        if severity in severity_count:
            severity_count[severity] += 1

        # Count event types
        if event_type not in event_type_count:
            event_type_count[event_type] = 0

        event_type_count[event_type] += 1

    print("\n=== CloudSentinel Security Analysis ===")
    print(f"Total Events: {total_events}")

    print("\n--- Severity Summary ---")
    print(f"HIGH:   {severity_count['HIGH']}")
    print(f"MEDIUM: {severity_count['MEDIUM']}")
    print(f"LOW:    {severity_count['LOW']}")

    print("\n--- Event Type Summary ---")

    for event_type, count in event_type_count.items():
        print(f"{event_type}: {count}")

    print("\n--- Security Status ---")

    if severity_count["HIGH"] > 0:
        print("⚠️ ALERT: High severity security events detected!")
    else:
        print("✅ No high severity events detected.")

    print("\nAnalysis completed.")


if __name__ == "__main__":
    analyze_events()
