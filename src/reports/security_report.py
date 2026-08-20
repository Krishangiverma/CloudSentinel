from datetime import datetime
from pathlib import Path

from src.data.database import get_all_events


REPORT_PATH = Path("reports/security_report.txt")


def generate_security_report():
    """
    Generate a security report from database events.
    """

    events = get_all_events()

    total_events = len(events)

    high_count = 0
    medium_count = 0
    low_count = 0

    event_types = {}

    for event in events:
        event_type = event[2]
        severity = event[3]

        # Count severity
        if severity == "HIGH":
            high_count += 1
        elif severity == "MEDIUM":
            medium_count += 1
        elif severity == "LOW":
            low_count += 1

        # Count event types
        if event_type not in event_types:
            event_types[event_type] = 0

        event_types[event_type] += 1

    # Make sure reports directory exists
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Create report
    report = []

    report.append("=" * 60)
    report.append("           CLOUDSENTINEL SECURITY REPORT")
    report.append("=" * 60)
    report.append("")
    report.append(f"Report Generated: {datetime.now()}")
    report.append("")

    report.append("--- SECURITY SUMMARY ---")
    report.append(f"Total Events : {total_events}")
    report.append(f"HIGH         : {high_count}")
    report.append(f"MEDIUM       : {medium_count}")
    report.append(f"LOW          : {low_count}")
    report.append("")

    report.append("--- EVENT TYPE SUMMARY ---")

    if event_types:
        for event_type, count in event_types.items():
            report.append(f"{event_type:<25} : {count}")
    else:
        report.append("No events found.")

    report.append("")

    report.append("--- SECURITY STATUS ---")

    if high_count > 0:
        report.append("ALERT: High severity security events detected!")
    else:
        report.append("STATUS: No high severity events detected.")

    report.append("")

    report.append("--- HIGH SEVERITY EVENTS ---")

    high_events = [event for event in events if event[3] == "HIGH"]

    if high_events:
        for event in high_events:
            event_id = event[0]
            timestamp = event[1]
            event_type = event[2]
            message = event[4]

            report.append(
                f"ID={event_id} | "
                f"{timestamp} | "
                f"{event_type} | "
                f"{message}"
            )
    else:
        report.append("No high severity events.")

    report.append("")
    report.append("=" * 60)
    report.append("           END OF SECURITY REPORT")
    report.append("=" * 60)

    # Save report
    REPORT_PATH.write_text("\n".join(report), encoding="utf-8")

    print("=== CloudSentinel Security Report ===")
    print(f"Report generated successfully.")
    print(f"Location: {REPORT_PATH}")
    print(f"Total events: {total_events}")
    print(f"High severity events: {high_count}")
    print(f"Medium severity events: {medium_count}")
    print(f"Low severity events: {low_count}")


if __name__ == "__main__":
    generate_security_report()
