from pathlib import Path

from data.database import get_event_statistics, get_recent_events


REPORT_PATH = Path("reports/security_report.txt")


def generate_security_report():
    """
    Generate a security summary report from the CloudSentinel database.
    """

    statistics = get_event_statistics()
    recent_events = get_recent_events(10)

    report = []

    report.append("=" * 60)
    report.append("           CLOUDSENTINEL SECURITY REPORT")
    report.append("=" * 60)

    report.append("")
    report.append("SECURITY EVENT SUMMARY")
    report.append("-" * 60)

    report.append(f"Total Events       : {statistics['total_events']}")
    report.append(f"HIGH Events        : {statistics['high_events']}")
    report.append(f"MEDIUM Events      : {statistics['medium_events']}")
    report.append(f"LOW Events         : {statistics['low_events']}")
    report.append(f"Brute-Force Events : {statistics['brute_force_events']}")

    report.append("")
    report.append("RECENT SECURITY EVENTS")
    report.append("-" * 60)

    if not recent_events:
        report.append("No security events found.")

    else:
        for event in recent_events:

            event_id = event[0]
            timestamp = event[1]
            event_type = event[2]
            severity = event[3]
            message = event[4]
            source = event[5]
            ip_address = event[6]

            report.append(
                f"[ID {event_id}] "
                f"[{severity}] "
                f"{event_type} | "
                f"IP={ip_address} | "
                f"{source}"
            )

            report.append(f"    {timestamp}")
            report.append(f"    {message}")
            report.append("")

    report.append("=" * 60)
    report.append("End of CloudSentinel Security Report")
    report.append("=" * 60)

    return "\n".join(report)


def save_security_report(report):
    """
    Save the generated security report to a text file.
    """

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with open(REPORT_PATH, "w") as file:
        file.write(report)

    print(f"\nSecurity report saved to: {REPORT_PATH}")


if __name__ == "__main__":

    report = generate_security_report()

    print(report)

    save_security_report(report)
