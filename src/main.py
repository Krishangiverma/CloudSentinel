from log_collector import collect_logs
from detector import detect_suspicious_event
from brute_force import detect_brute_force
from system_monitor import get_system_metrics
from alert_manager import process_alerts, save_alerts


def main():

    print("\n==========================================")
    print("          CloudSentinel Security")
    print("==========================================")

    # ----------------------------------------
    # 1. System Monitoring
    # ----------------------------------------

    print("\n--- System Monitoring ---")

    metrics = get_system_metrics()

    print(f"CPU Usage: {metrics['cpu_percent']}%")
    print(f"Memory Usage: {metrics['memory_percent']}%")
    print(f"Disk Usage: {metrics['disk_percent']}%")

    # ----------------------------------------
    # 2. Collect Security Logs
    # ----------------------------------------

    print("\n--- Security Log Collection ---")

    logs = collect_logs()

    if logs is None:
        print("No logs collected.")
        logs = []

    print(f"Collected {len(logs)} log entries.")

    # ----------------------------------------
    # 3. Suspicious Event Detection
    # ----------------------------------------

    print("\n--- Security Events ---")

    events = []

    for log in logs:

        event = detect_suspicious_event(log)

        if event is not None:

            events.append(event)

            try:
                event.display()

            except AttributeError:
                print(event)

    # ----------------------------------------
    # 4. Brute Force Detection
    # ----------------------------------------

    print("\n--- Brute Force Detection ---")

    brute_force_event = detect_brute_force(logs)

    if brute_force_event is not None:

        events.append(brute_force_event)

        try:
            brute_force_event.display()

        except AttributeError:
            print(brute_force_event)

    else:
        print("No brute-force attack detected.")

    # ----------------------------------------
    # 5. Save Security Report
    # ----------------------------------------

    print("\n--- Saving Security Report ---")

    with open("reports/security_report.txt", "w") as report:

        report.write("CloudSentinel Security Report\n")
        report.write("=" * 40 + "\n\n")

        # System Information
        report.write("SYSTEM MONITORING\n")
        report.write("-" * 40 + "\n")

        report.write(
            f"CPU Usage: {metrics['cpu_percent']}%\n"
        )

        report.write(
            f"Memory Usage: {metrics['memory_percent']}%\n"
        )

        report.write(
            f"Disk Usage: {metrics['disk_percent']}%\n"
        )

        report.write("\n")

        # Security Events
        report.write("SECURITY EVENTS\n")
        report.write("-" * 40 + "\n")

        for event in events:

            report.write(str(event))
            report.write("\n")

        report.write("\n")

        # Final Count
        report.write("=" * 40 + "\n")

        report.write(
            f"Total security events detected: {len(events)}\n"
        )

        report.write("=" * 40 + "\n")

    print("Security report saved to:")
    print("reports/security_report.txt")

    # ----------------------------------------
    # 6. Final Result
    # ----------------------------------------

    print("\n==========================================")
    print(
        f"Total security events detected: {len(events)}"
    )
    print("==========================================")

    # ----------------------------------------
    # 7. Automated Security Alerts
    # ----------------------------------------

    print("\n--- Security Alerts ---")

    alerts = process_alerts(events)

    if alerts:

        for alert in alerts:
            print(alert)

        save_alerts(alerts)

        print("\nSecurity alerts saved to:")
        print("reports/security_alerts.txt")

    else:

        print("No security alerts generated.")


if __name__ == "__main__":
    main()
