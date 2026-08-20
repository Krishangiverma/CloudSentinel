from log_collector import collect_logs
from detector import detect_suspicious_event
from brute_force import detect_brute_force
from system_monitor import get_system_metrics
from alert_manager import process_alerts, save_alerts
from data.database import initialize_database, save_event


def main():

    # ============================================================
    # CLOUDSENTINEL START
    # ============================================================

    print("\n==============================================")
    print("          CloudSentinel Security")
    print("==============================================")

    # ============================================================
    # 0. INITIALIZE DATABASE
    # ============================================================

    print("\n--- Database Initialization ---")

    initialize_database()

    # ============================================================
    # 1. SYSTEM MONITORING
    # ============================================================

    print("\n--- System Monitoring ---")

    metrics = get_system_metrics()

    print(f"CPU Usage: {metrics['cpu_percent']}%")
    print(f"Memory Usage: {metrics['memory_percent']}%")
    print(f"Disk Usage: {metrics['disk_percent']}%")

    # ============================================================
    # 2. SECURITY LOG COLLECTION
    # ============================================================

    print("\n--- Security Log Collection ---")

    logs = collect_logs()

    if logs is None:
        print("No logs collected.")
        logs = []

    print(f"Collected {len(logs)} log entries.")

    # ============================================================
    # 3. SUSPICIOUS EVENT DETECTION
    # ============================================================

    print("\n--- Security Events ---")

    events = []

    for log in logs:

        event = detect_suspicious_event(log)

        if event is not None:

            # Add event to current run
            events.append(event)

            # Save event permanently to database
            save_event(event)

            # Display event
            try:
                event.display()
            except AttributeError:
                print(event)

    # ============================================================
    # 4. BRUTE FORCE DETECTION
    # ============================================================

    print("\n--- Brute Force Detection ---")

    brute_force_event = detect_brute_force(logs)

    if brute_force_event is not None:

        # Add brute-force event to current run
        events.append(brute_force_event)

        # Save brute-force event permanently
        save_event(brute_force_event)

        # Display brute-force event
        try:
            brute_force_event.display()
        except AttributeError:
            print(brute_force_event)

    else:

        print("No brute-force attack detected.")

    # ============================================================
    # 5. SAVE SECURITY REPORT
    # ============================================================

    print("\n--- Saving Security Report ---")

    with open("reports/security_report.txt", "w") as report:

        report.write("CloudSentinel Security Report\n")
        report.write("=" * 40 + "\n\n")

        # --------------------------------------------------------
        # System Information
        # --------------------------------------------------------

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

        # --------------------------------------------------------
        # Security Events
        # --------------------------------------------------------

        report.write("SECURITY EVENTS\n")
        report.write("-" * 40 + "\n")

        if events:

            for event in events:

                report.write(str(event))
                report.write("\n")

        else:

            report.write("No security events detected.\n")

        report.write("\n")

        # --------------------------------------------------------
        # Final Count
        # --------------------------------------------------------

        report.write("SUMMARY\n")
        report.write("-" * 40 + "\n")

        report.write(
            f"Total security events detected: {len(events)}\n"
        )

    print("Security report saved to:")
    print("reports/security_report.txt")

    # ============================================================
    # 6. FINAL RESULT
    # ============================================================

    print("\n==============================================")
    print(
        f"Total security events detected: {len(events)}"
    )
    print("==============================================")

    # ============================================================
    # 7. AUTOMATED SECURITY ALERTS
    # ============================================================

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


# ================================================================
# PROGRAM ENTRY POINT
# ================================================================

if __name__ == "__main__":
    main()
