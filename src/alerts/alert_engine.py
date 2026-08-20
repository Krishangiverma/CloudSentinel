from src.data.database import get_all_events


def generate_alerts():
    """
    Generate security alerts from stored events.
    """

    events = get_all_events()

    if not events:
        print("No events found. No alerts generated.")
        return

    alerts = []

    for event in events:
        event_id = event[0]
        timestamp = event[1]
        event_type = event[2]
        severity = event[3]
        message = event[4]
        source = event[5]

        if severity == "HIGH":
            alert = {
                "event_id": event_id,
                "timestamp": timestamp,
                "event_type": event_type,
                "severity": severity,
                "message": message,
                "source": source
            }

            alerts.append(alert)

    print("\n=== CloudSentinel Alert Engine ===")

    if not alerts:
        print("No security alerts detected.")
        return

    print(f"Total alerts generated: {len(alerts)}")

    print("\n--- Security Alerts ---")

    for alert in alerts:
        print(
            f"[ALERT] "
            f"ID={alert['event_id']} | "
            f"Severity={alert['severity']} | "
            f"Type={alert['event_type']} | "
            f"Message={alert['message']}"
        )

    print("\nAlert generation completed.")


if __name__ == "__main__":
    generate_alerts()
