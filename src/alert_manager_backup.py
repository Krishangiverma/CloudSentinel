from datetime import datetime


def generate_alert(event):
    """
    Generate a security alert from a detected SecurityEvent.
    """

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Get event information safely
    event_type = getattr(event, "event_type", "UNKNOWN")
    severity = getattr(event, "severity", "UNKNOWN")
    message = getattr(event, "message", str(event))

    # HIGH severity events
    if severity == "HIGH":
        return (
            f"[ALERT] {timestamp} | "
            f"SEVERITY: HIGH | "
            f"TYPE: {event_type} | "
            f"{message}"
        )

    # Medium severity events
    elif severity == "MEDIUM":
        return (
            f"[WARNING] {timestamp} | "
            f"SEVERITY: MEDIUM | "
            f"TYPE: {event_type} | "
            f"{message}"
        )

    # Low / informational events
    else:
        return (
            f"[INFO] {timestamp} | "
            f"SEVERITY: {severity} | "
            f"TYPE: {event_type} | "
            f"{message}"
        )


def process_alerts(events):
    """
    Generate alerts for a list of security events.
    """

    alerts = []

    for event in events:
        alert = generate_alert(event)
        alerts.append(alert)

    return alerts


def save_alerts(alerts, filename="reports/security_alerts.txt"):
    """
    Save generated alerts to a file.
    """

    with open(filename, "w") as alert_file:
        alert_file.write("CloudSentinel Security Alerts\n")
        alert_file.write("=" * 50 + "\n\n")

        for alert in alerts:
            alert_file.write(alert + "\n")

    return filename
