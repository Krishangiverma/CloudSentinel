from datetime import datetime


def calculate_risk(event):
    """
    Calculate a risk score based on the security event.
    """

    if event.event_type == "BRUTE_FORCE":
        return 90

    if event.event_type == "FAILED_LOGIN":
        return 50

    if event.severity == "CRITICAL":
        return 100

    if event.severity == "HIGH":
        return 80

    if event.severity == "MEDIUM":
        return 50

    if event.severity == "LOW":
        return 20

    return 10


def get_priority(risk_score):
    """
    Convert risk score into a security priority.
    """

    if risk_score >= 90:
        return "CRITICAL"

    if risk_score >= 70:
        return "HIGH"

    if risk_score >= 40:
        return "MEDIUM"

    return "LOW"


def generate_alert(event):
    """
    Convert a security event into a structured security alert.
    """

    alert_id = "ALERT-" + datetime.now().strftime("%Y%m%d%H%M%S%f")

    risk_score = calculate_risk(event)
    priority = get_priority(risk_score)

    alert = {
        "alert_id": alert_id,
        "timestamp": datetime.now().isoformat(),
        "severity": event.severity,
        "priority": priority,
        "risk_score": risk_score,
        "event_type": event.event_type,
        "message": event.message
    }

    return alert


def process_alerts(events):
    """
    Process all detected security events
    and generate structured alerts.
    """

    alerts = []

    for event in events:
        alert = generate_alert(event)
        alerts.append(alert)

    return alerts


def format_alert(alert):
    """
    Convert an alert dictionary into a readable string.
    """

    return (
        f"[{alert['priority']}] "
        f"{alert['alert_id']} | "
        f"{alert['timestamp']} | "
        f"SEVERITY: {alert['severity']} | "
        f"RISK: {alert['risk_score']} | "
        f"TYPE: {alert['event_type']} | "
        f"{alert['message']}"
    )


def save_alerts(alerts):
    """
    Save generated security alerts to a file.
    """

    with open("reports/security_alerts.txt", "w") as file:

        file.write("CloudSentinel Security Alerts\n")
        file.write("=" * 70 + "\n\n")

        for alert in alerts:
            file.write(format_alert(alert))
            file.write("\n")

        file.write("\n")
        file.write("=" * 70 + "\n")
        file.write(f"Total alerts: {len(alerts)}\n")
