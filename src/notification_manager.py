"""
CloudSentinel Notification Manager

Responsible for displaying security alerts
and logging notifications.
"""

from datetime import datetime


LOG_FILE = "logs/notifications.log"


def send_notification(alert):
    """
    Display a security alert and save it to the notification log.
    """

    if not isinstance(alert, dict):
        print("[ERROR] Invalid alert format.")
        return False

    alert_type = alert.get(
        "event_type",
        alert.get("alert_type", "UNKNOWN")
    )

    severity = alert.get("severity", "UNKNOWN")

    message = alert.get(
        "message",
        "No message provided"
    )

    ip_address = alert.get(
        "ip_address",
        alert.get("source_ip", "Unknown")
    )

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    notification = (
        f"[{timestamp}] "
        f"Alert Type: {alert_type} | "
        f"Severity: {severity} | "
        f"IP: {ip_address} | "
        f"Message: {message}"
    )

    # Console notification
    print()
    print("=" * 60)
    print("CLOUDSENTINEL SECURITY ALERT")
    print("=" * 60)
    print(f"Time       : {timestamp}")
    print(f"Alert Type : {alert_type}")
    print(f"Severity   : {severity}")
    print(f"IP Address : {ip_address}")
    print(f"Message    : {message}")
    print("=" * 60)
    print()

    # Save notification to log file
    try:
        with open(LOG_FILE, "a") as log_file:
            log_file.write(notification + "\n")

    except OSError as error:
        print(f"[ERROR] Could not write notification log: {error}")
        return False

    return True


def notify_alert(alert):
    """
    Wrapper for sending an alert notification.
    """

    return send_notification(alert)


if __name__ == "__main__":

    test_alert = {
        "event_type": "BRUTE_FORCE",
        "severity": "HIGH",
        "message": "Multiple failed login attempts detected",
        "ip_address": "192.168.1.100"
    }

    print("[TEST] Sending notification...")

    result = send_notification(test_alert)

    if result:
        print("[TEST] Notification sent and logged successfully.")
    else:
        print("[TEST] Notification failed.")
