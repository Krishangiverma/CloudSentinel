"""
CloudSentinel Notification Manager

Responsible for displaying security alerts,
logging notifications, preventing duplicates,
and applying alert cooldowns.
"""

from datetime import datetime, timedelta
import os


LOG_FILE = "logs/notifications.log"

# Automatically create logs directory if it does not exist
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# Cooldown period for repeated alerts
COOLDOWN_SECONDS = 60

# Store the last notification time for each alert
_last_notification_times = {}


def _get_alert_key(alert):
    """
    Create a unique key for an alert.
    """

    return (
        alert.get("event_type", alert.get("alert_type", "UNKNOWN")),
        alert.get("severity", "UNKNOWN"),
        alert.get(
            "ip_address",
            alert.get("source_ip", "Unknown")
        ),
        alert.get("message", "No message provided"),
    )


def send_notification(alert):
    """
    Display and log a security alert.

    Repeated alerts are ignored during the cooldown period.
    """

    if not isinstance(alert, dict):
        print("[ERROR] Invalid alert format.")
        return False

    alert_key = _get_alert_key(alert)
    current_time = datetime.now()

    # Check cooldown
    last_time = _last_notification_times.get(alert_key)

    if last_time is not None:
        elapsed_time = current_time - last_time

        if elapsed_time < timedelta(seconds=COOLDOWN_SECONDS):
            remaining = (
                COOLDOWN_SECONDS - elapsed_time.total_seconds()
            )

            print(
                "[INFO] Alert cooldown active. "
                f"Notification skipped ({remaining:.1f}s remaining)."
            )

            return False

    # Update last notification time
    _last_notification_times[alert_key] = current_time

    alert_type = alert.get(
        "event_type",
        alert.get("alert_type", "UNKNOWN")
    )

    severity = alert.get(
        "severity",
        "UNKNOWN"
    )

    message = alert.get(
        "message",
        "No message provided"
    )

    ip_address = alert.get(
        "ip_address",
        alert.get("source_ip", "Unknown")
    )

    timestamp = current_time.strftime("%Y-%m-%d %H:%M:%S")

    # Display notification
    print()
    print("=" * 60)
    print("CLOUDSENTINEL SECURITY ALERT")
    print("=" * 60)
    print(f"Time        : {timestamp}")
    print(f"Alert Type  : {alert_type}")
    print(f"Severity    : {severity}")
    print(f"IP Address  : {ip_address}")
    print(f"Message     : {message}")
    print("=" * 60)

    # Log notification
    try:
        with open(LOG_FILE, "a") as log_file:
            log_file.write(
                f"[{timestamp}] "
                f"Alert Type: {alert_type} | "
                f"Severity: {severity} | "
                f"IP: {ip_address} | "
                f"Message: {message}\n"
            )
    except OSError as error:
        print(f"[ERROR] Failed to write notification log: {error}")
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
        "ip_address": "192.168.1.100",
    }

    print("=" * 60)
    print("CloudSentinel Notification Manager Test")
    print("=" * 60)

    print("\n[TEST 1] First notification:")

    result1 = send_notification(test_alert)

    print(
        f"Result: {'SENT' if result1 else 'SKIPPED'}"
    )

    print("\n[TEST 2] Immediate duplicate:")

    result2 = send_notification(test_alert)

    print(
        f"Result: {'SENT' if result2 else 'SKIPPED'}"
    )

    print("\nCooldown configured for:")
    print(f"{COOLDOWN_SECONDS} seconds")

    print("\n" + "=" * 60)
