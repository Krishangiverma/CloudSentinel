from datetime import datetime
from models.event import SecurityEvent


def generate_alert(event):
    """
    Generate a security alert for a detected security event.
    """

    if not isinstance(event, SecurityEvent):
        return

    print()
    print("=" * 75)
    print("                 🚨 CLOUDSENTINEL SECURITY ALERT")
    print("=" * 75)

    print(f"Time     : {event.timestamp}")
    print(f"Type     : {event.event_type}")
    print(f"Severity : {event.severity}")
    print(f"Source   : {event.source}")
    print(f"IP       : {event.ip_address}")
    print(f"Message  : {event.message}")

    print("=" * 75)


def process_event(event):
    """
    Process a security event and generate an alert
    when severity is HIGH.
    """

    if event.severity == "HIGH":
        generate_alert(event)
    else:
        print(
            f"[INFO] {event.event_type} event received "
            f"with severity {event.severity}."
        )


if __name__ == "__main__":

    test_event = SecurityEvent(
        timestamp=datetime.now(),
        event_type="BRUTE_FORCE",
        severity="HIGH",
        message="Brute-force attack detected from 192.168.1.50: 3 failed attempts",
        source="auth.log",
        ip_address="192.168.1.50"
    )

    process_event(test_event)
