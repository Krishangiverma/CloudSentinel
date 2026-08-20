from datetime import datetime


def send_alert(event):
    """
    Display a security alert for a detected event.
    """

    print("\n" + "=" * 50)
    print("🚨 CLOUDSENTINEL SECURITY ALERT 🚨")
    print("=" * 50)

    try:
        print(f"Severity : {event.severity}")
        print(f"Type     : {event.event_type}")
        print(f"Time     : {event.timestamp}")
        print(f"Message  : {event.message}")

    except AttributeError:
        print("Security Event:", event)

    print(f"Alert Time: {datetime.now()}")
    print("=" * 50)


def send_alerts(events):
    """
    Send alerts for all detected security events.
    """

    if not events:
        print("\n[INFO] No security alerts to send.")
        return

    print("\n--- Sending Security Alerts ---")

    for event in events:
        send_alert(event)
