from datetime import datetime

from event import SecurityEvent
from alert_manager import process_alerts, save_alerts


def main():
    event = SecurityEvent(
        timestamp=datetime.now(),
        event_type="BRUTE_FORCE",
        severity="CRITICAL",
        message="Multiple failed SSH login attempts detected"
    )

    alerts = process_alerts([event])

    print("\n--- Generated Alerts ---")

    for alert in alerts:
        print(alert)

    save_alerts(alerts)

    print("\nAlert saved successfully.")


if __name__ == "__main__":
    main()
