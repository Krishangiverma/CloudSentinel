"""
CloudSentinel Main Application

Main entry point for the CloudSentinel security monitoring system.
"""

from src.alert_manager import process_alert


def main():
    print("=" * 60)
    print("              CloudSentinel Security Monitor")
    print("=" * 60)

    print()
    print("[INFO] CloudSentinel started.")
    print("[INFO] Alert Manager loaded successfully.")
    print()

    # ---------------------------------------------------------
    # Test security event
    # ---------------------------------------------------------

    test_event = {
        "event_type": "BRUTE_FORCE",
        "severity": "HIGH",
        "message": "Brute-force attack detected from 192.168.1.50: 5 failed attempts",
        "ip_address": "192.168.1.50"
    }

    print("-" * 60)
    print("[STEP 1] Processing security event...")
    print("-" * 60)

    try:
        alert = process_alert(test_event)

        print("[OK] Security event processed.")

        if alert:
            print("[OK] Security alert created and saved.")
            print()
            print("Alert Details:")
            print(f"  Event Type : {alert.event_type}")
            print(f"  Severity   : {alert.severity}")
            print(f"  Message    : {alert.message}")
            print(f"  IP Address : {alert.ip_address}")
        else:
            print("[INFO] No alert was created.")

    except Exception as error:
        print("[ERROR] Failed to process security event.")
        print(f"[ERROR] {error}")

    print()
    print("=" * 60)
    print("          CloudSentinel Main Test Completed")
    print("=" * 60)


if __name__ == "__main__":
    main()
