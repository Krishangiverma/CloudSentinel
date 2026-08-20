import time
from pathlib import Path

from config.settings import AUTH_LOG_PATH


def monitor_log():
    """Continuously monitor auth.log for new entries."""

    log_path = Path(AUTH_LOG_PATH)

    if not log_path.exists():
        print(f"[ERROR] Log file not found: {log_path}")
        return

    print("====================================")
    print("     CloudSentinel Real-Time Monitor")
    print("====================================")
    print(f"[INFO] Monitoring: {log_path}")
    print("[INFO] Waiting for new log entries...")
    print("[INFO] Press Ctrl+C to stop.\n")

    try:
        with open(log_path, "r", errors="ignore") as file:

            # Move to the end of the file.
            # We only want NEW entries.
            file.seek(0, 2)

            while True:
                line = file.readline()

                if not line:
                    time.sleep(1)
                    continue

                line = line.strip()

                if line:
                    print(f"[NEW LOG] {line}")

    except KeyboardInterrupt:
        print("\n[INFO] Real-time monitoring stopped.")

    except PermissionError:
        print("[ERROR] Permission denied while reading auth.log.")
        print("[INFO] Try running the monitor with sudo.")


if __name__ == "__main__":
    monitor_log()
