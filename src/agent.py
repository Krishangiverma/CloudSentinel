import time

LOG_FILE = "/var/log/auth.log"


def monitor_logs():
    print("CloudSentinel Agent started...")
    print(f"Monitoring: {LOG_FILE}")

    with open(LOG_FILE, "r") as log:
        log.seek(0, 2)

        while True:
            line = log.readline()

            if line:
                print("NEW EVENT:", line.strip())
            else:
                time.sleep(1)


if __name__ == "__main__":
    monitor_logs()
