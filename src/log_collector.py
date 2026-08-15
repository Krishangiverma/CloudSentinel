import time

LOG_FILE = "/var/log/auth.log"


def monitor_logs():
    with open(LOG_FILE, "r") as file:
        file.seek(0, 2)

        while True:
            line = file.readline()

            if not line:
                time.sleep(0.5)
                continue

            line = line.strip()

            if "Failed password" in line:
                print("🚨 Failed login detected!")
                print(line)


def main():
    print("CloudSentinel live monitoring started...")
    monitor_logs()


if __name__ == "__main__":
    main()
