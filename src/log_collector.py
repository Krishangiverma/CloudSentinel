import time
import sys

DEFAULT_LOG_FILE = "/var/log/auth.log"


def monitor_logs(log_file):
    with open(log_file, "r") as file:
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
    log_file = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_LOG_FILE

    print(f"CloudSentinel monitoring: {log_file}")
    monitor_logs(log_file)


if __name__ == "__main__":
    main()
