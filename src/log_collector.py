LOG_FILE = "/var/log/auth.log"


def read_logs():
    with open(LOG_FILE, "r") as file:
        return file.readlines()


def detect_failed_logins(logs):
    failed_logins = []

    for log in logs:
        if "Failed password" in log:
            failed_logins.append(log.strip())

    return failed_logins


def main():
    logs = read_logs()

    failed_logins = detect_failed_logins(logs)

    print(f"Total logs: {len(logs)}")
    print(f"Failed login attempts: {len(failed_logins)}")

    print("\nFailed Login Events:")

    for event in failed_logins[-10:]:
        print(event)


if __name__ == "__main__":
    main()
