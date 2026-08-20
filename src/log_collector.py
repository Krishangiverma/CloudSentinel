import subprocess

LOG_FILE = "/var/log/auth.log"


def collect_logs():
    result = subprocess.run(
        ["sudo", "tail", "-n", "20", LOG_FILE],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("Error reading security logs.")
        return []

    print("=== CloudSentinel Security Logs ===")
    print(result.stdout)

    return result.stdout.splitlines()


if __name__ == "__main__":
    collect_logs()
