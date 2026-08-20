import subprocess
import os


LOG_FILES = {
    "auth.log": "/var/log/auth.log",
    "syslog": "/var/log/syslog",
}


def collect_file_logs(log_name, log_file, lines=20):
    """
    Collect the latest security-related logs from a log file.
    """

    if not os.path.exists(log_file):
        print(f"[WARNING] {log_name} not found: {log_file}")
        return []

    try:
        result = subprocess.run(
            ["sudo", "tail", "-n", str(lines), log_file],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            print(f"[ERROR] Could not read {log_name}.")
            return []

        logs = result.stdout.splitlines()

        print(f"\n=== CloudSentinel: {log_name} ===")

        if logs:
            for log in logs:
                print(log)
        else:
            print("No logs found.")

        return logs

    except Exception as e:
        print(f"[ERROR] Failed to collect {log_name}: {e}")
        return []


def collect_logs():
    """
    Collect logs from all configured sources.
    """

    all_logs = []

    for log_name, log_file in LOG_FILES.items():
        logs = collect_file_logs(log_name, log_file)

        for log in logs:
            all_logs.append({
                "source": log_name,
                "message": log
            })

    return all_logs


if __name__ == "__main__":

    collected_logs = collect_logs()

    print("\n=== CloudSentinel Collection Summary ===")
    print(f"Total logs collected: {len(collected_logs)}")

    for entry in collected_logs[:5]:
        print(
            f"[{entry['source']}] "
            f"{entry['message']}"
        )
