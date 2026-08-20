from log_collector import collect_logs
from detector import analyze_logs


def run_cloudsentinel():
    print("===================================")
    print("      CloudSentinel Security Scan")
    print("===================================")

    # Step 1: Collect logs from multiple sources
    logs = collect_logs()

    print("\n=== Detection Engine ===")

    # Step 2: Analyze collected logs
    events = analyze_logs(logs)

    # Step 3: Display detected events
    if events:
        print(f"\nDetected {len(events)} suspicious events:\n")

        for event in events:
            event.display()

    else:
        print("No suspicious events detected.")

    print("\n===================================")
    print("       Scan Completed")
    print("===================================")


if __name__ == "__main__":
    run_cloudsentinel()
