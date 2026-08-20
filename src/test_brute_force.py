from brute_force import detect_brute_force


# Fake failed-login logs for testing
test_logs = [
    "Failed password for user krishangi",
    "Failed password for user krishangi",
    "Failed password for user krishangi",
    "Failed password for user krishangi",
    "Failed password for user krishangi",
    "Failed password for user krishangi",
]


print("=== CloudSentinel Brute Force Test ===")

event = detect_brute_force(test_logs)

if event is not None:
    print("\n[ALERT] Brute-force attack detected!")

    try:
        event.display()
    except AttributeError:
        print(event)

else:
    print("\n[OK] No brute-force attack detected.")
