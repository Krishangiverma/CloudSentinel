from brute_force import detect_brute_force


test_logs = [
    "Failed password for invalid user admin",
    "Failed password for invalid user test",
    "Failed password for invalid user attacker",
    "Normal user session opened"
]


detected, count = detect_brute_force(test_logs)

print("=== CloudSentinel Brute-Force Test ===")
print(f"Failed authentication attempts: {count}")

if detected:
    print("🚨 ALERT: Possible brute-force attack detected!")
else:
    print("NORMAL: No brute-force attack detected.")
