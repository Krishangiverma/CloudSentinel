from ip_detector import detect_brute_force_by_ip


test_logs = [
    "Failed password for invalid user admin from 192.168.1.10 port 54321 ssh2",
    "Failed password for invalid user test from 192.168.1.10 port 54322 ssh2",
    "Failed password for invalid user root from 192.168.1.10 port 54323 ssh2",
    "Failed password for invalid user guest from 192.168.1.20 port 54324 ssh2",
]

event = detect_brute_force_by_ip(test_logs)

print("=== CloudSentinel IP Detection Test ===")

if event:
    print("[ALERT] Brute-force attack detected!")

    try:
        event.display()
    except AttributeError:
        print(event)
else:
    print("[OK] No brute-force attack detected.")
