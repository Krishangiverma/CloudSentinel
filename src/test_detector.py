from detector import detect_suspicious_event

test_events = [
    "Normal user session opened",
    "Failed password for invalid user attacker",
    "Successful login for krishangi"
]

for event in test_events:
    if detect_suspicious_event(event):
        print("🚨 ALERT:", event)
    else:
        print("NORMAL:", event)
