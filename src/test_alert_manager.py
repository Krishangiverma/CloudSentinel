from datetime import datetime

from event import SecurityEvent

from alert_manager import (
    calculate_risk,
    get_priority,
    generate_alert,
    process_alerts,
    format_alert,
    save_alerts,
)


print("==============================================")
print("     CloudSentinel Alert Manager Test")
print("==============================================")


# ============================================================
# TEST 1: BRUTE FORCE EVENT
# ============================================================

print("\n--- TEST 1: Brute Force Event ---")

brute_force_event = SecurityEvent(
    timestamp=datetime.now(),
    event_type="BRUTE_FORCE",
    severity="HIGH",
    message="6 failed authentication attempts detected"
)

print("Event Type :", brute_force_event.event_type)
print("Severity   :", brute_force_event.severity)
print("Message    :", brute_force_event.message)


# ============================================================
# TEST 2: RISK CALCULATION
# ============================================================

print("\n--- TEST 2: Risk Calculation ---")

risk_score = calculate_risk(brute_force_event)

print("Risk Score :", risk_score)


# ============================================================
# TEST 3: PRIORITY CALCULATION
# ============================================================

print("\n--- TEST 3: Priority Calculation ---")

priority = get_priority(risk_score)

print("Priority   :", priority)


# ============================================================
# TEST 4: ALERT GENERATION
# ============================================================

print("\n--- TEST 4: Alert Generation ---")

alert = generate_alert(brute_force_event)

print("\nGenerated Alert:")
print(alert)


# ============================================================
# TEST 5: FORMAT ALERT
# ============================================================

print("\n--- TEST 5: Formatted Alert ---")

formatted_alert = format_alert(alert)

print(formatted_alert)


# ============================================================
# TEST 6: FAILED LOGIN EVENT
# ============================================================

print("\n--- TEST 6: Failed Login Event ---")

failed_login_event = SecurityEvent(
    timestamp=datetime.now(),
    event_type="FAILED_LOGIN",
    severity="MEDIUM",
    message="Failed authentication attempt detected"
)

print("Event Type :", failed_login_event.event_type)
print("Severity   :", failed_login_event.severity)
print("Message    :", failed_login_event.message)

failed_login_risk = calculate_risk(failed_login_event)

print("Risk Score :", failed_login_risk)

failed_login_priority = get_priority(failed_login_risk)

print("Priority   :", failed_login_priority)

failed_login_alert = generate_alert(failed_login_event)

print("\nGenerated Alert:")
print(failed_login_alert)


# ============================================================
# TEST 7: PROCESS MULTIPLE ALERTS
# ============================================================

print("\n--- TEST 7: Processing Multiple Security Events ---")

events = [
    brute_force_event,
    failed_login_event
]

alerts = process_alerts(events)

print("Total Events :", len(events))
print("Total Alerts :", len(alerts))


# ============================================================
# TEST 8: DISPLAY ALL ALERTS
# ============================================================

print("\n--- TEST 8: All Generated Alerts ---")

for index, alert_item in enumerate(alerts, start=1):

    print("\nAlert", index)
    print("-" * 50)

    print(format_alert(alert_item))


# ============================================================
# TEST 9: SAVE ALERTS
# ============================================================

print("\n--- TEST 9: Saving Alerts ---")

save_alerts(alerts)

print("Alerts saved successfully.")


# ============================================================
# FINAL SUMMARY
# ============================================================

print("\n==============================================")
print("        Alert Manager Test Complete")
print("==============================================")

print("\nBrute Force:")
print("Risk Score :", risk_score)
print("Priority   :", priority)

print("\nFailed Login:")
print("Risk Score :", failed_login_risk)
print("Priority   :", failed_login_priority)

print("\nTotal Alerts Generated :", len(alerts))

print("\nCloudSentinel Alert Manager is working.")
