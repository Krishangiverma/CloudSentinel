"""
CloudSentinel Attack Correlation Engine

Correlates multiple security events to identify
possible coordinated attacks.
"""


def correlate_events(events, threshold=3):
    """
    Correlate security events by source IP.

    If the same IP generates multiple security events,
    group them together as a possible attack pattern.
    """

    ip_groups = {}

    for event in events:
        ip_address = event.get("ip_address", "UNKNOWN")

        if ip_address not in ip_groups:
            ip_groups[ip_address] = []

        ip_groups[ip_address].append(event)

    attacks = []

    for ip_address, ip_events in ip_groups.items():

        if ip_address == "UNKNOWN":
            continue

        if len(ip_events) >= threshold:

            risk_scores = [
                event.get("risk_score", 0)
                for event in ip_events
            ]

            max_risk = max(risk_scores) if risk_scores else 0

            if max_risk >= 80:
                risk_level = "CRITICAL"
            elif max_risk >= 60:
                risk_level = "HIGH"
            elif max_risk >= 35:
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW"

            event_types = {}

            for event in ip_events:
                event_type = event.get(
                    "event_type",
                    "UNKNOWN"
                )

                event_types[event_type] = (
                    event_types.get(event_type, 0) + 1
                )

            attacks.append({
                "ip_address": ip_address,
                "event_count": len(ip_events),
                "event_types": event_types,
                "max_risk_score": max_risk,
                "risk_level": risk_level,
                "status": "POSSIBLE_ATTACK",
            })

    return attacks
