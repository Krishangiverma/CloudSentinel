"""Generate safe, plain-text incident investigation reports."""

from datetime import datetime, timezone


def _safe_text(value, limit=2000):
    """Normalize untrusted values for readable, single-line report output."""
    if value is None:
        return "N/A"

    text = str(value)
    text = "".join(
        char if char.isprintable() else " "
        for char in text
    )
    return " ".join(text.split())[:limit] or "N/A"


def _section(title):
    return [title, "-" * len(title)]


def generate_incident_report(incident):
    """Build a downloadable plain-text report from a correlated incident."""
    if not isinstance(incident, dict):
        raise ValueError("Incident must be a dictionary.")

    evidence = incident.get("evidence")
    if not isinstance(evidence, dict):
        evidence = {}

    risk = evidence.get("risk")
    if not isinstance(risk, dict):
        risk = {}

    timeline = evidence.get("timeline")
    if not isinstance(timeline, list):
        timeline = []

    generated_at = datetime.now(timezone.utc).isoformat()

    lines = [
        "CLOUDSENTINEL INCIDENT INVESTIGATION REPORT",
        "=" * 44,
        f"Generated at (UTC): {generated_at}",
        f"Incident ID: {_safe_text(incident.get('incident_id'), 120)}",
        f"Status: {_safe_text(incident.get('status'), 80)}",
        "",
    ]

    lines.extend(_section("INCIDENT SUMMARY"))
    lines.extend([
        f"Attack pattern: {_safe_text(incident.get('attack_pattern'))}",
        f"Source IP: {_safe_text(incident.get('ip_address'))}",
        f"First seen: {_safe_text(incident.get('first_seen'))}",
        f"Last seen: {_safe_text(incident.get('last_seen'))}",
        f"Event count: {_safe_text(incident.get('event_count'))}",
        f"Investigation summary: {_safe_text(incident.get('investigation_summary'))}",
        "",
    ])

    lines.extend(_section("RISK ASSESSMENT"))
    lines.extend([
        f"Risk level: {_safe_text(incident.get('risk_level'))}",
        f"Maximum risk score: {_safe_text(incident.get('max_risk_score'))}/100",
        f"Critical events: {_safe_text(risk.get('critical_event_count', incident.get('critical_event_count', 0)))}",
        f"High-risk events: {_safe_text(risk.get('high_risk_event_count', incident.get('high_risk_event_count', 0)))}",
        "Scoring model: base severity + event-type bonus + threat-intelligence score, capped at 100.",
        "Interpretation: risk scores prioritize investigation; they do not independently prove malicious activity.",
        "",
    ])

    lines.extend(_section("RESPONSE RECOMMENDATIONS"))
    recommendations = incident.get("response_recommendations", [])
    if isinstance(recommendations, list) and recommendations:
        for recommendation in recommendations:
            lines.append(f"- {_safe_text(recommendation)}")
    else:
        lines.append("No response recommendations recorded.")
    lines.append("")

    lines.extend(_section("EVENT EVIDENCE"))
    if timeline:
        for index, event in enumerate(timeline, start=1):
            if not isinstance(event, dict):
                continue
            lines.extend([
                f"Evidence {index}",
                f"  Event ID: {_safe_text(event.get('event_id'))}",
                f"  Timestamp: {_safe_text(event.get('timestamp'))}",
                f"  Type: {_safe_text(event.get('event_type'))}",
                f"  Severity: {_safe_text(event.get('severity'))}",
                f"  Risk score: {_safe_text(event.get('risk_score'))}",
                f"  Source IP: {_safe_text(event.get('ip_address'))}",
                f"  Source: {_safe_text(event.get('source'))}",
                f"  Message: {_safe_text(event.get('message'))}",
            ])
            lines.append("")
    else:
        lines.append("No event timeline evidence was recorded.")
        lines.append("")

    lines.extend(_section("KNOWN LIMITATIONS"))
    lines.extend([
        "- This report reflects the incident data available at generation time.",
        "- Correlation and risk scoring can produce false positives or miss activity.",
        "- Threat-intelligence coverage may be incomplete or unavailable.",
        "- Validate the underlying logs and evidence before taking response action.",
        "",
        "END OF REPORT",
    ])

    return "\n".join(lines) + "\n"
