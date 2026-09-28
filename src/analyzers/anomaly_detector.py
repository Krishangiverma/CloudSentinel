"""
CloudSentinel Day 104: Local, dependency-free anomaly detector prototype.

This is an explainable heuristic/frequency-based prototype, not a trained
machine-learning model. Day 105 will evaluate it against a baseline.
It does not modify SecurityEvent objects or existing risk scores.
"""

from collections import Counter
from dataclasses import dataclass
from typing import Any, Iterable


AUTH_FAILURE_TYPES = {
    "LOGIN_FAILURE",
    "FAILED_LOGIN",
    "AUTH_FAILURE",
    "BRUTE_FORCE",
}

HIGH_SIGNAL_TYPES = {
    "BRUTE_FORCE",
    "MALWARE",
    "INTRUSION",
    "UNAUTHORIZED_ACCESS",
    "PORT_SCAN",
    "SUSPICIOUS_LOGIN",
}


@dataclass(frozen=True)
class AnomalyResult:
    """Explainable anomaly result for one input event."""

    anomaly_score: int
    is_anomaly: bool
    reasons: tuple[str, ...]
    event_type: str
    source_ip: str


def _value(event: Any, key: str, default: Any = None) -> Any:
    """Read a field from a dictionary or an event-like object."""
    if isinstance(event, dict):
        return event.get(key, default)
    return getattr(event, key, default)


def _text(event: Any, key: str, default: str = "") -> str:
    value = _value(event, key, default)
    return str(value if value is not None else default).strip()


def detect_anomalies(
    events: Iterable[Any],
    threshold: int = 60,
    burst_threshold: int = 3,
) -> list[AnomalyResult]:
    """
    Score events using transparent rules and batch frequency signals.

    Frequency is calculated across the supplied batch, not a time window.
    Scores are heuristic indicators, not probabilities or calibrated risk.
    """
    if not 0 <= threshold <= 100:
        raise ValueError("threshold must be between 0 and 100")
    if burst_threshold < 2:
        raise ValueError("burst_threshold must be at least 2")

    batch = list(events)

    event_types = [
        _text(event, "event_type", "UNKNOWN").upper() or "UNKNOWN"
        for event in batch
    ]
    source_ips = [
        (
            _text(event, "ip_address")
            or _text(event, "ip")
            or "N/A"
        )
        for event in batch
    ]

    ip_counts = Counter(
        ip for ip in source_ips if ip and ip != "N/A"
    )

    results = []

    for event, event_type, source_ip in zip(
        batch, event_types, source_ips
    ):
        score = 0
        reasons = []

        severity = _text(event, "severity", "LOW").upper()
        message = _text(event, "message").lower()

        if severity == "CRITICAL":
            score += 30
            reasons.append("critical_severity")
        elif severity == "HIGH":
            score += 20
            reasons.append("high_severity")
        elif severity == "MEDIUM":
            score += 10
            reasons.append("medium_severity")

        if event_type in HIGH_SIGNAL_TYPES:
            score += 25
            reasons.append("high_signal_event_type")

        auth_failure = (
            event_type in AUTH_FAILURE_TYPES
            or any(
                phrase in message
                for phrase in (
                    "failed password",
                    "failed login",
                    "authentication failure",
                    "invalid password",
                )
            )
        )
        if auth_failure:
            score += 15
            reasons.append("authentication_failure_signal")

        if (
            source_ip != "N/A"
            and ip_counts[source_ip] >= burst_threshold
        ):
            score += 25
            reasons.append("repeated_source_ip_in_batch")

        score = min(score, 100)

        results.append(
            AnomalyResult(
                anomaly_score=score,
                is_anomaly=score >= threshold,
                reasons=tuple(reasons),
                event_type=event_type,
                source_ip=source_ip,
            )
        )

    return results
