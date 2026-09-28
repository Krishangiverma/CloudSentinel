"""
Day 110: Dependency-free local statistical anomaly model.

This is an experimental, trainable statistical prototype, not a
production security detector. Train it on representative benign events.
It does not mutate events or change CloudSentinel risk scores.
"""

from dataclasses import dataclass
from statistics import mean, pstdev
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

AUTH_FAILURE_PHRASES = (
    "failed password",
    "failed login",
    "authentication failure",
    "invalid password",
)

FEATURE_NAMES = (
    "message_length",
    "severity_weight",
    "event_type_length",
    "source_length",
    "has_user",
    "has_ip",
    "auth_failure_signal",
    "high_signal_event_type",
)

SEVERITY_WEIGHTS = {
    "LOW": 0.0,
    "MEDIUM": 1.0,
    "HIGH": 2.0,
    "CRITICAL": 3.0,
}


def _get(event: Any, key: str, default: Any = None) -> Any:
    if isinstance(event, dict):
        return event.get(key, default)
    return getattr(event, key, default)


def extract_features(event: Any) -> tuple[float, ...]:
    """Extract deterministic numeric features from an event."""
    message = str(_get(event, "message", "") or "")
    event_type = str(_get(event, "event_type", "UNKNOWN") or "UNKNOWN")
    source = str(_get(event, "source", "UNKNOWN") or "UNKNOWN")
    severity = str(_get(event, "severity", "LOW") or "LOW").upper()
    user = _get(event, "user")
    ip = str(
        _get(event, "ip_address", _get(event, "ip", "N/A")) or "N/A"
    )

    normalized_type = event_type.strip().upper()
    normalized_message = message.lower()
    auth_failure_signal = (
        normalized_type in AUTH_FAILURE_TYPES
        or any(phrase in normalized_message for phrase in AUTH_FAILURE_PHRASES)
    )

    return (
        float(len(message)),
        SEVERITY_WEIGHTS.get(severity, 0.0),
        float(len(event_type)),
        float(len(source)),
        float(user is not None and bool(str(user).strip())),
        float(ip.strip().upper() not in ("", "N/A", "NONE")),
        float(auth_failure_signal),
        float(normalized_type in HIGH_SIGNAL_TYPES),
    )


@dataclass(frozen=True)
class LocalMLResult:
    anomaly_score: float
    is_anomaly: bool
    feature_deviations: tuple[tuple[str, float], ...]


class LocalStatisticalAnomalyModel:
    """
    Simple Gaussian-style deviation model fitted on benign events.

    Each feature is scored by absolute standardized deviation from the
    benign training mean. Zero-variance features use a small scale floor.
    The score is a heuristic deviation score, not a probability.
    """

    def __init__(
        self,
        threshold: float = 3.0,
        scale_floor: float = 1.0,
        indicator_scale_floor: float = 0.25,
    ):
        if threshold <= 0:
            raise ValueError("threshold must be positive")
        if scale_floor <= 0:
            raise ValueError("scale_floor must be positive")
        if indicator_scale_floor <= 0:
            raise ValueError("indicator_scale_floor must be positive")

        self.threshold = float(threshold)
        self.scale_floor = float(scale_floor)
        self.indicator_scale_floor = float(indicator_scale_floor)
        self._means: tuple[float, ...] | None = None
        self._scales: tuple[float, ...] | None = None
        self.training_count = 0

    @property
    def is_fitted(self) -> bool:
        return self._means is not None and self._scales is not None

    def fit(self, benign_events: Iterable[Any]):
        """Fit feature distributions from benign-only training examples."""
        rows = [extract_features(event) for event in benign_events]
        if len(rows) < 2:
            raise ValueError("at least two benign training events are required")

        columns = list(zip(*rows))
        self._means = tuple(mean(column) for column in columns)

        indicator_features = {"auth_failure_signal", "high_signal_event_type"}
        self._scales = tuple(
            max(
                pstdev(column),
                self.indicator_scale_floor
                if feature_name in indicator_features
                else self.scale_floor,
            )
            for feature_name, column in zip(FEATURE_NAMES, columns)
        )
        self.training_count = len(rows)
        return self

    def predict_one(self, event: Any) -> LocalMLResult:
        """Score one event against the fitted benign feature profile."""
        if not self.is_fitted:
            raise RuntimeError("model must be fitted before prediction")

        features = extract_features(event)
        deviations = tuple(
            (name, abs(value - center) / scale)
            for name, value, center, scale in zip(
                FEATURE_NAMES, features, self._means, self._scales
            )
        )
        score = max((value for _, value in deviations), default=0.0)

        return LocalMLResult(
            anomaly_score=score,
            is_anomaly=score >= self.threshold,
            feature_deviations=tuple(
                (name, value)
                for name, value in deviations
                if value >= self.threshold
            ),
        )

    def predict(self, events: Iterable[Any]) -> list[LocalMLResult]:
        """Predict for an iterable of events without changing them."""
        return [self.predict_one(event) for event in events]
