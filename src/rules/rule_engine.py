"""
CloudSentinel Rule Engine.

Provides a reusable abstraction for evaluating security
detection rules against normalized log/event dictionaries.

Day 36:
- Rule abstraction
- RuleEngine abstraction
- Reusable condition evaluation
- Backward-compatible event generation
"""

from dataclasses import dataclass, field
from typing import Callable, Any


@dataclass
class DetectionRule:
    """
    Represents one detection rule.

    A rule contains:
        name        : unique rule name
        condition   : function that decides whether the rule matches
        event_type  : CloudSentinel event classification
        severity    : resulting severity
        description : human-readable rule description
        metadata    : extensible rule information
    """

    name: str
    condition: Callable[[dict], bool]
    event_type: str
    severity: str
    description: str = ""
    metadata: dict = field(default_factory=dict)

    def matches(self, event: dict) -> bool:
        """Return True when this rule matches the event."""

        if not isinstance(event, dict):
            return False

        try:
            return bool(self.condition(event))
        except Exception:
            return False

    def create_detection(self, event: dict) -> dict:
        """Create a normalized detection from a matching event."""

        return {
            "rule_name": self.name,
            "event_type": self.event_type,
            "severity": self.severity,
            "message": event.get("message", ""),
            "source": event.get("source", "unknown"),
            "ip": event.get("ip", "N/A"),
            "metadata": dict(self.metadata),
        }


class RuleEngine:
    """
    Generic rule evaluation engine.

    Rules can be registered, removed and evaluated without
    changing the engine itself.
    """

    def __init__(self, rules=None):
        self._rules = []

        if rules:
            for rule in rules:
                self.register(rule)

    def register(self, rule: DetectionRule):
        """Register a detection rule."""

        if not isinstance(rule, DetectionRule):
            raise TypeError(
                "rule must be a DetectionRule instance"
            )

        self._rules.append(rule)

    def unregister(self, rule_name: str) -> bool:
        """Remove a rule by name."""

        original_count = len(self._rules)

        self._rules = [
            rule
            for rule in self._rules
            if rule.name != rule_name
        ]

        return len(self._rules) < original_count

    def clear(self):
        """Remove all registered rules."""

        self._rules.clear()

    def list_rules(self):
        """Return registered rules."""

        return list(self._rules)

    def evaluate(self, event: dict):
        """
        Evaluate one event against all registered rules.

        Returns:
            List of detections.
        """

        detections = []

        for rule in self._rules:

            if rule.matches(event):

                detections.append(
                    rule.create_detection(event)
                )

        return detections

    def evaluate_many(self, events):
        """
        Evaluate multiple events.

        Returns:
            Flattened list of detections.
        """

        detections = []

        for event in events:
            detections.extend(
                self.evaluate(event)
            )

        return detections
