from dataclasses import dataclass, field
from typing import Callable, Dict, List, Any


@dataclass
class DetectionRule:
    """
    Represents a single detection rule.
    """

    name: str
    condition: Callable[[dict], bool]
    event_type: str
    severity: str
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def matches(self, event: dict) -> bool:
        """
        Check whether this rule matches the supplied event.
        """
        try:
            return bool(self.condition(event))
        except Exception:
            return False

    def create_detection(self, event: dict) -> dict:
        """
        Convert a matching event into a detection result.
        """
        return {
            "rule_name": self.name,
            "event_type": self.event_type,
            "severity": self.severity,
            "message": event.get("message", ""),
            "source": event.get("source", "unknown"),
            "ip": event.get("ip", "N/A"),
            "metadata": self.metadata,
        }


class RuleEngine:
    """
    Detection engine responsible for evaluating events
    against registered detection rules.
    """

    def __init__(self, rules: List[DetectionRule] | None = None):
        self._rules: List[DetectionRule] = []

        if rules:
            for rule in rules:
                self.register(rule)

    def register(self, rule: DetectionRule) -> None:
        """
        Register a detection rule.
        """
        if not isinstance(rule, DetectionRule):
            raise TypeError("rule must be a DetectionRule instance")

        self._rules.append(rule)

    def unregister(self, rule_name: str) -> bool:
        """
        Remove a rule by name.

        Returns True if a rule was removed,
        otherwise False.
        """
        for index, rule in enumerate(self._rules):
            if rule.name == rule_name:
                del self._rules[index]
                return True

        return False

    def clear(self) -> None:
        """
        Remove all registered rules.
        """
        self._rules.clear()

    def list_rules(self) -> List[DetectionRule]:
        """
        Return all registered rules.
        """
        return list(self._rules)

    def evaluate(self, event: dict) -> List[dict]:
        """
        Evaluate one event against every registered rule.
        """
        detections = []

        for rule in self._rules:
            if rule.matches(event):
                detections.append(
                    rule.create_detection(event)
                )

        return detections

    def evaluate_many(self, events: List[dict]) -> List[dict]:
        """
        Evaluate multiple events.
        """
        detections = []

        for event in events:
            detections.extend(self.evaluate(event))

        return detections


def create_engine_from_yaml(path: str) -> RuleEngine:
    """
    Create a RuleEngine populated with rules loaded from YAML.
    """
    from src.rules.rule_loader import load_rules_from_yaml

    rules = load_rules_from_yaml(path)

    return RuleEngine(rules)
