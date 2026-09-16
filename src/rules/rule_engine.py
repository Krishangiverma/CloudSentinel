from dataclasses import dataclass, field
from typing import Callable, Dict, List, Any


# ============================================================
# DETECTION RULE
# ============================================================

@dataclass
class DetectionRule:
    """
    Represents a single CloudSentinel detection rule.

    The rule contains both detection logic and metadata used
    by the SOC detection management layer.
    """

    name: str
    condition: Callable[[dict], bool]
    event_type: str
    severity: str

    description: str = ""

    # Day 39 rule-management metadata
    rule_id: str = ""
    category: str = "general"
    enabled: bool = True
    tags: List[str] = field(default_factory=list)

    metadata: Dict[str, Any] = field(
        default_factory=dict
    )

    def matches(self, event: dict) -> bool:
        """
        Check whether this rule matches the supplied event.

        Disabled rules never generate detections.
        """

        if not self.enabled:
            return False

        try:
            return bool(
                self.condition(event)
            )
        except Exception:
            return False

    def create_detection(self, event: dict) -> dict:
        """
        Convert a matching event into a detection result.
        """

        return {
            "rule_name": self.name,
            "rule_id": self.rule_id,
            "event_type": self.event_type,
            "severity": self.severity,
            "message": event.get(
                "message",
                "",
            ),
            "source": event.get(
                "source",
                "unknown",
            ),
            "ip": event.get(
                "ip",
                "N/A",
            ),
            "category": self.category,
            "tags": self.tags,
            "metadata": self.metadata,
        }


# ============================================================
# RULE ENGINE
# ============================================================

class RuleEngine:
    """
    Detection engine responsible for evaluating events
    against registered detection rules.
    """

    VALID_SEVERITIES = {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }

    def __init__(
        self,
        rules: List[DetectionRule] | None = None,
    ):
        self._rules: List[DetectionRule] = []

        if rules:
            for rule in rules:
                self.register(rule)

    # --------------------------------------------------------
    # REGISTER
    # --------------------------------------------------------

    def register(
        self,
        rule: DetectionRule,
    ) -> None:
        """
        Register a detection rule.
        """

        if not isinstance(
            rule,
            DetectionRule,
        ):
            raise TypeError(
                "rule must be a DetectionRule instance"
            )

        if not rule.name.strip():
            raise ValueError(
                "rule name cannot be empty"
            )

        normalized_severity = (
            str(rule.severity)
            .upper()
        )

        if normalized_severity not in self.VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity: {rule.severity}"
            )

        rule.severity = normalized_severity

        if any(
            existing.name == rule.name
            for existing in self._rules
        ):
            raise ValueError(
                f"Duplicate rule name: {rule.name}"
            )

        self._rules.append(rule)

    # --------------------------------------------------------
    # UNREGISTER
    # --------------------------------------------------------

    def unregister(
        self,
        rule_name: str,
    ) -> bool:
        """
        Remove a rule by name.

        Returns True if a rule was removed,
        otherwise False.
        """

        for index, rule in enumerate(
            self._rules
        ):

            if rule.name == rule_name:
                del self._rules[index]
                return True

        return False

    # --------------------------------------------------------
    # CLEAR
    # --------------------------------------------------------

    def clear(self) -> None:
        """
        Remove all registered rules.
        """

        self._rules.clear()

    # --------------------------------------------------------
    # LIST RULES
    # --------------------------------------------------------

    def list_rules(
        self,
    ) -> List[DetectionRule]:
        """
        Return all registered rules.
        """

        return list(self._rules)

    # --------------------------------------------------------
    # ENABLE RULE
    # --------------------------------------------------------

    def enable(
        self,
        rule_name: str,
    ) -> bool:
        """
        Enable a rule by name.
        """

        for rule in self._rules:

            if rule.name == rule_name:
                rule.enabled = True
                return True

        return False

    # --------------------------------------------------------
    # DISABLE RULE
    # --------------------------------------------------------

    def disable(
        self,
        rule_name: str,
    ) -> bool:
        """
        Disable a rule by name.
        """

        for rule in self._rules:

            if rule.name == rule_name:
                rule.enabled = False
                return True

        return False

    # --------------------------------------------------------
    # STATISTICS
    # --------------------------------------------------------

    def statistics(self) -> Dict[str, Any]:
        """
        Return high-level statistics about
        registered detection rules.
        """

        total = len(
            self._rules
        )

        enabled = sum(
            1
            for rule in self._rules
            if rule.enabled
        )

        disabled = (
            total - enabled
        )

        severity_counts = {
            "LOW": 0,
            "MEDIUM": 0,
            "HIGH": 0,
            "CRITICAL": 0,
        }

        category_counts = {}

        for rule in self._rules:

            severity = (
                str(rule.severity)
                .upper()
            )

            if severity in severity_counts:
                severity_counts[
                    severity
                ] += 1

            category = (
                rule.category
                or "general"
            )

            category_counts[
                category
            ] = (
                category_counts.get(
                    category,
                    0,
                )
                + 1
            )

        return {
            "total": total,
            "enabled": enabled,
            "disabled": disabled,
            "severity": severity_counts,
            "categories": category_counts,
        }

    # --------------------------------------------------------
    # EVALUATE
    # --------------------------------------------------------

    def evaluate(
        self,
        event: dict,
    ) -> List[dict]:
        """
        Evaluate one event against every
        registered detection rule.
        """

        detections = []

        for rule in self._rules:

            if rule.matches(event):

                detections.append(
                    rule.create_detection(
                        event
                    )
                )

        return detections

    # --------------------------------------------------------
    # EVALUATE MANY
    # --------------------------------------------------------

    def evaluate_many(
        self,
        events: List[dict],
    ) -> List[dict]:
        """
        Evaluate multiple events.
        """

        detections = []

        for event in events:

            detections.extend(
                self.evaluate(event)
            )

        return detections


# ============================================================
# YAML ENGINE FACTORY
# ============================================================

def create_engine_from_yaml(
    path: str,
) -> RuleEngine:
    """
    Create a RuleEngine populated with
    rules loaded from YAML.
    """

    from src.rules.rule_loader import (
        load_rules_from_yaml
    )

    rules = load_rules_from_yaml(
        path
    )

    return RuleEngine(
        rules
    )
