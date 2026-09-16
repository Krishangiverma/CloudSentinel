from pathlib import Path
from typing import List

import yaml

from src.rules.rule_engine import DetectionRule


# ============================================================
# EVENT TYPE MAPPING
# ============================================================

EVENT_TYPE_MAP = {
    "ssh_failed_password": "SUSPICIOUS_ACTIVITY",
    "ssh_invalid_user": "SUSPICIOUS_ACTIVITY",
    "authentication_failure": "SUSPICIOUS_ACTIVITY",
    "brute_force": "BRUTE_FORCE",
    "sudo_activity": "SUDO_ACTIVITY",
    "session_opened": "SECURITY_LOG",
    "session_closed": "SECURITY_LOG",
    "cron_activity": "SECURITY_LOG",
}


# ============================================================
# CONDITION BUILDER
# ============================================================

def _build_condition(condition_text: str):
    """
    Build a case-insensitive message matching condition
    from a YAML rule.
    """

    condition_text = str(
        condition_text
    ).lower()

    def condition(event: dict) -> bool:
        message = str(
            event.get(
                "message",
                "",
            )
        ).lower()

        return condition_text in message

    return condition


# ============================================================
# YAML RULE LOADER
# ============================================================

def load_rules_from_yaml(
    path: str,
) -> List[DetectionRule]:
    """
    Load detection rules from YAML and convert them
    into DetectionRule objects.
    """

    config_path = Path(path)

    if not config_path.exists():
        raise FileNotFoundError(
            f"Rule configuration not found: {config_path}"
        )

    with config_path.open(
        "r",
        encoding="utf-8",
    ) as file:
        config = yaml.safe_load(file) or {}

    rules_config = config.get(
        "rules",
        [],
    )

    if not isinstance(
        rules_config,
        list,
    ):
        raise ValueError(
            "'rules' must be a list"
        )

    rules = []

    required_fields = [
        "name",
        "condition",
        "threshold",
        "window",
        "severity",
        "MITRE",
    ]

    for rule_config in rules_config:

        if not isinstance(
            rule_config,
            dict,
        ):
            raise ValueError(
                "Each rule must be a mapping"
            )

        missing_fields = [
            field
            for field in required_fields
            if field not in rule_config
        ]

        if missing_fields:
            raise ValueError(
                f"Rule "
                f"'{rule_config.get('name', 'unknown')}' "
                f"is missing fields: "
                f"{missing_fields}"
            )

        rule_name = rule_config["name"]

        event_type = EVENT_TYPE_MAP.get(
            rule_name,
            "SUSPICIOUS_ACTIVITY",
        )

        rule = DetectionRule(
            name=rule_name,
            condition=_build_condition(
                rule_config["condition"]
            ),
            event_type=event_type,
            severity=rule_config["severity"],
            description=(
                f"YAML rule: {rule_name}"
            ),
            metadata={
                "threshold": rule_config["threshold"],
                "window": rule_config["window"],
                "MITRE": rule_config["MITRE"],
            },
        )

        rules.append(rule)

    return rules
