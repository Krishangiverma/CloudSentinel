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
# VALID VALUES
# ============================================================

VALID_SEVERITIES = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
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
# RULE VALIDATION
# ============================================================

def _validate_rule(rule_config: dict) -> None:
    """
    Validate one YAML detection rule.

    Raises ValueError when the rule configuration
    is invalid.
    """

    required_fields = [
        "name",
        "condition",
        "threshold",
        "window",
        "severity",
        "MITRE",
    ]

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

    # --------------------------------------------------------
    # NAME
    # --------------------------------------------------------

    name = rule_config["name"]

    if not isinstance(
        name,
        str,
    ) or not name.strip():

        raise ValueError(
            "Rule name must be a non-empty string"
        )

    # --------------------------------------------------------
    # CONDITION
    # --------------------------------------------------------

    condition = rule_config["condition"]

    if not isinstance(
        condition,
        str,
    ) or not condition.strip():

        raise ValueError(
            f"Rule '{name}' has an invalid condition"
        )

    # --------------------------------------------------------
    # THRESHOLD
    # --------------------------------------------------------

    threshold = rule_config["threshold"]

    if (
        isinstance(threshold, bool)
        or not isinstance(
            threshold,
            int,
        )
        or threshold < 1
    ):

        raise ValueError(
            f"Rule '{name}' threshold must be "
            f"a positive integer"
        )

    # --------------------------------------------------------
    # WINDOW
    # --------------------------------------------------------

    window = rule_config["window"]

    if (
        isinstance(window, bool)
        or not isinstance(
            window,
            int,
        )
        or window < 1
    ):

        raise ValueError(
            f"Rule '{name}' window must be "
            f"a positive integer"
        )

    # --------------------------------------------------------
    # SEVERITY
    # --------------------------------------------------------

    severity = str(
        rule_config["severity"]
    ).upper()

    if severity not in VALID_SEVERITIES:

        raise ValueError(
            f"Rule '{name}' has invalid severity: "
            f"{rule_config['severity']}"
        )

    # --------------------------------------------------------
    # MITRE
    # --------------------------------------------------------

    mitre = rule_config["MITRE"]

    if not isinstance(
        mitre,
        str,
    ) or not mitre.strip():

        raise ValueError(
            f"Rule '{name}' has an invalid MITRE value"
        )

    # --------------------------------------------------------
    # OPTIONAL ENABLED
    # --------------------------------------------------------

    if "enabled" in rule_config:

        if not isinstance(
            rule_config["enabled"],
            bool,
        ):

            raise ValueError(
                f"Rule '{name}' enabled must be "
                f"true or false"
            )

    # --------------------------------------------------------
    # OPTIONAL TAGS
    # --------------------------------------------------------

    if "tags" in rule_config:

        if not isinstance(
            rule_config["tags"],
            list,
        ):

            raise ValueError(
                f"Rule '{name}' tags must be a list"
            )

        if not all(
            isinstance(tag, str)
            for tag in rule_config["tags"]
        ):

            raise ValueError(
                f"Rule '{name}' tags must contain "
                f"only strings"
            )


# ============================================================
# YAML RULE LOADER
# ============================================================

def load_rules_from_yaml(
    path: str,
) -> List[DetectionRule]:
    """
    Load detection rules from YAML and convert
    them into DetectionRule objects.
    """

    config_path = Path(path)

    if not config_path.exists():

        raise FileNotFoundError(
            f"Rule configuration not found: "
            f"{config_path}"
        )

    with config_path.open(
        "r",
        encoding="utf-8",
    ) as file:

        config = (
            yaml.safe_load(file)
            or {}
        )

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

    seen_names = set()

    for rule_config in rules_config:

        if not isinstance(
            rule_config,
            dict,
        ):

            raise ValueError(
                "Each rule must be a mapping"
            )

        _validate_rule(
            rule_config
        )

        rule_name = rule_config[
            "name"
        ]

        # ----------------------------------------------------
        # DUPLICATE RULE CHECK
        # ----------------------------------------------------

        if rule_name in seen_names:

            raise ValueError(
                f"Duplicate rule name: "
                f"{rule_name}"
            )

        seen_names.add(
            rule_name
        )

        # ----------------------------------------------------
        # EVENT TYPE
        # ----------------------------------------------------

        event_type = EVENT_TYPE_MAP.get(
            rule_name,
            "SUSPICIOUS_ACTIVITY",
        )

        # ----------------------------------------------------
        # OPTIONAL METADATA
        # ----------------------------------------------------

        rule_id = str(
            rule_config.get(
                "id",
                rule_name.upper(),
            )
        )

        description = str(
            rule_config.get(
                "description",
                f"YAML rule: {rule_name}",
            )
        )

        category = str(
            rule_config.get(
                "category",
                "general",
            )
        )

        enabled = rule_config.get(
            "enabled",
            True,
        )

        tags = rule_config.get(
            "tags",
            [],
        )

        # ----------------------------------------------------
        # CREATE RULE
        # ----------------------------------------------------

        rule = DetectionRule(
            name=rule_name,
            condition=_build_condition(
                rule_config["condition"]
            ),
            event_type=event_type,
            severity=str(
                rule_config["severity"]
            ).upper(),
            description=description,
            rule_id=rule_id,
            category=category,
            enabled=enabled,
            tags=tags,
            metadata={
                "threshold": rule_config[
                    "threshold"
                ],
                "window": rule_config[
                    "window"
                ],
                "MITRE": rule_config[
                    "MITRE"
                ],
            },
        )

        rules.append(
            rule
        )

    return rules
