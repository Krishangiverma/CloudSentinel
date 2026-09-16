import tempfile
from pathlib import Path

import pytest

from src.rules.rule_loader import load_rules_from_yaml


def test_load_rules_from_yaml():
    yaml_content = """
rules:
  - name: test_rule
    condition: "failed password"
    threshold: 1
    window: 60
    severity: HIGH
    MITRE: T1110
"""

    with tempfile.TemporaryDirectory() as temp_dir:
        path = Path(temp_dir) / "rules.yaml"
        path.write_text(
            yaml_content,
            encoding="utf-8",
        )

        rules = load_rules_from_yaml(
            str(path)
        )

        assert len(rules) == 1
        assert rules[0].name == "test_rule"
        assert rules[0].severity == "HIGH"
        assert rules[0].metadata["threshold"] == 1
        assert rules[0].metadata["window"] == 60
        assert rules[0].metadata["MITRE"] == "T1110"


def test_yaml_rule_condition_matches():
    yaml_content = """
rules:
  - name: failed_login
    condition: "failed password"
    threshold: 1
    window: 60
    severity: MEDIUM
    MITRE: T1110
"""

    with tempfile.TemporaryDirectory() as temp_dir:
        path = Path(temp_dir) / "rules.yaml"
        path.write_text(
            yaml_content,
            encoding="utf-8",
        )

        rules = load_rules_from_yaml(
            str(path)
        )

        event = {
            "message": "Failed password from 10.0.0.5",
            "source": "sshd",
            "ip": "10.0.0.5",
        }

        assert rules[0].matches(event) is True


def test_yaml_rule_condition_does_not_match():
    yaml_content = """
rules:
  - name: failed_login
    condition: "failed password"
    threshold: 1
    window: 60
    severity: MEDIUM
    MITRE: T1110
"""

    with tempfile.TemporaryDirectory() as temp_dir:
        path = Path(temp_dir) / "rules.yaml"
        path.write_text(
            yaml_content,
            encoding="utf-8",
        )

        rules = load_rules_from_yaml(
            str(path)
        )

        event = {
            "message": "Successful login",
            "source": "sshd",
            "ip": "10.0.0.5",
        }

        assert rules[0].matches(event) is False


def test_missing_required_field():
    yaml_content = """
rules:
  - name: incomplete_rule
    condition: "failed password"
    severity: HIGH
"""

    with tempfile.TemporaryDirectory() as temp_dir:
        path = Path(temp_dir) / "rules.yaml"
        path.write_text(
            yaml_content,
            encoding="utf-8",
        )

        with pytest.raises(ValueError):
            load_rules_from_yaml(
                str(path)
            )


def test_missing_rule_file():
    with pytest.raises(FileNotFoundError):
        load_rules_from_yaml(
            "does_not_exist.yaml"
        )


def test_event_type_mapping():
    yaml_content = """
rules:
  - name: session_opened
    condition: "session opened"
    threshold: 1
    window: 60
    severity: LOW
    MITRE: T1078
"""

    with tempfile.TemporaryDirectory() as temp_dir:
        path = Path(temp_dir) / "rules.yaml"
        path.write_text(
            yaml_content,
            encoding="utf-8",
        )

        rules = load_rules_from_yaml(
            str(path)
        )

        assert rules[0].event_type == "SECURITY_LOG"
# ============================================================
# DAY 39 VALIDATION TESTS
# ============================================================

def test_invalid_severity_is_rejected():
    yaml_content = """
rules:
  - name: invalid_severity
    condition: "failed password"
    threshold: 1
    window: 60
    severity: UNKNOWN
    MITRE: T1110
"""

    with tempfile.TemporaryDirectory() as temp_dir:
        path = Path(temp_dir) / "rules.yaml"

        path.write_text(
            yaml_content,
            encoding="utf-8",
        )

        with pytest.raises(ValueError):
            load_rules_from_yaml(
                str(path)
            )


def test_invalid_threshold_is_rejected():
    yaml_content = """
rules:
  - name: invalid_threshold
    condition: "failed password"
    threshold: 0
    window: 60
    severity: HIGH
    MITRE: T1110
"""

    with tempfile.TemporaryDirectory() as temp_dir:
        path = Path(temp_dir) / "rules.yaml"

        path.write_text(
            yaml_content,
            encoding="utf-8",
        )

        with pytest.raises(ValueError):
            load_rules_from_yaml(
                str(path)
            )


def test_invalid_window_is_rejected():
    yaml_content = """
rules:
  - name: invalid_window
    condition: "failed password"
    threshold: 1
    window: 0
    severity: HIGH
    MITRE: T1110
"""

    with tempfile.TemporaryDirectory() as temp_dir:
        path = Path(temp_dir) / "rules.yaml"

        path.write_text(
            yaml_content,
            encoding="utf-8",
        )

        with pytest.raises(ValueError):
            load_rules_from_yaml(
                str(path)
            )


def test_duplicate_rule_names_are_rejected():
    yaml_content = """
rules:
  - name: duplicate_rule
    condition: "failed password"
    threshold: 1
    window: 60
    severity: HIGH
    MITRE: T1110

  - name: duplicate_rule
    condition: "invalid user"
    threshold: 1
    window: 60
    severity: MEDIUM
    MITRE: T1078
"""

    with tempfile.TemporaryDirectory() as temp_dir:
        path = Path(temp_dir) / "rules.yaml"

        path.write_text(
            yaml_content,
            encoding="utf-8",
        )

        with pytest.raises(ValueError):
            load_rules_from_yaml(
                str(path)
            )


def test_optional_rule_metadata_is_loaded():
    yaml_content = """
rules:
  - id: AUTH-001
    name: ssh_test
    description: Detect SSH authentication attacks
    category: authentication
    condition: "failed password"
    threshold: 3
    window: 60
    severity: HIGH
    MITRE: T1110
    enabled: true
    tags:
      - ssh
      - authentication
      - brute-force
"""

    with tempfile.TemporaryDirectory() as temp_dir:
        path = Path(temp_dir) / "rules.yaml"

        path.write_text(
            yaml_content,
            encoding="utf-8",
        )

        rules = load_rules_from_yaml(
            str(path)
        )

        rule = rules[0]

        assert rule.rule_id == "AUTH-001"
        assert rule.description == (
            "Detect SSH authentication attacks"
        )
        assert rule.category == "authentication"
        assert rule.enabled is True
        assert rule.tags == [
            "ssh",
            "authentication",
            "brute-force",
        ]
