"""
Day 36 tests for the CloudSentinel Rule Engine.
"""

from rules.rule_engine import DetectionRule, RuleEngine


def test_rule_matches_event():
    rule = DetectionRule(
        name="test_failed_login",
        condition=lambda event: (
            "failed" in event.get("message", "").lower()
        ),
        event_type="SUSPICIOUS_ACTIVITY",
        severity="MEDIUM",
    )

    engine = RuleEngine([rule])

    event = {
        "message": "Failed password for attacker",
        "source": "auth.log",
    }

    detections = engine.evaluate(event)

    assert len(detections) == 1
    assert detections[0]["rule_name"] == "test_failed_login"
    assert detections[0]["event_type"] == "SUSPICIOUS_ACTIVITY"
    assert detections[0]["severity"] == "MEDIUM"


def test_non_matching_event_returns_no_detection():
    rule = DetectionRule(
        name="test_failed_login",
        condition=lambda event: (
            "failed" in event.get("message", "").lower()
        ),
        event_type="SUSPICIOUS_ACTIVITY",
        severity="MEDIUM",
    )

    engine = RuleEngine([rule])

    event = {
        "message": "Successful login",
    }

    assert engine.evaluate(event) == []


def test_multiple_rules_can_match():
    rule_one = DetectionRule(
        name="failed_password",
        condition=lambda event: (
            "failed password" in event.get("message", "").lower()
        ),
        event_type="SUSPICIOUS_ACTIVITY",
        severity="MEDIUM",
    )

    rule_two = DetectionRule(
        name="invalid_user",
        condition=lambda event: (
            "invalid user" in event.get("message", "").lower()
        ),
        event_type="SUSPICIOUS_ACTIVITY",
        severity="MEDIUM",
    )

    engine = RuleEngine([
        rule_one,
        rule_two,
    ])

    event = {
        "message": (
            "Failed password for invalid user attacker"
        )
    }

    detections = engine.evaluate(event)

    assert len(detections) == 2


def test_rule_registration_and_unregistration():
    rule = DetectionRule(
        name="temporary_rule",
        condition=lambda event: True,
        event_type="TEST",
        severity="LOW",
    )

    engine = RuleEngine()

    engine.register(rule)

    assert len(engine.list_rules()) == 1

    removed = engine.unregister("temporary_rule")

    assert removed is True
    assert len(engine.list_rules()) == 0


def test_evaluate_many():
    rule = DetectionRule(
        name="failed_login",
        condition=lambda event: (
            "failed" in event.get("message", "").lower()
        ),
        event_type="SUSPICIOUS_ACTIVITY",
        severity="MEDIUM",
    )

    engine = RuleEngine([rule])

    events = [
        {"message": "Failed login"},
        {"message": "Successful login"},
        {"message": "Failed password"},
    ]

    detections = engine.evaluate_many(events)

    assert len(detections) == 2


def test_invalid_rule_registration_is_rejected():
    engine = RuleEngine()

    try:
        engine.register("not a rule")
        assert False, "Expected TypeError"
    except TypeError as error:
        assert "DetectionRule" in str(error)
