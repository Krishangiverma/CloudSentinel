from src.analyzers.authentication_detector import (
    detect_failed_logins,
    detect_brute_force,
    detect_password_spraying,
    detect_suspicious_logins,
    analyze_authentication,
)


def make_event(message, ip="192.168.1.50"):
    return {
        "message": message,
        "source": "sshd",
        "ip": ip,
    }


def test_failed_login_detection():
    logs = [
        make_event(
            "Failed password for user alice from 192.168.1.50"
        ),
        make_event(
            "Successful login for alice from 192.168.1.50"
        ),
    ]

    detections = detect_failed_logins(logs)

    assert len(detections) == 1
    assert detections[0]["event_type"] == "FAILED_LOGIN"
    assert detections[0]["severity"] == "HIGH"
    assert detections[0]["username"] == "alice"


def test_brute_force_detection():
    logs = [
        make_event(
            "Failed password for user alice from 192.168.1.50"
        ),
        make_event(
            "Failed password for user alice from 192.168.1.50"
        ),
        make_event(
            "Failed password for user alice from 192.168.1.50"
        ),
    ]

    detections = detect_brute_force(logs)

    assert len(detections) == 1
    assert detections[0]["event_type"] == "BRUTE_FORCE"
    assert detections[0]["attempt_count"] == 3


def test_brute_force_below_threshold():
    logs = [
        make_event(
            "Failed password for user alice from 192.168.1.50"
        ),
        make_event(
            "Failed password for user alice from 192.168.1.50"
        ),
    ]

    detections = detect_brute_force(logs)

    assert detections == []


def test_password_spraying_detection():
    logs = [
        make_event(
            "Failed password for user alice from 192.168.1.50"
        ),
        make_event(
            "Failed password for user bob from 192.168.1.50"
        ),
        make_event(
            "Failed password for user admin from 192.168.1.50"
        ),
    ]

    detections = detect_password_spraying(logs)

    assert len(detections) == 1
    assert detections[0]["event_type"] == "PASSWORD_SPRAYING"
    assert detections[0]["username_count"] == 3
    assert detections[0]["usernames"] == [
        "admin",
        "alice",
        "bob",
    ]


def test_password_spraying_below_threshold():
    logs = [
        make_event(
            "Failed password for user alice from 192.168.1.50"
        ),
        make_event(
            "Failed password for user bob from 192.168.1.50"
        ),
    ]

    detections = detect_password_spraying(logs)

    assert detections == []


def test_suspicious_login_after_failures():
    logs = [
        make_event(
            "Failed password for user admin from 192.168.1.50"
        ),
        make_event(
            "Accepted password for admin from 192.168.1.50"
        ),
    ]

    detections = detect_suspicious_logins(logs)

    assert len(detections) == 1
    assert detections[0]["event_type"] == "SUSPICIOUS_LOGIN"
    assert detections[0]["severity"] == "HIGH"


def test_normal_successful_login_not_flagged():
    logs = [
        make_event(
            "Accepted password for admin from 192.168.1.50"
        ),
    ]

    detections = detect_suspicious_logins(logs)

    assert detections == []


def test_invalid_user_username_extraction():
    logs = [
        make_event(
            "Failed password for invalid user attacker "
            "from 192.168.1.50"
        ),
    ]

    detections = detect_failed_logins(logs)

    assert len(detections) == 1
    assert detections[0]["username"] == "attacker"


def test_complete_authentication_analysis():
    logs = [
        make_event(
            "Failed password for user alice from 192.168.1.50"
        ),
        make_event(
            "Failed password for user bob from 192.168.1.50"
        ),
        make_event(
            "Failed password for user admin from 192.168.1.50"
        ),
        make_event(
            "Accepted password for admin from 192.168.1.50"
        ),
    ]

    detections = analyze_authentication(logs)

    event_types = {
        detection["event_type"]
        for detection in detections
    }

    assert "FAILED_LOGIN" in event_types
    assert "BRUTE_FORCE" in event_types
    assert "PASSWORD_SPRAYING" in event_types
    assert "SUSPICIOUS_LOGIN" in event_types



# Day 100: timestamp-aware brute-force regression tests.
from datetime import datetime, timedelta, timezone


def make_timestamped_event(message, ip, timestamp):
    return {
        "message": message,
        "source": "sshd",
        "ip": ip,
        "timestamp": timestamp,
    }


def test_day100_brute_force_detects_attempts_inside_time_window():
    start = datetime(2026, 10, 18, 10, 0, 0, tzinfo=timezone.utc)
    logs = [
        make_timestamped_event(
            "Failed password for user alice",
            "192.168.1.50",
            start + timedelta(seconds=offset),
        )
        for offset in (0, 20, 40)
    ]

    detections = detect_brute_force(logs, threshold=3, window_seconds=60)

    assert len(detections) == 1
    assert detections[0]["attempt_count"] == 3


def test_day100_brute_force_does_not_combine_attempts_outside_window():
    start = datetime(2026, 10, 18, 10, 0, 0, tzinfo=timezone.utc)
    logs = [
        make_timestamped_event(
            "Failed password for user alice",
            "192.168.1.50",
            start + timedelta(seconds=offset),
        )
        for offset in (0, 70, 140)
    ]

    detections = detect_brute_force(logs, threshold=3, window_seconds=60)

    assert detections == []


def test_day100_brute_force_supports_iso_timestamp_strings():
    start = datetime(2026, 10, 18, 10, 0, 0, tzinfo=timezone.utc)
    logs = [
        make_timestamped_event(
            "Failed password for user alice",
            "192.168.1.50",
            (start + timedelta(seconds=offset)).isoformat(),
        )
        for offset in (0, 10, 20)
    ]

    detections = detect_brute_force(logs, threshold=3, window_seconds=60)

    assert len(detections) == 1
    assert detections[0]["attempt_count"] == 3


def test_day100_brute_force_rejects_invalid_window():
    import pytest

    logs = [
        make_event("Failed password for user alice")
        for _ in range(3)
    ]

    with pytest.raises(ValueError):
        detect_brute_force(logs, threshold=3, window_seconds=-1)


def test_day100_brute_force_ignores_missing_timestamps_when_valid_ones_exist():
    start = datetime(2026, 10, 18, 10, 0, 0, tzinfo=timezone.utc)
    logs = [
        make_timestamped_event(
            "Failed password for user alice",
            "192.168.1.50",
            start,
        ),
        make_timestamped_event(
            "Failed password for user alice",
            "192.168.1.50",
            start + timedelta(seconds=10),
        ),
        make_event("Failed password for user alice"),
    ]

    # The legacy event has no IP, so it must not affect this IP's count.
    detections = detect_brute_force(logs, threshold=3, window_seconds=60)
    assert detections == []


def test_day100_brute_force_accepts_exact_window_boundary():
    start = datetime(2026, 10, 18, 10, 0, 0, tzinfo=timezone.utc)
    logs = [
        make_timestamped_event(
            "Failed password for user alice",
            "192.168.1.50",
            start + timedelta(seconds=offset),
        )
        for offset in (0, 30, 60)
    ]

    detections = detect_brute_force(logs, threshold=3, window_seconds=60)

    assert len(detections) == 1
    assert detections[0]["attempt_count"] == 3


def test_day100_brute_force_rejects_zero_threshold():
    import pytest

    with pytest.raises(ValueError):
        detect_brute_force([], threshold=0)


def test_day100_mixed_valid_and_missing_timestamps_do_not_combine():
    start = datetime(2026, 10, 18, 10, 0, 0, tzinfo=timezone.utc)
    ip = "192.168.1.50"

    logs = [
        make_timestamped_event(
            "Failed password for user alice",
            ip,
            start,
        ),
        make_timestamped_event(
            "Failed password for user alice",
            ip,
            start + timedelta(seconds=10),
        ),
        make_timestamped_event(
            "Failed password for user alice",
            ip,
            None,
        ),
    ]

    detections = detect_brute_force(logs, threshold=3, window_seconds=60)

    assert detections == []


def test_day100_invalid_timestamps_do_not_trigger_legacy_fallback():
    ip = "192.168.1.50"
    logs = [
        make_timestamped_event(
            "Failed password for user alice",
            ip,
            "not-a-valid-timestamp",
        )
        for _ in range(3)
    ]

    detections = detect_brute_force(logs, threshold=3, window_seconds=60)

    assert detections == []
