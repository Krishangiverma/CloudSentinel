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

