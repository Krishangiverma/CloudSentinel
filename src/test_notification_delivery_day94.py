from unittest.mock import mock_open, patch

import notification_manager as notifications


ALERT = {
    "event_type": "BRUTE_FORCE_DAY94_TEST",
    "severity": "HIGH",
    "message": "Simulated notification delivery test",
    "ip_address": "192.0.2.94",
}


def setup_function():
    notifications._last_notification_times.clear()


def test_transient_log_failure_retries_and_then_succeeds(tmp_path):
    log_path = tmp_path / "notifications.log"
    real_open = open
    attempts = {"count": 0}

    def flaky_open(*args, **kwargs):
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise OSError("simulated temporary failure")
        return real_open(*args, **kwargs)

    with (
        patch.object(notifications, "LOG_FILE", str(log_path)),
        patch.object(notifications, "open", flaky_open, create=True),
        patch("builtins.print"),
    ):
        result = notifications.send_notification(ALERT)

    assert result is True
    assert attempts["count"] == 2
    assert log_path.read_text().count("BRUTE_FORCE_DAY94_TEST") == 1
    assert notifications._get_alert_key(ALERT) in notifications._last_notification_times


def test_all_log_write_attempts_fail_without_setting_cooldown():
    with (
        patch.object(notifications, "open", side_effect=OSError("simulated failure"), create=True) as mocked_open,
        patch("builtins.print"),
    ):
        result = notifications.send_notification(ALERT)

    assert result is False
    assert mocked_open.call_count == notifications.MAX_LOG_WRITE_ATTEMPTS
    assert notifications._get_alert_key(ALERT) not in notifications._last_notification_times


def test_successful_delivery_activates_cooldown():
    with (
        patch.object(notifications, "LOG_FILE", "unused-test-log"),
        patch.object(notifications, "open", mock_open(), create=True),
        patch("builtins.print"),
    ):
        first = notifications.send_notification(ALERT)
        second = notifications.send_notification(ALERT)

    assert first is True
    assert second is False


def test_retry_count_is_bounded_to_three_attempts():
    with (
        patch.object(notifications, "open", side_effect=OSError("simulated failure"), create=True) as mocked_open,
        patch("builtins.print"),
    ):
        result = notifications.send_notification(ALERT)

    assert result is False
    assert mocked_open.call_count == 3
