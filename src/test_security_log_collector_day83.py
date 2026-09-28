import pytest

from src.collectors import security_log


def test_zero_limit_processes_no_events(monkeypatch):
    def unexpected_call():
        raise AssertionError("Logs should not be read for limit=0")

    monkeypatch.setattr(security_log, "read_security_logs", unexpected_call)

    assert security_log.collect_and_save_events(limit=0) == 0


@pytest.mark.parametrize("limit", [-1, -5])
def test_negative_limit_is_rejected(limit):
    with pytest.raises(ValueError, match="non-negative"):
        security_log.collect_and_save_events(limit=limit)


@pytest.mark.parametrize("limit", [True, 1.5, "2", None])
def test_non_integer_limit_is_rejected(limit):
    with pytest.raises(TypeError, match="non-negative integer"):
        security_log.collect_and_save_events(limit=limit)


def test_positive_limit_processes_latest_entries(monkeypatch):
    logs = ["old\n", "middle\n", "latest\n"]
    processed = []
    saved = []

    monkeypatch.setattr(
        security_log, "read_security_logs", lambda: logs
    )
    monkeypatch.setattr(
        security_log,
        "create_security_event",
        lambda line: line.strip(),
    )
    monkeypatch.setattr(
        security_log,
        "ingest_event",
        lambda event: processed.append(event) or event,
    )
    monkeypatch.setattr(
        security_log, "save_event", lambda event: saved.append(event)
    )

    assert security_log.collect_and_save_events(limit=2) == 2
    assert processed == ["middle", "latest"]
    assert saved == ["middle", "latest"]


def test_empty_logs_return_zero(monkeypatch):
    monkeypatch.setattr(security_log, "read_security_logs", lambda: [])

    assert security_log.collect_and_save_events(limit=5) == 0
