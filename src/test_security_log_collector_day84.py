from src.collectors import security_log


def test_read_security_logs_returns_empty_if_file_missing(monkeypatch):
    class MissingLogPath:
        def exists(self):
            return False

        def __str__(self):
            return "/fake/auth.log"

    monkeypatch.setattr(security_log, "LOG_PATH", MissingLogPath())

    assert security_log.read_security_logs() == []


def test_read_security_logs_handles_permission_error(monkeypatch):
    class FakePath:
        def exists(self):
            return True

        def __str__(self):
            return "/fake/auth.log"

    def raise_permission_error(*args, **kwargs):
        raise PermissionError("permission denied")

    monkeypatch.setattr(security_log, "LOG_PATH", FakePath())
    monkeypatch.setattr("builtins.open", raise_permission_error)

    assert security_log.read_security_logs() == []


def test_ingestion_failure_does_not_stop_remaining_events(monkeypatch):
    logs = ["first log\n", "second log\n", "third log\n"]
    processed = []
    saved = []

    monkeypatch.setattr(
        security_log, "read_security_logs", lambda: logs
    )
    monkeypatch.setattr(
        security_log, "create_security_event", lambda line: line.strip()
    )

    def sometimes_fail(event):
        processed.append(event)
        if event == "second log":
            raise RuntimeError("simulated ingestion failure")
        return event

    monkeypatch.setattr(security_log, "ingest_event", sometimes_fail)
    monkeypatch.setattr(
        security_log, "save_event", lambda event: saved.append(event)
    )

    count = security_log.collect_and_save_events(limit=3)

    assert processed == ["first log", "second log", "third log"]
    assert saved == ["first log", "third log"]
    assert count == 2
