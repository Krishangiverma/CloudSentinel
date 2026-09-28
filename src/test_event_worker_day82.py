import logging
import threading

from src.workers import event_worker


def test_worker_continues_after_ingestion_failure(monkeypatch, caplog):
    processed = []
    second_event_processed = threading.Event()

    def fake_ingest(event):
        if event == "bad-event":
            raise ValueError("simulated ingestion failure")

        processed.append(event)
        second_event_processed.set()
        return event

    monkeypatch.setattr(event_worker, "ingest_event", fake_ingest)

    worker = event_worker.EventWorker()

    with caplog.at_level(logging.ERROR, logger=event_worker.__name__):
        worker.start()
        worker.submit("bad-event")
        worker.submit("good-event")

        try:
            assert second_event_processed.wait(timeout=3)
        finally:
            worker.stop()

    assert processed == ["good-event"]
    assert "Event ingestion failed" in caplog.text
    assert worker.event_queue.unfinished_tasks == 0


def test_worker_processes_multiple_valid_events(monkeypatch):
    processed = []
    all_processed = threading.Event()

    def fake_ingest(event):
        processed.append(event)
        if len(processed) == 3:
            all_processed.set()
        return event

    monkeypatch.setattr(event_worker, "ingest_event", fake_ingest)

    worker = event_worker.EventWorker()
    worker.start()

    try:
        worker.submit("event-1")
        worker.submit("event-2")
        worker.submit("event-3")

        assert all_processed.wait(timeout=3)
    finally:
        worker.stop()

    assert processed == ["event-1", "event-2", "event-3"]
    assert worker.event_queue.unfinished_tasks == 0
