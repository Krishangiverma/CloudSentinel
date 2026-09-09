from datetime import datetime

from src.models.event import SecurityEvent
from src.workers import EventWorker


def test_worker_processes_event():
    worker = EventWorker()
    worker.start()

    event = SecurityEvent(
        timestamp=datetime.now(),
        event_type="WORKER_TEST",
        severity="LOW",
        message="Background worker test event",
        source="Day30",
    )

    worker.submit(event)
    worker.event_queue.join()
    worker.stop()

    assert worker.event_queue.empty()


if __name__ == "__main__":
    test_worker_processes_event()
    print("WORKER TEST: PASS")
