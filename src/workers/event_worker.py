"""
CloudSentinel Background Event Worker.

Consumes events from an in-memory queue and processes them
through the canonical ingestion pipeline.
"""

import queue
import threading

from src.ingestion import ingest_event


class EventWorker:
    """Background worker for asynchronous event processing."""

    def __init__(self):
        self.event_queue = queue.Queue()
        self._stop_event = threading.Event()
        self._thread = None

    def start(self):
        """Start the background worker thread."""
        if self._thread and self._thread.is_alive():
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="CloudSentinelEventWorker",
            daemon=True,
        )
        self._thread.start()

    def submit(self, event):
        """Submit an event for background processing."""
        self.event_queue.put(event)

    def stop(self):
        """Stop the worker after queued events are processed."""
        self._stop_event.set()

        if self._thread:
            self._thread.join(timeout=5)

    def _run(self):
        """Consume and process queued events."""
        while not self._stop_event.is_set() or not self.event_queue.empty():
            try:
                event = self.event_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            try:
                ingest_event(event)
            finally:
                self.event_queue.task_done()
