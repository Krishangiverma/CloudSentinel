"""
CloudSentinel Background Event Worker.

Consumes queued events through the canonical ingestion pipeline.
Individual event failures are logged without terminating the worker.
"""

import logging
import queue
import threading

from src.ingestion import ingest_event


logger = logging.getLogger(__name__)


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
        """Consume queued events until stopped and the queue is empty."""
        while not self._stop_event.is_set() or not self.event_queue.empty():
            try:
                event = self.event_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            try:
                ingest_event(event)
            except Exception:
                # Do not log raw event contents, which may contain
                # sensitive authentication or security information.
                logger.exception(
                    "Event ingestion failed; worker will continue."
                )
            finally:
                self.event_queue.task_done()
