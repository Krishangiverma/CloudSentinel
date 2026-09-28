# CloudSentinel Background Worker Architecture

## Purpose

CloudSentinel uses a lightweight background worker to process submitted
security events asynchronously through the canonical ingestion function.
A separate in-process event bus supports publish/subscribe delivery to
registered real-time consumers.

These components reduce coupling between event producers, ingestion, and
real-time subscribers. They are process-local mechanisms, not distributed
messaging infrastructure.

## Background Event Worker

### Processing Flow

```text
Event Producer
      |
      v
EventWorker.submit(event)
      |
      v
Python queue.Queue
      |
      v
Daemon Worker Thread
      |
      v
src.ingestion.ingest_event(event)
      |
      v
Canonical Event Ingestion
```

### Lifecycle and Behavior

- `start()` starts the worker thread if it is not already running.
- `submit(event)` places an event on the in-memory queue.
- The worker retrieves queued events and passes them to `ingest_event()`.
- Each retrieved queue item is acknowledged with `task_done()`, including
  items whose ingestion raises an exception.
- Ingestion exceptions are logged without logging the raw event contents.
- A failed event does not, by itself, terminate the worker loop.
- `stop()` sets a stop flag and waits for the thread for up to five seconds.

### Shutdown Limitations

The worker loop checks the stop flag and whether the queue is empty. The
five-second join is a bounded wait, not proof that all work has completed.
If ingestion is still running after the timeout, the thread may remain active.

Callers that require confirmed completion should verify worker and queue state
rather than assuming `stop()` always drains all events before returning.

The queue is in memory. Pending events are not durable across process crashes
or restarts.

## Real-Time Event Bus

The event bus in `src/realtime/event_bus.py` provides an in-process
publish/subscribe mechanism.

### Behavior

- `subscribe(callback)` registers a callback if it is not already registered.
- `publish(event)` snapshots the current subscriber list under a lock.
- Registered callbacks are invoked for the published event.
- Exceptions raised by individual callbacks are caught so that other
  subscribers can still be invoked.

The event bus does not provide persistent delivery, replay, cross-process
distribution, or delivery guarantees after a process failure.

## Component Responsibilities

| Component | Responsibility |
|---|---|
| `src/workers/event_worker.py` | Queue-based asynchronous ingestion |
| `src/ingestion/` | Canonical ingestion functionality |
| `src/realtime/event_bus.py` | In-process event publication and subscriptions |
| `src/api/websocket.py` | WebSocket delivery infrastructure |
| `src/test_event_worker.py` | Basic worker processing test |
| `src/test_event_bus.py` | Event bus tests |

## Operational Boundaries

- The worker queue and event bus exist within the current Python process.
- The worker uses a daemon thread and does not provide durable job storage.
- A bounded `stop()` wait does not guarantee that a slow ingestion operation
  has completed.
- Callback exception handling is best-effort isolation, not guaranteed delivery.
- Multi-process deployment requires careful review of event distribution and
  shared state; in-memory components are not automatically shared between workers.
- A durable broker or distributed worker system is outside the current
  implementation scope.

## Testing

Run the focused worker and event bus tests from the repository root:

```bash
python -m pytest -q src/test_event_worker.py src/test_event_bus.py
```

Run the complete test suite before committing broader changes.
