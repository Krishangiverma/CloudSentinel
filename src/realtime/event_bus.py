"""
CloudSentinel Real-Time Event Bus.

Provides a lightweight in-process publish/subscribe mechanism
for validated security events.
"""

from threading import Lock


_subscribers = []
_lock = Lock()


def subscribe(callback):
    """
    Register a callback for validated security events.
    """

    if callback not in _subscribers:
        with _lock:
            if callback not in _subscribers:
                _subscribers.append(callback)


def publish(event):
    """
    Publish a validated security event to all subscribers.
    """

    with _lock:
        subscribers = list(_subscribers)
    print("[Realtime] Subscribers:", len(subscribers))

    for callback in subscribers:
        try:
            callback(event)
        except Exception as error:
            print(
                "[Realtime] Subscriber error:"
                f" {error}"
            )
