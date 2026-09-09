"""
CloudSentinel WebSocket Infrastructure.

Provides real-time communication between the CloudSentinel
backend and connected SOC dashboard clients.
"""

from datetime import date, datetime

from flask_socketio import SocketIO, emit

from src.realtime.event_bus import subscribe


# ============================================================
# SOCKET.IO INSTANCE
# ============================================================

socketio = SocketIO(
    cors_allowed_origins="*",
    async_mode="threading",
)


# ============================================================
# JSON-SAFE SERIALIZATION
# ============================================================

def serialize_value(value):
    """
    Convert common Python values into JSON-safe values.

    Flask-SocketIO ultimately serializes event payloads as JSON.
    datetime/date objects are converted to ISO-8601 strings.
    """

    if value is None:
        return None

    if isinstance(value, (datetime, date)):
        return value.isoformat()

    if isinstance(value, dict):
        return {
            key: serialize_value(val)
            for key, val in value.items()
        }

    if isinstance(value, (list, tuple)):
        return [
            serialize_value(item)
            for item in value
        ]

    return value


def serialize_timestamp(value):
    """
    Convert a timestamp into a JSON-safe string.

    Supports datetime/date objects as well as existing strings.
    """

    if value is None:
        return None

    if isinstance(value, (datetime, date)):
        return value.isoformat()

    return str(value)


# ============================================================
# EVENT PAYLOAD BUILDER
# ============================================================

def build_event_payload(event):
    """
    Build a normalized, JSON-safe WebSocket payload.

    Supports both dictionary-based events and object-based
    SecurityEvent instances.
    """

    if isinstance(event, dict):

        payload = {
            "id": event.get("id"),
            "timestamp": serialize_timestamp(
                event.get("timestamp")
            ),
            "event_type": event.get(
                "event_type",
                "UNKNOWN"
            ),
            "severity": event.get(
                "severity",
                "LOW"
            ),
            "message": event.get(
                "message",
                "No message available"
            ),
            "source": event.get(
                "source",
                "UNKNOWN"
            ),
            "ip_address": event.get(
                "ip_address",
                "N/A"
            ),
            "risk_score": event.get(
                "risk_score"
            ),
            "risk_level": event.get(
                "risk_level"
            ),
        }

    else:

        payload = {
            "id": getattr(
                event,
                "id",
                None
            ),
            "timestamp": serialize_timestamp(
                getattr(
                    event,
                    "timestamp",
                    None
                )
            ),
            "event_type": getattr(
                event,
                "event_type",
                "UNKNOWN"
            ),
            "severity": getattr(
                event,
                "severity",
                "LOW"
            ),
            "message": getattr(
                event,
                "message",
                "No message available"
            ),
            "source": getattr(
                event,
                "source",
                "UNKNOWN"
            ),
            "ip_address": getattr(
                event,
                "ip_address",
                "N/A"
            ),
            "risk_score": getattr(
                event,
                "risk_score",
                None
            ),
            "risk_level": getattr(
                event,
                "risk_level",
                None
            ),
        }

    # Make absolutely sure every nested value is JSON-safe.
    return serialize_value(payload)


# ============================================================
# EVENT BUS SUBSCRIPTION
# ============================================================

def handle_realtime_event(event):
    """
    Receive validated events from the internal event bus
    and broadcast them to connected dashboard clients.
    """

    try:

        payload = build_event_payload(event)

        socketio.emit(
            "security_event",
            payload
        )

        print(
            "[WebSocket] Security event broadcast:"
            f" {payload['event_type']} |"
            f" {payload['severity']}"
        )

        return payload

    except Exception as error:

        print(
            "[WebSocket] Broadcast error:"
            f" {error}"
        )

        return None


# Subscribe the WebSocket broadcaster to validated events.
subscribe(handle_realtime_event)


# ============================================================
# CONNECTION HANDLERS
# ============================================================

@socketio.on("connect")
def handle_connect():
    """
    Handle a new SOC dashboard WebSocket connection.
    """

    print(
        "[WebSocket] Dashboard client connected."
    )

    emit(
        "connection_status",
        {
            "status": "connected",
            "message": (
                "CloudSentinel real-time "
                "connection established."
            )
        }
    )


@socketio.on("disconnect")
def handle_disconnect():
    """
    Handle a dashboard WebSocket disconnection.
    """

    print(
        "[WebSocket] Dashboard client disconnected."
    )


# ============================================================
# EVENT BROADCAST
# ============================================================

def broadcast_event(event):
    """
    Backward-compatible wrapper for event broadcasting.

    This function is retained so existing imports or tests
    that reference broadcast_event() continue to work.
    """

    return handle_realtime_event(event)
