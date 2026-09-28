from datetime import date, datetime, timezone

import src.api.websocket as ws
from src.api.app import app


def test_serialize_value_handles_nested_values():
    value = {
        "created": date(2026, 10, 10),
        "nested": {
            "times": (datetime(2026, 10, 10, tzinfo=timezone.utc), None)
        },
    }

    result = ws.serialize_value(value)

    assert result["created"] == "2026-10-10"
    assert result["nested"]["times"][0] == "2026-10-10T00:00:00+00:00"
    assert result["nested"]["times"][1] is None


def test_serialize_timestamp_handles_supported_values():
    assert ws.serialize_timestamp(None) is None
    assert ws.serialize_timestamp(date(2026, 10, 10)) == "2026-10-10"
    assert ws.serialize_timestamp("already-a-string") == "already-a-string"


def test_build_event_payload_supports_dictionary():
    result = ws.build_event_payload({
        "id": 7,
        "timestamp": datetime(2026, 10, 10, tzinfo=timezone.utc),
        "event_type": "BRUTE_FORCE",
        "severity": "HIGH",
        "message": "Multiple failed logins",
        "source": "auth.log",
        "ip_address": "192.0.2.10",
        "risk_score": 85,
        "risk_level": "HIGH",
    })

    assert result["id"] == 7
    assert result["timestamp"] == "2026-10-10T00:00:00+00:00"
    assert result["event_type"] == "BRUTE_FORCE"
    assert result["severity"] == "HIGH"
    assert result["risk_score"] == 85
    assert result["risk_level"] == "HIGH"


def test_build_event_payload_applies_dictionary_defaults():
    result = ws.build_event_payload({})

    assert result["event_type"] == "UNKNOWN"
    assert result["severity"] == "LOW"
    assert result["message"] == "No message available"
    assert result["source"] == "UNKNOWN"
    assert result["ip_address"] == "N/A"
    assert result["timestamp"] is None


def test_build_event_payload_supports_object():
    class SampleEvent:
        id = 12
        timestamp = date(2026, 10, 10)
        event_type = "SSH_LOGIN"
        severity = "MEDIUM"
        message = "Login detected"
        source = "test"
        ip_address = "198.51.100.5"
        risk_score = 45
        risk_level = "MEDIUM"

    result = ws.build_event_payload(SampleEvent())

    assert result["id"] == 12
    assert result["timestamp"] == "2026-10-10"
    assert result["event_type"] == "SSH_LOGIN"
    assert result["severity"] == "MEDIUM"
    assert result["ip_address"] == "198.51.100.5"


def test_websocket_connect_emits_connection_status():
    client = ws.socketio.test_client(app)

    try:
        assert client.is_connected()

        received = client.get_received()
        status_events = [
            event for event in received
            if event["name"] == "connection_status"
        ]

        assert status_events
        assert status_events[0]["args"][0]["status"] == "connected"
    finally:
        client.disconnect()


def test_handle_realtime_event_broadcasts_payload(monkeypatch):
    emitted = []
    monkeypatch.setattr(
        ws.socketio,
        "emit",
        lambda name, payload: emitted.append((name, payload)),
    )

    event = {
        "event_type": "PORT_SCAN",
        "severity": "HIGH",
        "message": "Possible port scan",
    }

    result = ws.handle_realtime_event(event)

    assert result["event_type"] == "PORT_SCAN"
    assert len(emitted) == 1
    assert emitted[0][0] == "security_event"
    assert emitted[0][1]["severity"] == "HIGH"


def test_handle_realtime_event_returns_none_on_error(monkeypatch):
    def raise_error(_event):
        raise ValueError("test serialization failure")

    monkeypatch.setattr(ws, "build_event_payload", raise_error)

    assert ws.handle_realtime_event({}) is None


def test_broadcast_event_delegates_to_handler(monkeypatch):
    expected = {"event_type": "TEST"}
    calls = []

    monkeypatch.setattr(
        ws,
        "handle_realtime_event",
        lambda event: calls.append(event) or expected,
    )

    event = {"event_type": "TEST"}

    assert ws.broadcast_event(event) is expected
    assert calls == [event]


def test_multiple_websocket_clients_connect_successfully():
    first_client = ws.socketio.test_client(app)
    second_client = ws.socketio.test_client(app)

    try:
        assert first_client.is_connected()
        assert second_client.is_connected()

        for client in (first_client, second_client):
            received = client.get_received()
            statuses = [
                item for item in received
                if item["name"] == "connection_status"
            ]

            assert statuses
            assert statuses[0]["args"][0]["status"] == "connected"
    finally:
        first_client.disconnect()
        second_client.disconnect()


def test_websocket_disconnect_completes(capsys):
    client = ws.socketio.test_client(app)

    assert client.is_connected()

    client.disconnect()

    assert not client.is_connected()
    assert "Dashboard client disconnected." in capsys.readouterr().out


def test_new_client_receives_connection_status_after_previous_disconnect():
    first_client = ws.socketio.test_client(app)

    try:
        assert first_client.is_connected()
    finally:
        first_client.disconnect()

    second_client = ws.socketio.test_client(app)

    try:
        assert second_client.is_connected()

        received = second_client.get_received()
        statuses = [
            item for item in received
            if item["name"] == "connection_status"
        ]

        assert statuses
        assert statuses[0]["args"][0]["status"] == "connected"
    finally:
        second_client.disconnect()
