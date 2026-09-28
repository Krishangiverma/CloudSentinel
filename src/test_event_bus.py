import src.api.websocket as ws
import src.realtime.event_bus as event_bus


def test_subscribe_registers_callback_once(monkeypatch):
    subscribers = []
    monkeypatch.setattr(event_bus, "_subscribers", subscribers)

    def callback(_event):
        pass

    event_bus.subscribe(callback)
    event_bus.subscribe(callback)

    assert subscribers == [callback]


def test_publish_dispatches_event_to_subscribers(monkeypatch):
    subscribers = []
    monkeypatch.setattr(event_bus, "_subscribers", subscribers)

    received = []

    def callback(event):
        received.append(event)

    event_bus.subscribe(callback)

    event = {"event_type": "TEST_EVENT"}
    event_bus.publish(event)

    assert received == [event]


def test_publish_continues_after_subscriber_error(monkeypatch, capsys):
    subscribers = []
    monkeypatch.setattr(event_bus, "_subscribers", subscribers)

    received = []

    def failing_callback(_event):
        raise RuntimeError("intentional test failure")

    def working_callback(event):
        received.append(event)

    event_bus.subscribe(failing_callback)
    event_bus.subscribe(working_callback)

    event = {"event_type": "PORT_SCAN"}
    event_bus.publish(event)

    assert received == [event]
    assert "Subscriber error" in capsys.readouterr().out


def test_publish_broadcasts_security_event_through_websocket(monkeypatch):
    monkeypatch.setattr(
        event_bus,
        "_subscribers",
        [ws.handle_realtime_event],
    )

    emitted = []
    monkeypatch.setattr(
        ws.socketio,
        "emit",
        lambda name, payload: emitted.append((name, payload)),
    )

    event = {
        "id": 101,
        "event_type": "BRUTE_FORCE",
        "severity": "HIGH",
        "message": "Repeated failed login attempts",
        "source": "test",
        "ip_address": "192.0.2.20",
        "risk_score": 85,
        "risk_level": "HIGH",
    }

    event_bus.publish(event)

    assert len(emitted) == 1
    assert emitted[0][0] == "security_event"
    assert emitted[0][1]["event_type"] == "BRUTE_FORCE"
    assert emitted[0][1]["severity"] == "HIGH"
    assert emitted[0][1]["risk_score"] == 85
