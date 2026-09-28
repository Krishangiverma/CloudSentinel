import json


def _sample_event():
    return (
        100,
        "2026-09-19T12:00:00",
        "TI_TEST",
        "HIGH",
        "Threat intelligence API test",
        "Day42",
        "8.8.8.8",
        json.dumps({
            "ips": ["8.8.8.8"],
            "domains": ["malicious.example.com"],
            "hashes": {
                "md5": [],
                "sha1": [],
                "sha256": [],
            },
        }),
        json.dumps({
            "total": 2,
            "items": [
                {
                    "ioc": "8.8.8.8",
                    "type": "ip",
                    "verdict": "unknown",
                },
                {
                    "ioc": "malicious.example.com",
                    "type": "domain",
                    "verdict": "unknown",
                },
            ],
        }),
        5,
    )


def test_api_events_returns_threat_intelligence(monkeypatch):
    from src.api.app import app

    monkeypatch.setattr(
        "src.api.app.get_all_events",
        lambda: [_sample_event()],
    )

    client = app.test_client()

    response = client.get("/api/events")

    assert response.status_code == 200

    data = response.get_json()

    assert data["count"] == 1

    event = data["events"][0]

    assert event["event_type"] == "TI_TEST"
    assert event["iocs"]["ips"] == ["8.8.8.8"]
    assert event["iocs"]["domains"] == [
        "malicious.example.com"
    ]
    assert event["threat_intel"]["total"] == 2
    assert event["threat_intel_score"] == 5
    assert event["risk_score"] == 75
    assert event["risk_level"] == "HIGH"


def test_api_stats_includes_persisted_threat_intel_score(monkeypatch):
    from src.api.app import app

    monkeypatch.setattr(
        "src.api.app.get_all_events",
        lambda: [_sample_event()],
    )

    client = app.test_client()

    response = client.get("/api/stats")

    assert response.status_code == 200

    data = response.get_json()

    assert data["total_events"] == 1
    assert data["risk"]["total_score"] == 75
    assert data["risk"]["average_score"] == 75
    assert data["risk"]["maximum_score"] == 75
    assert data["risk"]["levels"]["HIGH"] == 1


def test_api_events_handles_empty_threat_intel(monkeypatch):
    from src.api.app import app

    event = list(_sample_event())

    event[7] = ""
    event[8] = ""
    event[9] = 0

    monkeypatch.setattr(
        "src.api.app.get_all_events",
        lambda: [tuple(event)],
    )

    client = app.test_client()

    response = client.get("/api/events")

    assert response.status_code == 200

    data = response.get_json()
    result = data["events"][0]

    assert result["iocs"] == {}
    assert result["threat_intel"] == {}
    assert result["threat_intel_score"] == 0
    assert result["risk_score"] == 70
    assert result["risk_level"] == "HIGH"


def test_api_events_returns_ml_anomaly_fields(monkeypatch):
    from src.api.app import app

    event = list(_sample_event())
    event.extend([
        0.91,
        1,
        json.dumps({"failed_logins": 2.5}),
    ])

    monkeypatch.setattr(
        "src.api.app.get_all_events",
        lambda: [tuple(event)],
    )

    response = app.test_client().get("/api/events")

    assert response.status_code == 200
    result = response.get_json()["events"][0]
    assert result["ml_anomaly_score"] == 0.91
    assert result["ml_is_anomaly"] is True
    assert result["ml_feature_deviations"] == {"failed_logins": 2.5}


def test_api_events_defaults_ml_fields_for_legacy_tuple(monkeypatch):
    from src.api.app import app

    monkeypatch.setattr(
        "src.api.app.get_all_events",
        lambda: [_sample_event()],
    )

    response = app.test_client().get("/api/events")

    assert response.status_code == 200
    result = response.get_json()["events"][0]
    assert result["ml_anomaly_score"] is None
    assert result["ml_is_anomaly"] is None
    assert result["ml_feature_deviations"] == {}


def test_api_events_handles_invalid_ml_deviation_json(monkeypatch):
    from src.api.app import app

    event = list(_sample_event())
    event.extend([0.25, 0, "{invalid"])

    monkeypatch.setattr(
        "src.api.app.get_all_events",
        lambda: [tuple(event)],
    )

    response = app.test_client().get("/api/events")

    assert response.status_code == 200
    result = response.get_json()["events"][0]
    assert result["ml_is_anomaly"] is False
    assert result["ml_feature_deviations"] == {}
