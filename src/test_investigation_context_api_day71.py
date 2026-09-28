"""Day 71 tests for the structured incident-context API."""

import src.api.app as app_module


def sample_incident():
    return {
        "incident_id": "INC-DAY71-001",
        "attack_pattern": "SSH_BRUTE_FORCE",
        "status": "OPEN",
        "event_count": 1,
        "events": [
            {
                "id": 101,
                "event_type": "BRUTE_FORCE",
                "severity": "HIGH",
                "risk_score": 75,
                "risk_level": "HIGH",
                "ip_address": "192.0.2.10",
                "timestamp": "2026-10-10T10:00:00",
                "iocs": {"ips": ["192.0.2.10"]},
            }
        ],
    }


def test_context_endpoint_returns_structured_context(monkeypatch):
    incident = sample_incident()
    expected_context = app_module.build_investigation_context(incident)

    monkeypatch.setattr(
        app_module,
        "_build_correlated_incidents",
        lambda: [incident],
    )
    monkeypatch.setattr(
        app_module,
        "build_investigation_context",
        lambda found: expected_context,
    )

    client = app_module.app.test_client()
    response = client.get(
        "/api/incidents/inc-day71-001/context"
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
    assert data["incident_id"] == "INC-DAY71-001"
    assert data["context"] == expected_context


def test_context_endpoint_returns_404_for_unknown_incident(monkeypatch):
    monkeypatch.setattr(
        app_module,
        "_build_correlated_incidents",
        lambda: [],
    )

    client = app_module.app.test_client()
    response = client.get(
        "/api/incidents/INC-NOT-FOUND/context"
    )

    assert response.status_code == 404
    data = response.get_json()
    assert data["status"] == "error"
    assert data["incident_id"] == "INC-NOT-FOUND"


def test_context_endpoint_returns_500_if_context_builder_fails(monkeypatch):
    incident = sample_incident()

    monkeypatch.setattr(
        app_module,
        "_build_correlated_incidents",
        lambda: [incident],
    )

    def fail_context(_incident):
        raise RuntimeError("test context failure")

    monkeypatch.setattr(
        app_module,
        "build_investigation_context",
        fail_context,
    )

    client = app_module.app.test_client()
    response = client.get(
        "/api/incidents/INC-DAY71-001/context"
    )

    assert response.status_code == 500
    assert response.get_json()["status"] == "error"
