"""Day 93 regression tests for incident-context API edge cases."""

import src.api.app as app_module


def test_context_endpoint_returns_json_404_for_whitespace_id(monkeypatch):
    monkeypatch.setattr(
        app_module,
        "_build_correlated_incidents",
        lambda: [],
    )

    response = app_module.app.test_client().get(
        "/api/incidents/%20/context"
    )

    assert response.status_code == 404
    assert response.is_json

    data = response.get_json()
    assert data["status"] == "error"
    assert data["message"] == "Security incident not found."


def test_context_endpoint_returns_json_404_for_unknown_unusual_id(
    monkeypatch,
):
    monkeypatch.setattr(
        app_module,
        "_build_correlated_incidents",
        lambda: [],
    )

    response = app_module.app.test_client().get(
        "/api/incidents/INC-UNKNOWN-93%21/context"
    )

    assert response.status_code == 404
    assert response.is_json

    data = response.get_json()
    assert data["status"] == "error"
    assert data["message"] == "Security incident not found."


def test_context_endpoint_matches_incident_id_case_insensitively(
    monkeypatch,
):
    incident = {
        "incident_id": "INC-DAY93-001",
        "events": [],
    }

    expected_context = app_module.build_investigation_context(incident)

    monkeypatch.setattr(
        app_module,
        "_build_correlated_incidents",
        lambda: [incident],
    )
    monkeypatch.setattr(
        app_module,
        "build_investigation_context",
        lambda _incident: expected_context,
    )

    response = app_module.app.test_client().get(
        "/api/incidents/inc-day93-001/context"
    )

    assert response.status_code == 200
    assert response.is_json

    data = response.get_json()
    assert data["status"] == "success"
    assert data["incident_id"] == "INC-DAY93-001"
    assert data["context"] == expected_context
