"""Day 73 regression tests for context validation in the API."""

import src.api.app as app_module


def test_context_endpoint_rejects_invalid_generated_context(monkeypatch):
    incident = {
        "incident_id": "INC-DAY73-INVALID",
        "events": [],
    }

    monkeypatch.setattr(
        app_module,
        "_build_correlated_incidents",
        lambda: [incident],
    )
    monkeypatch.setattr(
        app_module,
        "build_investigation_context",
        lambda _incident: {"schema_version": "invalid"},
    )

    response = app_module.app.test_client().get(
        "/api/incidents/INC-DAY73-INVALID/context"
    )

    assert response.status_code == 500
    data = response.get_json()
    assert data["status"] == "error"
    assert data["incident_id"] == "INC-DAY73-INVALID"
    assert data["message"] == (
        "Generated incident context failed validation."
    )
    assert data["validation_errors"]
    assert any(
        "Missing required section:" in error
        or "Unsupported schema_version" in error
        for error in data["validation_errors"]
    )
