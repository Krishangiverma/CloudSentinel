"""Day 92 tests for secure investigation-context API errors."""

import src.api.app as app_module


def test_context_endpoint_does_not_expose_internal_exception(monkeypatch):
    incident_id = "INC-DAY92-ERROR"
    incident = {
        "incident_id": incident_id,
        "events": [],
    }
    secret_detail = "INTERNAL_DATABASE_SECRET_92"

    monkeypatch.setattr(
        app_module,
        "_build_correlated_incidents",
        lambda: [incident],
    )

    def fail_context(_incident):
        raise RuntimeError(secret_detail)

    monkeypatch.setattr(
        app_module,
        "build_investigation_context",
        fail_context,
    )

    response = app_module.app.test_client().get(
        f"/api/incidents/{incident_id}/context"
    )

    assert response.status_code == 500

    data = response.get_json()
    assert data["status"] == "error"
    assert data["message"] == "Failed to build incident context."
    assert "error" not in data
    assert secret_detail not in response.get_data(as_text=True)


def test_context_endpoint_still_rejects_invalid_context(monkeypatch):
    incident_id = "INC-DAY92-INVALID"
    incident = {
        "incident_id": incident_id,
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
        f"/api/incidents/{incident_id}/context"
    )

    assert response.status_code == 500

    data = response.get_json()
    assert data["status"] == "error"
    assert data["message"] == (
        "Generated incident context failed validation."
    )
    assert data["validation_errors"]
    assert "context" not in data
