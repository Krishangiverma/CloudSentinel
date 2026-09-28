"""Day 74 regression tests for nested context validation at the API layer."""

from copy import deepcopy

import src.api.app as app_module
from src.test_investigation_context_validator_day72 import valid_context


def test_context_endpoint_rejects_invalid_nested_risk_score(monkeypatch):
    incident_id = "INC-DAY74-INVALID"

    incident = {
        "incident_id": incident_id,
        "events": [],
    }

    context = deepcopy(valid_context())
    context["incident"]["incident_id"] = incident_id
    context["risk"]["max_score"] = "high"

    monkeypatch.setattr(
        app_module,
        "_build_correlated_incidents",
        lambda: [incident],
    )
    monkeypatch.setattr(
        app_module,
        "build_investigation_context",
        lambda _incident: context,
    )

    response = app_module.app.test_client().get(
        f"/api/incidents/{incident_id}/context"
    )

    assert response.status_code == 500

    data = response.get_json()
    assert data["status"] == "error"
    assert data["incident_id"] == incident_id
    assert data["message"] == (
        "Generated incident context failed validation."
    )
    assert "risk.max_score must be numeric." in data["validation_errors"]
    assert "context" not in data
