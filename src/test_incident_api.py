"""
Day 35 tests for the CloudSentinel incident investigation API.
"""

from src.api.app import app


def test_incidents_endpoint_returns_valid_response():

    client = app.test_client()

    response = client.get("/api/incidents")

    assert response.status_code == 200

    data = response.get_json()

    assert "count" in data
    assert "incidents" in data
    assert isinstance(data["incidents"], list)


def test_nonexistent_incident_returns_404():

    client = app.test_client()

    response = client.get(
        "/api/incidents/INC-9999"
    )

    assert response.status_code == 404

    data = response.get_json()

    assert data["status"] == "error"
    assert data["incident_id"] == "INC-9999"


def test_existing_incident_can_be_retrieved():

    client = app.test_client()

    incidents_response = client.get(
        "/api/incidents"
    )

    assert incidents_response.status_code == 200

    incidents = (
        incidents_response
        .get_json()
        ["incidents"]
    )

    if not incidents:
        # The database may legitimately contain no
        # correlated incidents during a clean test run.
        return

    incident_id = incidents[0]["incident_id"]

    response = client.get(
        f"/api/incidents/{incident_id}"
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["status"] == "success"
    assert "incident" in data

    incident = data["incident"]

    assert incident["incident_id"] == incident_id
    assert "ip_address" in incident
    assert "event_count" in incident
    assert "event_types" in incident
    assert "attack_pattern" in incident
    assert "first_seen" in incident
    assert "last_seen" in incident
    assert "max_risk_score" in incident
    assert "risk_level" in incident
    assert "status" in incident
    assert "events" in incident


def test_incident_id_lookup_is_case_insensitive():

    client = app.test_client()

    incidents_response = client.get(
        "/api/incidents"
    )

    incidents = (
        incidents_response
        .get_json()
        ["incidents"]
    )

    if not incidents:
        return

    incident_id = incidents[0]["incident_id"]

    response = client.get(
        f"/api/incidents/{incident_id.lower()}"
    )

    assert response.status_code == 200

    data = response.get_json()

    assert (
        data["incident"]["incident_id"]
        == incident_id
    )
