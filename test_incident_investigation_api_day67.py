"""
CloudSentinel Day 67 - Incident Investigation API tests.

Validates the read-only investigation endpoint that exposes:
    - incident metadata
    - attack graph
    - incident timeline
"""

from src.api.app import app


def _get_first_incident_id(client):
    response = client.get("/api/incidents")

    assert response.status_code == 200

    data = response.get_json()
    incidents = data.get("incidents", [])

    if not incidents:
        return None

    return incidents[0]["incident_id"]


def test_investigation_endpoint_returns_404_for_unknown_incident():
    client = app.test_client()

    response = client.get(
        "/api/incidents/INC-9999/investigation"
    )

    assert response.status_code == 404

    data = response.get_json()

    assert data["status"] == "error"
    assert data["incident_id"] == "INC-9999"


def test_investigation_endpoint_returns_graph_and_timeline():
    client = app.test_client()

    incident_id = _get_first_incident_id(client)

    if incident_id is None:
        return

    response = client.get(
        f"/api/incidents/{incident_id}/investigation"
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["status"] == "success"
    assert data["incident_id"] == incident_id

    assert "investigation" in data

    investigation = data["investigation"]

    assert "timeline" in investigation
    assert "graph" in investigation


def test_investigation_timeline_has_expected_structure():
    client = app.test_client()

    incident_id = _get_first_incident_id(client)

    if incident_id is None:
        return

    response = client.get(
        f"/api/incidents/{incident_id}/investigation"
    )

    assert response.status_code == 200

    investigation = response.get_json()["investigation"]
    timeline = investigation["timeline"]

    assert isinstance(timeline, dict)

    assert timeline["incident_id"] == incident_id
    assert "entries" in timeline
    assert "relationships" in timeline

    assert isinstance(timeline["entries"], list)
    assert isinstance(timeline["relationships"], list)


def test_investigation_graph_has_expected_structure():
    client = app.test_client()

    incident_id = _get_first_incident_id(client)

    if incident_id is None:
        return

    response = client.get(
        f"/api/incidents/{incident_id}/investigation"
    )

    assert response.status_code == 200

    investigation = response.get_json()["investigation"]
    graph = investigation["graph"]

    assert isinstance(graph, dict)

    assert graph["incident_id"] == incident_id
    assert "node_count" in graph
    assert "edge_count" in graph
    assert "nodes" in graph
    assert "edges" in graph

    assert isinstance(graph["nodes"], list)
    assert isinstance(graph["edges"], list)

    assert graph["node_count"] == len(graph["nodes"])
    assert graph["edge_count"] == len(graph["edges"])


def test_investigation_endpoint_is_case_insensitive():
    client = app.test_client()

    incident_id = _get_first_incident_id(client)

    if incident_id is None:
        return

    uppercase_id = incident_id.upper()
    lowercase_id = incident_id.lower()

    response_upper = client.get(
        f"/api/incidents/{uppercase_id}/investigation"
    )

    response_lower = client.get(
        f"/api/incidents/{lowercase_id}/investigation"
    )

    assert response_upper.status_code == 200
    assert response_lower.status_code == 200

    upper_data = response_upper.get_json()
    lower_data = response_lower.get_json()

    assert upper_data["status"] == "success"
    assert lower_data["status"] == "success"

    assert (
        upper_data["investigation"]["graph"]
        == lower_data["investigation"]["graph"]
    )

    assert (
        upper_data["investigation"]["timeline"]
        == lower_data["investigation"]["timeline"]
    )
