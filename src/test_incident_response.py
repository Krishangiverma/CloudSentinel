"""
Day 44 tests for CloudSentinel incident response intelligence.
"""

from src.analyzers.attack_correlator import correlate_events


def _event(
    event_id,
    event_type,
    ip="10.10.10.10",
    risk_score=90,
    risk_level="CRITICAL",
    threat_intel_score=0,
    iocs=None,
):
    return {
        "id": event_id,
        "timestamp": f"2026-09-24 10:0{event_id}:00",
        "event_type": event_type,
        "severity": "HIGH",
        "message": f"Test {event_type}",
        "source": "CloudSentinel",
        "ip_address": ip,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "threat_intel_score": threat_intel_score,
        "iocs": iocs or {
            "ips": [],
            "domains": [],
            "hashes": {
                "md5": [],
                "sha1": [],
                "sha256": [],
            },
        },
    }


def test_incident_contains_response_recommendations():
    events = [
        _event(1, "BRUTE_FORCE"),
        _event(2, "BRUTE_FORCE"),
        _event(3, "BRUTE_FORCE"),
    ]

    incidents = correlate_events(events)

    assert len(incidents) == 1

    incident = incidents[0]

    assert "response_recommendations" in incident
    assert isinstance(
        incident["response_recommendations"],
        list,
    )
    assert len(
        incident["response_recommendations"]
    ) > 0


def test_brute_force_incident_recommends_source_ip_review():
    events = [
        _event(1, "BRUTE_FORCE"),
        _event(2, "BRUTE_FORCE"),
        _event(3, "BRUTE_FORCE"),
    ]

    incident = correlate_events(events)[0]

    recommendations = " ".join(
        incident["response_recommendations"]
    ).lower()

    assert "ip" in recommendations
    assert (
        "block" in recommendations
        or "review" in recommendations
    )


def test_ioc_incident_recommends_ioc_investigation():
    iocs = {
        "ips": ["203.0.113.10"],
        "domains": ["malicious.example"],
        "hashes": {
            "md5": [],
            "sha1": [],
            "sha256": [],
        },
    }

    events = [
        _event(
            1,
            "MALWARE",
            iocs=iocs,
            threat_intel_score=5,
        ),
        _event(
            2,
            "MALWARE",
            iocs=iocs,
            threat_intel_score=5,
        ),
        _event(
            3,
            "MALWARE",
            iocs=iocs,
            threat_intel_score=5,
        ),
    ]

    incident = correlate_events(events)[0]

    recommendations = " ".join(
        incident["response_recommendations"]
    ).lower()

    assert (
        "ioc" in recommendations
        or "indicator" in recommendations
    )


def test_response_recommendations_are_deterministic():
    events = [
        _event(1, "PORT_SCAN", risk_score=70, risk_level="HIGH"),
        _event(2, "PORT_SCAN", risk_score=70, risk_level="HIGH"),
        _event(3, "PORT_SCAN", risk_score=70, risk_level="HIGH"),
    ]

    first = correlate_events(events)[0]
    second = correlate_events(events)[0]

    assert (
        first["response_recommendations"]
        == second["response_recommendations"]
    )


def test_api_evidence_contains_response_recommendations():
    from src.api.app import app

    client = app.test_client()

    response = client.get("/api/incidents")

    assert response.status_code == 200

    data = response.get_json()

    incidents = data["incidents"]

    if not incidents:
        return

    incident_id = incidents[0]["incident_id"]

    response = client.get(
        f"/api/incidents/{incident_id}"
    )

    assert response.status_code == 200

    incident = response.get_json()["incident"]

    assert "response_recommendations" in incident
    assert isinstance(
        incident["response_recommendations"],
        list,
    )

    assert "evidence" in incident
    assert (
        "response_recommendations"
        in incident["evidence"]
    )

    assert (
        incident["evidence"]["response_recommendations"]
        == incident["response_recommendations"]
    )


def test_api_response_recommendations_are_non_empty():
    from src.api.app import app

    client = app.test_client()

    response = client.get("/api/incidents")

    assert response.status_code == 200

    data = response.get_json()

    for incident in data["incidents"]:

        recommendations = incident.get(
            "response_recommendations",
            [],
        )

        assert isinstance(
            recommendations,
            list,
        )

        assert len(recommendations) > 0


def test_critical_incident_has_immediate_response_priority():
    events = [
        _event(1, "MALWARE", risk_score=100, risk_level="CRITICAL"),
        _event(2, "MALWARE", risk_score=100, risk_level="CRITICAL"),
        _event(3, "MALWARE", risk_score=100, risk_level="CRITICAL"),
    ]

    incident = correlate_events(events)[0]

    assert incident["response_priority"] == "IMMEDIATE"


def test_high_incident_has_high_response_priority():
    events = [
        _event(1, "PORT_SCAN", risk_score=70, risk_level="HIGH"),
        _event(2, "PORT_SCAN", risk_score=70, risk_level="HIGH"),
        _event(3, "PORT_SCAN", risk_score=70, risk_level="HIGH"),
    ]

    incident = correlate_events(events)[0]

    assert incident["response_priority"] == "HIGH"


def test_medium_incident_has_standard_response_priority():
    events = [
        _event(
            1,
            "SUSPICIOUS_LOGIN",
            risk_score=40,
            risk_level="MEDIUM",
        ),
        _event(
            2,
            "SUSPICIOUS_LOGIN",
            risk_score=40,
            risk_level="MEDIUM",
        ),
        _event(
            3,
            "SUSPICIOUS_LOGIN",
            risk_score=40,
            risk_level="MEDIUM",
        ),
    ]

    incident = correlate_events(events)[0]

    assert incident["response_priority"] == "STANDARD"


def test_response_priority_is_deterministic():
    events = [
        _event(1, "BRUTE_FORCE"),
        _event(2, "BRUTE_FORCE"),
        _event(3, "BRUTE_FORCE"),
    ]

    first = correlate_events(events)[0]
    second = correlate_events(events)[0]

    assert (
        first["response_priority"]
        == second["response_priority"]
    )


def test_api_evidence_contains_response_priority():
    from src.api.app import app

    client = app.test_client()

    response = client.get("/api/incidents")

    assert response.status_code == 200

    incidents = response.get_json()["incidents"]

    if not incidents:
        return

    incident_id = incidents[0]["incident_id"]

    response = client.get(
        f"/api/incidents/{incident_id}"
    )

    assert response.status_code == 200

    incident = response.get_json()["incident"]

    assert "response_priority" in incident
    assert incident["response_priority"] in (
        "IMMEDIATE",
        "HIGH",
        "STANDARD",
    )

    assert "response_priority" in incident["evidence"]

    assert (
        incident["evidence"]["response_priority"]
        == incident["response_priority"]
    )


def test_response_priority_matches_risk_level():
    events = [
        _event(
            1,
            "MALWARE",
            risk_score=100,
            risk_level="CRITICAL",
        ),
        _event(
            2,
            "MALWARE",
            risk_score=100,
            risk_level="CRITICAL",
        ),
        _event(
            3,
            "MALWARE",
            risk_score=100,
            risk_level="CRITICAL",
        ),
    ]

    incident = correlate_events(events)[0]

    assert incident["risk_level"] == "CRITICAL"
    assert incident["response_priority"] == "IMMEDIATE"
    assert (
        incident["evidence"]["response_priority"]
        == "IMMEDIATE"
    )


def test_new_incident_starts_open():
    events = [
        _event(1, "BRUTE_FORCE"),
        _event(2, "BRUTE_FORCE"),
        _event(3, "BRUTE_FORCE"),
    ]

    incident = correlate_events(events)[0]

    assert incident["status"] == "OPEN"


def test_incident_status_is_exposed_in_evidence():
    events = [
        _event(1, "MALWARE"),
        _event(2, "MALWARE"),
        _event(3, "MALWARE"),
    ]

    incident = correlate_events(events)[0]

    assert incident["status"] == "OPEN"
    assert incident["evidence"]["metadata"]["status"] == "OPEN"


def test_incident_status_is_deterministic():
    events = [
        _event(1, "PORT_SCAN"),
        _event(2, "PORT_SCAN"),
        _event(3, "PORT_SCAN"),
    ]

    first = correlate_events(events)[0]
    second = correlate_events(events)[0]

    assert first["status"] == second["status"]
    assert first["status"] == "OPEN"


def test_open_can_transition_to_investigating():
    from src.analyzers.attack_correlator import transition_incident_status

    assert (
        transition_incident_status(
            "OPEN",
            "INVESTIGATING",
        )
        == "INVESTIGATING"
    )


def test_investigating_can_transition_to_resolved():
    from src.analyzers.attack_correlator import transition_incident_status

    assert (
        transition_incident_status(
            "INVESTIGATING",
            "RESOLVED",
        )
        == "RESOLVED"
    )


def test_open_can_transition_directly_to_resolved():
    from src.analyzers.attack_correlator import transition_incident_status

    assert (
        transition_incident_status(
            "OPEN",
            "RESOLVED",
        )
        == "RESOLVED"
    )


def test_resolved_cannot_transition_back_to_open():
    from src.analyzers.attack_correlator import transition_incident_status

    try:
        transition_incident_status(
            "RESOLVED",
            "OPEN",
        )
        assert False
    except ValueError:
        pass


def test_resolved_cannot_transition_back_to_investigating():
    from src.analyzers.attack_correlator import transition_incident_status

    try:
        transition_incident_status(
            "RESOLVED",
            "INVESTIGATING",
        )
        assert False
    except ValueError:
        pass


def test_invalid_status_is_rejected():
    from src.analyzers.attack_correlator import transition_incident_status

    try:
        transition_incident_status(
            "UNKNOWN",
            "OPEN",
        )
        assert False
    except ValueError:
        pass


def test_incident_status_defaults_to_open():
    from src.data.database import (
        get_incident_status,
        set_incident_status,
    )

    incident_id = "TEST-STATUS-001"

    set_incident_status(
        incident_id,
        "OPEN",
    )

    assert (
        get_incident_status(incident_id)
        == "OPEN"
    )


def test_incident_status_can_be_updated():
    from src.data.database import (
        get_incident_status,
        set_incident_status,
    )

    incident_id = "TEST-STATUS-002"

    set_incident_status(
        incident_id,
        "OPEN",
    )

    set_incident_status(
        incident_id,
        "INVESTIGATING",
    )

    assert (
        get_incident_status(incident_id)
        == "INVESTIGATING"
    )


def test_incident_status_is_persistent():
    from src.data.database import (
        get_incident_status,
        set_incident_status,
    )

    incident_id = "TEST-STATUS-003"

    set_incident_status(
        incident_id,
        "RESOLVED",
    )

    # Read again through the database layer.
    assert (
        get_incident_status(incident_id)
        == "RESOLVED"
    )


def test_incident_status_api_updates_to_investigating():
    from src.api.app import app

    client = app.test_client()

    incidents_response = client.get(
        "/api/incidents"
    )

    assert incidents_response.status_code == 200

    incidents = incidents_response.get_json()[
        "incidents"
    ]

    assert incidents

    incident_id = incidents[0]["incident_id"]

    from src.data.database import set_incident_status

    set_incident_status(
        incident_id,
        "OPEN"
    )

    response = client.patch(
        f"/api/incidents/{incident_id}/status",
        json={
            "status": "INVESTIGATING"
        }
    )

    assert response.status_code == 200

    payload = response.get_json()

    assert payload["status"] == "success"
    assert payload["incident"]["status"] == "INVESTIGATING"
    assert (
        payload["incident"]["evidence"]["metadata"]["status"]
        == "INVESTIGATING"
    )


def test_incident_status_api_persists_after_reload():
    from src.api.app import app

    client = app.test_client()

    incidents_response = client.get(
        "/api/incidents"
    )

    assert incidents_response.status_code == 200

    incidents = incidents_response.get_json()[
        "incidents"
    ]

    assert incidents

    incident_id = incidents[0]["incident_id"]

    from src.data.database import set_incident_status

    set_incident_status(
        incident_id,
        "OPEN"
    )

    client.patch(
        f"/api/incidents/{incident_id}/status",
        json={
            "status": "INVESTIGATING"
        }
    )

    reloaded_response = client.get(
        f"/api/incidents/{incident_id}"
    )

    assert reloaded_response.status_code == 200

    reloaded_incident = (
        reloaded_response
        .get_json()["incident"]
    )

    assert (
        reloaded_incident["status"]
        == "INVESTIGATING"
    )

    assert (
        reloaded_incident["evidence"]["metadata"]["status"]
        == "INVESTIGATING"
    )


def test_incident_status_api_rejects_invalid_transition():
    from src.api.app import app

    client = app.test_client()

    incidents_response = client.get(
        "/api/incidents"
    )

    assert incidents_response.status_code == 200

    incidents = incidents_response.get_json()[
        "incidents"
    ]

    assert incidents

    incident_id = incidents[0]["incident_id"]

    client.patch(
        f"/api/incidents/{incident_id}/status",
        json={
            "status": "RESOLVED"
        }
    )

    response = client.patch(
        f"/api/incidents/{incident_id}/status",
        json={
            "status": "OPEN"
        }
    )

    assert response.status_code == 400

    payload = response.get_json()

    assert payload["status"] == "error"
    assert (
        payload["current_status"]
        == "RESOLVED"
    )


def test_incident_status_api_returns_404_for_unknown_incident():
    from src.api.app import app

    client = app.test_client()

    response = client.patch(
        "/api/incidents/INC-NOT-FOUND/status",
        json={
            "status": "INVESTIGATING"
        }
    )

    assert response.status_code == 404

    payload = response.get_json()

    assert payload["status"] == "error"
    assert (
        payload["message"]
        == "Security incident not found."
    )


def test_incident_lifecycle_api_open_to_investigating_to_resolved():
    """Verify the complete incident status lifecycle through the API."""
    from src.api.app import app
    from src.data.database import set_incident_status

    client = app.test_client()

    incidents_response = client.get("/api/incidents")
    assert incidents_response.status_code == 200

    incidents = incidents_response.get_json()["incidents"]
    assert incidents

    incident_id = incidents[0]["incident_id"]

    try:
        set_incident_status(incident_id, "OPEN")

        investigating_response = client.patch(
            f"/api/incidents/{incident_id}/status",
            json={"status": "INVESTIGATING"},
        )
        assert investigating_response.status_code == 200
        assert (
            investigating_response.get_json()["incident"]["status"]
            == "INVESTIGATING"
        )

        resolved_response = client.patch(
            f"/api/incidents/{incident_id}/status",
            json={"status": "RESOLVED"},
        )
        assert resolved_response.status_code == 200
        assert (
            resolved_response.get_json()["incident"]["status"]
            == "RESOLVED"
        )

        reloaded_response = client.get(
            f"/api/incidents/{incident_id}"
        )
        assert reloaded_response.status_code == 200

        reloaded_incident = reloaded_response.get_json()["incident"]
        assert reloaded_incident["status"] == "RESOLVED"
        assert (
            reloaded_incident["evidence"]["metadata"]["status"]
            == "RESOLVED"
        )
    finally:
        set_incident_status(incident_id, "OPEN")
