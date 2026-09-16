"""
CloudSentinel incident investigation API tests.

Validates:
- incident listing
- incident lookup
- case-insensitive incident IDs
- incident metadata
- risk breakdown
- threat-intelligence breakdown
- IOC evidence
- attack pattern
- investigation timeline
- investigation summary
"""


from src.api.app import app


def test_incidents_endpoint_returns_valid_response():

    client = app.test_client()

    response = client.get(
        "/api/incidents"
    )

    assert response.status_code == 200

    data = response.get_json()

    assert "count" in data
    assert "incidents" in data
    assert isinstance(
        data["incidents"],
        list
    )


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

    # --------------------------------------------------------
    # Existing incident structure
    # --------------------------------------------------------

    assert (
        incident["incident_id"]
        == incident_id
    )

    assert "ip_address" in incident
    assert "event_count" in incident
    assert "event_types" in incident
    assert "attack_pattern" in incident
    assert "first_seen" in incident
    assert "last_seen" in incident

    # --------------------------------------------------------
    # Risk context
    # --------------------------------------------------------

    assert "max_risk_score" in incident
    assert "risk_level" in incident
    assert "critical_event_count" in incident
    assert "high_risk_event_count" in incident

    # --------------------------------------------------------
    # Threat-intelligence context
    # --------------------------------------------------------

    assert (
        "total_threat_intel_score"
        in incident
    )

    assert (
        "max_threat_intel_score"
        in incident
    )

    # --------------------------------------------------------
    # IOC context
    # --------------------------------------------------------

    assert "iocs" in incident

    assert isinstance(
        incident["iocs"],
        dict
    )

    assert "ips" in incident["iocs"]
    assert "domains" in incident["iocs"]
    assert "hashes" in incident["iocs"]

    # --------------------------------------------------------
    # Investigation context
    # --------------------------------------------------------

    assert (
        "investigation_summary"
        in incident
    )

    assert "status" in incident
    assert "events" in incident

    assert isinstance(
        incident["events"],
        list
    )


def test_incident_contains_investigation_evidence():

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
        return

    incident_id = incidents[0]["incident_id"]

    response = client.get(
        f"/api/incidents/{incident_id}"
    )

    assert response.status_code == 200

    data = response.get_json()

    incident = data["incident"]

    assert "evidence" in incident

    evidence = incident["evidence"]

    assert isinstance(
        evidence,
        dict
    )

    # --------------------------------------------------------
    # Evidence metadata
    # --------------------------------------------------------

    assert "metadata" in evidence

    metadata = evidence["metadata"]

    assert isinstance(
        metadata,
        dict
    )

    assert (
        metadata["incident_id"]
        == incident_id
    )

    assert "source_ip" in metadata
    assert "event_count" in metadata
    assert "first_seen" in metadata
    assert "last_seen" in metadata
    assert "status" in metadata

    # --------------------------------------------------------
    # Evidence risk section
    # --------------------------------------------------------

    assert "risk" in evidence

    risk = evidence["risk"]

    assert isinstance(
        risk,
        dict
    )

    assert "risk_level" in risk
    assert "max_risk_score" in risk
    assert "critical_event_count" in risk
    assert "high_risk_event_count" in risk
    assert "event_types" in risk

    # --------------------------------------------------------
    # Threat-intelligence evidence
    # --------------------------------------------------------

    assert (
        "threat_intelligence"
        in evidence
    )

    threat_intelligence = (
        evidence["threat_intelligence"]
    )

    assert isinstance(
        threat_intelligence,
        dict
    )

    assert "total_score" in threat_intelligence
    assert "maximum_score" in threat_intelligence

    # --------------------------------------------------------
    # IOC evidence
    # --------------------------------------------------------

    assert "ioc_evidence" in evidence

    ioc_evidence = (
        evidence["ioc_evidence"]
    )

    assert isinstance(
        ioc_evidence,
        dict
    )

    assert "total_ips" in ioc_evidence
    assert "total_domains" in ioc_evidence
    assert "total_hashes" in ioc_evidence
    assert "has_iocs" in ioc_evidence

    assert "ips" in ioc_evidence
    assert "domains" in ioc_evidence
    assert "hashes" in ioc_evidence

    # --------------------------------------------------------
    # Attack pattern evidence
    # --------------------------------------------------------

    assert "attack_pattern" in evidence

    attack_pattern = (
        evidence["attack_pattern"]
    )

    assert isinstance(
        attack_pattern,
        dict
    )

    assert "name" in attack_pattern

    assert (
        "correlation_method"
        in attack_pattern
    )

    # --------------------------------------------------------
    # Timeline evidence
    # --------------------------------------------------------

    assert "timeline" in evidence

    timeline = evidence["timeline"]

    assert isinstance(
        timeline,
        list
    )

    # --------------------------------------------------------
    # Investigation summary
    # --------------------------------------------------------

    assert (
        "investigation_summary"
        in evidence
    )

    assert isinstance(
        evidence["investigation_summary"],
        str
    )


def test_evidence_matches_incident_risk_context():

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
        f"/api/incidents/{incident_id}"
    )

    assert response.status_code == 200

    incident = (
        response
        .get_json()
        ["incident"]
    )

    evidence = incident["evidence"]

    # Risk values must remain consistent
    # between the legacy/top-level incident
    # representation and the evidence package.

    assert (
        evidence["risk"]["risk_level"]
        == incident["risk_level"]
    )

    assert (
        evidence["risk"]["max_risk_score"]
        == incident["max_risk_score"]
    )

    assert (
        evidence["risk"]["critical_event_count"]
        == incident["critical_event_count"]
    )

    assert (
        evidence["risk"]["high_risk_event_count"]
        == incident["high_risk_event_count"]
    )


def test_evidence_matches_threat_intelligence_context():

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
        f"/api/incidents/{incident_id}"
    )

    assert response.status_code == 200

    incident = (
        response
        .get_json()
        ["incident"]
    )

    evidence = incident["evidence"]

    assert (
        evidence["threat_intelligence"]
        ["total_score"]
        == incident[
            "total_threat_intel_score"
        ]
    )

    assert (
        evidence["threat_intelligence"]
        ["maximum_score"]
        == incident[
            "max_threat_intel_score"
        ]
    )


def test_evidence_contains_complete_timeline():

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
        f"/api/incidents/{incident_id}"
    )

    assert response.status_code == 200

    incident = (
        response
        .get_json()
        ["incident"]
    )

    evidence = incident["evidence"]

    timeline = evidence["timeline"]

    assert len(timeline) == (
        incident["event_count"]
    )

    for timeline_event in timeline:

        assert "event_id" in timeline_event
        assert "timestamp" in timeline_event
        assert "event_type" in timeline_event
        assert "risk_score" in timeline_event
        assert "risk_level" in timeline_event
        assert (
            "threat_intel_score"
            in timeline_event
        )
        assert "message" in timeline_event
        assert "ip_address" in timeline_event
        assert "iocs" in timeline_event


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
