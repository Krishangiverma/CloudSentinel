from src.api.app import app


def test_get_all_mitre_mappings():
    client = app.test_client()

    response = client.get(
        "/api/mitre/mappings"
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["status"] == "ok"
    assert data["count"] == 8
    assert len(data["mappings"]) == 8


def test_get_specific_mitre_mapping():
    client = app.test_client()

    response = client.get(
        "/api/mitre/mappings/PRIV-001"
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["status"] == "ok"

    mapping = data["mapping"]

    assert mapping["rule_id"] == "PRIV-001"
    assert mapping["rule_name"] == "sudo_activity"
    assert mapping["mapping"]["technique_id"] == "T1548"
    assert mapping["mapping"]["subtechnique_id"] == "T1548.003"


def test_unknown_mitre_rule_returns_404():
    client = app.test_client()

    response = client.get(
        "/api/mitre/mappings/DOES-NOT-EXIST"
    )

    assert response.status_code == 404

    data = response.get_json()

    assert data["status"] == "error"
