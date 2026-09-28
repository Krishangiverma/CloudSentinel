"""Day 111: Incident status audit-history tests."""

import pytest

from src.data import database


@pytest.fixture
def isolated_database(tmp_path, monkeypatch):
    """Use a temporary database instead of the project database."""
    monkeypatch.setattr(
        database,
        "DB_PATH",
        tmp_path / "cloudsentinel_test.db",
    )
    database.initialize_database()
    return database.DB_PATH


def test_status_history_records_changes_in_order(isolated_database):
    database.set_incident_status("inc-test-001", "OPEN")
    database.set_incident_status("inc-test-001", "INVESTIGATING")
    database.set_incident_status("inc-test-001", "RESOLVED")

    history = database.get_incident_status_history("inc-test-001")

    assert [entry["previous_status"] for entry in history] == [
        None,
        "OPEN",
        "INVESTIGATING",
    ]
    assert [entry["new_status"] for entry in history] == [
        "OPEN",
        "INVESTIGATING",
        "RESOLVED",
    ]
    assert all(entry["changed_at"] for entry in history)


def test_status_history_is_case_insensitive_for_incident_id(
    isolated_database,
):
    database.set_incident_status("inc-test-002", "OPEN")
    database.set_incident_status("inc-test-002", "INVESTIGATING")

    history = database.get_incident_status_history("INC-TEST-002")

    assert len(history) == 2
    assert history[-1]["new_status"] == "INVESTIGATING"


def test_repeating_same_status_does_not_add_duplicate_history(
    isolated_database,
):
    database.set_incident_status("inc-test-003", "OPEN")
    database.set_incident_status("inc-test-003", "OPEN")

    history = database.get_incident_status_history("inc-test-003")

    assert len(history) == 1


def test_unknown_incident_has_empty_status_history(isolated_database):
    history = database.get_incident_status_history("INC-UNKNOWN")

    assert history == []


def test_status_history_survives_database_reinitialization(
    isolated_database,
):
    database.set_incident_status("inc-test-004", "OPEN")
    database.set_incident_status("inc-test-004", "INVESTIGATING")

    database.initialize_database()

    history = database.get_incident_status_history("inc-test-004")

    assert len(history) == 2
    assert history[0]["new_status"] == "OPEN"
    assert history[1]["new_status"] == "INVESTIGATING"


def test_history_api_returns_chronological_history(monkeypatch):
    from importlib import import_module

    api_module = import_module("src.api.app")
    client = api_module.app.test_client()

    monkeypatch.setattr(
        api_module,
        "_build_correlated_incidents",
        lambda: [{"incident_id": "INC-TEST-API"}],
    )
    monkeypatch.setattr(
        api_module,
        "get_incident_status_history",
        lambda incident_id: [
            {
                "previous_status": None,
                "new_status": "OPEN",
                "changed_at": "2026-10-23T10:00:00",
            },
            {
                "previous_status": "OPEN",
                "new_status": "INVESTIGATING",
                "changed_at": "2026-10-23T10:05:00",
            },
        ],
    )

    response = client.get("/api/incidents/inc-test-api/history")

    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
    assert data["incident_id"] == "INC-TEST-API"
    assert data["count"] == 2
    assert [item["new_status"] for item in data["history"]] == [
        "OPEN",
        "INVESTIGATING",
    ]


def test_history_api_returns_empty_history_for_existing_incident(monkeypatch):
    from importlib import import_module

    api_module = import_module("src.api.app")
    client = api_module.app.test_client()

    monkeypatch.setattr(
        api_module,
        "_build_correlated_incidents",
        lambda: [{"incident_id": "INC-EMPTY"}],
    )
    monkeypatch.setattr(
        api_module,
        "get_incident_status_history",
        lambda incident_id: [],
    )

    response = client.get("/api/incidents/INC-EMPTY/history")

    assert response.status_code == 200
    data = response.get_json()
    assert data["count"] == 0
    assert data["history"] == []


def test_history_api_returns_404_for_unknown_incident(monkeypatch):
    from importlib import import_module

    api_module = import_module("src.api.app")
    client = api_module.app.test_client()

    monkeypatch.setattr(
        api_module,
        "_build_correlated_incidents",
        lambda: [{"incident_id": "INC-EXISTS"}],
    )

    response = client.get("/api/incidents/INC-MISSING/history")

    assert response.status_code == 404
    assert response.get_json()["status"] == "error"
