import sqlite3

import pytest

from src.data import database


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    """Use a fresh temporary SQLite database for each test."""
    test_db = tmp_path / "cloudsentinel_test.db"
    monkeypatch.setattr(database, "DB_PATH", test_db)
    return test_db


def test_initialize_database_creates_required_tables(isolated_db):
    database.initialize_database()

    with sqlite3.connect(isolated_db) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }

    assert {
        "security_events",
        "saved_hunt_queries",
        "hunt_investigations",
        "incident_status",
        "security_alerts",
    }.issubset(tables)


def test_initialize_database_is_idempotent(isolated_db):
    database.initialize_database()
    database.initialize_database()

    with sqlite3.connect(isolated_db) as connection:
        columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(security_events)"
            )
        }

    assert {
        "iocs_json",
        "threat_intel_json",
        "threat_intel_score",
        "user",
        "ml_anomaly_score",
        "ml_is_anomaly",
        "ml_feature_deviations_json",
    }.issubset(columns)


def test_save_and_retrieve_event(isolated_db):
    database.save_event({
        "timestamp": "2026-10-19T10:00:00",
        "event_type": "BRUTE_FORCE",
        "severity": "HIGH",
        "message": "Test authentication failures",
        "source": "day101-test",
        "ip_address": "192.0.2.10",
        "user": "test-user",
        "iocs": {"ips": ["192.0.2.10"]},
        "threat_intel": {"total": 1, "items": []},
        "threat_intel_score": 10,
    })

    events = database.get_all_events()

    assert len(events) == 1
    event = events[0]

    assert event[2] == "BRUTE_FORCE"
    assert event[3] == "HIGH"
    assert event[4] == "Test authentication failures"
    assert event[6] == "192.0.2.10"
    assert event[9] == 10
    assert event[10] == "test-user"
    assert event[11] is None
    assert event[12] is None
    assert event[13] == "{}"


def test_existing_security_events_table_gets_missing_columns(isolated_db):
    with sqlite3.connect(isolated_db) as connection:
        connection.execute("""
            CREATE TABLE security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                source TEXT,
                ip_address TEXT DEFAULT 'N/A'
            )
        """)
        connection.execute("""
            INSERT INTO security_events
            (timestamp, event_type, severity, message, source, ip_address)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            "2026-10-19T10:00:00",
            "TEST",
            "LOW",
            "Existing record",
            "migration-test",
            "N/A",
        ))

    database.initialize_database()

    with sqlite3.connect(isolated_db) as connection:
        columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(security_events)"
            )
        }
        row = connection.execute(
            "SELECT message FROM security_events"
        ).fetchone()

    assert {"iocs_json", "threat_intel_json", "threat_intel_score", "user"} <= columns
    assert row == ("Existing record",)


def test_save_and_retrieve_ml_anomaly_fields(isolated_db):
    database.save_event({
        "timestamp": "2026-10-24T10:00:00",
        "event_type": "ML_TEST",
        "severity": "MEDIUM",
        "message": "ML persistence test",
        "source": "day113-test",
        "ip_address": "192.0.2.50",
        "ml_anomaly_score": 0.875,
        "ml_is_anomaly": True,
        "ml_feature_deviations": {"failed_logins": 2.25},
    })

    event = database.get_all_events()[0]

    assert event[11] == pytest.approx(0.875)
    assert event[12] == 1
    assert database._json_loads(event[13], {}) == {
        "failed_logins": 2.25
    }
