import json
import sqlite3
from pathlib import Path
from datetime import datetime

from config.settings import DATABASE_PATH


# ============================================================
# CloudSentinel Database Configuration
# ============================================================

DB_PATH = Path(DATABASE_PATH)


# ============================================================
# Default Threat Intelligence Structures
# ============================================================

DEFAULT_IOCS = {
    "ips": [],
    "domains": [],
    "urls": [],
    "hashes": {
        "md5": [],
        "sha1": [],
        "sha256": [],
    },
}

DEFAULT_THREAT_INTEL = {
    "total": 0,
    "items": [],
}


# ============================================================
# Helper Functions
# ============================================================

def _get_value(obj, key, default=None):
    """
    Safely get a value from either a dictionary or object.
    """

    if isinstance(obj, dict):
        return obj.get(key, default)

    return getattr(obj, key, default)


def _json_dumps(value, default):
    """
    Safely serialize a value to JSON.
    """

    try:
        return json.dumps(value)
    except (TypeError, ValueError):
        return json.dumps(default)


def _json_loads(value, default):
    """
    Safely deserialize JSON.
    """

    if not value:
        return default

    try:
        result = json.loads(value)

        if isinstance(result, type(default)):
            return result

    except (TypeError, ValueError, json.JSONDecodeError):
        pass

    return default


# ============================================================
# Database Migration
# ============================================================

def _migrate_security_events_table(cursor):
    """
    Add threat-intelligence and Day-113 ML columns to an existing
    security_events table. Existing data and column positions
    are preserved; new columns are appended.
    """

    cursor.execute(
        "PRAGMA table_info(security_events)"
    )

    columns = {
        row[1]
        for row in cursor.fetchall()
    }

    migrations = [
        (
            "iocs_json",
            """
            ALTER TABLE security_events
            ADD COLUMN iocs_json TEXT
            """
        ),
        (
            "threat_intel_json",
            """
            ALTER TABLE security_events
            ADD COLUMN threat_intel_json TEXT
            """
        ),
        (
            "threat_intel_score",
            """
            ALTER TABLE security_events
            ADD COLUMN threat_intel_score INTEGER DEFAULT 0
            """
        ),
        (
            "user",
            """
            ALTER TABLE security_events
            ADD COLUMN user TEXT
            """
        ),
        (
            "ml_anomaly_score",
            """
            ALTER TABLE security_events
            ADD COLUMN ml_anomaly_score REAL
            """
        ),
        (
            "ml_is_anomaly",
            """
            ALTER TABLE security_events
            ADD COLUMN ml_is_anomaly INTEGER
            """
        ),
        (
            "ml_feature_deviations_json",
            """
            ALTER TABLE security_events
            ADD COLUMN ml_feature_deviations_json TEXT
            """
        ),
    ]

    for column_name, sql in migrations:

        if column_name not in columns:
            cursor.execute(sql)


# ============================================================
# Day-50 Hunting Tables Migration
# ============================================================

def _migrate_hunting_tables(cursor):
    """
    Create Day-50 threat-hunting persistence tables.

    Existing security event data is not modified.
    """

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS saved_hunt_queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT,
            query_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS hunt_investigations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            query_json TEXT NOT NULL,
            event_ids_json TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'OPEN',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )


# ============================================================
# Day-51 Hunt Investigation Migration
# ============================================================

def _migrate_hunt_investigations_table(cursor):
    """
    Add Day-51 hunt-to-incident linkage.

    Existing investigations remain valid because incident_id
    is nullable.
    """

    cursor.execute(
        "PRAGMA table_info(hunt_investigations)"
    )

    columns = {
        row[1]
        for row in cursor.fetchall()
    }

    if "incident_id" not in columns:

        cursor.execute(
            """
            ALTER TABLE hunt_investigations
            ADD COLUMN incident_id TEXT
            """
        )


# ============================================================
# Initialize Database
# ============================================================

def initialize_database():
    """
    Create the CloudSentinel database and perform
    backward-compatible schema migration.
    """

    DB_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    # --------------------------------------------------------
    # Security Events Table
    # --------------------------------------------------------

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            source TEXT,
            ip_address TEXT DEFAULT 'N/A'
        )
        """
    )

    # --------------------------------------------------------
    # Day-42 Migration
    # --------------------------------------------------------

    _migrate_security_events_table(cursor)

    # --------------------------------------------------------
    # Day-50 Hunting Tables
    # --------------------------------------------------------

    _migrate_hunting_tables(cursor)

    # --------------------------------------------------------
    # Day-51 Hunt-to-Incident Migration
    # --------------------------------------------------------

    _migrate_hunt_investigations_table(cursor)

    # --------------------------------------------------------
    # Incident Status Table
    # --------------------------------------------------------

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS incident_status (
            incident_id TEXT PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'OPEN',
            updated_at TEXT NOT NULL
        )
        """
    )

    # --------------------------------------------------------
    # Day-111 Incident Status Audit History
    # --------------------------------------------------------

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS incident_status_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT NOT NULL,
            previous_status TEXT,
            new_status TEXT NOT NULL,
            changed_at TEXT NOT NULL
        )
        """
    )

    # --------------------------------------------------------
    # Security Alerts Table
    # --------------------------------------------------------

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            ip_address TEXT DEFAULT 'N/A',
            created_at TEXT NOT NULL,
            status TEXT DEFAULT 'NEW'
        )
        """
    )

    connection.commit()
    connection.close()

    print("Database initialized successfully.")


# ============================================================
# Save Security Event
# ============================================================

def save_event(event):
    """
    Save a security event into the database.

    Supports dictionary-based and object-based events.
    Threat-intelligence data is stored as JSON.
    """

    DB_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    # Ensure migration exists before inserting.
    initialize_database()

    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    timestamp = _get_value(
        event,
        "timestamp",
        datetime.now().isoformat()
    )

    event_type = _get_value(
        event,
        "event_type",
        "UNKNOWN"
    )

    severity = _get_value(
        event,
        "severity",
        "LOW"
    )

    message = _get_value(
        event,
        "message",
        "No message available"
    )

    source = _get_value(
        event,
        "source",
        "UNKNOWN"
    )

    ip_address = _get_value(
        event,
        "ip_address",
        "N/A"
    )

    user = _get_value(
        event,
        "user",
        None
    )

    iocs = _get_value(
        event,
        "iocs",
        DEFAULT_IOCS
    )

    threat_intel = _get_value(
        event,
        "threat_intel",
        DEFAULT_THREAT_INTEL
    )

    threat_intel_score = _get_value(
        event,
        "threat_intel_score",
        0
    )

    try:
        threat_intel_score = int(threat_intel_score)
    except (TypeError, ValueError):
        threat_intel_score = 0

    ml_anomaly_score = _get_value(event, "ml_anomaly_score", None)
    try:
        ml_anomaly_score = (
            float(ml_anomaly_score)
            if ml_anomaly_score is not None
            else None
        )
    except (TypeError, ValueError):
        ml_anomaly_score = None

    ml_is_anomaly = _get_value(event, "ml_is_anomaly", None)
    if ml_is_anomaly is not None:
        if isinstance(ml_is_anomaly, str):
            flag = ml_is_anomaly.strip().lower()
            if flag in {"true", "1", "yes"}:
                ml_is_anomaly = 1
            elif flag in {"false", "0", "no"}:
                ml_is_anomaly = 0
            else:
                ml_is_anomaly = None
        else:
            ml_is_anomaly = int(bool(ml_is_anomaly))

    ml_feature_deviations = _get_value(
        event, "ml_feature_deviations", {}
    )
    if not isinstance(ml_feature_deviations, dict):
        ml_feature_deviations = {}

    cursor.execute(
        """
        INSERT INTO security_events
        (
            timestamp, event_type, severity, message, source,
            ip_address, iocs_json, threat_intel_json,
            threat_intel_score, user, ml_anomaly_score,
            ml_is_anomaly, ml_feature_deviations_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            str(timestamp),
            str(event_type),
            str(severity),
            str(message),
            str(source),
            str(ip_address),
            _json_dumps(iocs, DEFAULT_IOCS),
            _json_dumps(threat_intel, DEFAULT_THREAT_INTEL),
            threat_intel_score,
            str(user) if user is not None else None,
            ml_anomaly_score,
            ml_is_anomaly,
            _json_dumps(ml_feature_deviations, {}),
        )
    )

    connection.commit()
    connection.close()

    print("Event saved to CloudSentinel database.")


# ============================================================
# Get All Security Events
# ============================================================

def get_all_events():
    """
    Retrieve all security events.

    Original columns remain at positions 0-6.

    Day-42 columns:

        7 = iocs_json
        8 = threat_intel_json
        9 = threat_intel_score

    Day-49 column:

        10 = user

    Day-113 ML columns:

        11 = ml_anomaly_score
        12 = ml_is_anomaly
        13 = ml_feature_deviations_json
    """

    DB_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    initialize_database()

    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            timestamp,
            event_type,
            severity,
            message,
            source,
            ip_address,
            iocs_json,
            threat_intel_json,
            threat_intel_score,
            user,
            ml_anomaly_score,
            ml_is_anomaly,
            ml_feature_deviations_json
        FROM security_events
        ORDER BY id DESC
        """
    )

    events = cursor.fetchall()

    connection.close()

    return events


# ============================================================
# Save Security Alert
# ============================================================

def save_alert(alert):
    """
    Save a security alert.

    Supports dictionary-based and object-based alerts.
    """

    DB_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    initialize_database()

    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    event_type = _get_value(
        alert,
        "event_type",
        "UNKNOWN"
    )

    severity = _get_value(
        alert,
        "severity",
        "LOW"
    )

    message = _get_value(
        alert,
        "message",
        "No message available"
    )

    ip_address = _get_value(
        alert,
        "ip_address",
        "N/A"
    )

    created_at = _get_value(
        alert,
        "created_at",
        datetime.now().isoformat()
    )

    status = _get_value(
        alert,
        "status",
        "NEW"
    )

    cursor.execute(
        """
        INSERT INTO security_alerts
        (
            event_type,
            severity,
            message,
            ip_address,
            created_at,
            status
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            str(event_type),
            str(severity),
            str(message),
            str(ip_address),
            str(created_at),
            str(status),
        )
    )

    connection.commit()
    connection.close()

    print("Alert saved to CloudSentinel database.")


# ============================================================
# Find Recent Duplicate Alert
# ============================================================

def find_recent_duplicate_alert(event_type, ip_address, since):
    """Return a recent matching alert, if one exists."""

    DB_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    initialize_database()

    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            event_type,
            severity,
            message,
            ip_address,
            created_at,
            status
        FROM security_alerts
        WHERE event_type = ?
          AND ip_address = ?
          AND created_at >= ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (
            str(event_type),
            str(ip_address),
            str(since),
        ),
    )

    alert = cursor.fetchone()

    connection.close()

    return alert


# ============================================================
# Get All Security Alerts
# ============================================================

def get_all_alerts():
    """
    Retrieve all security alerts.
    """

    DB_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    initialize_database()

    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            event_type,
            severity,
            message,
            ip_address,
            created_at,
            status
        FROM security_alerts
        ORDER BY id DESC
        """
    )

    alerts = cursor.fetchall()

    connection.close()

    return alerts


# ============================================================
# Incident Status Persistence
# ============================================================

def get_incident_status(incident_id):
    """
    Retrieve the persisted status for an incident.

    Unknown incidents default to OPEN.
    """

    DB_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    initialize_database()

    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    normalized_id = str(
        incident_id
    ).strip().upper()

    cursor.execute(
        """
        SELECT status
        FROM incident_status
        WHERE incident_id = ?
        """,
        (normalized_id,),
    )

    row = cursor.fetchone()

    connection.close()

    if row is None:
        return "OPEN"

    return str(
        row[0]
    ).strip().upper()


def set_incident_status(
    incident_id,
    status,
):
    """
    Persist an incident status and record genuine status changes.

    The caller remains responsible for validating lifecycle transitions.
    Current status and audit history are updated atomically.
    """

    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    initialize_database()

    normalized_id = str(incident_id).strip().upper()
    normalized_status = str(status).strip().upper()

    if not normalized_id:
        raise ValueError("Incident ID must not be empty.")
    if not normalized_status:
        raise ValueError("Incident status must not be empty.")

    changed_at = datetime.now().isoformat()

    connection = sqlite3.connect(DB_PATH)

    try:
        cursor = connection.cursor()
        cursor.execute("BEGIN IMMEDIATE")

        cursor.execute(
            """
            SELECT status
            FROM incident_status
            WHERE incident_id = ?
            """,
            (normalized_id,),
        )
        row = cursor.fetchone()
        previous_status = (
            str(row[0]).strip().upper()
            if row is not None
            else None
        )

        # Avoid duplicate history rows for repeated status requests.
        if previous_status != normalized_status:
            cursor.execute(
                """
                INSERT INTO incident_status (
                    incident_id, status, updated_at
                )
                VALUES (?, ?, ?)
                ON CONFLICT(incident_id)
                DO UPDATE SET
                    status = excluded.status,
                    updated_at = excluded.updated_at
                """,
                (normalized_id, normalized_status, changed_at),
            )

            cursor.execute(
                """
                INSERT INTO incident_status_history (
                    incident_id,
                    previous_status,
                    new_status,
                    changed_at
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    normalized_id,
                    previous_status,
                    normalized_status,
                    changed_at,
                ),
            )

        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def get_incident_status_history(incident_id):
    """Return status-change history in chronological order."""

    normalized_id = str(incident_id).strip().upper()
    if not normalized_id:
        return []

    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    initialize_database()

    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row

    try:
        rows = connection.execute(
            """
            SELECT
                previous_status,
                new_status,
                changed_at
            FROM incident_status_history
            WHERE incident_id = ?
            ORDER BY id ASC
            """,
            (normalized_id,),
        ).fetchall()

        return [dict(row) for row in rows]
    finally:
        connection.close()
