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
    Add Day-42 threat-intelligence columns to an existing
    security_events table.

    Existing data is preserved.
    Existing column positions remain unchanged.
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
    ]

    for column_name, sql in migrations:

        if column_name not in columns:
            cursor.execute(sql)


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
        threat_intel_score = int(
            threat_intel_score
        )
    except (TypeError, ValueError):
        threat_intel_score = 0

    cursor.execute(
        """
        INSERT INTO security_events
        (
            timestamp,
            event_type,
            severity,
            message,
            source,
            ip_address,
            iocs_json,
            threat_intel_json,
            threat_intel_score
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            str(timestamp),
            str(event_type),
            str(severity),
            str(message),
            str(source),
            str(ip_address),
            _json_dumps(iocs, DEFAULT_IOCS),
            _json_dumps(
                threat_intel,
                DEFAULT_THREAT_INTEL
            ),
            threat_intel_score,
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
            threat_intel_score
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
