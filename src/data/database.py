import sqlite3
from pathlib import Path
from datetime import datetime

from config.settings import DATABASE_PATH


# ============================================================
# CloudSentinel Database Configuration
# ============================================================

DB_PATH = Path(DATABASE_PATH)


# ============================================================
# Helper Functions
# ============================================================

def _get_value(obj, key, default=None):
    """
    Safely get a value from either:

    1. Dictionary
    2. Object with attributes
    """

    if isinstance(obj, dict):
        return obj.get(key, default)

    return getattr(obj, key, default)


# ============================================================
# Initialize Database
# ============================================================

def initialize_database():
    """
    Create the CloudSentinel database and required tables.
    """

    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

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

    Supports both dictionary-based and object-based events.
    """

    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

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

    cursor.execute(
        """
        INSERT INTO security_events
        (
            timestamp,
            event_type,
            severity,
            message,
            source,
            ip_address
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            str(timestamp),
            str(event_type),
            str(severity),
            str(message),
            str(source),
            str(ip_address),
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
    Retrieve all security events from the database.

    Returns:
        List of tuples
    """

    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

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
            ip_address
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
    Save a security alert into the security_alerts table.

    Supports both:

    1. Dictionary-based alerts
    2. Object-based alerts

    This prevents errors such as:

        AttributeError:
        'dict' object has no attribute 'event_type'
    """

    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    # --------------------------------------------------------
    # Extract Alert Information
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Insert Alert
    # --------------------------------------------------------

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
# Get All Security Alerts
# ============================================================

def get_all_alerts():
    """
    Retrieve all security alerts from the database.

    Returns:
        List of tuples
    """

    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

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
# Get New Alerts
# ============================================================

def get_new_alerts():
    """
    Retrieve only alerts whose status is NEW.
    """

    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

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
        WHERE status = 'NEW'
        ORDER BY id DESC
        """
    )

    alerts = cursor.fetchall()

    connection.close()

    return alerts


# ============================================================
# Update Alert Status
# ============================================================

def update_alert_status(alert_id, status):
    """
    Update the status of a security alert.

    Supported statuses:

        NEW
        ACKNOWLEDGED
        RESOLVED
    """

    allowed_statuses = {
        "NEW",
        "ACKNOWLEDGED",
        "RESOLVED"
    }

    status = str(status).upper()

    if status not in allowed_statuses:
        raise ValueError(
            f"Invalid alert status: {status}. "
            f"Allowed values: {allowed_statuses}"
        )

    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE security_alerts
        SET status = ?
        WHERE id = ?
        """,
        (
            status,
            alert_id
        )
    )

    if cursor.rowcount == 0:
        print(f"Warning: Alert {alert_id} not found.")
    else:
        print(
            f"Alert {alert_id} status updated to {status}."
        )

    connection.commit()
    connection.close()


# ============================================================
# Count Security Events
# ============================================================

def count_events():
    """
    Return the total number of stored security events.
    """

    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM security_events
        """
    )

    count = cursor.fetchone()[0]

    connection.close()

    return count


# ============================================================
# Count Security Alerts
# ============================================================

def count_alerts():
    """
    Return the total number of stored security alerts.
    """

    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM security_alerts
        """
    )

    count = cursor.fetchone()[0]

    connection.close()

    return count


# ============================================================
# Count Alerts By Severity
# ============================================================

def count_alerts_by_severity():
    """
    Return alert statistics grouped by severity.

    Example:

        {
            "HIGH": 2,
            "MEDIUM": 1,
            "LOW": 0
        }
    """

    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT severity, COUNT(*)
        FROM security_alerts
        GROUP BY severity
        """
    )

    rows = cursor.fetchall()

    connection.close()

    statistics = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for severity, count in rows:

        severity = str(severity).upper()

        if severity in statistics:
            statistics[severity] = count

    return statistics


# ============================================================
# Count Alerts By Status
# ============================================================

def count_alerts_by_status():
    """
    Return alert statistics grouped by status.
    """

    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT status, COUNT(*)
        FROM security_alerts
        GROUP BY status
        """
    )

    rows = cursor.fetchall()

    connection.close()

    statistics = {
        "NEW": 0,
        "ACKNOWLEDGED": 0,
        "RESOLVED": 0
    }

    for status, count in rows:

        status = str(status).upper()

        if status in statistics:
            statistics[status] = count

    return statistics


# ============================================================
# Main - Database Verification
# ============================================================

if __name__ == "__main__":

    initialize_database()

    print()
    print("=" * 55)
    print("       CloudSentinel Database Verification")
    print("=" * 55)

    # --------------------------------------------------------
    # Security Events
    # --------------------------------------------------------

    events = get_all_events()

    print()
    print(f"Total security events: {len(events)}")

    print()
    print("Recent Security Events:")
    print("-" * 55)

    for event in events[:5]:
        print(event)

    # --------------------------------------------------------
    # Security Alerts
    # --------------------------------------------------------

    alerts = get_all_alerts()

    print()
    print(f"Total security alerts: {len(alerts)}")

    print()
    print("Recent Security Alerts:")
    print("-" * 55)

    for alert in alerts[:5]:
        print(alert)

    # --------------------------------------------------------
    # New Alerts
    # --------------------------------------------------------

    new_alerts = get_new_alerts()

    print()
    print(f"New security alerts: {len(new_alerts)}")

    # --------------------------------------------------------
    # Alert Statistics
    # --------------------------------------------------------

    severity_stats = count_alerts_by_severity()

    print()
    print("Alert Severity Statistics:")
    print("-" * 55)

    print(f"HIGH   : {severity_stats['HIGH']}")
    print(f"MEDIUM : {severity_stats['MEDIUM']}")
    print(f"LOW    : {severity_stats['LOW']}")

    # --------------------------------------------------------
    # Status Statistics
    # --------------------------------------------------------

    status_stats = count_alerts_by_status()

    print()
    print("Alert Status Statistics:")
    print("-" * 55)

    print(f"NEW          : {status_stats['NEW']}")
    print(
        f"ACKNOWLEDGED : "
        f"{status_stats['ACKNOWLEDGED']}"
    )
    print(
        f"RESOLVED     : "
        f"{status_stats['RESOLVED']}"
    )

    # --------------------------------------------------------
    # Verification Complete
    # --------------------------------------------------------

    print()
    print("=" * 55)
    print("Database verification completed.")
    print("=" * 55)
