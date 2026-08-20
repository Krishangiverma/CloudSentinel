import sqlite3
from pathlib import Path


# Database location
DB_PATH = Path("data/cloudsentinel.db")


def initialize_database():
    """
    Create the CloudSentinel database and security_events table.
    """

    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DB_PATH)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            source TEXT
        )
    """)

    connection.commit()
    connection.close()

    print("Database initialized successfully.")


def save_event(event):
    """
    Save a SecurityEvent object into the database.
    """

    connection = sqlite3.connect(DB_PATH)

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO security_events
        (timestamp, event_type, severity, message, source)
        VALUES (?, ?, ?, ?, ?)
    """, (
        str(event.timestamp),
        event.event_type,
        event.severity,
        event.message,
        event.source
    ))

    connection.commit()
    connection.close()


def get_all_events():
    """
    Retrieve all security events from the database.
    """

    connection = sqlite3.connect(DB_PATH)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT id, timestamp, event_type, severity, message, source
        FROM security_events
        ORDER BY id DESC
    """)

    events = cursor.fetchall()

    connection.close()

    return events


if __name__ == "__main__":
    initialize_database()
