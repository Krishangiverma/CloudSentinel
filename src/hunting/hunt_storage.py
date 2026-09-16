"""
CloudSentinel Threat Hunting Persistence.

Provides persistence for:
    - Saved hunting queries
    - Investigation snapshots
    - Investigation timelines
"""

import json
import sqlite3
from datetime import datetime

from src.data.database import DB_PATH, initialize_database
from src.hunting.hunt_engine import HuntQuery


class HuntStorage:
    """Persistence layer for Day-50 threat hunting."""

    def __init__(self, db_path=None):
        self.db_path = db_path or DB_PATH

        if db_path is None:
            initialize_database()
        else:
            self._initialize_custom_database()

    def _initialize_custom_database(self):
        """Initialize Day-50 tables in a custom database."""

        connection = sqlite3.connect(self.db_path)

        try:
            cursor = connection.cursor()

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

            connection.commit()

        finally:
            connection.close()

    def _connect(self):
        """Create a SQLite connection."""
        return sqlite3.connect(self.db_path)

    @staticmethod
    def _now():
        """Return the current ISO timestamp."""
        return datetime.now().isoformat()

    @staticmethod
    def _query_to_json(query):
        """Serialize a HuntQuery."""
        if not isinstance(query, HuntQuery):
            raise TypeError(
                "query must be a HuntQuery instance"
            )

        return json.dumps(
            query.to_dict(),
            sort_keys=True
        )

    @staticmethod
    def _query_from_json(value):
        """Deserialize a HuntQuery."""
        data = json.loads(value)

        return HuntQuery(
            ip=data.get("ip"),
            user=data.get("user"),
            event_type=data.get("event_type"),
            severity=data.get("severity"),
            start_time=data.get("start_time"),
            end_time=data.get("end_time"),
            min_risk=data.get("min_risk"),
            max_risk=data.get("max_risk"),
        )

    # ========================================================
    # Saved Hunting Queries
    # ========================================================

    def save_query(
        self,
        name,
        query,
        description=None,
    ):
        """Persist a reusable hunting query."""

        name = str(name).strip()

        if not name:
            raise ValueError(
                "Saved hunt name cannot be empty"
            )

        query_json = self._query_to_json(query)
        now = self._now()

        connection = self._connect()

        try:
            cursor = connection.cursor()

            cursor.execute(
                """
                INSERT INTO saved_hunt_queries
                (
                    name,
                    description,
                    query_json,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    name,
                    description,
                    query_json,
                    now,
                    now,
                )
            )

            connection.commit()

            return cursor.lastrowid

        finally:
            connection.close()

    def list_queries(self):
        """Return all saved hunting queries."""

        connection = self._connect()

        try:
            cursor = connection.cursor()

            cursor.execute(
                """
                SELECT
                    id,
                    name,
                    description,
                    query_json,
                    created_at,
                    updated_at
                FROM saved_hunt_queries
                ORDER BY id DESC
                """
            )

            rows = cursor.fetchall()

        finally:
            connection.close()

        results = []

        for row in rows:
            results.append(
                {
                    "id": row[0],
                    "name": row[1],
                    "description": row[2],
                    "query": json.loads(row[3]),
                    "created_at": row[4],
                    "updated_at": row[5],
                }
            )

        return results

    def get_query(self, query_id):
        """Return one saved hunting query."""

        connection = self._connect()

        try:
            cursor = connection.cursor()

            cursor.execute(
                """
                SELECT
                    id,
                    name,
                    description,
                    query_json,
                    created_at,
                    updated_at
                FROM saved_hunt_queries
                WHERE id = ?
                """,
                (query_id,)
            )

            row = cursor.fetchone()

        finally:
            connection.close()

        if row is None:
            return None

        return {
            "id": row[0],
            "name": row[1],
            "description": row[2],
            "query": json.loads(row[3]),
            "created_at": row[4],
            "updated_at": row[5],
        }

    def load_query(self, query_id):
        """Load a saved query as a HuntQuery object."""

        saved = self.get_query(query_id)

        if saved is None:
            return None

        return self._query_from_json(
            json.dumps(saved["query"])
        )

    def delete_query(self, query_id):
        """Delete a saved hunting query."""

        connection = self._connect()

        try:
            cursor = connection.cursor()

            cursor.execute(
                """
                DELETE FROM saved_hunt_queries
                WHERE id = ?
                """,
                (query_id,)
            )

            deleted = cursor.rowcount > 0

            connection.commit()

            return deleted

        finally:
            connection.close()

    # ========================================================
    # Investigations
    # ========================================================

    def create_investigation(
        self,
        title,
        query,
        event_ids,
        status="OPEN",
    ):
        """
        Create an investigation snapshot.

        Event IDs are stored so the investigation represents
        the hunt results at investigation creation time.
        """

        title = str(title).strip()

        if not title:
            raise ValueError(
                "Investigation title cannot be empty"
            )

        if not isinstance(event_ids, list):
            raise TypeError(
                "event_ids must be a list"
            )

        normalized_ids = []

        for event_id in event_ids:

            try:
                normalized_ids.append(
                    int(event_id)
                )

            except (TypeError, ValueError):
                continue

        query_json = self._query_to_json(query)
        event_ids_json = json.dumps(
            normalized_ids
        )

        now = self._now()

        connection = self._connect()

        try:
            cursor = connection.cursor()

            cursor.execute(
                """
                INSERT INTO hunt_investigations
                (
                    title,
                    query_json,
                    event_ids_json,
                    status,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    title,
                    query_json,
                    event_ids_json,
                    status,
                    now,
                    now,
                )
            )

            connection.commit()

            return cursor.lastrowid

        finally:
            connection.close()

    def list_investigations(self):
        """Return investigation summaries."""

        connection = self._connect()

        try:
            cursor = connection.cursor()

            cursor.execute(
                """
                SELECT
                    id,
                    title,
                    query_json,
                    event_ids_json,
                    status,
                    created_at,
                    updated_at
                FROM hunt_investigations
                ORDER BY id DESC
                """
            )

            rows = cursor.fetchall()

        finally:
            connection.close()

        results = []

        for row in rows:
            event_ids = json.loads(row[3])

            results.append(
                {
                    "id": row[0],
                    "title": row[1],
                    "query": json.loads(row[2]),
                    "event_count": len(event_ids),
                    "event_ids": event_ids,
                    "status": row[4],
                    "created_at": row[5],
                    "updated_at": row[6],
                }
            )

        return results

    def get_investigation(self, investigation_id):
        """Return one investigation."""

        connection = self._connect()

        try:
            cursor = connection.cursor()

            cursor.execute(
                """
                SELECT
                    id,
                    title,
                    query_json,
                    event_ids_json,
                    status,
                    created_at,
                    updated_at
                FROM hunt_investigations
                WHERE id = ?
                """,
                (investigation_id,)
            )

            row = cursor.fetchone()

        finally:
            connection.close()

        if row is None:
            return None

        return {
            "id": row[0],
            "title": row[1],
            "query": json.loads(row[2]),
            "event_ids": json.loads(row[3]),
            "status": row[4],
            "created_at": row[5],
            "updated_at": row[6],
        }

    def get_investigation_timeline(
        self,
        investigation_id,
    ):
        """
        Build a chronological investigation timeline.

        The timeline is reconstructed from the event IDs stored
        in the investigation snapshot.
        """

        investigation = self.get_investigation(
            investigation_id
        )

        if investigation is None:
            return None

        event_ids = set(
            investigation["event_ids"]
        )

        if not event_ids:
            return []

        from src.data.database import get_all_events

        events = get_all_events()

        timeline = []

        for event in events:

            if event[0] not in event_ids:
                continue

            user = (
                event[10]
                if len(event) > 10
                else None
            )

            timeline.append(
                {
                    "id": event[0],
                    "timestamp": event[1],
                    "event_type": event[2],
                    "severity": event[3],
                    "message": event[4],
                    "source": event[5],
                    "ip_address": event[6],
                    "user": user,
                    "threat_intel_score": (
                        event[9]
                        if len(event) > 9
                        else 0
                    ),
                }
            )

        timeline.sort(
            key=lambda item: (
                item["timestamp"] is None,
                str(item["timestamp"])
            )
        )

        return timeline
