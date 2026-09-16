"""
CloudSentinel Threat Hunting Engine.

Provides structured filtering over persisted security events.

Supported filters:
    - IP address
    - user
    - event type
    - severity
    - start time
    - end time
    - minimum risk
    - maximum risk
"""

from datetime import datetime

from src.analyzers.risk_engine import analyze_event_risk
from src.data.database import get_all_events


class HuntQuery:
    """
    Structured threat-hunting query.

    All fields are optional, allowing analysts to combine
    multiple filters into one investigation query.
    """

    def __init__(
        self,
        ip=None,
        user=None,
        event_type=None,
        severity=None,
        start_time=None,
        end_time=None,
        min_risk=None,
        max_risk=None,
    ):
        self.ip = ip
        self.user = user
        self.event_type = event_type
        self.severity = severity
        self.start_time = start_time
        self.end_time = end_time
        self.min_risk = min_risk
        self.max_risk = max_risk

    def to_dict(self):
        """Return a JSON-safe representation of the query."""

        return {
            "ip": self.ip,
            "user": self.user,
            "event_type": self.event_type,
            "severity": self.severity,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "min_risk": self.min_risk,
            "max_risk": self.max_risk,
        }


class HuntEngine:
    """
    Threat-hunting query engine.

    The engine reads persisted events and applies filters
    without modifying the underlying database.
    """

    def __init__(self, event_loader=None):
        self.event_loader = (
            event_loader
            if event_loader is not None
            else get_all_events
        )

    @staticmethod
    def _normalize(value):
        """Normalize optional string filters."""

        if value is None:
            return None

        value = str(value).strip()

        if not value:
            return None

        return value

    @staticmethod
    def _parse_time(value):
        """Parse supported timestamp values."""

        if value is None:
            return None

        if isinstance(value, datetime):
            return value

        value = str(value).strip()

        if not value:
            return None

        # Historical/test events may contain the literal
        # string "None" instead of a valid timestamp.
        if value.lower() in {"none", "null"}:
            return None

        try:
            return datetime.fromisoformat(value)
        except ValueError:
            raise ValueError(
                f"Invalid timestamp: {value}"
            )

    @staticmethod
    def _risk_score(event):
        """Calculate the current risk score for an event."""

        result = analyze_event_risk(
            {
                "severity": event[3],
                "event_type": event[2],
                "threat_intel_score": (
                    event[9]
                    if len(event) > 9
                    else 0
                ),
            }
        )

        return int(result.get("risk_score", 0))

    def search(self, query):
        """
        Execute a threat-hunting query.

        Returns a list of normalized event dictionaries.
        """

        if not isinstance(query, HuntQuery):
            raise TypeError(
                "query must be a HuntQuery instance"
            )

        ip_filter = self._normalize(query.ip)
        user_filter = self._normalize(query.user)
        event_type_filter = self._normalize(
            query.event_type
        )
        severity_filter = self._normalize(
            query.severity
        )

        start_time = self._parse_time(
            query.start_time
        )

        end_time = self._parse_time(
            query.end_time
        )

        min_risk = (
            int(query.min_risk)
            if query.min_risk is not None
            else None
        )

        max_risk = (
            int(query.max_risk)
            if query.max_risk is not None
            else None
        )

        events = self.event_loader()

        results = []

        for event in events:

            timestamp = self._parse_time(
                event[1]
            )

            # Events without a valid timestamp cannot participate
            # in time-based hunting, so skip them safely.
            if timestamp is None:
                continue

            event_ip = (
                str(event[6]).strip()
                if event[6] is not None
                else "N/A"
            )

            event_user = (
                str(event[10]).strip()
                if len(event) > 10
                and event[10] is not None
                else None
            )

            event_type = str(
                event[2]
            ).strip().upper()

            severity = str(
                event[3]
            ).strip().upper()

            # ------------------------------------------------
            # IP filter
            # ------------------------------------------------

            if (
                ip_filter is not None
                and event_ip.lower()
                != ip_filter.lower()
            ):
                continue

            # ------------------------------------------------
            # User filter
            # ------------------------------------------------

            if user_filter is not None:

                if event_user is None:
                    continue

                if (
                    event_user.lower()
                    != user_filter.lower()
                ):
                    continue

            # ------------------------------------------------
            # Event type filter
            # ------------------------------------------------

            if (
                event_type_filter is not None
                and event_type
                != event_type_filter.upper()
            ):
                continue

            # ------------------------------------------------
            # Severity filter
            # ------------------------------------------------

            if (
                severity_filter is not None
                and severity
                != severity_filter.upper()
            ):
                continue

            # ------------------------------------------------
            # Time filters
            # ------------------------------------------------

            if (
                start_time is not None
                and timestamp < start_time
            ):
                continue

            if (
                end_time is not None
                and timestamp > end_time
            ):
                continue

            # ------------------------------------------------
            # Risk filters
            # ------------------------------------------------

            risk_score = self._risk_score(event)

            if (
                min_risk is not None
                and risk_score < min_risk
            ):
                continue

            if (
                max_risk is not None
                and risk_score > max_risk
            ):
                continue

            results.append(
                {
                    "id": event[0],
                    "timestamp": event[1],
                    "event_type": event[2],
                    "severity": event[3],
                    "message": event[4],
                    "source": event[5],
                    "ip_address": event[6],
                    "user": event_user,
                    "risk_score": risk_score,
                }
            )

        return results
