"""
CloudSentinel Day 64 incident timeline model.

The timeline consumes an investigation-ready incident and the
Day 63 attack graph.

It provides:
    Event -> ordered evidence
    Correlation -> relationship evidence
    Attack-stage progression -> inferred causal relationship

Correlation is not treated as proven causation.
A LEADS_TO relationship requires temporal ordering and
forward attack-stage progression.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from src.attack_graph.attack_graph import (
    AttackGraph,
    build_attack_graph,
)


ATTACK_STAGE_ORDER = (
    "RECONNAISSANCE",
    "ACCESS",
    "CREDENTIAL",
    "PRIVILEGE",
)

_STAGE_INDEX = {
    stage: index
    for index, stage in enumerate(ATTACK_STAGE_ORDER)
}


def _parse_timestamp(value: Any) -> Optional[datetime]:
    """Safely parse a CloudSentinel timestamp."""
    if value is None:
        return None

    text = str(value).strip()

    if not text:
        return None

    normalized = text.replace("Z", "+00:00")

    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def _timestamp_key(event: Dict[str, Any]):
    """Return deterministic event ordering."""
    timestamp = _parse_timestamp(event.get("timestamp"))

    return (
        timestamp is None,
        timestamp or datetime.max,
        str(event.get("id", "")),
    )


def _stage_index(stage: Optional[str]) -> Optional[int]:
    """Return ordered attack-stage index."""
    if stage is None:
        return None

    return _STAGE_INDEX.get(str(stage).upper())


@dataclass(frozen=True)
class TimelineEntry:
    """One ordered piece of incident evidence."""

    sequence: int
    event_id: Any
    timestamp: Optional[str]
    event_type: str
    severity: str
    risk_score: int
    risk_level: str
    attack_stage: Optional[str]
    source_ip: Optional[str]
    user: Optional[str]
    message: str
    elapsed_seconds: Optional[float]
    evidence_type: str = "SECURITY_EVENT"

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serializable entry."""
        return {
            "sequence": self.sequence,
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "attack_stage": self.attack_stage,
            "source_ip": self.source_ip,
            "user": self.user,
            "message": self.message,
            "elapsed_seconds": self.elapsed_seconds,
            "evidence_type": self.evidence_type,
        }


@dataclass(frozen=True)
class TimelineRelationship:
    """Relationship between two timeline events."""

    source_event_id: Any
    target_event_id: Any
    relationship: str
    basis: List[str] = field(default_factory=list)
    correlation_reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serializable relationship."""
        return {
            "source_event_id": self.source_event_id,
            "target_event_id": self.target_event_id,
            "relationship": self.relationship,
            "basis": list(self.basis),
            "correlation_reasons": list(
                self.correlation_reasons
            ),
        }


@dataclass
class IncidentTimeline:
    """Deterministic ordered incident timeline."""

    incident_id: str
    entries: List[TimelineEntry] = field(default_factory=list)
    relationships: List[TimelineRelationship] = field(
        default_factory=list
    )

    def add_entry(self, entry: TimelineEntry) -> None:
        """Add an entry unless its event ID already exists."""
        if any(
            existing.event_id == entry.event_id
            for existing in self.entries
        ):
            return

        self.entries.append(entry)

    def add_relationship(
        self,
        relationship: TimelineRelationship,
    ) -> None:
        """Add a relationship unless already present."""
        for existing in self.relationships:
            if (
                existing.source_event_id
                == relationship.source_event_id
                and existing.target_event_id
                == relationship.target_event_id
                and existing.relationship
                == relationship.relationship
            ):
                return

        self.relationships.append(relationship)

    def to_dict(self) -> Dict[str, Any]:
        """Return the complete timeline."""
        return {
            "incident_id": self.incident_id,
            "entry_count": len(self.entries),
            "relationship_count": len(
                self.relationships
            ),
            "entries": [
                entry.to_dict()
                for entry in self.entries
            ],
            "relationships": [
                relationship.to_dict()
                for relationship in self.relationships
            ],
        }


def _graph_node_lookup(
    graph: AttackGraph,
) -> Dict[Any, Any]:
    """Map event IDs to Day 63 graph nodes."""
    return {
        node.event_id: node
        for node in graph.nodes
    }


def _correlation_lookup(
    incident: Dict[str, Any],
) -> Dict[Tuple[Any, Any], List[str]]:
    """Map correlated event pairs to their evidence reasons."""
    correlation = incident.get("correlation", {})

    if not isinstance(correlation, dict):
        return {}

    relationships = correlation.get(
        "relationships",
        [],
    )

    if not isinstance(relationships, list):
        return {}

    result: Dict[Tuple[Any, Any], List[str]] = {}

    for relationship in relationships:
        if not isinstance(relationship, dict):
            continue

        source_id = relationship.get("event_id")
        target_id = relationship.get(
            "related_event_id"
        )

        if source_id is None or target_id is None:
            continue

        reasons = relationship.get("reasons", [])

        if not isinstance(reasons, list):
            reasons = []

        result[(source_id, target_id)] = [
            str(reason)
            for reason in reasons
        ]

    return result


def _build_entries(
    incident: Dict[str, Any],
    graph: AttackGraph,
) -> List[TimelineEntry]:
    """Build deterministic ordered evidence."""
    events = incident.get("events", [])

    if not isinstance(events, list):
        return []

    ordered_events = sorted(
        events,
        key=_timestamp_key,
    )

    node_lookup = _graph_node_lookup(graph)

    first_timestamp = None

    for event in ordered_events:
        parsed = _parse_timestamp(
            event.get("timestamp")
        )

        if parsed is not None:
            first_timestamp = parsed
            break

    entries: List[TimelineEntry] = []

    for sequence, event in enumerate(
        ordered_events,
        start=1,
    ):
        event_id = event.get("id")

        if event_id is None:
            continue

        timestamp = event.get("timestamp")
        parsed_timestamp = _parse_timestamp(timestamp)

        elapsed_seconds = None

        if (
            first_timestamp is not None
            and parsed_timestamp is not None
        ):
            elapsed_seconds = (
                parsed_timestamp - first_timestamp
            ).total_seconds()

        node = node_lookup.get(event_id)

        risk_score = event.get(
            "risk_score",
            0,
        ) or 0

        try:
            risk_score = int(risk_score)
        except (TypeError, ValueError):
            risk_score = 0

        attack_stage = (
            node.attack_stage
            if node is not None
            else None
        )

        entries.append(
            TimelineEntry(
                sequence=sequence,
                event_id=event_id,
                timestamp=timestamp,
                event_type=str(
                    event.get(
                        "event_type",
                        "UNKNOWN",
                    )
                ).upper(),
                severity=str(
                    event.get(
                        "severity",
                        "UNKNOWN",
                    )
                ).upper(),
                risk_score=risk_score,
                risk_level=str(
                    event.get(
                        "risk_level",
                        "LOW",
                    )
                ).upper(),
                attack_stage=attack_stage,
                source_ip=event.get(
                    "ip_address"
                ),
                user=event.get("user"),
                message=str(
                    event.get(
                        "message",
                        "",
                    )
                ),
                elapsed_seconds=elapsed_seconds,
            )
        )

    return entries


def _resolve_event_id(
    value: str,
    entries: List[TimelineEntry],
) -> Any:
    """Resolve graph string IDs to original event IDs."""
    for entry in entries:
        if str(entry.event_id) == value:
            return entry.event_id

    return value


def _build_relationships(
    incident: Dict[str, Any],
    graph: AttackGraph,
    entries: List[TimelineEntry],
) -> List[TimelineRelationship]:
    """
    Build evidence-backed timeline relationships.

    CORRELATED:
        Existing correlation relationship.

    FOLLOWS:
        Correlated events with temporal ordering but no
        forward attack-stage progression.

    LEADS_TO:
        Correlated events with temporal ordering and a
        forward attack-stage transition.
    """
    correlation_lookup = _correlation_lookup(
        incident
    )

    node_lookup = _graph_node_lookup(graph)

    entry_lookup = {
        entry.event_id: entry
        for entry in entries
    }

    relationships: List[
        TimelineRelationship
    ] = []

    for edge in graph.edges:
        source_id = edge.source_node_id.removeprefix(
            "EVENT-"
        )
        target_id = edge.target_node_id.removeprefix(
            "EVENT-"
        )

        source_event_id = _resolve_event_id(
            source_id,
            entries,
        )

        target_event_id = _resolve_event_id(
            target_id,
            entries,
        )

        source_entry = entry_lookup.get(
            source_event_id
        )
        target_entry = entry_lookup.get(
            target_event_id
        )

        if (
            source_entry is None
            or target_entry is None
        ):
            continue

        source_node = node_lookup.get(
            source_event_id
        )
        target_node = node_lookup.get(
            target_event_id
        )

        source_stage = (
            source_node.attack_stage
            if source_node is not None
            else None
        )

        target_stage = (
            target_node.attack_stage
            if target_node is not None
            else None
        )

        source_stage_index = _stage_index(
            source_stage
        )
        target_stage_index = _stage_index(
            target_stage
        )

        reasons = correlation_lookup.get(
            (
                source_event_id,
                target_event_id,
            ),
            list(edge.reasons),
        )

        basis = [
            "TEMPORAL_ORDER",
            "CORRELATION_EVIDENCE",
        ]

        relationship_type = "FOLLOWS"

        if (
            source_stage_index is not None
            and target_stage_index is not None
            and source_stage_index
            < target_stage_index
        ):
            relationship_type = "LEADS_TO"
            basis.append(
                "FORWARD_ATTACK_STAGE_TRANSITION"
            )

        relationships.append(
            TimelineRelationship(
                source_event_id=source_event_id,
                target_event_id=target_event_id,
                relationship=relationship_type,
                basis=basis,
                correlation_reasons=list(
                    reasons
                ),
            )
        )

    return relationships


def build_incident_timeline(
    incident: Dict[str, Any],
    graph: Optional[AttackGraph] = None,
) -> IncidentTimeline:
    """
    Build a deterministic Day 64 incident timeline.

    The supplied incident is never modified.
    """
    incident_id = str(
        incident.get(
            "incident_id",
            "UNKNOWN",
        )
    )

    if graph is None:
        graph = build_attack_graph(
            incident
        )

    timeline = IncidentTimeline(
        incident_id=incident_id
    )

    entries = _build_entries(
        incident,
        graph,
    )

    for entry in entries:
        timeline.add_entry(entry)

    relationships = _build_relationships(
        incident,
        graph,
        entries,
    )

    for relationship in relationships:
        timeline.add_relationship(
            relationship
        )

    return timeline

