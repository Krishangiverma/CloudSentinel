"""
CloudSentinel Attack Graph Data Model.

Day 63:
    Build a deterministic attack-chain / attack-graph model.

The model is intentionally independent from the existing correlation engine.
It consumes an investigation-ready incident and represents:

    Event -> Node
    Relationship -> Edge
    Attack stage -> Node metadata

The model is deterministic and JSON-serializable so it can later support
Day 64 incident timelines and Day 67 graph visualization.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional


@dataclass(frozen=True)
class AttackGraphNode:
    """One security event represented as an attack-graph node."""

    node_id: str
    event_id: Any
    event_type: str
    timestamp: Optional[str]
    attack_stage: Optional[str] = None
    risk_score: int = 0
    risk_level: str = "LOW"
    source_ip: Optional[str] = None
    user: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serializable node representation."""
        return {
            "node_id": self.node_id,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "attack_stage": self.attack_stage,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "source_ip": self.source_ip,
            "user": self.user,
        }


@dataclass(frozen=True)
class AttackGraphEdge:
    """Directed relationship between two attack-graph nodes."""

    source_node_id: str
    target_node_id: str
    relationship: str
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serializable edge representation."""
        return {
            "source_node_id": self.source_node_id,
            "target_node_id": self.target_node_id,
            "relationship": self.relationship,
            "reasons": list(self.reasons),
        }


@dataclass
class AttackGraph:
    """Deterministic attack-chain / attack-graph representation."""

    incident_id: str
    nodes: List[AttackGraphNode] = field(default_factory=list)
    edges: List[AttackGraphEdge] = field(default_factory=list)

    def add_node(self, node: AttackGraphNode) -> None:
        """Add a node unless the node ID already exists."""
        if any(existing.node_id == node.node_id for existing in self.nodes):
            return

        self.nodes.append(node)

    def add_edge(self, edge: AttackGraphEdge) -> None:
        """Add an edge unless the same relationship already exists."""
        for existing in self.edges:
            if (
                existing.source_node_id == edge.source_node_id
                and existing.target_node_id == edge.target_node_id
                and existing.relationship == edge.relationship
            ):
                return

        self.edges.append(edge)

    def to_dict(self) -> Dict[str, Any]:
        """Return the complete graph as a JSON-serializable dictionary."""
        return {
            "incident_id": self.incident_id,
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
        }


def _normalize_stage_map(attack_chain: Dict[str, Any]) -> Dict[Any, str]:
    """Map event IDs to their deterministic attack stages."""
    stage_map: Dict[Any, str] = {}

    for evidence in attack_chain.get("stage_evidence", []):
        event_id = evidence.get("event_id")
        stage = evidence.get("stage")

        if event_id is not None and stage:
            stage_map[event_id] = str(stage)

    return stage_map


def _event_node_id(event_id: Any) -> str:
    """Create a stable graph node identifier from an event ID."""
    return f"EVENT-{event_id}"


def _build_nodes(
    events: Iterable[Dict[str, Any]],
    attack_chain: Dict[str, Any],
) -> List[AttackGraphNode]:
    """Convert incident events into deterministic graph nodes."""
    stage_map = _normalize_stage_map(attack_chain)

    ordered_events = sorted(
        list(events),
        key=lambda event: (
            str(event.get("timestamp", "")),
            str(event.get("id", "")),
        ),
    )

    nodes: List[AttackGraphNode] = []

    for event in ordered_events:
        event_id = event.get("id")

        if event_id is None:
            continue

        risk_score = event.get("risk_score", 0) or 0

        try:
            risk_score = int(risk_score)
        except (TypeError, ValueError):
            risk_score = 0

        nodes.append(
            AttackGraphNode(
                node_id=_event_node_id(event_id),
                event_id=event_id,
                event_type=str(
                    event.get("event_type", "UNKNOWN")
                ).upper(),
                timestamp=event.get("timestamp"),
                attack_stage=stage_map.get(event_id),
                risk_score=risk_score,
                risk_level=str(
                    event.get("risk_level", "LOW")
                ).upper(),
                source_ip=event.get("ip_address"),
                user=event.get("user"),
            )
        )

    return nodes


def _build_relationship_edges(
    correlation: Dict[str, Any],
) -> List[AttackGraphEdge]:
    """Convert Day 61/62 correlation relationships into graph edges."""
    edges: List[AttackGraphEdge] = []

    for relationship in correlation.get("relationships", []):
        source_event_id = relationship.get("event_id")
        target_event_id = relationship.get("related_event_id")

        if source_event_id is None or target_event_id is None:
            continue

        reasons = relationship.get("reasons", [])

        if not isinstance(reasons, list):
            reasons = []

        edges.append(
            AttackGraphEdge(
                source_node_id=_event_node_id(source_event_id),
                target_node_id=_event_node_id(target_event_id),
                relationship="CORRELATED",
                reasons=[str(reason) for reason in reasons],
            )
        )

    return edges


def build_attack_graph(incident: Dict[str, Any]) -> AttackGraph:
    """
    Build an attack graph from an existing CloudSentinel incident.

    Existing incident fields are consumed without modifying the incident.
    """
    incident_id = str(incident.get("incident_id", "UNKNOWN"))

    graph = AttackGraph(incident_id=incident_id)

    events = incident.get("events", [])
    if not isinstance(events, list):
        events = []

    attack_chain = incident.get("attack_chain", {})
    if not isinstance(attack_chain, dict):
        attack_chain = {}

    correlation = incident.get("correlation", {})
    if not isinstance(correlation, dict):
        correlation = {}

    for node in _build_nodes(events, attack_chain):
        graph.add_node(node)

    for edge in _build_relationship_edges(correlation):
        graph.add_edge(edge)

    return graph
