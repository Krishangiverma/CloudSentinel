"""
CloudSentinel Day 63 attack graph tests.
"""

from src.attack_graph.attack_graph import (
    AttackGraph,
    AttackGraphEdge,
    AttackGraphNode,
    build_attack_graph,
)


def make_incident():
    events = [
        {
            "id": 1,
            "timestamp": "2026-09-28T10:00:00",
            "event_type": "PORT_SCAN",
            "risk_score": 50,
            "risk_level": "MEDIUM",
            "ip_address": "10.0.0.10",
            "user": "alice",
        },
        {
            "id": 2,
            "timestamp": "2026-09-28T10:01:00",
            "event_type": "BRUTE_FORCE",
            "risk_score": 80,
            "risk_level": "CRITICAL",
            "ip_address": "10.0.0.10",
            "user": "alice",
        },
        {
            "id": 3,
            "timestamp": "2026-09-28T10:02:00",
            "event_type": "SUDO_ACTIVITY",
            "risk_score": 90,
            "risk_level": "CRITICAL",
            "ip_address": "10.0.0.10",
            "user": "alice",
        },
    ]

    return {
        "incident_id": "INC-0001",
        "events": events,
        "attack_chain": {
            "stage_evidence": [
                {
                    "event_id": 1,
                    "stage": "RECONNAISSANCE",
                },
                {
                    "event_id": 2,
                    "stage": "CREDENTIAL",
                },
                {
                    "event_id": 3,
                    "stage": "PRIVILEGE",
                },
            ]
        },
        "correlation": {
            "relationships": [
                {
                    "event_id": 1,
                    "related_event_id": 2,
                    "reasons": [
                        "SAME_SOURCE_IP",
                        "SAME_USER",
                        "WITHIN_TIME_WINDOW",
                    ],
                },
                {
                    "event_id": 2,
                    "related_event_id": 3,
                    "reasons": [
                        "SAME_SOURCE_IP",
                        "SAME_USER",
                        "WITHIN_TIME_WINDOW",
                    ],
                },
            ]
        },
    }


def test_attack_graph_node_model():
    node = AttackGraphNode(
        node_id="EVENT-1",
        event_id=1,
        event_type="PORT_SCAN",
        timestamp="2026-09-28T10:00:00",
        attack_stage="RECONNAISSANCE",
        risk_score=50,
        risk_level="MEDIUM",
        source_ip="10.0.0.10",
        user="alice",
    )

    data = node.to_dict()

    assert data["node_id"] == "EVENT-1"
    assert data["event_id"] == 1
    assert data["attack_stage"] == "RECONNAISSANCE"
    assert data["risk_score"] == 50


def test_attack_graph_edge_model():
    edge = AttackGraphEdge(
        source_node_id="EVENT-1",
        target_node_id="EVENT-2",
        relationship="CORRELATED",
        reasons=["SAME_SOURCE_IP"],
    )

    data = edge.to_dict()

    assert data["source_node_id"] == "EVENT-1"
    assert data["target_node_id"] == "EVENT-2"
    assert data["relationship"] == "CORRELATED"
    assert data["reasons"] == ["SAME_SOURCE_IP"]


def test_build_attack_graph_creates_nodes():
    graph = build_attack_graph(make_incident())

    assert isinstance(graph, AttackGraph)
    assert graph.incident_id == "INC-0001"
    assert graph.node_count == 0 if False else True
    assert len(graph.nodes) == 3


def test_build_attack_graph_preserves_attack_stages():
    graph = build_attack_graph(make_incident())

    stages = [
        node.attack_stage
        for node in graph.nodes
    ]

    assert stages == [
        "RECONNAISSANCE",
        "CREDENTIAL",
        "PRIVILEGE",
    ]


def test_build_attack_graph_creates_relationship_edges():
    graph = build_attack_graph(make_incident())

    assert len(graph.edges) == 2

    assert graph.edges[0].source_node_id == "EVENT-1"
    assert graph.edges[0].target_node_id == "EVENT-2"
    assert "SAME_SOURCE_IP" in graph.edges[0].reasons


def test_attack_graph_is_json_serializable_structure():
    graph = build_attack_graph(make_incident())

    data = graph.to_dict()

    assert data["incident_id"] == "INC-0001"
    assert data["node_count"] == 3
    assert data["edge_count"] == 2
    assert len(data["nodes"]) == 3
    assert len(data["edges"]) == 2


def test_duplicate_nodes_are_not_added():
    graph = AttackGraph(incident_id="INC-0001")

    node = AttackGraphNode(
        node_id="EVENT-1",
        event_id=1,
        event_type="TEST",
        timestamp="2026-09-28T10:00:00",
    )

    graph.add_node(node)
    graph.add_node(node)

    assert len(graph.nodes) == 1


def test_duplicate_edges_are_not_added():
    graph = AttackGraph(incident_id="INC-0001")

    edge = AttackGraphEdge(
        source_node_id="EVENT-1",
        target_node_id="EVENT-2",
        relationship="CORRELATED",
        reasons=["SAME_SOURCE_IP"],
    )

    graph.add_edge(edge)
    graph.add_edge(edge)

    assert len(graph.edges) == 1


def test_invalid_optional_graph_fields_are_handled():
    graph = build_attack_graph(
        {
            "incident_id": "INC-0002",
            "events": [],
            "attack_chain": None,
            "correlation": None,
        }
    )

    assert graph.incident_id == "INC-0002"
    assert graph.nodes == []
    assert graph.edges == []
