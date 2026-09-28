"""
CloudSentinel Day 64 incident timeline tests.
"""

import json

from src.timeline.incident_timeline import (
    IncidentTimeline,
    TimelineEntry,
    TimelineRelationship,
    build_incident_timeline,
)


def make_incident():
    events = [
        {
            "id": 1,
            "timestamp": "2026-09-28T10:00:00",
            "event_type": "PORT_SCAN",
            "severity": "MEDIUM",
            "risk_score": 50,
            "risk_level": "MEDIUM",
            "ip_address": "10.0.0.10",
            "user": "alice",
            "message": "Port scan detected",
        },
        {
            "id": 2,
            "timestamp": "2026-09-28T10:01:00",
            "event_type": "BRUTE_FORCE",
            "severity": "HIGH",
            "risk_score": 80,
            "risk_level": "HIGH",
            "ip_address": "10.0.0.10",
            "user": "alice",
            "message": "Brute force detected",
        },
        {
            "id": 3,
            "timestamp": "2026-09-28T10:02:00",
            "event_type": "SUDO_ACTIVITY",
            "severity": "CRITICAL",
            "risk_score": 90,
            "risk_level": "CRITICAL",
            "ip_address": "10.0.0.10",
            "user": "alice",
            "message": "Privilege activity detected",
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


def test_timeline_model():
    entry = TimelineEntry(
        sequence=1,
        event_id=1,
        timestamp="2026-09-28T10:00:00",
        event_type="PORT_SCAN",
        severity="MEDIUM",
        risk_score=50,
        risk_level="MEDIUM",
        attack_stage="RECONNAISSANCE",
        source_ip="10.0.0.10",
        user="alice",
        message="Port scan detected",
        elapsed_seconds=0,
    )

    data = entry.to_dict()

    assert data["sequence"] == 1
    assert data["event_id"] == 1
    assert data["attack_stage"] == "RECONNAISSANCE"
    assert data["elapsed_seconds"] == 0


def test_timeline_relationship_model():
    relationship = TimelineRelationship(
        source_event_id=1,
        target_event_id=2,
        relationship="LEADS_TO",
        basis=[
            "TEMPORAL_ORDER",
            "CORRELATION_EVIDENCE",
            "FORWARD_ATTACK_STAGE_TRANSITION",
        ],
        correlation_reasons=["SAME_SOURCE_IP"],
    )

    data = relationship.to_dict()

    assert data["source_event_id"] == 1
    assert data["target_event_id"] == 2
    assert data["relationship"] == "LEADS_TO"
    assert "TEMPORAL_ORDER" in data["basis"]


def test_build_incident_timeline_orders_evidence():
    incident = make_incident()

    incident["events"] = list(
        reversed(incident["events"])
    )

    timeline = build_incident_timeline(incident)

    assert isinstance(timeline, IncidentTimeline)

    assert [
        entry.event_id
        for entry in timeline.entries
    ] == [1, 2, 3]

    assert [
        entry.sequence
        for entry in timeline.entries
    ] == [1, 2, 3]


def test_timeline_preserves_attack_stages():
    timeline = build_incident_timeline(
        make_incident()
    )

    assert [
        entry.attack_stage
        for entry in timeline.entries
    ] == [
        "RECONNAISSANCE",
        "CREDENTIAL",
        "PRIVILEGE",
    ]


def test_timeline_calculates_elapsed_seconds():
    timeline = build_incident_timeline(
        make_incident()
    )

    assert timeline.entries[0].elapsed_seconds == 0
    assert timeline.entries[1].elapsed_seconds == 60
    assert timeline.entries[2].elapsed_seconds == 120


def test_forward_attack_chain_creates_leads_to_relationships():
    timeline = build_incident_timeline(
        make_incident()
    )

    assert [
        relationship.relationship
        for relationship in timeline.relationships
    ] == [
        "LEADS_TO",
        "LEADS_TO",
    ]

    assert (
        timeline.relationships[0].source_event_id
        == 1
    )

    assert (
        timeline.relationships[0].target_event_id
        == 2
    )

    assert (
        "FORWARD_ATTACK_STAGE_TRANSITION"
        in timeline.relationships[0].basis
    )


def test_same_stage_correlation_is_not_called_causal():
    incident = make_incident()

    incident["attack_chain"][
        "stage_evidence"
    ] = [
        {
            "event_id": 1,
            "stage": "RECONNAISSANCE",
        },
        {
            "event_id": 2,
            "stage": "RECONNAISSANCE",
        },
        {
            "event_id": 3,
            "stage": "PRIVILEGE",
        },
    ]

    timeline = build_incident_timeline(
        incident
    )

    assert (
        timeline.relationships[0].relationship
        == "FOLLOWS"
    )

    assert (
        "FORWARD_ATTACK_STAGE_TRANSITION"
        not in timeline.relationships[0].basis
    )


def test_timeline_keeps_correlation_reasons():
    timeline = build_incident_timeline(
        make_incident()
    )

    assert (
        timeline.relationships[0]
        .correlation_reasons
        == [
            "SAME_SOURCE_IP",
            "SAME_USER",
            "WITHIN_TIME_WINDOW",
        ]
    )


def test_timeline_is_json_serializable():
    timeline = build_incident_timeline(
        make_incident()
    )

    data = timeline.to_dict()

    json.dumps(data)

    assert data["incident_id"] == "INC-0001"
    assert data["entry_count"] == 3
    assert data["relationship_count"] == 2


def test_duplicate_entries_are_not_added():
    timeline = IncidentTimeline(
        incident_id="INC-0001"
    )

    entry = TimelineEntry(
        sequence=1,
        event_id=1,
        timestamp=None,
        event_type="TEST",
        severity="LOW",
        risk_score=0,
        risk_level="LOW",
        attack_stage=None,
        source_ip=None,
        user=None,
        message="",
        elapsed_seconds=None,
    )

    timeline.add_entry(entry)
    timeline.add_entry(entry)

    assert len(timeline.entries) == 1


def test_duplicate_relationships_are_not_added():
    timeline = IncidentTimeline(
        incident_id="INC-0001"
    )

    relationship = TimelineRelationship(
        source_event_id=1,
        target_event_id=2,
        relationship="LEADS_TO",
    )

    timeline.add_relationship(relationship)
    timeline.add_relationship(relationship)

    assert len(timeline.relationships) == 1


def test_invalid_incident_fields_are_handled():
    timeline = build_incident_timeline(
        {
            "incident_id": "INC-0002",
            "events": [],
            "attack_chain": None,
            "correlation": None,
        }
    )

    assert timeline.incident_id == "INC-0002"
    assert timeline.entries == []
    assert timeline.relationships == []
