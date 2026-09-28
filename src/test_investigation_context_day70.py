import json
from datetime import datetime

import pytest

from src.ai.investigation_context import (
    CONTEXT_SCHEMA_VERSION,
    build_investigation_context,
)


def make_incident():
    return {
        "incident_id": "INC-DAY70-001",
        "attack_pattern": {
            "name": "BRUTE_FORCE_ACTIVITY",
        },
        "status": "INVESTIGATING",
        "confidence": 0.91,
        "response_priority": "HIGH",
        "max_risk_score": 85,
        "events": [
            {
                "id": 1,
                "timestamp": "2026-09-29T10:00:00",
                "event_type": "BRUTE_FORCE",
                "severity": "HIGH",
                "message": "Repeated failed SSH login attempts",
                "source": "CloudSentinel",
                "ip_address": "10.0.0.10",
                "user": "admin",
                "risk_score": 85,
                "risk_level": "CRITICAL",
                "threat_intel_score": 15,
                "iocs": {
                    "ips": ["10.0.0.10"],
                    "domains": [],
                    "urls": [],
                    "hashes": {
                        "md5": [],
                        "sha1": [],
                        "sha256": [],
                    },
                },
                "detections": ["ssh_failed_password"],
                "mitre": {
                    "technique_id": "T1110",
                    "technique": "Brute Force",
                },
            },
            {
                "id": 2,
                "timestamp": "2026-09-29T10:01:00",
                "event_type": "SUSPICIOUS_LOGIN",
                "severity": "MEDIUM",
                "message": "Suspicious successful login",
                "source": "CloudSentinel",
                "ip_address": "10.0.0.10",
                "user": "admin",
                "risk_score": 60,
                "risk_level": "HIGH",
                "threat_intel_score": 5,
                "iocs": {
                    "ips": ["10.0.0.10", "192.168.1.5"],
                    "domains": ["example.test"],
                    "urls": ["https://example.test/login"],
                    "hashes": {
                        "md5": ["abc123"],
                        "sha1": [],
                        "sha256": ["deadbeef"],
                    },
                },
                "detection_rule": "suspicious_login",
                "mitre_attack": {
                    "technique_id": "T1078",
                    "technique": "Valid Accounts",
                },
            },
        ],
        "attack_chain": {
            "stages_present": [
                "ACCESS",
                "CREDENTIAL",
            ],
            "stage_count": 2,
            "multi_stage_attack": True,
        },
    }


def test_invalid_incident_is_rejected():
    with pytest.raises(ValueError):
        build_investigation_context(None)


def test_context_has_expected_top_level_sections():
    context = build_investigation_context(
        make_incident()
    )

    assert context["schema_version"] == CONTEXT_SCHEMA_VERSION

    assert set(context) == {
        "schema_version",
        "incident",
        "risk",
        "events",
        "iocs",
        "detections",
        "mitre_attack",
        "attack_chain",
        "attack_graph",
        "timeline",
    }


def test_risk_context_is_deterministic():
    context = build_investigation_context(
        make_incident()
    )

    risk = context["risk"]

    assert risk["max_score"] == 85
    assert risk["average_score"] == 72.5
    assert risk["risk_level"] == "CRITICAL"
    assert risk["event_scores"] == [85, 60]
    assert risk["level_counts"]["CRITICAL"] == 1
    assert risk["level_counts"]["HIGH"] == 1
    assert risk["max_threat_intel_score"] == 15


def test_iocs_are_aggregated_and_deduplicated():
    context = build_investigation_context(
        make_incident()
    )

    iocs = context["iocs"]

    assert iocs["summary"]["total_ips"] == 2
    assert iocs["summary"]["total_domains"] == 1
    assert iocs["summary"]["total_urls"] == 1
    assert iocs["summary"]["total_hashes"] == 2
    assert iocs["summary"]["has_iocs"] is True

    assert iocs["indicators"]["ips"] == [
        "10.0.0.10",
        "192.168.1.5",
    ]

    assert iocs["indicators"]["domains"] == [
        "example.test"
    ]


def test_detection_and_mitre_evidence_are_preserved():
    context = build_investigation_context(
        make_incident()
    )

    assert [
        "ssh_failed_password"
    ] in context["detections"]

    assert "suspicious_login" in context["detections"]

    assert {
        "technique_id": "T1110",
        "technique": "Brute Force",
    } in context["mitre_attack"]

    assert {
        "technique_id": "T1078",
        "technique": "Valid Accounts",
    } in context["mitre_attack"]


def test_graph_and_timeline_are_reused():
    context = build_investigation_context(
        make_incident()
    )

    graph = context["attack_graph"]
    timeline = context["timeline"]

    assert graph["incident_id"] == "INC-DAY70-001"
    assert "nodes" in graph
    assert "edges" in graph
    assert graph["node_count"] >= 1

    assert timeline["incident_id"] == "INC-DAY70-001"
    assert "entries" in timeline
    assert "relationships" in timeline
    assert timeline["entry_count"] >= 1


def test_context_is_json_serializable():
    context = build_investigation_context(
        make_incident()
    )

    encoded = json.dumps(
        context,
        sort_keys=True,
    )

    assert isinstance(encoded, str)
    assert "INC-DAY70-001" in encoded


def test_context_is_deterministic():
    incident = make_incident()

    first = build_investigation_context(
        incident
    )

    second = build_investigation_context(
        incident
    )

    assert first == second


def test_datetime_event_is_json_safe():
    incident = make_incident()

    incident["events"][0]["timestamp"] = datetime(
        2026,
        9,
        29,
        10,
        0,
    )

    context = build_investigation_context(
        incident
    )

    assert (
        context["events"][0]["timestamp"]
        == "2026-09-29T10:00:00"
    )

    json.dumps(context)
