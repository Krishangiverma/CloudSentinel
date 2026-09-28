import json


from analyzers.confidence_scorer import (
    calculate_confidence,
    score_incident,
)
from analyzers.attack_correlator import correlate_events


def make_event(
    event_id,
    timestamp,
    event_type,
    ip="10.0.0.10",
    user="alice",
    risk_score=50,
    risk_level="MEDIUM",
    threat_intel_score=0,
):
    return {
        "id": event_id,
        "timestamp": timestamp,
        "event_type": event_type,
        "severity": risk_level,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "threat_intel_score": threat_intel_score,
        "message": f"Test event {event_id}",
        "source": "CloudSentinel",
        "ip_address": ip,
        "user": user,
        "iocs": [],
    }


def make_incident(
    event_count=5,
    stage_count=2,
    relationship_count=2,
    source_ips=None,
    users=None,
    complete_chain=False,
):
    events = [
        make_event(
            index + 1,
            f"2026-09-28T10:0{index}:00+00:00",
            "BRUTE_FORCE",
            risk_score=70,
            risk_level="HIGH",
        )
        for index in range(event_count)
    ]

    relationships = [
        {
            "source_event_id": index + 1,
            "target_event_id": index + 2,
            "reasons": [
                "SAME_SOURCE_IP",
                "WITHIN_TIME_WINDOW",
            ],
        }
        for index in range(relationship_count)
    ]

    stages = [
        "RECONNAISSANCE",
        "ACCESS",
        "CREDENTIAL",
        "PRIVILEGE",
    ][:stage_count]

    stage_evidence = {}

    for index, event in enumerate(events):
        stage = stages[min(index, len(stages) - 1)]
        stage_evidence[str(event["id"])] = stage

    return {
        "incident_id": "INC-0001",
        "event_count": event_count,
        "events": events,
        "source_ips": source_ips or ["10.0.0.10"],
        "users": users or ["alice"],
        "max_risk_score": 70,
        "max_threat_intel_score": 20,
        "critical_event_count": 0,
        "high_risk_event_count": 2,
        "attack_chain": {
            "stage_count": stage_count,
            "complete_attack_chain": complete_chain,
            "stage_evidence": stage_evidence,
        },
        "correlation": {
            "relationships": relationships,
        },
    }


def test_confidence_score_is_bounded():
    result = calculate_confidence(make_incident())

    assert 0 <= result["score"] <= 100


def test_confidence_has_all_factors():
    result = calculate_confidence(make_incident())

    assert set(result["factors"]) == {
        "event_evidence",
        "multi_stage_coverage",
        "correlation_relationships",
        "identity_continuity",
        "temporal_coherence",
        "supporting_evidence",
    }


def test_factor_total_is_100_or_less():
    result = calculate_confidence(make_incident())

    assert sum(result["factors"].values()) <= 100


def test_complete_attack_chain_gets_full_stage_confidence():
    incomplete = calculate_confidence(
        make_incident(
            stage_count=2,
            complete_chain=False,
        )
    )

    complete = calculate_confidence(
        make_incident(
            stage_count=4,
            complete_chain=True,
        )
    )

    assert complete["factors"]["multi_stage_coverage"] == 25
    assert (
        complete["factors"]["multi_stage_coverage"]
        > incomplete["factors"]["multi_stage_coverage"]
    )


def test_relationships_increase_confidence():
    no_relationships = calculate_confidence(
        make_incident(relationship_count=0)
    )

    relationships = calculate_confidence(
        make_incident(relationship_count=3)
    )

    assert no_relationships["factors"]["correlation_relationships"] == 0
    assert relationships["factors"]["correlation_relationships"] == 15


def test_identity_continuity_is_scored():
    result = calculate_confidence(
        make_incident(
            source_ips=["10.0.0.10"],
            users=["alice"],
        )
    )

    assert result["factors"]["identity_continuity"] == 15


def test_temporal_coherence_is_scored():
    result = calculate_confidence(make_incident())

    assert result["factors"]["temporal_coherence"] == 10


def test_invalid_timestamps_do_not_create_temporal_confidence():
    incident = make_incident()

    for event in incident["events"]:
        event["timestamp"] = "not-a-timestamp"

    result = calculate_confidence(incident)

    assert result["factors"]["temporal_coherence"] == 0


def test_supporting_evidence_is_scored():
    result = calculate_confidence(make_incident())

    assert result["factors"]["supporting_evidence"] > 0


def test_result_contains_explainable_reasons():
    result = calculate_confidence(make_incident())

    assert isinstance(result["reasons"], list)
    assert result["reasons"]


def test_score_incident_alias_matches_calculator():
    incident = make_incident()

    assert score_incident(incident) == calculate_confidence(incident)


def test_result_is_json_serializable():
    result = calculate_confidence(make_incident())

    json.dumps(result)


def test_empty_incident_has_zero_confidence():
    result = calculate_confidence(
        {
            "event_count": 0,
            "events": [],
            "source_ips": [],
            "users": [],
            "attack_chain": {},
            "correlation": {},
        }
    )

    assert result["score"] == 0
    assert result["level"] == "LOW"


def test_existing_correlator_exposes_confidence():
    events = [
        make_event(
            1,
            "2026-09-28T10:00:00+00:00",
            "PORT_SCAN",
            risk_score=40,
            risk_level="MEDIUM",
        ),
        make_event(
            2,
            "2026-09-28T10:01:00+00:00",
            "BRUTE_FORCE",
            risk_score=70,
            risk_level="HIGH",
        ),
        make_event(
            3,
            "2026-09-28T10:02:00+00:00",
            "CREDENTIAL_ACCESS",
            risk_score=80,
            risk_level="HIGH",
        ),
    ]

    incidents = correlate_events(
        events,
        threshold=3,
        time_window_seconds=300,
    )

    assert len(incidents) == 1

    incident = incidents[0]

    assert "confidence_score" in incident
    assert "confidence_level" in incident
    assert "confidence" in incident

    assert incident["confidence_score"] == incident["confidence"]["score"]
    assert incident["confidence_level"] == incident["confidence"]["level"]

    assert 0 <= incident["confidence_score"] <= 100
