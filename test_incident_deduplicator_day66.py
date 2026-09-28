from analyzers.incident_deduplicator import (
    incidents_are_related,
    merge_incidents,
    deduplicate_incidents,
)


def make_event(
    event_id,
    timestamp,
    event_type="BRUTE_FORCE",
    ip="10.0.0.10",
    user="alice",
    risk_score=70,
    risk_level="HIGH",
):
    return {
        "id": event_id,
        "timestamp": timestamp,
        "event_type": event_type,
        "severity": risk_level,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "threat_intel_score": 0,
        "message": f"Test event {event_id}",
        "source": "CloudSentinel",
        "ip_address": ip,
        "user": user,
        "iocs": {
            "ips": [],
            "domains": [],
            "hashes": {
                "md5": [],
                "sha1": [],
                "sha256": [],
            },
        },
    }


def make_incident(
    incident_id,
    events,
    ip="10.0.0.10",
    user="alice",
):
    return {
        "incident_id": incident_id,
        "ip_address": ip,
        "source_ips": [ip],
        "users": [user],
        "events": events,
        "event_count": len(events),
        "event_types": {},
        "attack_pattern": "BRUTE_FORCE_ACTIVITY",
        "first_seen": events[0]["timestamp"],
        "last_seen": events[-1]["timestamp"],
        "max_risk_score": 70,
        "risk_level": "HIGH",
        "max_threat_intel_score": 0,
        "total_threat_intel_score": 0,
        "critical_event_count": 0,
        "high_risk_event_count": len(events),
        "iocs": {
            "ips": [],
            "domains": [],
            "hashes": {
                "md5": [],
                "sha1": [],
                "sha256": [],
            },
        },
        "attack_chain": {
            "stage_count": 1,
            "complete_attack_chain": False,
        },
        "correlation": {
            "relationships": [],
        },
        "confidence_score": 50,
        "confidence_level": "MEDIUM",
        "confidence": {
            "score": 50,
            "level": "MEDIUM",
        },
        "status": "OPEN",
    }


def test_related_incidents_share_source_and_time():
    first = make_incident(
        "INC-0001",
        [
            make_event(
                1,
                "2026-09-29T10:00:00+00:00",
            ),
        ],
    )

    second = make_incident(
        "INC-0002",
        [
            make_event(
                2,
                "2026-09-29T10:03:00+00:00",
            ),
        ],
    )

    assert incidents_are_related(
        first,
        second,
        window_seconds=300,
    )


def test_related_incidents_can_share_user():
    first = make_incident(
        "INC-0001",
        [
            make_event(
                1,
                "2026-09-29T10:00:00+00:00",
                ip="10.0.0.10",
                user="alice",
            ),
        ],
        ip="10.0.0.10",
        user="alice",
    )

    second = make_incident(
        "INC-0002",
        [
            make_event(
                2,
                "2026-09-29T10:02:00+00:00",
                ip="10.0.0.20",
                user="alice",
            ),
        ],
        ip="10.0.0.20",
        user="alice",
    )

    assert incidents_are_related(
        first,
        second,
    )


def test_different_identity_does_not_merge():
    first = make_incident(
        "INC-0001",
        [
            make_event(
                1,
                "2026-09-29T10:00:00+00:00",
                ip="10.0.0.10",
                user="alice",
            ),
        ],
        ip="10.0.0.10",
        user="alice",
    )

    second = make_incident(
        "INC-0002",
        [
            make_event(
                2,
                "2026-09-29T10:01:00+00:00",
                ip="10.0.0.20",
                user="bob",
            ),
        ],
        ip="10.0.0.20",
        user="bob",
    )

    assert not incidents_are_related(
        first,
        second,
    )


def test_far_apart_incidents_do_not_merge():
    first = make_incident(
        "INC-0001",
        [
            make_event(
                1,
                "2026-09-29T10:00:00+00:00",
            ),
        ],
    )

    second = make_incident(
        "INC-0002",
        [
            make_event(
                2,
                "2026-09-29T11:00:00+00:00",
            ),
        ],
    )

    assert not incidents_are_related(
        first,
        second,
        window_seconds=300,
    )


def test_merge_removes_duplicate_events():
    event_one = make_event(
        1,
        "2026-09-29T10:00:00+00:00",
    )

    event_two = make_event(
        2,
        "2026-09-29T10:01:00+00:00",
    )

    first = make_incident(
        "INC-0001",
        [event_one, event_two],
    )

    second = make_incident(
        "INC-0002",
        [event_two],
    )

    merged = merge_incidents(
        [first, second]
    )

    assert merged["incident_id"] == "INC-0001"

    assert [
        event["id"]
        for event in merged["events"]
    ] == [1, 2]

    assert merged["event_count"] == 2


def test_merge_recalculates_confidence():
    first = make_incident(
        "INC-0001",
        [
            make_event(
                1,
                "2026-09-29T10:00:00+00:00",
            ),
            make_event(
                2,
                "2026-09-29T10:01:00+00:00",
            ),
        ],
    )

    second = make_incident(
        "INC-0002",
        [
            make_event(
                3,
                "2026-09-29T10:02:00+00:00",
            ),
        ],
    )

    merged = merge_incidents(
        [first, second]
    )

    assert "confidence" in merged
    assert "confidence_score" in merged
    assert "confidence_level" in merged

    assert (
        merged["confidence_score"]
        == merged["confidence"]["score"]
    )


def test_deduplication_merges_related_incidents():
    incidents = [
        make_incident(
            "INC-0001",
            [
                make_event(
                    1,
                    "2026-09-29T10:00:00+00:00",
                ),
                make_event(
                    2,
                    "2026-09-29T10:01:00+00:00",
                ),
            ],
        ),
        make_incident(
            "INC-0002",
            [
                make_event(
                    3,
                    "2026-09-29T10:03:00+00:00",
                ),
            ],
        ),
    ]

    result = deduplicate_incidents(
        incidents,
        window_seconds=300,
    )

    assert len(result) == 1

    assert result[0]["incident_id"] == "INC-0001"

    assert result[0]["event_count"] == 3


def test_unrelated_incidents_remain_separate():
    incidents = [
        make_incident(
            "INC-0001",
            [
                make_event(
                    1,
                    "2026-09-29T10:00:00+00:00",
                    ip="10.0.0.10",
                    user="alice",
                ),
            ],
            ip="10.0.0.10",
            user="alice",
        ),
        make_incident(
            "INC-0002",
            [
                make_event(
                    2,
                    "2026-09-29T10:01:00+00:00",
                    ip="10.0.0.20",
                    user="bob",
                ),
            ],
            ip="10.0.0.20",
            user="bob",
        ),
    ]

    result = deduplicate_incidents(
        incidents,
    )

    assert len(result) == 2


def test_deduplication_is_deterministic():
    first = make_incident(
        "INC-0001",
        [
            make_event(
                1,
                "2026-09-29T10:00:00+00:00",
            ),
        ],
    )

    second = make_incident(
        "INC-0002",
        [
            make_event(
                2,
                "2026-09-29T10:02:00+00:00",
            ),
        ],
    )

    result_one = deduplicate_incidents(
        [first, second]
    )

    result_two = deduplicate_incidents(
        [second, first]
    )

    assert result_one == result_two


def test_negative_window_is_rejected():
    try:
        deduplicate_incidents(
            [],
            window_seconds=-1,
        )
        assert False
    except ValueError as error:
        assert "cannot be negative" in str(error)
