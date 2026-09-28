"""
Day 46 tests for the CloudSentinel MITRE ATT&CK mapping model.
"""

import pytest

from src.mitre.mapping import MITREMapping


# ============================================================
# BASIC MAPPING
# ============================================================

def test_basic_mitre_mapping():

    mapping = MITREMapping(
        tactic="Credential Access",
        technique_id="T1110",
        technique="Brute Force",
        evidence=[
            "Multiple failed SSH authentication attempts"
        ],
        confidence=0.95,
    )

    assert mapping.tactic == "Credential Access"
    assert mapping.technique_id == "T1110"
    assert mapping.technique == "Brute Force"
    assert mapping.subtechnique_id is None
    assert mapping.subtechnique is None
    assert mapping.confidence == 0.95


# ============================================================
# SUB-TECHNIQUE
# ============================================================

def test_subtechnique_mapping():

    mapping = MITREMapping(
        tactic="Privilege Escalation",
        technique_id="T1548",
        technique="Abuse Elevation Control Mechanism",
        subtechnique_id="T1548.003",
        subtechnique="Sudo and Sudo Caching",
        evidence=[
            "sudo activity detected"
        ],
        confidence=0.90,
    )

    assert mapping.technique_id == "T1548"
    assert mapping.subtechnique_id == "T1548.003"
    assert mapping.subtechnique == (
        "Sudo and Sudo Caching"
    )


# ============================================================
# FACTORY PARSING
# ============================================================

def test_factory_parses_combined_subtechnique_id():

    mapping = MITREMapping.from_technique_id(
        tactic="Privilege Escalation",
        technique_id="T1548.003",
        technique="Abuse Elevation Control Mechanism",
        subtechnique="Sudo and Sudo Caching",
        evidence=[
            "sudo activity detected"
        ],
        confidence=0.90,
    )

    assert mapping.technique_id == "T1548"
    assert mapping.subtechnique_id == "T1548.003"


# ============================================================
# SERIALIZATION
# ============================================================

def test_mapping_serializes_to_dict():

    mapping = MITREMapping(
        tactic="Credential Access",
        technique_id="T1110",
        technique="Brute Force",
        evidence=[
            "failed password"
        ],
        confidence=0.80,
    )

    data = mapping.to_dict()

    assert data["tactic"] == "Credential Access"
    assert data["technique_id"] == "T1110"
    assert data["technique"] == "Brute Force"
    assert data["evidence"] == [
        "failed password"
    ]
    assert data["confidence"] == 0.80


# ============================================================
# INVALID TECHNIQUE
# ============================================================

def test_invalid_technique_id_is_rejected():

    with pytest.raises(ValueError):

        MITREMapping(
            tactic="Credential Access",
            technique_id="INVALID",
            technique="Brute Force",
        )


# ============================================================
# INVALID SUB-TECHNIQUE
# ============================================================

def test_invalid_subtechnique_id_is_rejected():

    with pytest.raises(ValueError):

        MITREMapping(
            tactic="Privilege Escalation",
            technique_id="T1548",
            technique="Abuse Elevation Control Mechanism",
            subtechnique_id="T1110.001",
            subtechnique="Invalid relationship",
        )


# ============================================================
# INVALID CONFIDENCE
# ============================================================

@pytest.mark.parametrize(
    "confidence",
    [-0.01, 1.01, 2.0],
)
def test_confidence_must_be_between_zero_and_one(
    confidence,
):

    with pytest.raises(ValueError):

        MITREMapping(
            tactic="Credential Access",
            technique_id="T1110",
            technique="Brute Force",
            confidence=confidence,
        )


# ============================================================
# INVALID EVIDENCE
# ============================================================

def test_evidence_must_be_a_list():

    with pytest.raises(TypeError):

        MITREMapping(
            tactic="Credential Access",
            technique_id="T1110",
            technique="Brute Force",
            evidence="failed password",
        )


# ============================================================
# DAY 98: SEMANTIC VALIDATION REGRESSION TESTS
# ============================================================

def test_subtechnique_id_requires_subtechnique_name():
    with pytest.raises(ValueError):
        MITREMapping(
            tactic="Privilege Escalation",
            technique_id="T1548",
            technique="Abuse Elevation Control Mechanism",
            subtechnique_id="T1548.003",
            evidence=["sudo activity detected"],
            confidence=0.80,
        )


def test_subtechnique_name_requires_subtechnique_id():
    with pytest.raises(ValueError):
        MITREMapping(
            tactic="Privilege Escalation",
            technique_id="T1548",
            technique="Abuse Elevation Control Mechanism",
            subtechnique="Sudo and Sudo Caching",
            evidence=["sudo activity detected"],
            confidence=0.80,
        )
