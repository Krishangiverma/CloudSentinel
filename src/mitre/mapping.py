"""
CloudSentinel MITRE ATT&CK mapping model.

Day 46:
    Provides a structured representation of MITRE ATT&CK
    technique mappings used by CloudSentinel detections.

Design goals:
    - Keep MITRE metadata structured.
    - Preserve backward compatibility with existing rule metadata.
    - Validate technique identifiers.
    - Validate analyst confidence.
    - Support evidence-based investigations.
"""

from dataclasses import dataclass, field
import re
from typing import Any, Dict, List, Optional


# ============================================================
# MITRE TECHNIQUE IDENTIFIER
# ============================================================

TECHNIQUE_ID_PATTERN = re.compile(
    r"^T\d{4}$"
)

SUBTECHNIQUE_ID_PATTERN = re.compile(
    r"^T\d{4}\.\d{3}$"
)


# ============================================================
# MITRE MAPPING
# ============================================================

@dataclass
class MITREMapping:
    """
    Structured MITRE ATT&CK mapping for a CloudSentinel
    detection.

    One mapping represents one tactic/technique relationship.

    Multiple MITREMapping objects can be attached to the same
    detection when a detection covers multiple ATT&CK techniques.
    """

    tactic: str

    technique_id: str

    technique: str

    subtechnique_id: Optional[str] = None

    subtechnique: Optional[str] = None

    evidence: List[str] = field(default_factory=list)

    confidence: float = 0.0
    mapping_status: str = "candidate"

    def __post_init__(self) -> None:
        """
        Validate and normalize the mapping after construction.
        """

        # ----------------------------------------------------
        # TACTIC
        # ----------------------------------------------------

        if not isinstance(self.tactic, str):
            raise TypeError("tactic must be a string")

        self.tactic = self.tactic.strip()

        if not self.tactic:
            raise ValueError("tactic cannot be empty")

        # ----------------------------------------------------
        # TECHNIQUE ID
        # ----------------------------------------------------

        if not isinstance(self.technique_id, str):
            raise TypeError("technique_id must be a string")

        self.technique_id = self.technique_id.strip().upper()

        if not TECHNIQUE_ID_PATTERN.fullmatch(
            self.technique_id
        ):
            raise ValueError(
                f"Invalid MITRE technique_id: "
                f"{self.technique_id}"
            )

        # ----------------------------------------------------
        # TECHNIQUE NAME
        # ----------------------------------------------------

        if not isinstance(self.technique, str):
            raise TypeError("technique must be a string")

        self.technique = self.technique.strip()

        if not self.technique:
            raise ValueError(
                "technique cannot be empty"
            )

        # ----------------------------------------------------
        # SUB-TECHNIQUE ID
        # ----------------------------------------------------

        if self.subtechnique_id is not None:

            if not isinstance(
                self.subtechnique_id,
                str,
            ):
                raise TypeError(
                    "subtechnique_id must be a string or None"
                )

            self.subtechnique_id = (
                self.subtechnique_id.strip().upper()
            )

            if not SUBTECHNIQUE_ID_PATTERN.fullmatch(
                self.subtechnique_id
            ):
                raise ValueError(
                    f"Invalid MITRE subtechnique_id: "
                    f"{self.subtechnique_id}"
                )

            expected_prefix = (
                self.technique_id + "."
            )

            if not self.subtechnique_id.startswith(
                expected_prefix
            ):
                raise ValueError(
                    "subtechnique_id must belong to "
                    "the supplied technique_id"
                )

        # ----------------------------------------------------
        # SUB-TECHNIQUE NAME
        # ----------------------------------------------------

        if self.subtechnique is not None:

            if not isinstance(
                self.subtechnique,
                str,
            ):
                raise TypeError(
                    "subtechnique must be a string or None"
                )

            self.subtechnique = (
                self.subtechnique.strip()
            )

            if not self.subtechnique:
                raise ValueError(
                    "subtechnique cannot be empty"
                )

        # ----------------------------------------------------
        # SUB-TECHNIQUE ID / NAME CONSISTENCY
        # ----------------------------------------------------

        if (self.subtechnique_id is None) != (
            self.subtechnique is None
        ):
            raise ValueError(
                "subtechnique_id and subtechnique "
                "must both be provided or both be None"
            )

        # ----------------------------------------------------
        # EVIDENCE
        # ----------------------------------------------------

        if not isinstance(
            self.evidence,
            list,
        ):
            raise TypeError(
                "evidence must be a list"
            )

        normalized_evidence = []

        for item in self.evidence:

            if not isinstance(item, str):
                raise TypeError(
                    "evidence items must be strings"
                )

            item = item.strip()

            if item:
                normalized_evidence.append(item)

        self.evidence = normalized_evidence

        # ----------------------------------------------------
        # MAPPING STATUS
        # ----------------------------------------------------

        allowed_statuses = {"candidate", "supported"}

        if not isinstance(self.mapping_status, str):
            raise TypeError("mapping_status must be a string")

        self.mapping_status = self.mapping_status.strip().lower()

        if self.mapping_status not in allowed_statuses:
            raise ValueError(
                "mapping_status must be 'candidate' or 'supported'"
            )

        # ----------------------------------------------------
        # CONFIDENCE
        # ----------------------------------------------------

        if isinstance(
            self.confidence,
            bool,
        ):
            raise TypeError(
                "confidence must be a number"
            )

        try:
            self.confidence = float(
                self.confidence
            )
        except (
            TypeError,
            ValueError,
        ) as exc:
            raise TypeError(
                "confidence must be a number"
            ) from exc

        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                "confidence must be between 0.0 and 1.0"
            )

    # ========================================================
    # FACTORY
    # ========================================================

    @classmethod
    def from_technique_id(
        cls,
        *,
        tactic: str,
        technique_id: str,
        technique: str,
        subtechnique: Optional[str] = None,
        evidence: Optional[List[str]] = None,
        confidence: float = 0.0,
        mapping_status: str = "candidate",
    ) -> "MITREMapping":
        """
        Build a mapping from either:

            T1110

        or:

            T1548.003

        When a combined sub-technique identifier is supplied,
        it is automatically separated into:

            technique_id = T1548
            subtechnique_id = T1548.003
        """

        normalized_id = str(
            technique_id
        ).strip().upper()

        parsed_technique_id = normalized_id
        parsed_subtechnique_id = None

        if SUBTECHNIQUE_ID_PATTERN.fullmatch(
            normalized_id
        ):
            parsed_technique_id = (
                normalized_id.split(".")[0]
            )

            parsed_subtechnique_id = normalized_id

        elif not TECHNIQUE_ID_PATTERN.fullmatch(
            normalized_id
        ):
            raise ValueError(
                f"Invalid MITRE technique identifier: "
                f"{technique_id}"
            )

        return cls(
            tactic=tactic,
            technique_id=parsed_technique_id,
            technique=technique,
            subtechnique_id=parsed_subtechnique_id,
            subtechnique=subtechnique,
            evidence=evidence or [],
            confidence=confidence,
            mapping_status=mapping_status,
        )

    # ========================================================
    # SERIALIZATION
    # ========================================================

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the mapping into a JSON/API-friendly
        dictionary.
        """

        return {
            "tactic": self.tactic,
            "technique_id": self.technique_id,
            "technique": self.technique,
            "subtechnique_id": self.subtechnique_id,
            "subtechnique": self.subtechnique,
            "evidence": list(self.evidence),
            "confidence": self.confidence,
            "mapping_status": self.mapping_status,
        }
