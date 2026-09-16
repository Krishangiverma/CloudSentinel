"""
CloudSentinel normalized threat-intelligence objects.

Day 59:
- Normalize provider results into a common threat-intelligence model.
- Keep the representation STIX 2.1-inspired for future interoperability.
- Preserve provider-specific raw data.
- Generate deterministic indicator object IDs.
- Build normalized indicator patterns for supported IOC types.

This module intentionally does not implement TAXII transport.
It provides a stable internal representation that can later be
serialized/exchanged through STIX/TAXII-compatible integrations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping, Optional
import uuid


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    """Return the current UTC timestamp in ISO-8601 format."""

    return (
        datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _normalize_timestamp(value: Any) -> Optional[str]:
    """
    Normalize provider timestamp values.

    Supported inputs:
    - None
    - strings
    - datetime objects
    """

    if value is None:
        return None

    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)

        return (
            value.astimezone(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )

    value = str(value).strip()

    if not value:
        return None

    return value


# ---------------------------------------------------------------------------
# STIX pattern helpers
# ---------------------------------------------------------------------------

def _escape_stix_value(value: str) -> str:
    """
    Escape a value for a simple STIX-like equality pattern.
    """

    value = str(value)

    value = value.replace("\\", "\\\\")
    value = value.replace("'", "\\'")

    return value


def _build_pattern(ioc_type: str, value: str) -> str:
    """
    Build a normalized STIX 2.1-style indicator pattern.

    Supported IOC types:
        ip
        domain
        url
        md5
        sha1
        sha256
    """

    normalized_type = str(ioc_type).strip().lower()
    escaped = _escape_stix_value(value)

    if normalized_type == "ip":
        return f"[ipv4-addr:value = '{escaped}']"

    if normalized_type == "domain":
        return f"[domain-name:value = '{escaped}']"

    if normalized_type == "url":
        return f"[url:value = '{escaped}']"

    if normalized_type == "md5":
        return f"[file:hashes.MD5 = '{escaped}']"

    if normalized_type == "sha1":
        return f"[file:hashes.SHA-1 = '{escaped}']"

    if normalized_type == "sha256":
        return f"[file:hashes.SHA-256 = '{escaped}']"

    raise ValueError(
        f"Unsupported IOC type for normalized indicator: {ioc_type}"
    )


# ---------------------------------------------------------------------------
# Deterministic object ID
# ---------------------------------------------------------------------------

def _build_object_id(ioc_type: str, value: str) -> str:
    """
    Generate a deterministic STIX-like indicator object ID.

    The same IOC type + value always produces the same object ID.
    """

    seed = (
        "cloudsentinel:indicator:"
        f"{str(ioc_type).strip().lower()}:"
        f"{str(value).strip().lower()}"
    )

    generated_uuid = uuid.uuid5(
        uuid.NAMESPACE_URL,
        seed,
    )

    return f"indicator--{generated_uuid}"


# ---------------------------------------------------------------------------
# IOC extraction helpers
# ---------------------------------------------------------------------------

def _get_ioc_type(ioc: Any) -> str:
    """
    Extract IOC type from an IOC model/object.
    """

    if isinstance(ioc, Mapping):
        value = (
            ioc.get("type")
            or ioc.get("ioc_type")
            or ioc.get("kind")
        )
    else:
        value = (
            getattr(ioc, "type", None)
            or getattr(ioc, "ioc_type", None)
            or getattr(ioc, "kind", None)
        )

    if value is None:
        raise ValueError("IOC type is required")

    return str(value).strip().lower()


def _get_ioc_value(ioc: Any) -> str:
    """
    Extract IOC value from an IOC model/object.
    """

    if isinstance(ioc, Mapping):
        value = (
            ioc.get("value")
            or ioc.get("ioc")
            or ioc.get("indicator")
        )
    else:
        value = (
            getattr(ioc, "value", None)
            or getattr(ioc, "ioc", None)
            or getattr(ioc, "indicator", None)
        )

    if value is None:
        raise ValueError("IOC value is required")

    value = str(value).strip()

    if not value:
        raise ValueError("IOC value is required")

    return value


def _get_provider_field(
    provider_result: Mapping[str, Any],
    *names: str,
) -> Any:
    """
    Return the first non-None provider field from a list of aliases.
    """

    for name in names:
        if name in provider_result:
            value = provider_result.get(name)

            if value is not None:
                return value

    return None


def _normalize_labels(value: Any) -> tuple[str, ...]:
    """
    Normalize provider labels into an immutable tuple.
    """

    if value is None:
        return ()

    if isinstance(value, str):
        value = value.strip()

        if not value:
            return ()

        return (value,)

    if isinstance(value, (list, tuple, set)):
        result = []

        for item in value:
            item = str(item).strip()

            if item:
                result.append(item)

        return tuple(result)

    return (str(value),)


# ---------------------------------------------------------------------------
# Normalized threat-intelligence object
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ThreatIntelObject:
    """
    Normalized threat-intelligence object.

    This is intentionally STIX-like rather than claiming to be a complete
    STIX object implementation.
    """

    # STIX-like core metadata
    object_type: str = "indicator"
    spec_version: str = "2.1"
    object_id: str = ""

    # CloudSentinel IOC identity
    ioc_type: str = ""
    value: str = ""

    # Indicator pattern
    pattern: str = ""
    pattern_type: str = "stix"

    # Provider information
    provider: Optional[str] = None
    source: Optional[str] = None

    # Enrichment state
    status: Optional[str] = None
    cached: bool = False

    # Reputation information
    reputation: Any = None
    confidence: Any = None

    # Provider observation information
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

    # STIX-like lifecycle timestamp
    valid_from: Optional[str] = None

    # Optional classification labels
    labels: tuple[str, ...] = field(default_factory=tuple)

    # Original provider response
    raw: Mapping[str, Any] = field(default_factory=dict)

    # -----------------------------------------------------------------------
    # Compatibility constructor
    # -----------------------------------------------------------------------

    @classmethod
    def from_provider_result(
        cls,
        ioc,
        provider_result,
        retrieved_at=None,
    ) -> "ThreatIntelObject":
        """
        Create a normalized object from a provider result.

        Kept as a classmethod for compatibility with existing
        CloudSentinel Day 59 tests and callers.
        """

        return from_provider_result(
            ioc,
            provider_result,
            retrieved_at=retrieved_at,
        )

    # -----------------------------------------------------------------------
    # Standard dictionary serialization
    # -----------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """
        Return the normalized object as a plain Python dictionary.
        """

        return {
            "object_type": self.object_type,
            "spec_version": self.spec_version,
            "object_id": self.object_id,
            "ioc_type": self.ioc_type,
            "value": self.value,
            "pattern": self.pattern,
            "pattern_type": self.pattern_type,
            "provider": self.provider,
            "source": self.source,
            "status": self.status,
            "cached": self.cached,
            "reputation": self.reputation,
            "confidence": self.confidence,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "valid_from": self.valid_from,
            "labels": list(self.labels),
            "raw": dict(self.raw),
        }

    # -----------------------------------------------------------------------
    # STIX-like serialization
    # -----------------------------------------------------------------------

    def to_stix_like_dict(self) -> dict[str, Any]:
        """
        Return a STIX-like dictionary representation.

        CloudSentinel-specific metadata is grouped under:
            x_cloudsentinel

        This keeps the custom extension fields together and matches the
        Day 59 serialization contract.
        """

        # -------------------------------------------------------------------
        # Core STIX-like fields
        # -------------------------------------------------------------------

        data: dict[str, Any] = {
            "type": self.object_type,
            "spec_version": self.spec_version,
            "id": self.object_id,
            "pattern": self.pattern,
            "pattern_type": self.pattern_type,
        }

        if self.valid_from is not None:
            data["valid_from"] = self.valid_from

        if self.labels:
            data["labels"] = list(self.labels)

        # -------------------------------------------------------------------
        # CloudSentinel extension object
        # -------------------------------------------------------------------

        cloudsentinel: dict[str, Any] = {
            "ioc_type": self.ioc_type,
            "value": self.value,
            "cached": self.cached,
        }

        if self.provider is not None:
            cloudsentinel["provider"] = self.provider

        if self.source is not None:
            cloudsentinel["source"] = self.source

        if self.status is not None:
            cloudsentinel["status"] = self.status

        if self.reputation is not None:
            cloudsentinel["reputation"] = self.reputation

        if self.confidence is not None:
            cloudsentinel["confidence"] = self.confidence

        if self.first_seen is not None:
            cloudsentinel["first_seen"] = self.first_seen

        if self.last_seen is not None:
            cloudsentinel["last_seen"] = self.last_seen

        # Preserve provider response for investigation/debugging.
        cloudsentinel["raw"] = dict(self.raw)

        data["x_cloudsentinel"] = cloudsentinel

        return data


# ---------------------------------------------------------------------------
# Provider result normalization
# ---------------------------------------------------------------------------

def from_provider_result(
    ioc,
    provider_result: Mapping[str, Any],
    retrieved_at: Optional[str] = None,
) -> ThreatIntelObject:
    """
    Normalize a CloudSentinel IOC provider result.

    Timestamp behavior:

        first_seen
            Comes only from the provider.

        last_seen
            Comes only from the provider.

        valid_from
            Uses provider first_seen when available.
            Otherwise uses retrieved_at.

    This distinction prevents CloudSentinel from claiming that an IOC
    was first observed at the time we merely queried the provider.
    """

    if not isinstance(provider_result, Mapping):
        raise TypeError(
            "provider_result must be a mapping/dictionary"
        )

    # -----------------------------------------------------------------------
    # IOC identity
    # -----------------------------------------------------------------------

    ioc_type = _get_ioc_type(ioc)
    value = _get_ioc_value(ioc)

    # -----------------------------------------------------------------------
    # Pattern
    # -----------------------------------------------------------------------

    pattern = _build_pattern(
        ioc_type,
        value,
    )

    # -----------------------------------------------------------------------
    # Provider metadata
    # -----------------------------------------------------------------------

    provider = _get_provider_field(
        provider_result,
        "provider",
        "provider_name",
    )

    source = _get_provider_field(
        provider_result,
        "source",
    )

    status = _get_provider_field(
        provider_result,
        "status",
    )

    cached = bool(
        provider_result.get(
            "cached",
            False,
        )
    )

    # -----------------------------------------------------------------------
    # Reputation
    # -----------------------------------------------------------------------

    reputation = _get_provider_field(
        provider_result,
        "reputation",
        "reputation_score",
        "score",
    )

    confidence = _get_provider_field(
        provider_result,
        "confidence",
        "confidence_score",
    )

    # -----------------------------------------------------------------------
    # Observation timestamps
    # -----------------------------------------------------------------------

    # IMPORTANT:
    # retrieved_at must NOT become first_seen.
    #
    # first_seen represents provider knowledge.
    # retrieved_at represents when CloudSentinel retrieved the information.
    first_seen = _normalize_timestamp(
        _get_provider_field(
            provider_result,
            "first_seen",
            "first_seen_at",
        )
    )

    last_seen = _normalize_timestamp(
        _get_provider_field(
            provider_result,
            "last_seen",
            "last_seen_at",
        )
    )

    normalized_retrieved_at = _normalize_timestamp(
        retrieved_at
    )

    # -----------------------------------------------------------------------
    # valid_from
    # -----------------------------------------------------------------------

    # If the provider gives us first_seen, it is the most meaningful
    # lifecycle timestamp.
    #
    # If it does not, retrieved_at is the best available timestamp for
    # when CloudSentinel created/normalized this object.
    valid_from = (
        first_seen
        or normalized_retrieved_at
        or _utc_now()
    )

    # -----------------------------------------------------------------------
    # Labels
    # -----------------------------------------------------------------------

    labels = _normalize_labels(
        _get_provider_field(
            provider_result,
            "labels",
            "tags",
        )
    )

    # -----------------------------------------------------------------------
    # Deterministic object ID
    # -----------------------------------------------------------------------

    object_id = _build_object_id(
        ioc_type,
        value,
    )

    # -----------------------------------------------------------------------
    # Final normalized object
    # -----------------------------------------------------------------------

    return ThreatIntelObject(
        object_type="indicator",
        spec_version="2.1",
        object_id=object_id,
        ioc_type=ioc_type,
        value=value,
        pattern=pattern,
        pattern_type="stix",
        provider=(
            str(provider)
            if provider is not None
            else None
        ),
        source=(
            str(source)
            if source is not None
            else None
        ),
        status=(
            str(status)
            if status is not None
            else None
        ),
        cached=cached,
        reputation=reputation,
        confidence=confidence,
        first_seen=first_seen,
        last_seen=last_seen,
        valid_from=valid_from,
        labels=labels,
        raw=dict(provider_result),
    )


# ---------------------------------------------------------------------------
# Compatibility alias
# ---------------------------------------------------------------------------

def normalize_provider_result(
    ioc,
    provider_result: Mapping[str, Any],
    retrieved_at: Optional[str] = None,
) -> ThreatIntelObject:
    """
    Explicit normalization alias.
    """

    return from_provider_result(
        ioc,
        provider_result,
        retrieved_at=retrieved_at,
    )


__all__ = [
    "ThreatIntelObject",
    "from_provider_result",
    "normalize_provider_result",
]
