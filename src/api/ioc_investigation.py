"""
CloudSentinel IOC Investigation API.

Day 60:
Provides a dedicated IOC investigation page and read-only
investigation API over persisted security-event evidence.
"""

import json
from collections import defaultdict

from flask import Blueprint, jsonify, render_template, request

from src.data.database import get_all_events
from src.analyzers.risk_engine import analyze_event_risk
from src.threat_intel.ioc_model import IOC, SUPPORTED_IOC_TYPES
from src.threat_intel.normalized import from_provider_result


ioc_investigation_bp = Blueprint(
    "ioc_investigation",
    __name__,
)


def _load_json(value, default):
    """Safely decode persisted JSON."""

    if not value:
        return default

    try:
        result = json.loads(value)

        if isinstance(result, type(default)):
            return result

    except (
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ):
        pass

    return default


def _calculate_risk(event):
    """Recalculate the persisted event risk consistently."""

    severity = event[3]
    event_type = event[2]

    threat_intel_score = (
        event[9]
        if len(event) > 9 and event[9] is not None
        else 0
    )

    try:
        threat_intel_score = int(
            threat_intel_score
        )
    except (
        TypeError,
        ValueError,
    ):
        threat_intel_score = 0

    base_risk = analyze_event_risk({
        "severity": severity,
        "event_type": event_type,
    })

    risk_score = min(
        base_risk["risk_score"]
        + threat_intel_score,
        100,
    )

    if risk_score >= 80:
        risk_level = "CRITICAL"
    elif risk_score >= 60:
        risk_level = "HIGH"
    elif risk_score >= 35:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return risk_score, risk_level, threat_intel_score


def _event_iocs(iocs):
    """
    Convert the persisted IOC structure into a flat list.

    Returns:
        [{"ioc_type": "...", "value": "..."}]
    """

    results = []

    for value in iocs.get("ips", []):
        results.append({
            "ioc_type": "ip",
            "value": str(value),
        })

    for value in iocs.get("domains", []):
        results.append({
            "ioc_type": "domain",
            "value": str(value),
        })

    for value in iocs.get("urls", []):
        results.append({
            "ioc_type": "url",
            "value": str(value),
        })

    hashes = iocs.get("hashes", {})

    if isinstance(hashes, dict):
        for hash_type in (
            "md5",
            "sha1",
            "sha256",
        ):
            for value in hashes.get(
                hash_type,
                [],
            ):
                results.append({
                    "ioc_type": hash_type,
                    "value": str(value),
                })

    return results


def _matches(ioc, target_type, target_value):
    """Case-insensitive IOC matching."""

    return (
        ioc["ioc_type"].lower()
        == target_type.lower()
        and ioc["value"].lower()
        == target_value.lower()
    )


def _build_normalized_indicator(
    target_type,
    target_value,
    threat_intel_items,
):
    """
    Build a Day-59 normalized indicator from
    the best available persisted TI result.
    """

    ioc = IOC(
        target_type,
        target_value,
    )

    provider_result = {
        "status": "not_enriched",
        "provider": None,
        "source": "CloudSentinel",
        "ioc": ioc.to_dict(),
        "reputation": None,
        "confidence": None,
        "first_seen": None,
        "last_seen": None,
        "cached": False,
    }

    for item in threat_intel_items:

        if not isinstance(item, dict):
            continue

        item_type = str(
            item.get("type", "")
        ).strip().lower()

        item_value = str(
            item.get("ioc", "")
        ).strip()

        if (
            item_type == target_type
            and item_value.lower()
            == target_value.lower()
        ):
            provider_result.update({
                "status": item.get(
                    "status",
                    "success",
                ),
                "provider": item.get(
                    "provider"
                ),
                "source": item.get(
                    "source",
                    "CloudSentinel",
                ),
                "reputation": item.get(
                    "reputation"
                ),
                "confidence": item.get(
                    "confidence"
                ),
                "first_seen": item.get(
                    "first_seen"
                ),
                "last_seen": item.get(
                    "last_seen"
                ),
                "cached": bool(
                    item.get(
                        "cached",
                        False,
                    )
                ),
            })

            break

    normalized = from_provider_result(
        ioc,
        provider_result,
    )

    return normalized.to_stix_like_dict()


def _catalog():
    """Build the IOC catalog used by the investigation page."""

    events = get_all_events()

    catalog = {}

    for event in events:

        iocs = _load_json(
            event[7] if len(event) > 7 else None,
            {},
        )

        risk_score, risk_level, _ = (
            _calculate_risk(event)
        )

        for ioc in _event_iocs(iocs):

            key = (
                ioc["ioc_type"],
                ioc["value"].lower(),
            )

            if key not in catalog:
                catalog[key] = {
                    "ioc_type": ioc["ioc_type"],
                    "value": ioc["value"],
                    "occurrences": 0,
                    "max_risk_score": 0,
                    "risk_levels": {},
                    "first_seen": event[1],
                    "last_seen": event[1],
                }

            item = catalog[key]

            item["occurrences"] += 1
            item["max_risk_score"] = max(
                item["max_risk_score"],
                risk_score,
            )

            item["first_seen"] = min(
                item["first_seen"],
                event[1],
            )

            item["last_seen"] = max(
                item["last_seen"],
                event[1],
            )

            item["risk_levels"][risk_level] = (
                item["risk_levels"].get(
                    risk_level,
                    0,
                )
                + 1
            )

    return sorted(
        catalog.values(),
        key=lambda item: (
            -item["max_risk_score"],
            -item["occurrences"],
            item["value"].lower(),
        ),
    )


def _investigate(
    target_type,
    target_value,
):
    """Return all persisted evidence for one IOC."""

    events = get_all_events()

    matched_events = []

    total_risk_score = 0
    max_risk_score = 0

    first_seen = None
    last_seen = None

    threat_intel_items = []

    for event in events:

        iocs = _load_json(
            event[7] if len(event) > 7 else None,
            {},
        )

        event_iocs = _event_iocs(iocs)

        if not any(
            _matches(
                ioc,
                target_type,
                target_value,
            )
            for ioc in event_iocs
        ):
            continue

        threat_intel = _load_json(
            event[8] if len(event) > 8 else None,
            {},
        )

        items = threat_intel.get(
            "items",
            [],
        )

        if isinstance(items, list):
            threat_intel_items.extend(
                item
                for item in items
                if isinstance(item, dict)
            )

        risk_score, risk_level, threat_intel_score = (
            _calculate_risk(event)
        )

        total_risk_score += risk_score
        max_risk_score = max(
            max_risk_score,
            risk_score,
        )

        timestamp = event[1]

        if first_seen is None:
            first_seen = timestamp
            last_seen = timestamp
        else:
            first_seen = min(
                first_seen,
                timestamp,
            )
            last_seen = max(
                last_seen,
                timestamp,
            )

        matched_events.append({
            "id": event[0],
            "timestamp": event[1],
            "event_type": event[2],
            "severity": event[3],
            "message": event[4],
            "source": event[5],
            "ip_address": event[6],
            "risk_score": risk_score,
            "risk_level": risk_level,
            "threat_intel_score": threat_intel_score,
            "threat_intel": threat_intel,
        })

    normalized = _build_normalized_indicator(
        target_type,
        target_value,
        threat_intel_items,
    )

    verdicts = []

    for item in threat_intel_items:

        if (
            str(item.get("ioc", "")).lower()
            == target_value.lower()
        ):
            verdict = item.get("verdict")

            if verdict:
                verdicts.append(
                    str(verdict)
                )

    return {
        "query": {
            "ioc_type": target_type,
            "value": target_value,
        },
        "summary": {
            "occurrences": len(
                matched_events
            ),
            "total_risk_score": total_risk_score,
            "max_risk_score": max_risk_score,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "verdicts": sorted(
                set(verdicts)
            ),
        },
        "normalized_indicator": normalized,
        "events": matched_events,
    }


@ioc_investigation_bp.route(
    "/ioc-investigation",
    methods=["GET"],
)
def ioc_investigation_page():
    """Serve the dedicated IOC investigation page."""

    return render_template(
        "ioc_investigation.html"
    )


@ioc_investigation_bp.route(
    "/api/ioc-investigation",
    methods=["GET"],
)
def ioc_investigation_api():
    """
    IOC investigation API.

    Without parameters:
        Returns the IOC catalog.

    With type/value:
        Returns investigation evidence for one IOC.
    """

    target_type = request.args.get(
        "type",
        "",
    ).strip().lower()

    target_value = request.args.get(
        "value",
        "",
    ).strip()

    if not target_type and not target_value:
        return jsonify({
            "status": "ok",
            "count": len(_catalog()),
            "iocs": _catalog(),
        })

    if target_type not in SUPPORTED_IOC_TYPES:
        return jsonify({
            "status": "error",
            "message": "Unsupported IOC type.",
            "supported_types": sorted(
                SUPPORTED_IOC_TYPES
            ),
        }), 400

    if not target_value:
        return jsonify({
            "status": "error",
            "message": "IOC value is required.",
        }), 400

    try:
        result = _investigate(
            target_type,
            target_value,
        )

        return jsonify({
            "status": "ok",
            **result,
        })

    except Exception as exc:
        return jsonify({
            "status": "error",
            "message": "IOC investigation failed.",
            "error": str(exc),
        }), 500
