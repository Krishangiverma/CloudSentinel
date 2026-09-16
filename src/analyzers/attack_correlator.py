"""
CloudSentinel Advanced Attack Correlation Engine.

Correlates security events into investigation-ready incidents.

Correlation strategy:

    Same source IP
        +
    Minimum event threshold
        +
    Event/risk/threat-intelligence/IOC context
        ↓
    Investigation-ready security incident

The engine remains deterministic so incident results are
reproducible and easy to test.
"""

DEFAULT_THRESHOLD = 3


# ============================================================
# RISK LEVEL
# ============================================================

def _risk_level_from_score(score):
    """Convert a numeric risk score into a CloudSentinel risk level."""

    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 35:
        return "MEDIUM"

    return "LOW"


# ============================================================
# TIMESTAMP SORTING
# ============================================================

def _timestamp_key(event):
    """
    Return a sortable representation of an event timestamp.

    String conversion keeps this function safe for datetime-like
    values and preserves deterministic behavior.
    """

    timestamp = event.get("timestamp")

    if timestamp is None:
        return ""

    return str(timestamp)


# ============================================================
# IOC NORMALIZATION
# ============================================================

def _normalize_iocs(iocs):
    """
    Normalize an event IOC dictionary into the canonical
    CloudSentinel IOC structure.
    """

    if not isinstance(iocs, dict):
        iocs = {}

    ips = iocs.get("ips", [])
    domains = iocs.get("domains", [])
    hashes = iocs.get("hashes", {})

    if not isinstance(ips, list):
        ips = []

    if not isinstance(domains, list):
        domains = []

    if not isinstance(hashes, dict):
        hashes = {}

    md5 = hashes.get("md5", [])
    sha1 = hashes.get("sha1", [])
    sha256 = hashes.get("sha256", [])

    if not isinstance(md5, list):
        md5 = []

    if not isinstance(sha1, list):
        sha1 = []

    if not isinstance(sha256, list):
        sha256 = []

    return {
        "ips": ips,
        "domains": domains,
        "hashes": {
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256,
        },
    }


# ============================================================
# IOC AGGREGATION
# ============================================================

def _aggregate_iocs(events):
    """
    Aggregate IOCs across all events in an incident.

    Duplicate IOC values are removed while preserving a
    deterministic sorted representation.
    """

    aggregated = {
        "ips": set(),
        "domains": set(),
        "hashes": {
            "md5": set(),
            "sha1": set(),
            "sha256": set(),
        },
    }

    for event in events:

        iocs = _normalize_iocs(
            event.get("iocs", {})
        )

        for ip in iocs["ips"]:

            if ip is not None and str(ip).strip():
                aggregated["ips"].add(
                    str(ip).strip()
                )

        for domain in iocs["domains"]:

            if domain is not None and str(domain).strip():
                aggregated["domains"].add(
                    str(domain).strip()
                )

        for hash_type in (
            "md5",
            "sha1",
            "sha256",
        ):

            for hash_value in iocs["hashes"][hash_type]:

                if (
                    hash_value is not None
                    and str(hash_value).strip()
                ):
                    aggregated["hashes"][hash_type].add(
                        str(hash_value).strip()
                    )

    return {
        "ips": sorted(
            aggregated["ips"]
        ),
        "domains": sorted(
            aggregated["domains"]
        ),
        "hashes": {
            "md5": sorted(
                aggregated["hashes"]["md5"]
            ),
            "sha1": sorted(
                aggregated["hashes"]["sha1"]
            ),
            "sha256": sorted(
                aggregated["hashes"]["sha256"]
            ),
        },
    }


# ============================================================
# IOC EVIDENCE SUMMARY
# ============================================================

def _build_ioc_evidence(aggregated_iocs):
    """
    Build a compact IOC evidence summary for SOC investigation.
    """

    ips = aggregated_iocs.get("ips", [])
    domains = aggregated_iocs.get("domains", [])
    hashes = aggregated_iocs.get("hashes", {})

    md5 = hashes.get("md5", [])
    sha1 = hashes.get("sha1", [])
    sha256 = hashes.get("sha256", [])

    total_hashes = (
        len(md5)
        + len(sha1)
        + len(sha256)
    )

    return {
        "total_ips": len(ips),
        "total_domains": len(domains),
        "total_hashes": total_hashes,
        "has_iocs": bool(
            ips
            or domains
            or md5
            or sha1
            or sha256
        ),
        "ips": ips,
        "domains": domains,
        "hashes": {
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256,
        },
    }


# ============================================================
# ATTACK PATTERN DETECTION
# ============================================================

def _detect_attack_pattern(events):
    """
    Infer a high-level attack pattern from correlated event types.

    This is deterministic rule-based correlation, not ML.
    """

    event_types = {
        str(
            event.get(
                "event_type",
                "UNKNOWN"
            )
        ).upper()
        for event in events
    }

    if (
        "BRUTE_FORCE" in event_types
        or "BRUTE FORCE" in event_types
    ):
        return "BRUTE_FORCE_ACTIVITY"

    if "MALWARE" in event_types:
        return "MALWARE_ACTIVITY"

    if (
        "PORT_SCAN" in event_types
        or "PORT SCAN" in event_types
    ):
        return "RECONNAISSANCE_ACTIVITY"

    if (
        "UNAUTHORIZED_ACCESS" in event_types
        or "UNAUTHORIZED ACCESS" in event_types
        or "INTRUSION" in event_types
    ):
        return "INTRUSION_ACTIVITY"

    if "SUSPICIOUS_LOGIN" in event_types:
        return "SUSPICIOUS_LOGIN_ACTIVITY"

    return "MULTI_EVENT_ACTIVITY"


# ============================================================
# INCIDENT STATUS TRANSITIONS
# ============================================================

def transition_incident_status(
    current_status,
    new_status,
):
    """
    Validate and apply a CloudSentinel incident status transition.

    Supported lifecycle:

        OPEN -> INVESTIGATING
        OPEN -> RESOLVED
        INVESTIGATING -> RESOLVED

    RESOLVED is terminal.
    """

    current = str(
        current_status or ""
    ).strip().upper()

    target = str(
        new_status or ""
    ).strip().upper()

    valid_statuses = {
        "OPEN",
        "INVESTIGATING",
        "RESOLVED",
    }

    if current not in valid_statuses:
        raise ValueError(
            f"Invalid current incident status: {current}"
        )

    if target not in valid_statuses:
        raise ValueError(
            f"Invalid target incident status: {target}"
        )

    allowed_transitions = {
        "OPEN": {
            "OPEN",
            "INVESTIGATING",
            "RESOLVED",
        },
        "INVESTIGATING": {
            "INVESTIGATING",
            "RESOLVED",
        },
        "RESOLVED": {
            "RESOLVED",
        },
    }

    if target not in allowed_transitions[current]:
        raise ValueError(
            f"Invalid incident status transition: "
            f"{current} -> {target}"
        )

    return target



# ============================================================
# RESPONSE PRIORITY
# ============================================================

def _build_response_priority(risk_level):
    """
    Convert incident risk level into a deterministic
    SOC response priority.
    """

    normalized_risk = str(
        risk_level or "LOW"
    ).upper()

    if normalized_risk == "CRITICAL":
        return "IMMEDIATE"

    if normalized_risk == "HIGH":
        return "HIGH"

    return "STANDARD"



# ============================================================
# RESPONSE RECOMMENDATIONS
# ============================================================

def _build_response_recommendations(
    attack_pattern,
    risk_level,
    max_risk_score,
    aggregated_iocs,
    critical_event_count,
    high_risk_event_count,
    max_threat_intel_score,
):
    """
    Build deterministic SOC response recommendations.

    Recommendations are rule-based and derived only from the
    incident context already calculated by the correlation engine.
    """

    recommendations = []

    normalized_pattern = str(
        attack_pattern or ""
    ).upper()

    normalized_risk = str(
        risk_level or "LOW"
    ).upper()

    # --------------------------------------------------------
    # High-risk incident handling
    # --------------------------------------------------------

    if normalized_risk in ("CRITICAL", "HIGH"):

        recommendations.append(
            "Review and contain the affected source IP before "
            "further investigation."
        )

    # --------------------------------------------------------
    # Brute-force activity
    # --------------------------------------------------------

    if normalized_pattern == "BRUTE_FORCE_ACTIVITY":

        recommendations.append(
            "Review authentication logs for the source IP and "
            "consider blocking or rate-limiting repeated login attempts."
        )

    # --------------------------------------------------------
    # Malware activity
    # --------------------------------------------------------

    if normalized_pattern == "MALWARE_ACTIVITY":

        recommendations.append(
            "Isolate affected systems and investigate the malware "
            "execution chain and persistence mechanisms."
        )

    # --------------------------------------------------------
    # Reconnaissance
    # --------------------------------------------------------

    if normalized_pattern == "RECONNAISSANCE_ACTIVITY":

        recommendations.append(
            "Review targeted services and network connections to "
            "identify the scope of reconnaissance activity."
        )

    # --------------------------------------------------------
    # Unauthorized access / intrusion
    # --------------------------------------------------------

    if normalized_pattern == "INTRUSION_ACTIVITY":

        recommendations.append(
            "Investigate the compromised access path and review "
            "privilege escalation or lateral movement activity."
        )

    # --------------------------------------------------------
    # Suspicious login
    # --------------------------------------------------------

    if normalized_pattern == "SUSPICIOUS_LOGIN_ACTIVITY":

        recommendations.append(
            "Validate the login source, account activity, and "
            "authentication history for unauthorized access."
        )

    # --------------------------------------------------------
    # IOC investigation
    # --------------------------------------------------------

    ioc_data = aggregated_iocs or {}

    ips = ioc_data.get("ips", [])
    domains = ioc_data.get("domains", [])
    hashes = ioc_data.get("hashes", {})

    has_hashes = any(
        hashes.get(hash_type, [])
        for hash_type in (
            "md5",
            "sha1",
            "sha256",
        )
    )

    if ips or domains or has_hashes:

        recommendations.append(
            "Investigate the correlated IOCs across endpoint, "
            "network, and security telemetry."
        )

    # --------------------------------------------------------
    # Threat intelligence
    # --------------------------------------------------------

    if max_threat_intel_score > 0:

        recommendations.append(
            "Validate threat-intelligence matches and prioritize "
            "confirmed indicators for containment and investigation."
        )

    # --------------------------------------------------------
    # Critical event evidence
    # --------------------------------------------------------

    if critical_event_count > 0:

        recommendations.append(
            "Preserve relevant logs and evidence from critical events "
            "before remediation."
        )

    # --------------------------------------------------------
    # High-risk evidence
    # --------------------------------------------------------

    elif high_risk_event_count > 0:

        recommendations.append(
            "Review high-risk event details and retain supporting "
            "security telemetry for investigation."
        )

    # --------------------------------------------------------
    # Risk fallback
    # --------------------------------------------------------

    if not recommendations:

        recommendations.append(
            "Continue monitoring the correlated activity and review "
            "supporting security events for additional indicators."
        )

    return recommendations



# ============================================================
# INCIDENT SUMMARY
# ============================================================

def _build_investigation_summary(
    event_count,
    attack_pattern,
    max_risk_score,
    risk_level,
    critical_event_count,
    high_risk_event_count,
    max_threat_intel_score,
):
    """
    Build a concise deterministic summary for SOC investigation.
    """

    summary = (
        f"{event_count} correlated security events detected "
        f"for {attack_pattern.replace('_', ' ').lower()}."
    )

    if critical_event_count > 0:
        summary += (
            f" {critical_event_count} critical event"
            f"{'s' if critical_event_count != 1 else ''} detected."
        )

    elif high_risk_event_count > 0:
        summary += (
            f" {high_risk_event_count} high-risk event"
            f"{'s' if high_risk_event_count != 1 else ''} detected."
        )

    if max_threat_intel_score > 0:
        summary += (
            f" Maximum threat-intelligence score: "
            f"{max_threat_intel_score}."
        )

    summary += (
        f" Incident risk is {risk_level} "
        f"with maximum risk score {max_risk_score}."
    )

    return summary


# ============================================================
# INVESTIGATION EVIDENCE PACKAGE
# ============================================================

def _build_investigation_evidence(
    incident_id,
    ip_address,
    ordered_events,
    event_types,
    attack_pattern,
    first_seen,
    last_seen,
    max_risk,
    risk_level,
    total_threat_intel_score,
    max_threat_intel_score,
    critical_event_count,
    high_risk_event_count,
    aggregated_iocs,
    investigation_summary,
    response_priority,
    response_recommendations,
):
    """
    Build a structured SOC investigation evidence package.

    The package groups incident metadata, risk, threat intelligence,
    IOC evidence, attack pattern, timeline, and investigation
    summary into one deterministic structure.
    """

    timeline = []

    for event in ordered_events:

        timeline.append({
            "event_id": event.get("id"),
            "timestamp": event.get("timestamp"),
            "event_type": event.get(
                "event_type",
                "UNKNOWN"
            ),
            "severity": event.get(
                "severity",
                "UNKNOWN"
            ),
            "risk_score": event.get(
                "risk_score",
                0
            ),
            "risk_level": event.get(
                "risk_level",
                "LOW"
            ),
            "threat_intel_score": event.get(
                "threat_intel_score",
                0
            ),
            "message": event.get(
                "message",
                ""
            ),
            "source": event.get(
                "source",
                ""
            ),
            "ip_address": event.get(
                "ip_address",
                ip_address
            ),
            "iocs": _normalize_iocs(
                event.get("iocs", {})
            ),
        })

    return {
        "metadata": {
            "incident_id": incident_id,
            "source_ip": ip_address,
            "event_count": len(ordered_events),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "status": "OPEN",
        },

        "risk": {
            "risk_level": risk_level,
            "max_risk_score": max_risk,
            "critical_event_count": critical_event_count,
            "high_risk_event_count": high_risk_event_count,
            "event_types": event_types,
        },

        "threat_intelligence": {
            "total_score": total_threat_intel_score,
            "maximum_score": max_threat_intel_score,
        },

        "ioc_evidence": _build_ioc_evidence(
            aggregated_iocs
        ),

        "attack_pattern": {
            "name": attack_pattern,
            "correlation_method": "RULE_BASED_EVENT_CORRELATION",
        },

        "timeline": timeline,

        "investigation_summary": investigation_summary,

        "response_priority": response_priority,

        "response_recommendations": (
            response_recommendations
        ),
    }


# ============================================================
# INCIDENT BUILDER
# ============================================================

def _build_incident(incident_id, ip_address, events):
    """
    Build one investigation-ready incident.
    """

    ordered_events = sorted(
        events,
        key=_timestamp_key
    )

    # --------------------------------------------------------
    # Risk information
    # --------------------------------------------------------

    risk_scores = [
        event.get("risk_score", 0) or 0
        for event in ordered_events
    ]

    max_risk = max(
        risk_scores
    ) if risk_scores else 0

    # --------------------------------------------------------
    # Threat intelligence information
    # --------------------------------------------------------

    threat_intel_scores = [
        event.get("threat_intel_score", 0) or 0
        for event in ordered_events
    ]

    max_threat_intel_score = (
        max(threat_intel_scores)
        if threat_intel_scores
        else 0
    )

    total_threat_intel_score = sum(
        threat_intel_scores
    )

    # --------------------------------------------------------
    # Risk/event counters
    # --------------------------------------------------------

    critical_event_count = sum(
        1
        for event in ordered_events
        if str(
            event.get("risk_level", "")
        ).upper() == "CRITICAL"
    )

    high_risk_event_count = sum(
        1
        for event in ordered_events
        if str(
            event.get("risk_level", "")
        ).upper() == "HIGH"
    )

    # --------------------------------------------------------
    # Event type distribution
    # --------------------------------------------------------

    event_types = {}

    for event in ordered_events:

        event_type = str(
            event.get(
                "event_type",
                "UNKNOWN"
            )
        ).upper()

        event_types[event_type] = (
            event_types.get(event_type, 0) + 1
        )

    # --------------------------------------------------------
    # IOC aggregation
    # --------------------------------------------------------

    aggregated_iocs = _aggregate_iocs(
        ordered_events
    )

    # --------------------------------------------------------
    # Attack pattern
    # --------------------------------------------------------

    attack_pattern = _detect_attack_pattern(
        ordered_events
    )

    risk_level = _risk_level_from_score(
        max_risk
    )

    # --------------------------------------------------------
    # Response recommendations
    # --------------------------------------------------------

    response_priority = _build_response_priority(
        risk_level
    )

    response_recommendations = _build_response_recommendations(
        attack_pattern=attack_pattern,
        risk_level=risk_level,
        max_risk_score=max_risk,
        aggregated_iocs=aggregated_iocs,
        critical_event_count=critical_event_count,
        high_risk_event_count=high_risk_event_count,
        max_threat_intel_score=max_threat_intel_score,
    )

    # --------------------------------------------------------
    # Investigation summary
    # --------------------------------------------------------

    investigation_summary = _build_investigation_summary(
        event_count=len(ordered_events),
        attack_pattern=attack_pattern,
        max_risk_score=max_risk,
        risk_level=risk_level,
        critical_event_count=critical_event_count,
        high_risk_event_count=high_risk_event_count,
        max_threat_intel_score=max_threat_intel_score,
    )

    # --------------------------------------------------------
    # Investigation evidence
    # --------------------------------------------------------

    first_seen = (
        ordered_events[0].get("timestamp")
        if ordered_events
        else None
    )

    last_seen = (
        ordered_events[-1].get("timestamp")
        if ordered_events
        else None
    )

    investigation_evidence = _build_investigation_evidence(
        incident_id=incident_id,
        ip_address=ip_address,
        ordered_events=ordered_events,
        event_types=event_types,
        attack_pattern=attack_pattern,
        first_seen=first_seen,
        last_seen=last_seen,
        max_risk=max_risk,
        risk_level=risk_level,
        total_threat_intel_score=total_threat_intel_score,
        max_threat_intel_score=max_threat_intel_score,
        critical_event_count=critical_event_count,
        high_risk_event_count=high_risk_event_count,
        aggregated_iocs=aggregated_iocs,
        investigation_summary=investigation_summary,
        response_priority=response_priority,
        response_recommendations=response_recommendations,
    )

    # --------------------------------------------------------
    # Final incident
    # --------------------------------------------------------

    return {
        "incident_id": incident_id,
        "ip_address": ip_address,

        "event_count": len(ordered_events),

        "event_types": event_types,

        "attack_pattern": attack_pattern,

        # SOC response guidance
        "response_priority": response_priority,

        "response_recommendations": (
            response_recommendations
        ),

        "first_seen": first_seen,

        "last_seen": last_seen,

        # Risk context
        "max_risk_score": max_risk,
        "risk_level": risk_level,

        # Threat-intelligence context
        "total_threat_intel_score": (
            total_threat_intel_score
        ),
        "max_threat_intel_score": (
            max_threat_intel_score
        ),

        # Investigation counters
        "critical_event_count": (
            critical_event_count
        ),
        "high_risk_event_count": (
            high_risk_event_count
        ),

        # Aggregated IOC intelligence
        "iocs": aggregated_iocs,

        # Human-readable SOC context
        "investigation_summary": (
            investigation_summary
        ),

        # Structured SOC evidence
        "evidence": investigation_evidence,

        # Existing workflow state
        "status": "OPEN",

        # Full investigation timeline
        "events": ordered_events,
    }


# ============================================================
# CORRELATE EVENTS
# ============================================================

def correlate_events(
    events,
    threshold=DEFAULT_THRESHOLD
):
    """
    Correlate security events by source IP.

    Events from the same valid source IP are grouped together.
    Groups meeting the threshold become investigation-ready
    incidents.

    Args:
        events: Iterable of event dictionaries.
        threshold: Minimum number of events required.

    Returns:
        List of incident dictionaries.
    """

    if threshold < 1:
        raise ValueError(
            "Correlation threshold must be at least 1."
        )

    ip_groups = {}

    for event in events:

        ip_address = event.get(
            "ip_address",
            "UNKNOWN"
        )

        if ip_address in (
            None,
            "",
            "UNKNOWN",
            "N/A",
        ):
            continue

        ip_groups.setdefault(
            ip_address,
            []
        ).append(event)

    incidents = []

    for index, ip_address in enumerate(
        sorted(ip_groups.keys(), key=str)
    ):

        grouped_events = ip_groups[
            ip_address
        ]

        if len(grouped_events) < threshold:
            continue

        incident_id = f"INC-{index + 1:04d}"

        incidents.append(
            _build_incident(
                incident_id=incident_id,
                ip_address=ip_address,
                events=grouped_events,
            )
        )

    return incidents
