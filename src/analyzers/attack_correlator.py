"""
CloudSentinel Advanced Attack Correlation Engine.

Day 61 correlation model:
    source identity + user identity + temporal proximity + event relationships
    -> investigation-ready incident

The engine remains deterministic so incident results are reproducible and
easy to test. Existing Day 60 IOC, threat-intelligence, risk, evidence,
response, and incident-status behavior is preserved.
"""

from datetime import datetime, timezone
from .confidence_scorer import calculate_confidence

DEFAULT_THRESHOLD = 3
DEFAULT_TIME_WINDOW_SECONDS = 300


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
# TIMESTAMP / IDENTITY HELPERS
# ============================================================

def _timestamp_key(event):
    """Return a deterministic sortable representation of an event timestamp."""
    timestamp = event.get("timestamp")
    if timestamp is None:
        return ""
    return str(timestamp)


def _parse_timestamp(value):
    """
    Parse common CloudSentinel ISO-8601 timestamps.

    Naive timestamps are treated as UTC for deterministic comparison.
    Invalid timestamps return None rather than raising.
    """
    if value is None:
        return None

    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value).strip()
        if not text:
            return None
        text = text.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
        except (TypeError, ValueError):
            return None

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def _is_valid_identity(value):
    """Return True for usable source/user identity values."""
    if value is None:
        return False
    return str(value).strip().upper() not in {
        "",
        "UNKNOWN",
        "N/A",
        "NONE",
        "NULL",
    }


def _source_identity(event):
    """Return a normalized source IP identity or None."""
    value = event.get("ip_address")
    if not _is_valid_identity(value):
        return None
    return str(value).strip()


def _user_identity(event):
    """Return a normalized user identity or None."""
    value = event.get("user")
    if not _is_valid_identity(value):
        return None
    return str(value).strip().lower()


# ============================================================
# DAY 62 MULTI-STAGE ATTACK CORRELATION
# ============================================================

ATTACK_STAGE_ORDER = (
    "RECONNAISSANCE",
    "ACCESS",
    "CREDENTIAL",
    "PRIVILEGE",
)

_RECONNAISSANCE_EVENT_TYPES = {
    "PORT_SCAN",
    "PORT SCAN",
    "NETWORK_SCAN",
    "NETWORK SCAN",
    "RECONNAISSANCE",
    "RECON",
}

_ACCESS_EVENT_TYPES = {
    "SUSPICIOUS_LOGIN",
    "SUSPICIOUS LOGIN",
    "UNAUTHORIZED_ACCESS",
    "UNAUTHORIZED ACCESS",
    "INTRUSION",
    "INITIAL_ACCESS",
    "SUCCESSFUL_LOGIN",
    "SUCCESSFUL LOGIN",
}

_CREDENTIAL_EVENT_TYPES = {
    "BRUTE_FORCE",
    "BRUTE FORCE",
    "PASSWORD_SPRAY",
    "PASSWORD SPRAY",
    "CREDENTIAL_ACCESS",
    "CREDENTIAL ACCESS",
    "CREDENTIAL_STUFFING",
    "CREDENTIAL STUFFING",
    "FAILED_LOGIN",
    "FAILED LOGIN",
}

_PRIVILEGE_EVENT_TYPES = {
    "SUDO_ACTIVITY",
    "SUDO ACTIVITY",
    "PRIVILEGE_ESCALATION",
    "PRIVILEGE ESCALATION",
    "ROOT_ACCESS",
    "ROOT ACCESS",
    "ADMIN_ACCESS",
    "ADMIN ACCESS",
}


def _classify_attack_stage(event):
    """
    Classify one event into a conservative attack stage.

    Event-type mappings are deterministic. SUSPICIOUS_ACTIVITY is mapped
    to CREDENTIAL only when its message explicitly indicates a failed
    authentication/password event; otherwise it remains unclassified.
    """
    event_type = str(event.get("event_type", "")).strip().upper()
    message = str(event.get("message", "")).strip().lower()

    if event_type in _RECONNAISSANCE_EVENT_TYPES:
        return "RECONNAISSANCE"

    if event_type in _ACCESS_EVENT_TYPES:
        return "ACCESS"

    if event_type in _CREDENTIAL_EVENT_TYPES:
        return "CREDENTIAL"

    if event_type in _PRIVILEGE_EVENT_TYPES:
        return "PRIVILEGE"

    if event_type == "SUSPICIOUS_ACTIVITY":
        credential_markers = (
            "failed password",
            "authentication failure",
            "invalid user",
            "failed login",
        )
        if any(marker in message for marker in credential_markers):
            return "CREDENTIAL"

    return None


def _build_attack_stage_metadata(ordered_events):
    """
    Build deterministic multi-stage attack-chain evidence.

    The legacy attack_pattern field is intentionally preserved for
    backward compatibility. Day 62 adds attack_chain metadata alongside it.
    """
    stage_evidence = []

    for event in ordered_events:
        stage = _classify_attack_stage(event)
        if stage is None:
            continue

        stage_evidence.append({
            "event_id": event.get("id"),
            "timestamp": event.get("timestamp"),
            "event_type": event.get("event_type", "UNKNOWN"),
            "stage": stage,
        })

    stage_sequence = []
    transitions = []

    for evidence in stage_evidence:
        stage = evidence["stage"]

        if not stage_sequence:
            stage_sequence.append(stage)
            continue

        previous_stage = stage_sequence[-1]

        if stage == previous_stage:
            continue

        transitions.append({
            "from_stage": previous_stage,
            "to_stage": stage,
            "event_id": evidence["event_id"],
            "timestamp": evidence["timestamp"],
        })
        stage_sequence.append(stage)

    present_stages = [
        stage
        for stage in ATTACK_STAGE_ORDER
        if stage in {item["stage"] for item in stage_evidence}
    ]

    forward_transitions = 0
    backward_transitions = 0

    for transition in transitions:
        from_index = ATTACK_STAGE_ORDER.index(
            transition["from_stage"]
        )
        to_index = ATTACK_STAGE_ORDER.index(
            transition["to_stage"]
        )

        if to_index > from_index:
            forward_transitions += 1
        elif to_index < from_index:
            backward_transitions += 1

    multi_stage_attack = len(present_stages) >= 2
    complete_attack_chain = all(
        stage in present_stages
        for stage in ATTACK_STAGE_ORDER
    )

    return {
        "stages_present": present_stages,
        "stage_sequence": stage_sequence,
        "stage_count": len(present_stages),
        "multi_stage_attack": multi_stage_attack,
        "complete_attack_chain": complete_attack_chain,
        "forward_transitions": forward_transitions,
        "backward_transitions": backward_transitions,
        "transitions": transitions,
        "stage_evidence": stage_evidence,
    }


# ============================================================
# IOC NORMALIZATION
# ============================================================

def _normalize_iocs(iocs):
    """Normalize an event IOC dictionary into the canonical IOC structure."""
    if not isinstance(iocs, dict):
        iocs = {}

    ips = iocs.get("ips", [])
    domains = iocs.get("domains", [])
    urls = iocs.get("urls", [])
    hashes = iocs.get("hashes", {})

    if not isinstance(ips, list):
        ips = []
    if not isinstance(domains, list):
        domains = []
    if not isinstance(urls, list):
        urls = []
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
        "urls": urls,
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
    """Aggregate and deterministically deduplicate IOCs across an incident."""
    aggregated = {
        "ips": set(),
        "domains": set(),
        "urls": set(),
        "hashes": {
            "md5": set(),
            "sha1": set(),
            "sha256": set(),
        },
    }

    for event in events:
        iocs = _normalize_iocs(event.get("iocs", {}))

        for ip in iocs["ips"]:
            if ip is not None and str(ip).strip():
                aggregated["ips"].add(str(ip).strip())

        for domain in iocs["domains"]:
            if domain is not None and str(domain).strip():
                aggregated["domains"].add(str(domain).strip())

        for url in iocs["urls"]:
            if url is not None and str(url).strip():
                aggregated["urls"].add(str(url).strip())

        for hash_type in ("md5", "sha1", "sha256"):
            for hash_value in iocs["hashes"][hash_type]:
                if hash_value is not None and str(hash_value).strip():
                    aggregated["hashes"][hash_type].add(
                        str(hash_value).strip()
                    )

    return {
        "ips": sorted(aggregated["ips"]),
        "domains": sorted(aggregated["domains"]),
        "urls": sorted(aggregated["urls"]),
        "hashes": {
            "md5": sorted(aggregated["hashes"]["md5"]),
            "sha1": sorted(aggregated["hashes"]["sha1"]),
            "sha256": sorted(aggregated["hashes"]["sha256"]),
        },
    }


def _build_ioc_evidence(aggregated_iocs):
    """Build a compact IOC evidence summary for SOC investigation."""
    ips = aggregated_iocs.get("ips", [])
    domains = aggregated_iocs.get("domains", [])
    urls = aggregated_iocs.get("urls", [])
    hashes = aggregated_iocs.get("hashes", {})

    md5 = hashes.get("md5", [])
    sha1 = hashes.get("sha1", [])
    sha256 = hashes.get("sha256", [])

    total_hashes = len(md5) + len(sha1) + len(sha256)

    return {
        "total_ips": len(ips),
        "total_domains": len(domains),
        "total_urls": len(urls),
        "total_hashes": total_hashes,
        "has_iocs": bool(ips or domains or urls or md5 or sha1 or sha256),
        "ips": ips,
        "domains": domains,
        "urls": urls,
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
    """Infer a high-level attack pattern from correlated event types."""
    event_types = {
        str(event.get("event_type", "UNKNOWN")).upper()
        for event in events
    }

    if "BRUTE_FORCE" in event_types or "BRUTE FORCE" in event_types:
        return "BRUTE_FORCE_ACTIVITY"

    if "MALWARE" in event_types:
        return "MALWARE_ACTIVITY"

    if "PORT_SCAN" in event_types or "PORT SCAN" in event_types:
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

def transition_incident_status(current_status, new_status):
    """Validate and apply a CloudSentinel incident status transition."""
    current = str(current_status or "").strip().upper()
    target = str(new_status or "").strip().upper()

    valid_statuses = {"OPEN", "INVESTIGATING", "RESOLVED"}

    if current not in valid_statuses:
        raise ValueError(f"Invalid current incident status: {current}")

    if target not in valid_statuses:
        raise ValueError(f"Invalid target incident status: {target}")

    allowed_transitions = {
        "OPEN": {"OPEN", "INVESTIGATING", "RESOLVED"},
        "INVESTIGATING": {"INVESTIGATING", "RESOLVED"},
        "RESOLVED": {"RESOLVED"},
    }

    if target not in allowed_transitions[current]:
        raise ValueError(
            f"Invalid incident status transition: {current} -> {target}"
        )

    return target


# ============================================================
# RESPONSE PRIORITY
# ============================================================

def _build_response_priority(risk_level):
    """Convert incident risk level into a deterministic SOC priority."""
    normalized_risk = str(risk_level or "LOW").upper()

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
    """Build deterministic SOC response recommendations."""
    recommendations = []

    normalized_pattern = str(attack_pattern or "").upper()
    normalized_risk = str(risk_level or "LOW").upper()

    if normalized_risk in ("CRITICAL", "HIGH"):
        recommendations.append(
            "Review and contain the affected source IP before "
            "further investigation."
        )

    if normalized_pattern == "BRUTE_FORCE_ACTIVITY":
        recommendations.append(
            "Review authentication logs for the source IP and "
            "consider blocking or rate-limiting repeated login attempts."
        )

    if normalized_pattern == "MALWARE_ACTIVITY":
        recommendations.append(
            "Isolate affected systems and investigate the malware "
            "execution chain and persistence mechanisms."
        )

    if normalized_pattern == "RECONNAISSANCE_ACTIVITY":
        recommendations.append(
            "Review targeted services and network connections to "
            "identify the scope of reconnaissance activity."
        )

    if normalized_pattern == "INTRUSION_ACTIVITY":
        recommendations.append(
            "Investigate the compromised access path and review "
            "privilege escalation or lateral movement activity."
        )

    if normalized_pattern == "SUSPICIOUS_LOGIN_ACTIVITY":
        recommendations.append(
            "Validate the login source, account activity, and "
            "authentication history for unauthorized access."
        )

    ioc_data = aggregated_iocs or {}
    ips = ioc_data.get("ips", [])
    domains = ioc_data.get("domains", [])
    hashes = ioc_data.get("hashes", {})

    has_hashes = any(
        hashes.get(hash_type, [])
        for hash_type in ("md5", "sha1", "sha256")
    )

    if ips or domains or has_hashes:
        recommendations.append(
            "Investigate the correlated IOCs across endpoint, "
            "network, and security telemetry."
        )

    if max_threat_intel_score > 0:
        recommendations.append(
            "Validate threat-intelligence matches and prioritize "
            "confirmed indicators for containment and investigation."
        )

    if critical_event_count > 0:
        recommendations.append(
            "Preserve relevant logs and evidence from critical events "
            "before remediation."
        )
    elif high_risk_event_count > 0:
        recommendations.append(
            "Review high-risk event details and retain supporting "
            "security telemetry for investigation."
        )

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
    """Build a concise deterministic summary for SOC investigation."""
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
# DAY 61 CORRELATION METADATA
# ============================================================

def _build_correlation_metadata(
    ordered_events,
    time_window_seconds,
):
    """
    Build deterministic temporal/identity relationship evidence.

    Correlation is based on:
      - same source IP
      - same normalized user
      - both events falling inside the configured time window
    """
    source_ips = sorted(
        {
            _source_identity(event)
            for event in ordered_events
            if _source_identity(event) is not None
        }
    )

    users = sorted(
        {
            _user_identity(event)
            for event in ordered_events
            if _user_identity(event) is not None
        }
    )

    relationships = []

    for index, left in enumerate(ordered_events):
        left_ts = _parse_timestamp(left.get("timestamp"))
        left_ip = _source_identity(left)
        left_user = _user_identity(left)

        for right in ordered_events[index + 1:]:
            right_ts = _parse_timestamp(right.get("timestamp"))
            right_ip = _source_identity(right)
            right_user = _user_identity(right)

            reasons = []

            if left_ip and right_ip and left_ip == right_ip:
                reasons.append("SAME_SOURCE_IP")

            if left_user and right_user and left_user == right_user:
                reasons.append("SAME_USER")

            if (
                left_ts is not None
                and right_ts is not None
                and abs((right_ts - left_ts).total_seconds())
                <= time_window_seconds
            ):
                reasons.append("WITHIN_TIME_WINDOW")

            if len(reasons) >= 2:
                relationships.append(
                    {
                        "event_id": left.get("id"),
                        "related_event_id": right.get("id"),
                        "reasons": reasons,
                    }
                )

    attack_chain = _build_attack_stage_metadata(
        ordered_events
    )

    return {
        "method": "TEMPORAL_IDENTITY_EVENT_CORRELATION",
        "time_window_seconds": time_window_seconds,
        "source_ips": source_ips,
        "users": users,
        "relationships": relationships,
        "attack_chain": attack_chain,
    }


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
    correlation_metadata,
):
    """Build the structured SOC investigation evidence package."""
    timeline = []

    for event in ordered_events:
        timeline.append({
            "event_id": event.get("id"),
            "timestamp": event.get("timestamp"),
            "event_type": event.get("event_type", "UNKNOWN"),
            "severity": event.get("severity", "UNKNOWN"),
            "risk_score": event.get("risk_score", 0),
            "risk_level": event.get("risk_level", "LOW"),
            "threat_intel_score": event.get("threat_intel_score", 0),
            "message": event.get("message", ""),
            "source": event.get("source", ""),
            "ip_address": event.get("ip_address", ip_address),
            "user": event.get("user"),
            "iocs": _normalize_iocs(event.get("iocs", {})),
        })

    return {
        "metadata": {
            "incident_id": incident_id,
            "source_ip": ip_address,
            "source_ips": correlation_metadata["source_ips"],
            "users": correlation_metadata["users"],
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
        "ioc_evidence": _build_ioc_evidence(aggregated_iocs),
        "attack_pattern": {
            "name": attack_pattern,
            "correlation_method": "RULE_BASED_EVENT_CORRELATION",
        },
        "correlation": correlation_metadata,
        "attack_chain": correlation_metadata["attack_chain"],
        "timeline": timeline,
        "investigation_summary": investigation_summary,
        "response_priority": response_priority,
        "response_recommendations": response_recommendations,
    }


# ============================================================
# INCIDENT BUILDER
# ============================================================

def _build_incident(
    incident_id,
    ip_address,
    events,
    time_window_seconds=DEFAULT_TIME_WINDOW_SECONDS,
):
    """Build one investigation-ready incident."""
    ordered_events = sorted(events, key=_timestamp_key)

    risk_scores = [
        event.get("risk_score", 0) or 0
        for event in ordered_events
    ]
    max_risk = max(risk_scores) if risk_scores else 0

    threat_intel_scores = [
        event.get("threat_intel_score", 0) or 0
        for event in ordered_events
    ]
    max_threat_intel_score = (
        max(threat_intel_scores) if threat_intel_scores else 0
    )
    total_threat_intel_score = sum(threat_intel_scores)

    critical_event_count = sum(
        1
        for event in ordered_events
        if str(event.get("risk_level", "")).upper() == "CRITICAL"
    )
    high_risk_event_count = sum(
        1
        for event in ordered_events
        if str(event.get("risk_level", "")).upper() == "HIGH"
    )

    event_types = {}
    for event in ordered_events:
        event_type = str(
            event.get("event_type", "UNKNOWN")
        ).upper()
        event_types[event_type] = event_types.get(event_type, 0) + 1

    aggregated_iocs = _aggregate_iocs(ordered_events)
    attack_pattern = _detect_attack_pattern(ordered_events)
    risk_level = _risk_level_from_score(max_risk)

    response_priority = _build_response_priority(risk_level)
    response_recommendations = _build_response_recommendations(
        attack_pattern=attack_pattern,
        risk_level=risk_level,
        max_risk_score=max_risk,
        aggregated_iocs=aggregated_iocs,
        critical_event_count=critical_event_count,
        high_risk_event_count=high_risk_event_count,
        max_threat_intel_score=max_threat_intel_score,
    )

    investigation_summary = _build_investigation_summary(
        event_count=len(ordered_events),
        attack_pattern=attack_pattern,
        max_risk_score=max_risk,
        risk_level=risk_level,
        critical_event_count=critical_event_count,
        high_risk_event_count=high_risk_event_count,
        max_threat_intel_score=max_threat_intel_score,
    )

    first_seen = (
        ordered_events[0].get("timestamp")
        if ordered_events else None
    )
    last_seen = (
        ordered_events[-1].get("timestamp")
        if ordered_events else None
    )

    correlation_metadata = _build_correlation_metadata(
        ordered_events,
        time_window_seconds,
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
        correlation_metadata=correlation_metadata,
    )

    source_ips = correlation_metadata["source_ips"]
    users = correlation_metadata["users"]
    attack_chain = correlation_metadata["attack_chain"]

    confidence = calculate_confidence(
        {
            "event_count": len(ordered_events),
            "events": ordered_events,
            "source_ips": source_ips,
            "users": users,
            "max_risk_score": max_risk,
            "max_threat_intel_score": max_threat_intel_score,
            "critical_event_count": critical_event_count,
            "high_risk_event_count": high_risk_event_count,
            "attack_chain": attack_chain,
            "correlation": correlation_metadata,
        },
        time_window_seconds=time_window_seconds,
    )

    return {
        "incident_id": incident_id,
        "ip_address": ip_address,
        "source_ips": source_ips,
        "users": users,
        "attack_chain": attack_chain,
        "confidence_score": confidence["score"],
        "confidence_level": confidence["level"],
        "confidence": confidence,
        "event_count": len(ordered_events),
        "event_types": event_types,
        "attack_pattern": attack_pattern,
        "response_priority": response_priority,
        "response_recommendations": response_recommendations,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "max_risk_score": max_risk,
        "risk_level": risk_level,
        "total_threat_intel_score": total_threat_intel_score,
        "max_threat_intel_score": max_threat_intel_score,
        "critical_event_count": critical_event_count,
        "high_risk_event_count": high_risk_event_count,
        "iocs": aggregated_iocs,
        "investigation_summary": investigation_summary,
        "evidence": investigation_evidence,
        "correlation": correlation_metadata,
        "status": "OPEN",
        "events": ordered_events,
    }


# ============================================================
# DAY 61 TEMPORAL / IDENTITY CORRELATION
# ============================================================

def _build_correlation_clusters(events, time_window_seconds):
    """
    Build deterministic event clusters using identity + temporal proximity.

    An event joins an existing cluster when:
      1. it has the same source IP OR same user as that cluster, and
      2. its timestamp is within the configured window from the cluster's
         first event.

    This keeps the correlation bounded and avoids indefinite chain growth.
    """
    ordered = sorted(
        list(events),
        key=lambda event: (
            _timestamp_key(event),
            str(event.get("id", "")),
        ),
    )

    clusters = []

    for event in ordered:
        source_ip = _source_identity(event)
        user = _user_identity(event)
        timestamp = _parse_timestamp(event.get("timestamp"))

        if source_ip is None and user is None:
            continue

        matched_cluster = None

        for cluster in clusters:
            cluster_timestamp = cluster["first_timestamp"]

            if (
                timestamp is None
                or cluster_timestamp is None
                or abs(
                    (timestamp - cluster_timestamp).total_seconds()
                ) > time_window_seconds
            ):
                continue

            same_ip = (
                source_ip is not None
                and source_ip in cluster["source_ips"]
            )
            same_user = (
                user is not None
                and user in cluster["users"]
            )

            if same_ip or same_user:
                matched_cluster = cluster
                break

        if matched_cluster is None:
            clusters.append({
                "events": [event],
                "first_timestamp": timestamp,
                "source_ips": (
                    {source_ip} if source_ip is not None else set()
                ),
                "users": {user} if user is not None else set(),
            })
            continue

        matched_cluster["events"].append(event)

        if source_ip is not None:
            matched_cluster["source_ips"].add(source_ip)

        if user is not None:
            matched_cluster["users"].add(user)

    return clusters


# ============================================================
# CORRELATE EVENTS
# ============================================================

def correlate_events(
    events,
    threshold=DEFAULT_THRESHOLD,
    time_window_seconds=DEFAULT_TIME_WINDOW_SECONDS,
):
    """
    Correlate security events using source identity, user identity,
    a bounded time window, and event relationships.

    Backward compatibility:
        correlate_events(events)
        correlate_events(events, threshold=3)

    Args:
        events: Iterable of event dictionaries.
        threshold: Minimum number of events required.
        time_window_seconds: Maximum event-to-cluster-first-event
            distance used for correlation.

    Returns:
        List of investigation-ready incident dictionaries.
    """
    if threshold < 1:
        raise ValueError(
            "Correlation threshold must be at least 1."
        )

    if time_window_seconds < 0:
        raise ValueError(
            "Correlation time window cannot be negative."
        )

    clusters = _build_correlation_clusters(
        events,
        time_window_seconds,
    )

    qualifying = [
        cluster
        for cluster in clusters
        if len(cluster["events"]) >= threshold
    ]

    # Preserve deterministic historical ordering:
    # source IP first, then user, then earliest timestamp.
    def cluster_sort_key(cluster):
        ips = sorted(cluster["source_ips"])
        users = sorted(cluster["users"])
        first_event = min(
            cluster["events"],
            key=lambda event: (
                _timestamp_key(event),
                str(event.get("id", "")),
            ),
        )
        return (
            ips[0] if ips else "~",
            users[0] if users else "~",
            _timestamp_key(first_event),
            str(first_event.get("id", "")),
        )

    qualifying.sort(key=cluster_sort_key)

    incidents = []

    for index, cluster in enumerate(qualifying, start=1):
        source_ips = sorted(cluster["source_ips"])

        if len(source_ips) == 1:
            incident_ip = source_ips[0]
        elif source_ips:
            incident_ip = "MULTIPLE"
        else:
            incident_ip = "UNKNOWN"

        incidents.append(
            _build_incident(
                incident_id=f"INC-{index:04d}",
                ip_address=incident_ip,
                events=cluster["events"],
                time_window_seconds=time_window_seconds,
            )
        )

    return incidents
