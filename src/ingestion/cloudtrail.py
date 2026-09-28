"""Convert CloudTrail-format records to CloudSentinel events."""

from datetime import datetime
import ipaddress

from src.ingestion.normalizer import normalize_event


def normalize_cloudtrail_record(record):
    """Convert one CloudTrail record into a canonical SecurityEvent."""
    if not isinstance(record, dict):
        raise ValueError("CloudTrail record must be a JSON object.")

    required = ("eventTime", "eventName", "eventSource")
    for field in required:
        if not isinstance(record.get(field), str) or not record[field].strip():
            raise ValueError(f"Missing or invalid CloudTrail field: {field}")

    try:
        timestamp = datetime.fromisoformat(
            record["eventTime"].strip().replace("Z", "+00:00")
        )
    except ValueError as error:
        raise ValueError("Invalid CloudTrail eventTime.") from error

    event_name = record["eventName"].strip()
    event_source = record["eventSource"].strip()
    source_ip = record.get("sourceIPAddress")

    if source_ip in (None, "", "-"):
        source_ip = "N/A"
    else:
        if not isinstance(source_ip, str):
            raise ValueError("CloudTrail sourceIPAddress must be a string.")
        try:
            source_ip = str(ipaddress.ip_address(source_ip.strip()))
        except ValueError as error:
            raise ValueError("Invalid CloudTrail sourceIPAddress.") from error

    identity = record.get("userIdentity") or {}
    if not isinstance(identity, dict):
        raise ValueError("CloudTrail userIdentity must be an object.")

    user = (
        identity.get("userName")
        or identity.get("principalId")
        or identity.get("arn")
        or identity.get("type")
        or "unknown"
    )

    error_code = record.get("errorCode")
    error_message = record.get("errorMessage")
    message = f"CloudTrail event {event_name} from {event_source}"
    if error_code:
        message += f"; errorCode={error_code}"
    if error_message:
        message += f"; errorMessage={error_message}"

    # Keep severity conservative; detection-specific severity belongs
    # to the detection layer, not an unverified ingestion assumption.
    canonical = {
        "timestamp": timestamp.isoformat(),
        "event_type": f"AWS_CLOUDTRAIL_{event_name}",
        "severity": "LOW",
        "message": message,
        "source": f"aws:cloudtrail/{event_source}",
        "ip_address": source_ip,
        "user": str(user),
        "raw_evidence": record,
    }

    return normalize_event(canonical)
