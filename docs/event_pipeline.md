# CloudSentinel Event Processing Pipeline

## Purpose

CloudSentinel processes security telemetry through a modular pipeline.
The pipeline separates event ingestion, normalization, validation, detection,
risk evaluation, correlation, and alert generation.

## Pipeline

Raw Event
    |
    v
Ingestion
    |
    v
Normalization
    |
    v
Validation
    |
    v
Detection
    |
    v
Risk Evaluation
    |
    v
Correlation
    |
    v
Alert / Incident
    |
    v
SOC Dashboard

## Stage Responsibilities

### 1. Ingestion

Responsible for accepting raw telemetry from supported sources.

Examples:

- Linux authentication logs
- Synthetic security events
- Future cloud telemetry

Input:

Raw event data.

Output:

Raw event object passed to normalization.

---

### 2. Normalization

Converts different input formats into the CloudSentinel canonical
security-event representation.

Examples:

- Raw log strings
- Dictionary events
- Future cloud events

Output:

Canonical SecurityEvent.

---

### 3. Validation

Ensures that normalized events satisfy the CloudSentinel event contract.

Validation includes:

- Required fields
- Valid timestamp
- Valid event type
- Valid severity
- Valid source
- Valid message
- Valid IP address when present

Invalid events must be rejected before detection.

---

### 4. Detection

Analyzes validated canonical events and identifies security conditions.

Examples:

- Failed authentication
- Brute-force activity
- Suspicious activity
- Sudo activity

Detection must consume canonical events rather than raw log formats.

---

### 5. Risk

Calculates or updates the risk associated with detected activity.

Risk evaluation must be deterministic and explainable.

Risk information should be attached to the event/alert without
destroying the original evidence.

---

### 6. Correlation

Groups related security activity using relationships such as:

- Source IP
- User identity
- Event type
- Time window
- Related events

Correlation produces higher-level attack context.

---

### 7. Alert

Converts detected/correlated security activity into an alert or incident.

Alerts may be:

- Stored
- Displayed
- Sent to notification systems
- Forwarded to the real-time SOC dashboard

---

## Interface Contract

Each stage should have a clear input/output boundary.

Ingestion:
    raw input -> raw event

Normalization:
    raw event -> SecurityEvent

Validation:
    SecurityEvent -> validated SecurityEvent
    invalid event -> validation error

Detection:
    validated SecurityEvent -> detection result(s)

Risk:
    detection result -> risk-enriched result

Correlation:
    risk-enriched result(s) -> correlated finding(s)

Alert:
    correlated finding -> alert/incident

## Compatibility

Existing CloudSentinel components should remain functional while the
new pipeline is introduced.

Legacy imports should be preserved where practical.

The refactor must not intentionally change existing detection behavior
unless the change is documented and tested.

## Day 29 Direction

The event pipeline will be implemented using modular components:

src/
    ingestion/
        pipeline.py
        normalizer.py
        validator.py

src/
    models/
        event.py

Detection, risk, correlation, and alert components remain independently
replaceable.

