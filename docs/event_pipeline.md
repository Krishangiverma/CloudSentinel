# CloudSentinel Event Processing Pipeline

## Purpose

CloudSentinel uses a modular event-processing architecture to transform
security telemetry into normalized events, detection findings, risk-enriched
results, alerts, and correlated incidents.

The pipeline is designed to separate ingestion, normalization, validation,
detection, risk evaluation, correlation, and presentation.

## High-Level Flow

```text
Linux Logs / Synthetic Events / Optional CloudTrail Records
                         |
                         v
                    Event Ingestion
                         |
                         v
                     Normalization
                         |
                         v
                      Validation
                         |
                         v
                  Detection and Analysis
                         |
                         v
                   Risk Enrichment
                         |
                         v
                 Attack Event Correlation
                         |
                         v
                    Alerts / Incidents
                         |
              +----------+----------+
              |                     |
              v                     v
        SQLite Persistence     Real-Time Event Bus
              |                     |
              v                     v
          Flask REST API       Flask-SocketIO
              |                     |
              +----------+----------+
                         |
                         v
                    SOC Dashboard
```

This diagram describes the logical architecture. Individual event paths can
vary according to the ingestion source and the component handling the event.

## Pipeline Stages

### 1. Ingestion

Accepts events from supported sources and passes input into the processing
workflow.

Examples include:

- Linux security-log data.
- Synthetic security events used for development and testing.
- AWS CloudTrail records through the optional integration.

CloudTrail support does not imply that an AWS account, credentials, or cloud
resources are automatically configured.

### 2. Normalization

Converts supported input formats into the canonical CloudSentinel event
representation.

The CloudTrail normalizer maps fields such as event time, event name, event
source, source IP address, and user identity into a normalized event. Original
record evidence is retained where supported.

### 3. Validation

Checks normalized events against the event contract before the relevant
processing stage continues.

Depending on the input path, validation can include required fields,
timestamps, event types, severity, source, message, and IP address format.

Invalid input should be rejected or reported rather than silently treated as
a valid security event.

### 4. Detection and Analysis

Analyzes events using the available detection and analyzer components.

Supported project capabilities include authentication-related detection,
brute-force detection, configurable YAML rules, and suspicious activity
analysis. Detection behavior depends on the relevant module and configuration.

### 5. Risk and Enrichment

Adds risk-related and contextual information to supported events and findings.

Available components include risk analysis, threat-intelligence enrichment,
and local ML-based anomaly analysis. Anomaly scores are signals for investigation,
not proof that an event is malicious.

### 6. Correlation

Relates security events to produce higher-level attack context.

Correlation can consider source identity, user identity, event relationships,
and temporal proximity. The resulting incident context helps investigators
understand related activity across multiple events.

### 7. Alert and Incident Handling

Detected and correlated findings can feed alert and incident workflows.

The application exposes endpoints for retrieving incidents, reviewing
investigation details and timelines, and managing incident status and history.

### 8. Persistence and Presentation

SQLite stores supported security data. The Flask API exposes event, statistics,
incident, hunting, and MITRE mapping functionality.

The real-time event bus and Flask-SocketIO infrastructure can deliver event
updates to connected dashboard clients.

The in-memory event bus and background queue are process-local; they are not
a durable distributed messaging system.

## Related Components

| Responsibility | Representative location |
|---|---|
| Flask application and API routes | `src/api/app.py` |
| WebSocket infrastructure | `src/api/websocket.py` |
| Event model | `src/models/event.py` |
| Ingestion pipeline | `src/ingestion/pipeline.py` |
| CloudTrail normalization | `src/ingestion/cloudtrail.py` |
| Optional CloudTrail client integration | `src/ingestion/aws_cloudtrail.py` |
| Event replay | `src/ingestion/replay.py` |
| Risk analysis | `src/analyzers/risk_engine.py` |
| Attack correlation | `src/analyzers/attack_correlator.py` |
| Local ML anomaly analysis | `src/analyzers/local_ml_anomaly.py` |
| Detection rules | `config/rules/detection_rules.yaml` |
| Database access | `src/data/database.py` |
| Background worker architecture | `docs/worker_architecture.md` |

## Design Principles

- Keep ingestion and detection responsibilities separated.
- Normalize supported inputs into a common event representation.
- Preserve source evidence where supported.
- Keep risk and correlation logic testable.
- Prefer deterministic validation and explicit error handling.
- Maintain compatibility with existing modules where practical.
- Test changes before committing them.

## Operational Boundaries

- The local SQLite database is not a shared database service.
- The in-memory event bus and worker queue do not guarantee recovery after
  process failure.
- Live AWS integration requires external client configuration and permissions.
- Public deployment requires separate authentication, authorization, transport
  security, and operational-hardening work.
