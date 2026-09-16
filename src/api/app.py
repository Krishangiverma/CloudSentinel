import sys
import json
from pathlib import Path

from flask import Flask, jsonify, request, render_template


# ============================================================
# PROJECT PATH SETUP
# ============================================================

# app.py is inside:
# CloudSentinel/src/api/app.py

# parents[2] gives:
# CloudSentinel/

PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Add project root to Python path
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ============================================================
# DATABASE IMPORTS
# ============================================================

from src.data.database import (
    get_all_events,
    get_incident_status,
    save_event,
    set_incident_status,
)
from src.analyzers.risk_engine import analyze_event_risk
from src.analyzers.attack_correlator import (
    correlate_events,
    transition_incident_status,
)
from src.api.websocket import socketio
from src.ingestion import ingest_event
from src.rules.rule_loader import load_rules_from_yaml
from src.mitre.registry import (
    build_detection_mitre_mappings,
    find_detection_mitre_mapping,
)
from src.hunting.hunt_engine import (
    HuntEngine,
    HuntQuery,
)
from src.hunting.hunt_storage import HuntStorage


# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(
    __name__,
    template_folder=str(PROJECT_ROOT / "templates")
)

# Initialize WebSocket infrastructure
socketio.init_app(app)


# ============================================================
# BASIC CONFIGURATION
# ============================================================

app.config["JSON_SORT_KEYS"] = False


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard", methods=["GET"])
def dashboard():
    """
    Serve the CloudSentinel security dashboard.
    """

    return render_template("dashboard.html")


# ============================================================
# HOME / ROOT ENDPOINT
# ============================================================

@app.route("/", methods=["GET"])
def home():
    """
    Basic API information endpoint.
    """

    return jsonify({
        "service": "CloudSentinel API",
        "status": "running",
        "version": "1.0",
        "endpoints": {
            "dashboard": "/dashboard",
            "health": "/api/health",
            "events": "/api/events",
            "stats": "/api/stats",
            "incidents": "/api/incidents"
        }
    })


# ============================================================
# HEALTH CHECK ENDPOINT
# ============================================================

@app.route("/api/health", methods=["GET"])
def health_check():
    """
    Check whether the CloudSentinel API is running.
    """

    return jsonify({
        "status": "ok",
        "service": "CloudSentinel API"
    })


# ============================================================
# GET ALL SECURITY EVENTS
# ============================================================

@app.route("/api/events", methods=["GET"])
def get_events():
    """
    Return all security events stored in the database.

    Includes:
        - IOC information
        - Threat-intelligence information
        - Threat-intelligence risk contribution
        - Final risk score
        - Final risk level
    """

    try:

        events = get_all_events()

        result = []

        for event in events:

            event_data = {
                "id": event[0],
                "timestamp": event[1],
                "event_type": event[2],
                "severity": event[3],
                "message": event[4],
                "source": event[5],
                "ip_address": event[6]
            }

            # ------------------------------------------------
            # Load persisted IOC data
            # ------------------------------------------------

            iocs = {}

            if len(event) > 7 and event[7]:

                try:
                    iocs = json.loads(event[7])

                except (
                    TypeError,
                    ValueError,
                    json.JSONDecodeError
                ):
                    iocs = {}

            # ------------------------------------------------
            # Load persisted threat-intelligence data
            # ------------------------------------------------

            threat_intel = {}

            if len(event) > 8 and event[8]:

                try:
                    threat_intel = json.loads(event[8])

                except (
                    TypeError,
                    ValueError,
                    json.JSONDecodeError
                ):
                    threat_intel = {}

            # ------------------------------------------------
            # Persisted TI score
            # ------------------------------------------------

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
                ValueError
            ):
                threat_intel_score = 0

            # ------------------------------------------------
            # Risk calculation
            #
            # Historical events already have their
            # threat-intelligence contribution persisted.
            # Reuse that value so API results remain
            # consistent with the original ingestion result.
            # ------------------------------------------------

            base_risk = analyze_event_risk({
                "severity": event[3],
                "event_type": event[2]
            })

            risk_score = min(
                base_risk["risk_score"]
                + threat_intel_score,
                100
            )

            if risk_score >= 80:
                risk_level = "CRITICAL"

            elif risk_score >= 60:
                risk_level = "HIGH"

            elif risk_score >= 35:
                risk_level = "MEDIUM"

            else:
                risk_level = "LOW"

            event_data.update({
                "iocs": iocs,
                "threat_intel": threat_intel,
                "threat_intel_score": threat_intel_score,
                "risk_score": risk_score,
                "risk_level": risk_level
            })

            result.append(event_data)

        return jsonify({
            "count": len(result),
            "events": result
        })

    except Exception as e:

        return jsonify({
            "status": "error",
            "message": "Failed to retrieve security events.",
            "error": str(e)
        }), 500


# ============================================================
# GET SECURITY EVENT STATISTICS
# ============================================================

@app.route("/api/stats", methods=["GET"])
def get_stats():
    """
    Return security event statistics including risk analysis.
    """

    try:

        events = get_all_events()

        total_events = len(events)
        severity_count = {}
        event_type_count = {}

        risk_level_count = {}
        total_risk_score = 0
        max_risk_score = 0

        for event in events:

            severity = event[3]
            event_type = event[2]

            # ------------------------------------------------
            # Count severity
            # ------------------------------------------------

            if severity not in severity_count:
                severity_count[severity] = 0

            severity_count[severity] += 1

            # ------------------------------------------------
            # Count event type
            # ------------------------------------------------

            if event_type not in event_type_count:
                event_type_count[event_type] = 0

            event_type_count[event_type] += 1

            # ------------------------------------------------
            # Calculate risk using persisted threat-intel score
            # ------------------------------------------------

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
                ValueError
            ):
                threat_intel_score = 0

            base_risk = analyze_event_risk({
                "severity": severity,
                "event_type": event_type
            })

            risk_score = min(
                base_risk["risk_score"]
                + threat_intel_score,
                100
            )

            if risk_score >= 80:
                risk_level = "CRITICAL"

            elif risk_score >= 60:
                risk_level = "HIGH"

            elif risk_score >= 35:
                risk_level = "MEDIUM"

            else:
                risk_level = "LOW"

            total_risk_score += risk_score
            max_risk_score = max(
                max_risk_score,
                risk_score
            )

            if risk_level not in risk_level_count:
                risk_level_count[risk_level] = 0

            risk_level_count[risk_level] += 1

        average_risk_score = (
            round(
                total_risk_score / total_events,
                2
            )
            if total_events > 0
            else 0
        )

        return jsonify({
            "total_events": total_events,
            "severity": severity_count,
            "event_types": event_type_count,
            "risk": {
                "total_score": total_risk_score,
                "average_score": average_risk_score,
                "maximum_score": max_risk_score,
                "levels": risk_level_count
            }
        })

    except Exception as e:

        return jsonify({
            "status": "error",
            "message": "Failed to generate statistics.",
            "error": str(e)
        }), 500


# ============================================================
# CREATE SECURITY EVENT
# ============================================================

@app.route("/api/events", methods=["POST"])
def create_event():
    """
    Create and save a new security event.
    """

    try:

        data = request.get_json(
            silent=True
        ) or {}

        event = {
            "timestamp": data.get("timestamp"),
            "event_type": data.get(
                "event_type",
                "UNKNOWN"
            ),
            "severity": data.get(
                "severity",
                "LOW"
            ),
            "message": data.get(
                "message",
                "No message available"
            ),
            "source": data.get(
                "source",
                "CloudSentinel"
            ),
            "ip_address": data.get(
                "ip_address",
                "N/A"
            ),
            "risk_score": data.get(
                "risk_score"
            )
        }

        ingest_event(event)

        return jsonify({
            "status": "success",
            "message": "Security event saved successfully.",
            "event": event
        }), 201

    except Exception as e:

        return jsonify({
            "status": "error",
            "message": "Failed to save security event.",
            "error": str(e)
        }), 500


# ============================================================
# DAY-50 THREAT HUNTING API
# ============================================================

def _build_hunt_query(data):
    """Build a HuntQuery from request JSON."""

    data = data or {}

    return HuntQuery(
        ip=data.get("ip"),
        user=data.get("user"),
        event_type=data.get("event_type"),
        severity=data.get("severity"),
        start_time=data.get("start_time"),
        end_time=data.get("end_time"),
        min_risk=data.get("min_risk"),
        max_risk=data.get("max_risk"),
    )


@app.route(
    "/api/hunts/search",
    methods=["POST"]
)
def hunt_search():
    """Execute a threat-hunting query."""

    try:

        data = request.get_json(
            silent=True
        ) or {}

        query = _build_hunt_query(data)

        engine = HuntEngine()

        results = engine.search(query)

        return jsonify({
            "status": "ok",
            "count": len(results),
            "query": query.to_dict(),
            "results": results,
        })

    except Exception as e:

        return jsonify({
            "status": "error",
            "message": "Failed to execute hunt query.",
            "error": str(e),
        }), 400


@app.route(
    "/api/hunts/saved",
    methods=["POST"]
)
def save_hunt_query():
    """Save a reusable threat-hunting query."""

    try:

        data = request.get_json(
            silent=True
        ) or {}

        name = data.get("name")
        description = data.get("description")

        query = _build_hunt_query(
            data.get("query", data)
        )

        storage = HuntStorage()

        query_id = storage.save_query(
            name=name,
            description=description,
            query=query,
        )

        saved = storage.get_query(
            query_id
        )

        return jsonify({
            "status": "ok",
            "message": "Hunt query saved.",
            "query": saved,
        }), 201

    except Exception as e:

        return jsonify({
            "status": "error",
            "message": "Failed to save hunt query.",
            "error": str(e),
        }), 400


@app.route(
    "/api/hunts/saved",
    methods=["GET"]
)
def list_saved_hunts():
    """Return all saved hunting queries."""

    try:

        storage = HuntStorage()

        queries = storage.list_queries()

        return jsonify({
            "status": "ok",
            "count": len(queries),
            "queries": queries,
        })

    except Exception as e:

        return jsonify({
            "status": "error",
            "message": "Failed to list saved hunt queries.",
            "error": str(e),
        }), 500


@app.route(
    "/api/hunts/saved/<int:query_id>",
    methods=["GET"]
)
def get_saved_hunt(query_id):
    """Return one saved hunting query."""

    try:

        storage = HuntStorage()

        saved = storage.get_query(
            query_id
        )

        if saved is None:

            return jsonify({
                "status": "error",
                "message": "Saved hunt query not found.",
                "query_id": query_id,
            }), 404

        return jsonify({
            "status": "ok",
            "query": saved,
        })

    except Exception as e:

        return jsonify({
            "status": "error",
            "message": "Failed to retrieve saved hunt query.",
            "error": str(e),
        }), 500


@app.route(
    "/api/hunts/saved/<int:query_id>",
    methods=["DELETE"]
)
def delete_saved_hunt(query_id):
    """Delete one saved hunting query."""

    try:

        storage = HuntStorage()

        deleted = storage.delete_query(
            query_id
        )

        if not deleted:

            return jsonify({
                "status": "error",
                "message": "Saved hunt query not found.",
                "query_id": query_id,
            }), 404

        return jsonify({
            "status": "ok",
            "message": "Saved hunt query deleted.",
            "query_id": query_id,
        })

    except Exception as e:

        return jsonify({
            "status": "error",
            "message": "Failed to delete saved hunt query.",
            "error": str(e),
        }), 500


@app.route(
    "/api/hunts/investigations",
    methods=["POST"]
)
def create_hunt_investigation():
    """Create an investigation from a hunt query."""

    try:

        data = request.get_json(
            silent=True
        ) or {}

        title = data.get(
            "title",
            "Threat Hunting Investigation"
        )

        query = _build_hunt_query(
            data.get("query", data)
        )

        engine = HuntEngine()

        results = engine.search(query)

        event_ids = [
            result["id"]
            for result in results
        ]

        storage = HuntStorage()

        investigation_id = (
            storage.create_investigation(
                title=title,
                query=query,
                event_ids=event_ids,
            )
        )

        investigation = (
            storage.get_investigation(
                investigation_id
            )
        )

        return jsonify({
            "status": "ok",
            "message": "Investigation created.",
            "investigation": investigation,
        }), 201

    except Exception as e:

        return jsonify({
            "status": "error",
            "message": "Failed to create investigation.",
            "error": str(e),
        }), 400


@app.route(
    "/api/hunts/investigations",
    methods=["GET"]
)
def list_hunt_investigations():
    """Return all hunting investigations."""

    try:

        storage = HuntStorage()

        investigations = (
            storage.list_investigations()
        )

        return jsonify({
            "status": "ok",
            "count": len(investigations),
            "investigations": investigations,
        })

    except Exception as e:

        return jsonify({
            "status": "error",
            "message": "Failed to list investigations.",
            "error": str(e),
        }), 500


@app.route(
    "/api/hunts/investigations/<int:investigation_id>",
    methods=["GET"]
)
def get_hunt_investigation(
    investigation_id
):
    """Return one hunting investigation."""

    try:

        storage = HuntStorage()

        investigation = (
            storage.get_investigation(
                investigation_id
            )
        )

        if investigation is None:

            return jsonify({
                "status": "error",
                "message": "Investigation not found.",
                "investigation_id": investigation_id,
            }), 404

        return jsonify({
            "status": "ok",
            "investigation": investigation,
        })

    except Exception as e:

        return jsonify({
            "status": "error",
            "message": "Failed to retrieve investigation.",
            "error": str(e),
        }), 500


@app.route(
    "/api/hunts/investigations/<int:investigation_id>/timeline",
    methods=["GET"]
)
def get_hunt_investigation_timeline(
    investigation_id
):
    """Return the chronological timeline of an investigation."""

    try:

        storage = HuntStorage()

        timeline = (
            storage.get_investigation_timeline(
                investigation_id
            )
        )

        if timeline is None:

            return jsonify({
                "status": "error",
                "message": "Investigation not found.",
                "investigation_id": investigation_id,
            }), 404

        return jsonify({
            "status": "ok",
            "investigation_id": investigation_id,
            "count": len(timeline),
            "timeline": timeline,
        })

    except Exception as e:

        return jsonify({
            "status": "error",
            "message": "Failed to retrieve investigation timeline.",
            "error": str(e),
        }), 500



# ============================================================
# API INFORMATION ENDPOINT
# ============================================================

@app.route("/api", methods=["GET"])
def api_info():
    """
    Return information about available API endpoints.
    """

    return jsonify({
        "name": "CloudSentinel Security Monitoring API",
        "version": "1.0",
        "description": (
            "REST API for retrieving security events "
            "and monitoring CloudSentinel."
        ),
        "endpoints": [
            {
                "method": "GET",
                "path": "/",
                "description": "API home"
            },
            {
                "method": "GET",
                "path": "/dashboard",
                "description": "Security monitoring dashboard"
            },
            {
                "method": "GET",
                "path": "/api",
                "description": "API information"
            },
            {
                "method": "GET",
                "path": "/api/health",
                "description": "Health check"
            },
            {
                "method": "GET",
                "path": "/api/events",
                "description": "Get all security events"
            },
            {
                "method": "GET",
                "path": "/api/stats",
                "description": "Get event statistics"
            },
            {
                "method": "GET",
                "path": "/api/incidents",
                "description": "Get correlated security incidents"
            },
            {
                "method": "GET",
                "path": "/api/incidents/<incident_id>",
                "description": "Get individual security incident"
            }
        ]
    })


# ============================================================
# GET CORRELATED SECURITY INCIDENTS
# ============================================================

# ============================================================
# MITRE ATT&CK DETECTION MAPPINGS
# ============================================================

MITRE_RULE_FILE = (
    PROJECT_ROOT
    / "config"
    / "rules"
    / "detection_rules.yaml"
)


def _load_mitre_detection_rules():
    """
    Load the current CloudSentinel detection rules
    used for MITRE ATT&CK mapping.
    """

    return load_rules_from_yaml(
        str(MITRE_RULE_FILE)
    )


@app.route(
    "/api/mitre/mappings",
    methods=["GET"]
)
def get_mitre_mappings():
    """
    Return MITRE ATT&CK mappings for all
    configured CloudSentinel detection rules.
    """

    try:

        rules = _load_mitre_detection_rules()

        mappings = build_detection_mitre_mappings(
            rules
        )

        return jsonify({
            "status": "ok",
            "count": len(mappings),
            "mappings": mappings,
        })

    except Exception as e:

        return jsonify({
            "status": "error",
            "message": (
                "Failed to retrieve MITRE "
                "detection mappings."
            ),
            "error": str(e),
        }), 500


@app.route(
    "/api/mitre/mappings/<rule_id>",
    methods=["GET"]
)
def get_mitre_mapping(rule_id):
    """
    Return the MITRE ATT&CK mapping for
    one detection rule.
    """

    try:

        rules = _load_mitre_detection_rules()

        mapping = find_detection_mitre_mapping(
            rules,
            rule_id,
        )

        if mapping is None:

            return jsonify({
                "status": "error",
                "message": (
                    f"Detection rule '{rule_id}' "
                    "was not found."
                ),
            }), 404

        return jsonify({
            "status": "ok",
            "mapping": mapping,
        })

    except Exception as e:

        return jsonify({
            "status": "error",
            "message": (
                "Failed to retrieve MITRE "
                "detection mapping."
            ),
            "error": str(e),
        }), 500



def _build_correlated_incidents():
    """
    Build investigation-ready incidents from stored security events.

    Restores persisted IOC and threat-intelligence data before
    running risk analysis and incident correlation.

    Database columns:

        0 = id
        1 = timestamp
        2 = event_type
        3 = severity
        4 = message
        5 = source
        6 = ip_address
        7 = iocs_json
        8 = threat_intel_json
        9 = threat_intel_score
    """

    events = get_all_events()

    analyzed_events = []

    for event in events:

        # ----------------------------------------------------
        # Load persisted IOC data
        # ----------------------------------------------------

        iocs = {}

        if len(event) > 7 and event[7]:

            try:
                iocs = json.loads(event[7])

            except (
                TypeError,
                ValueError,
                json.JSONDecodeError
            ):
                iocs = {}

        # ----------------------------------------------------
        # Load persisted threat-intelligence data
        # ----------------------------------------------------

        threat_intel = {}

        if len(event) > 8 and event[8]:

            try:
                threat_intel = json.loads(event[8])

            except (
                TypeError,
                ValueError,
                json.JSONDecodeError
            ):
                threat_intel = {}

        # ----------------------------------------------------
        # Load persisted threat-intelligence score
        # ----------------------------------------------------

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
            ValueError
        ):
            threat_intel_score = 0

        # ----------------------------------------------------
        # Build complete event
        # ----------------------------------------------------

        event_data = {
            "id": event[0],
            "timestamp": event[1],
            "event_type": event[2],
            "severity": event[3],
            "message": event[4],
            "source": event[5],
            "ip_address": event[6],
            "iocs": iocs,
            "threat_intel": threat_intel,
            "threat_intel_score": threat_intel_score
        }

        # ----------------------------------------------------
        # Analyze event risk
        # ----------------------------------------------------

        analyzed_event = analyze_event_risk(
            event_data
        )

        # ----------------------------------------------------
        # Preserve persisted TI information
        # ----------------------------------------------------

        analyzed_event["iocs"] = iocs

        analyzed_event["threat_intel"] = (
            threat_intel
        )

        analyzed_event["threat_intel_score"] = (
            threat_intel_score
        )

        analyzed_events.append(
            analyzed_event
        )

    # --------------------------------------------------------
    # Correlate enriched events
    # --------------------------------------------------------

    incidents = correlate_events(
        analyzed_events
    )

    # --------------------------------------------------------
    # Restore persisted incident lifecycle status
    # --------------------------------------------------------

    for incident in incidents:

        incident_id = incident.get(
            "incident_id"
        )

        if not incident_id:
            continue

        persisted_status = get_incident_status(
            incident_id
        )

        incident["status"] = persisted_status

        evidence = incident.get(
            "evidence"
        )

        if isinstance(evidence, dict):

            metadata = evidence.get(
                "metadata"
            )

            if isinstance(metadata, dict):
                metadata["status"] = persisted_status

    return incidents


# ============================================================
# GET CORRELATED SECURITY INCIDENTS
# ============================================================

@app.route("/api/incidents", methods=["GET"])
def get_incidents():
    """
    Return all correlated security incidents.
    """

    try:

        incidents = _build_correlated_incidents()

        return jsonify({
            "count": len(incidents),
            "incidents": incidents
        })

    except Exception as e:

        return jsonify({
            "status": "error",
            "message": "Failed to correlate security incidents.",
            "error": str(e)
        }), 500


# ============================================================
# UPDATE SECURITY INCIDENT STATUS
# ============================================================

@app.route(
    "/api/incidents/<incident_id>/status",
    methods=["PATCH"]
)
def update_incident_status(incident_id):
    """
    Update the lifecycle status of a security incident.

    Supported lifecycle:

        OPEN
            |
            v
        INVESTIGATING
            |
            v
        RESOLVED

    RESOLVED is terminal.
    """

    try:

        incidents = _build_correlated_incidents()

        normalized_id = str(
            incident_id
        ).strip().upper()

        target_incident = None

        for incident in incidents:

            if incident.get(
                "incident_id",
                ""
            ).upper() == normalized_id:

                target_incident = incident
                break

        if target_incident is None:

            return jsonify({
                "status": "error",
                "message": "Security incident not found.",
                "incident_id": incident_id
            }), 404

        payload = request.get_json(
            silent=True
        )

        if not isinstance(payload, dict):

            return jsonify({
                "status": "error",
                "message": "Request body must be a JSON object."
            }), 400

        requested_status = payload.get(
            "status"
        )

        if requested_status is None:

            return jsonify({
                "status": "error",
                "message": "Incident status is required."
            }), 400

        current_status = get_incident_status(
            normalized_id
        )

        try:

            new_status = transition_incident_status(
                current_status,
                requested_status
            )

        except ValueError as error:

            return jsonify({
                "status": "error",
                "message": str(error),
                "incident_id": normalized_id,
                "current_status": current_status,
                "requested_status": requested_status
            }), 400

        set_incident_status(
            normalized_id,
            new_status
        )

        target_incident["status"] = new_status

        evidence = target_incident.get(
            "evidence"
        )

        if isinstance(evidence, dict):

            metadata = evidence.get(
                "metadata"
            )

            if isinstance(metadata, dict):
                metadata["status"] = new_status

        return jsonify({
            "status": "success",
            "message": "Incident status updated.",
            "incident": target_incident
        })

    except Exception as error:

        return jsonify({
            "status": "error",
            "message": "Failed to update security incident status.",
            "error": str(error)
        }), 500


# ============================================================
# GET INDIVIDUAL SECURITY INCIDENT
# ============================================================

@app.route(
    "/api/incidents/<incident_id>",
    methods=["GET"]
)
def get_incident(incident_id):
    """
    Return one complete correlated security incident.

    Example:
        GET /api/incidents/INC-0001
    """

    try:

        incidents = _build_correlated_incidents()

        normalized_id = str(
            incident_id
        ).strip().upper()

        for incident in incidents:

            if incident["incident_id"].upper() == normalized_id:

                return jsonify({
                    "status": "success",
                    "incident": incident
                })

        return jsonify({
            "status": "error",
            "message": "Security incident not found.",
            "incident_id": incident_id
        }), 404

    except Exception as e:

        return jsonify({
            "status": "error",
            "message": "Failed to retrieve security incident.",
            "error": str(e)
        }), 500


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def page_not_found(error):
    """
    Handle unknown routes.
    """

    return jsonify({
        "status": "error",
        "message": "Endpoint not found.",
        "path": request.path
    }), 404


@app.errorhandler(405)
def method_not_allowed(error):
    """
    Handle unsupported HTTP methods.
    """

    return jsonify({
        "status": "error",
        "message": "HTTP method not allowed.",
        "method": request.method,
        "path": request.path
    }), 405


@app.errorhandler(500)
def internal_server_error(error):
    """
    Handle unexpected server errors.
    """

    return jsonify({
        "status": "error",
        "message": "Internal server error."
    }), 500


# ============================================================
# APPLICATION START
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("CloudSentinel API")
    print("=" * 60)

    print(
        f"Project root: {PROJECT_ROOT}"
    )

    print()
    print("Available endpoints:")
    print("  GET /")
    print("  GET /dashboard")
    print("  GET /api")
    print("  GET /api/health")
    print("  GET /api/events")
    print("  GET /api/stats")
    print("  GET /api/incidents")
    print("  GET /api/incidents/<incident_id>")

    print()
    print("Starting Flask development server...")
    print("=" * 60)

    socketio.run(
        app,
        host="0.0.0.0",
        port=5000,
        debug=False,
        allow_unsafe_werkzeug=True
    )
