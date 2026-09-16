import sys
from pathlib import Path

from flask import Flask, jsonify, request, render_template


# ============================================================
# PROJECT PATH SETUP
# ============================================================

# app.py is inside:
# CloudSentinel/src/api/app.py
#
# parents[2] gives:
# CloudSentinel/

PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Add project root to Python path
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ============================================================
# DATABASE IMPORTS
# ============================================================

from src.data.database import get_all_events, save_event
from src.analyzers.risk_engine import analyze_event_risk
from src.analyzers.attack_correlator import correlate_events
from src.api.websocket import socketio
from src.ingestion import ingest_event


# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(__name__, template_folder=str(PROJECT_ROOT / "templates"))

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
            "stats": "/api/stats"
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
                "ip_address": event[6],
            }

            # ------------------------------------------------
            # Load persisted IOC data
            # ------------------------------------------------

            iocs = {}

            if len(event) > 7 and event[7]:

                try:
                    import json

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
                    import json

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

            # Count severity
            if severity not in severity_count:
                severity_count[severity] = 0
            severity_count[severity] += 1

            # Count event type
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

            base_risk = analyze_event_risk({
                "severity": severity,
                "event_type": event_type
            })

            risk_score = min(
                base_risk["risk_score"]
                + int(threat_intel_score),
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
            max_risk_score = max(max_risk_score, risk_score)

            if risk_level not in risk_level_count:
                risk_level_count[risk_level] = 0
            risk_level_count[risk_level] += 1

        average_risk_score = (
            round(total_risk_score / total_events, 2)
            if total_events > 0 else 0
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
    """Create and save a new security event."""
    try:
        data = request.get_json(silent=True) or {}

        event = {
            "timestamp": data.get("timestamp"),
            "event_type": data.get("event_type", "UNKNOWN"),
            "severity": data.get("severity", "LOW"),
            "message": data.get("message", "No message available"),
            "source": data.get("source", "CloudSentinel"),
            "ip_address": data.get("ip_address", "N/A"),
            "risk_score": data.get("risk_score")
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
            }
        ]
    })


# ============================================================
# GET CORRELATED SECURITY INCIDENTS
# ============================================================

def _build_correlated_incidents():
    """
    Build investigation-ready incidents from stored security events.

    The same correlation path is shared by both the collection
    endpoint and individual incident investigation endpoint.
    """

    events = get_all_events()

    analyzed_events = []

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

        analyzed_events.append(
            analyze_event_risk(event_data)
        )

    return correlate_events(analyzed_events)


# ============================================================
# GET CORRELATED SECURITY INCIDENTS
# ============================================================

@app.route("/api/incidents", methods=["GET"])
def get_incidents():
    """Return all correlated security incidents."""

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
# GET INDIVIDUAL SECURITY INCIDENT
# ============================================================

@app.route("/api/incidents/<incident_id>", methods=["GET"])
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

    print(f"Project root: {PROJECT_ROOT}")

    print()
    print("Available endpoints:")
    print("  GET /")
    print("  GET /dashboard")
    print("  GET /api")
    print("  GET /api/health")
    print("  GET /api/events")
    print("  GET /api/stats")
    print("  GET /api/incidents")

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
