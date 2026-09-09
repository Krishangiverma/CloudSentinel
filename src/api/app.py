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


# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(__name__, template_folder=str(PROJECT_ROOT / "templates"))


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
    """

    try:

        # Get events from database
        events = get_all_events()

        result = []

        # Convert database tuples into JSON objects
        for event in events:

            result.append({
                "id": event[0],
                "timestamp": event[1],
                "event_type": event[2],
                "severity": event[3],
                "message": event[4],
                "source": event[5],
                "ip_address": event[6],
                        "risk_score": analyze_event_risk({"severity": event[3], "event_type": event[2]})["risk_score"],
                        "risk_level": analyze_event_risk({"severity": event[3], "event_type": event[2]})["risk_level"]
            })

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

            # Calculate risk
            risk = analyze_event_risk({
                "severity": severity,
                "event_type": event_type
            })

            risk_score = risk["risk_score"]
            risk_level = risk["risk_level"]

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
            "ip_address": data.get("ip_address", "N/A")
        }

        save_event(event)

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

@app.route("/api/incidents", methods=["GET"])
def get_incidents():
    """Return correlated security events grouped into possible attacks."""
    try:
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

            analyzed_events.append(analyze_event_risk(event_data))

        attacks = correlate_events(analyzed_events)

        return jsonify({
            "count": len(attacks),
            "incidents": attacks
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": "Failed to correlate security incidents.",
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

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
