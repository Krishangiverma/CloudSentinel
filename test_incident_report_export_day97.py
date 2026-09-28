import src.api.app as app_module


def sample_incident(message="Repeated failed SSH logins"):
    return {
        "incident_id": "INC-DAY97-001",
        "ip_address": "192.0.2.10",
        "status": "OPEN",
        "attack_pattern": "SSH_BRUTE_FORCE",
        "first_seen": "2026-10-18T08:00:00Z",
        "last_seen": "2026-10-18T08:05:00Z",
        "event_count": 1,
        "risk_level": "HIGH",
        "max_risk_score": 75,
        "critical_event_count": 0,
        "high_risk_event_count": 1,
        "investigation_summary": "Repeated failed SSH logins.",
        "response_recommendations": ["Review authentication logs."],
        "evidence": {
            "risk": {
                "critical_event_count": 0,
                "high_risk_event_count": 1,
            },
            "timeline": [
                {
                    "event_id": 97,
                    "timestamp": "2026-10-18T08:05:00Z",
                    "event_type": "SSH_LOGIN_FAILURE",
                    "severity": "HIGH",
                    "risk_score": 75,
                    "ip_address": "192.0.2.10",
                    "source": "auth.log",
                    "message": message,
                }
            ],
        },
    }


def setup_client(monkeypatch, incidents):
    monkeypatch.setattr(
        app_module,
        "_build_correlated_incidents",
        lambda: incidents,
    )
    app_module.app.config["TESTING"] = True
    return app_module.app.test_client()


def test_report_download_returns_plain_text_attachment(monkeypatch):
    incident = sample_incident()
    client = setup_client(monkeypatch, [incident])

    response = client.get("/api/incidents/inc-day97-001/report")

    assert response.status_code == 200
    assert response.mimetype == "text/plain"
    assert "attachment;" in response.headers["Content-Disposition"]
    assert "cloudsentinel_INC-DAY97-001_report.txt" in (
        response.headers["Content-Disposition"]
    )

    report = response.get_data(as_text=True)
    assert "CLOUDSENTINEL INCIDENT INVESTIGATION REPORT" in report
    assert "INC-DAY97-001" in report
    assert "RISK ASSESSMENT" in report
    assert "EVENT EVIDENCE" in report
    assert "KNOWN LIMITATIONS" in report
    assert "75/100" in report


def test_report_unknown_incident_returns_404(monkeypatch):
    client = setup_client(monkeypatch, [sample_incident()])

    response = client.get("/api/incidents/DOES-NOT-EXIST/report")

    assert response.status_code == 404
    assert response.get_json()["message"] == "Security incident not found."


def test_report_failure_does_not_disclose_exception(monkeypatch):
    def fail():
        raise RuntimeError("database password or internal path")

    client = setup_client(monkeypatch, [])
    monkeypatch.setattr(
        app_module,
        "_build_correlated_incidents",
        fail,
    )

    response = client.get("/api/incidents/INC-DAY97-001/report")

    assert response.status_code == 500
    body = response.get_data(as_text=True)
    assert "Failed to generate incident report." in body
    assert "database password" not in body
    assert "internal path" not in body


def test_report_escapes_newlines_in_untrusted_event_text(monkeypatch):
    malicious_message = "Suspicious input\nRISK LEVEL: LOW\nFAKE SECTION"
    client = setup_client(
        monkeypatch,
        [sample_incident(message=malicious_message)],
    )

    response = client.get("/api/incidents/INC-DAY97-001/report")

    assert response.status_code == 200
    report = response.get_data(as_text=True)
    assert "Suspicious input RISK LEVEL: LOW FAKE SECTION" in report
    assert "\nRISK LEVEL: LOW\n" not in report
    assert "\nFAKE SECTION\n" not in report
