"""Test-only authentication setup for legacy API regression tests."""

import pytest
from flask.testing import FlaskClient


LEGACY_API_TEST_MODULES = {
    "test_api_threat_intel.py",
    "test_incident_api.py",
    "test_incident_response.py",
    "test_incident_status_history_day111.py",
    "test_investigation_context_api_day71.py",
    "test_investigation_context_api_day73.py",
    "test_investigation_context_api_day74.py",
    "test_investigation_context_api_day92.py",
    "test_investigation_context_api_day93.py",
    "test_mitre_api.py",
    "test_incident_investigation_api_day67.py",
    "test_incident_report_export_day97.py",
}


@pytest.fixture(autouse=True)
def configure_legacy_api_test_auth(request, monkeypatch):
    """Authenticate legacy API test clients without weakening production."""
    if request.node.path.name not in LEGACY_API_TEST_MODULES:
        return

    from src.api import auth
    from src.api.app import app

    monkeypatch.setenv(auth.AUTH_USERNAME_ENV, "legacy-test-operator")
    monkeypatch.setenv(
        auth.AUTH_PASSWORD_HASH_ENV,
        "test-only-placeholder-hash",
    )
    monkeypatch.setenv(
        auth.AUTH_SECRET_KEY_ENV,
        "test-only-secret-key-long-enough-for-pytest",
    )

    monkeypatch.setitem(
        app.config,
        "SECRET_KEY",
        "test-only-flask-session-signing-key",
    )
    monkeypatch.setitem(app.config, "SESSION_COOKIE_SECURE", False)

    csrf_token = "legacy-test-csrf-token"

    class AuthenticatedTestClient(FlaskClient):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)

            with self.session_transaction() as session:
                session[auth.SESSION_USER_KEY] = "legacy-test-operator"
                session[auth.CSRF_SESSION_KEY] = csrf_token

        def open(self, *args, **kwargs):
            method = kwargs.get("method", "GET").upper()

            if method in {"POST", "PUT", "PATCH", "DELETE"}:
                headers = dict(kwargs.get("headers") or {})
                headers.setdefault("X-CSRF-Token", csrf_token)
                kwargs["headers"] = headers

            return super().open(*args, **kwargs)

    monkeypatch.setattr(app, "test_client_class", AuthenticatedTestClient)
