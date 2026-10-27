"""Day 119 integration tests for authentication middleware CSRF protection."""

from werkzeug.security import generate_password_hash

from src.api import auth
from src.api.app import app


def _authenticated_client(monkeypatch):
    """Create a test client with valid auth configuration and session."""
    monkeypatch.setenv(auth.AUTH_USERNAME_ENV, "soc-operator")
    monkeypatch.setenv(
        auth.AUTH_PASSWORD_HASH_ENV,
        generate_password_hash("test-only-password"),
    )
    monkeypatch.setenv(
        auth.AUTH_SECRET_KEY_ENV,
        "test-only-secret-key-long-enough-for-integration-tests",
    )

    monkeypatch.setitem(
        app.config,
        "SECRET_KEY",
        "test-only-flask-session-secret",
    )
    monkeypatch.setitem(app.config, "TESTING", True)
    monkeypatch.setitem(app.config, "SESSION_COOKIE_SECURE", False)

    client = app.test_client()

    with client.session_transaction() as session:
        session[auth.SESSION_USER_KEY] = "soc-operator"
        session[auth.CSRF_SESSION_KEY] = "test-csrf-token"

    return client


def test_state_changing_request_without_csrf_token_is_rejected(monkeypatch):
    client = _authenticated_client(monkeypatch)

    response = client.patch("/__csrf_middleware_test__")

    assert response.status_code == 400
    assert b"CSRF" in response.data


def test_state_changing_request_with_invalid_csrf_token_is_rejected(
    monkeypatch,
):
    client = _authenticated_client(monkeypatch)

    response = client.patch(
        "/__csrf_middleware_test__",
        headers={"X-CSRF-Token": "wrong-token"},
    )

    assert response.status_code == 400
    assert b"CSRF" in response.data


def test_valid_csrf_header_passes_middleware(monkeypatch):
    client = _authenticated_client(monkeypatch)

    response = client.patch(
        "/__csrf_middleware_test__",
        headers={"X-CSRF-Token": "test-csrf-token"},
    )

    # The intentionally nonexistent endpoint should reach Flask's 404,
    # rather than being rejected by the CSRF middleware.
    assert response.status_code == 404


def test_valid_csrf_token_in_json_passes_middleware(monkeypatch):
    client = _authenticated_client(monkeypatch)

    response = client.patch(
        "/__csrf_middleware_test__",
        json={"csrf_token": "test-csrf-token"},
    )

    assert response.status_code == 404


def test_valid_csrf_token_in_form_passes_middleware(monkeypatch):
    client = _authenticated_client(monkeypatch)

    response = client.patch(
        "/__csrf_middleware_test__",
        data={"csrf_token": "test-csrf-token"},
    )

    assert response.status_code == 404
