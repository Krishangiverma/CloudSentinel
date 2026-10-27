"""Isolated route tests for CloudSentinel login and logout."""

import re

import pytest
from flask import Flask
from werkzeug.security import generate_password_hash

from src.api import auth
from src.api.auth_routes import auth_bp


@pytest.fixture
def auth_client(monkeypatch):
    monkeypatch.setenv(auth.AUTH_USERNAME_ENV, "soc-operator")
    monkeypatch.setenv(
        auth.AUTH_PASSWORD_HASH_ENV,
        generate_password_hash("test-only-password"),
    )

    test_app = Flask(__name__, template_folder="../templates")
    test_app.config.update(
        SECRET_KEY="test-only-signing-key",
        TESTING=True,
    )
    test_app.register_blueprint(auth_bp)

    @test_app.get("/dashboard")
    def dashboard():
        return "dashboard"

    with test_app.test_client() as client:
        yield client


def extract_csrf_token(html):
    """Extract the CSRF value rendered into the login form."""
    match = re.search(
        r'name="csrf_token" value="([^"]+)"',
        html,
    )
    assert match, "Login form did not render a CSRF token."
    return match.group(1)


def test_login_page_renders_form_and_csrf_token(auth_client):
    response = auth_client.get("/login")

    assert response.status_code == 200
    assert b"CloudSentinel" in response.data
    assert b'name="csrf_token"' in response.data


def test_login_rejects_missing_csrf_token(auth_client):
    response = auth_client.post(
        "/login",
        data={
            "username": "soc-operator",
            "password": "test-only-password",
        },
    )

    assert response.status_code == 400


def test_login_rejects_invalid_credentials(auth_client):
    page = auth_client.get("/login")
    token = extract_csrf_token(page.get_data(as_text=True))

    response = auth_client.post(
        "/login",
        data={
            "csrf_token": token,
            "username": "soc-operator",
            "password": "wrong-password",
        },
    )

    assert response.status_code == 401
    assert b"Invalid username or password." in response.data


def test_login_accepts_valid_credentials(auth_client):
    page = auth_client.get("/login")
    token = extract_csrf_token(page.get_data(as_text=True))

    response = auth_client.post(
        "/login",
        data={
            "csrf_token": token,
            "username": "soc-operator",
            "password": "test-only-password",
        },
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/dashboard")

    with auth_client.session_transaction() as current_session:
        assert current_session[auth.SESSION_USER_KEY] == "soc-operator"
        assert current_session[auth.CSRF_SESSION_KEY]


@pytest.mark.parametrize(
    "destination",
    [
        "https://evil.example",
        "//evil.example/path",
        r"/\evil.example",
    ],
)
def test_login_rejects_external_redirects(auth_client, destination):
    page = auth_client.get("/login")
    token = extract_csrf_token(page.get_data(as_text=True))

    response = auth_client.post(
        "/login",
        data={
            "csrf_token": token,
            "username": "soc-operator",
            "password": "test-only-password",
            "next": destination,
        },
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/dashboard")


def test_logout_requires_csrf_token(auth_client):
    response = auth_client.post("/logout")

    assert response.status_code == 400


def test_logout_clears_authenticated_session(auth_client):
    page = auth_client.get("/login")
    token = extract_csrf_token(page.get_data(as_text=True))

    auth_client.post(
        "/login",
        data={
            "csrf_token": token,
            "username": "soc-operator",
            "password": "test-only-password",
        },
    )

    with auth_client.session_transaction() as current_session:
        logout_token = current_session[auth.CSRF_SESSION_KEY]

    response = auth_client.post(
        "/logout",
        data={"csrf_token": logout_token},
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")

    with auth_client.session_transaction() as current_session:
        assert auth.SESSION_USER_KEY not in current_session
        assert auth.CSRF_SESSION_KEY not in current_session


def test_login_does_not_authenticate_when_credentials_are_unconfigured(
    auth_client,
    monkeypatch,
):
    monkeypatch.delenv(auth.AUTH_USERNAME_ENV, raising=False)

    page = auth_client.get("/login")
    token = extract_csrf_token(page.get_data(as_text=True))

    response = auth_client.post(
        "/login",
        data={
            "csrf_token": token,
            "username": "soc-operator",
            "password": "test-only-password",
        },
    )

    assert response.status_code == 503

    with auth_client.session_transaction() as current_session:
        assert auth.SESSION_USER_KEY not in current_session
