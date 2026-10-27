"""Day 119 tests for CloudSentinel authentication primitives."""

import pytest
from flask import Flask, session
from werkzeug.security import generate_password_hash

from src.api import auth


@pytest.fixture
def auth_app(monkeypatch):
    monkeypatch.setenv(auth.AUTH_USERNAME_ENV, "soc-operator")
    monkeypatch.setenv(
        auth.AUTH_PASSWORD_HASH_ENV,
        generate_password_hash("test-only-password"),
    )

    test_app = Flask(__name__)
    test_app.config["SECRET_KEY"] = "test-only-signing-key"
    test_app.config["TESTING"] = True

    return test_app


def test_credentials_require_configured_username_and_password_hash(
    monkeypatch,
):
    monkeypatch.delenv(auth.AUTH_USERNAME_ENV, raising=False)
    monkeypatch.delenv(auth.AUTH_PASSWORD_HASH_ENV, raising=False)

    assert auth.credentials_configured() is False
    assert auth.verify_credentials("soc-operator", "anything") is False


def test_credentials_accept_correct_username_and_password(auth_app):
    with auth_app.test_request_context("/"):
        assert auth.verify_credentials(
            "soc-operator",
            "test-only-password",
        ) is True


@pytest.mark.parametrize(
    ("username", "password"),
    [
        ("wrong-user", "test-only-password"),
        ("soc-operator", "wrong-password"),
        ("", ""),
        (None, "test-only-password"),
        ("soc-operator", None),
    ],
)
def test_credentials_reject_invalid_values(auth_app, username, password):
    with auth_app.test_request_context("/"):
        assert auth.verify_credentials(username, password) is False


def test_malformed_password_hash_is_rejected(monkeypatch):
    monkeypatch.setenv(auth.AUTH_USERNAME_ENV, "soc-operator")
    monkeypatch.setenv(auth.AUTH_PASSWORD_HASH_ENV, "not-a-valid-password-hash")

    with Flask(__name__).test_request_context("/"):
        assert auth.verify_credentials("soc-operator", "anything") is False


def test_login_establishes_fresh_session_and_csrf_token(auth_app):
    with auth_app.test_request_context("/"):
        session["old_value"] = "must-be-cleared"

        auth.establish_login("soc-operator")

        assert "old_value" not in session
        assert auth.is_authenticated() is True
        assert auth.get_csrf_token()
        assert len(auth.get_csrf_token()) >= 32


def test_session_is_not_authenticated_if_configured_username_changes(
    auth_app,
    monkeypatch,
):
    with auth_app.test_request_context("/"):
        auth.establish_login("soc-operator")
        monkeypatch.setenv(auth.AUTH_USERNAME_ENV, "different-operator")

        assert auth.is_authenticated() is False


def test_clear_login_removes_session_and_csrf_token(auth_app):
    with auth_app.test_request_context("/"):
        auth.establish_login("soc-operator")
        auth.clear_login()

        assert auth.is_authenticated() is False
        assert auth.CSRF_SESSION_KEY not in session


def test_csrf_token_validation_requires_matching_session_token(auth_app):
    with auth_app.test_request_context("/"):
        token = auth.get_csrf_token()

        assert auth.validate_csrf_token(token) is True
        assert auth.validate_csrf_token("tampered-token") is False
        assert auth.validate_csrf_token("") is False
        assert auth.validate_csrf_token(None) is False


def test_csrf_token_can_be_read_from_request_header(auth_app):
    with auth_app.test_request_context(
        "/",
        headers={auth.CSRF_HEADER_NAME: "header-token"},
    ):
        session[auth.CSRF_SESSION_KEY] = "header-token"

        assert auth.validate_csrf_token() is True


def test_secret_key_is_never_silently_generated(monkeypatch):
    monkeypatch.delenv(auth.AUTH_SECRET_KEY_ENV, raising=False)

    assert auth.secret_key_from_environment() is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("true", True),
        ("1", True),
        ("YES", True),
        ("on", True),
        ("false", False),
        ("0", False),
        ("", False),
    ],
)
def test_secure_cookie_setting(monkeypatch, value, expected):
    monkeypatch.setenv("CLOUDSENTINEL_COOKIE_SECURE", value)

    assert auth.secure_cookie_setting() is expected
