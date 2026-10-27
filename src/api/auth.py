"""
CloudSentinel authentication security primitives.

Credentials and the Flask signing key must be supplied through
environment variables. No default production credentials are provided.
"""

import hmac
import os
import secrets

from flask import current_app, jsonify, redirect, request, session, url_for
from werkzeug.security import check_password_hash


AUTH_USERNAME_ENV = "CLOUDSENTINEL_USERNAME"
AUTH_PASSWORD_HASH_ENV = "CLOUDSENTINEL_PASSWORD_HASH"
AUTH_SECRET_KEY_ENV = "CLOUDSENTINEL_SECRET_KEY"

SESSION_USER_KEY = "cloudsentinel_user"
CSRF_SESSION_KEY = "cloudsentinel_csrf_token"
CSRF_HEADER_NAME = "X-CSRF-Token"


def credentials_configured():
    """Return whether both login credential settings are present."""
    return bool(
        os.environ.get(AUTH_USERNAME_ENV)
        and os.environ.get(AUTH_PASSWORD_HASH_ENV)
    )


def verify_credentials(username, password):
    """Verify credentials against the configured password hash."""
    expected_username = os.environ.get(AUTH_USERNAME_ENV)
    password_hash = os.environ.get(AUTH_PASSWORD_HASH_ENV)

    if not expected_username or not password_hash:
        return False

    if not isinstance(username, str) or not isinstance(password, str):
        return False

    if not hmac.compare_digest(username, expected_username):
        return False

    try:
        return check_password_hash(password_hash, password)
    except (TypeError, ValueError):
        return False


def is_authenticated():
    """Check whether the current session has an authenticated user."""
    username = session.get(SESSION_USER_KEY)
    configured_username = os.environ.get(AUTH_USERNAME_ENV)

    return bool(
        username
        and configured_username
        and hmac.compare_digest(username, configured_username)
    )


def establish_login(username):
    """Start a fresh authenticated session."""
    session.clear()
    session[SESSION_USER_KEY] = username
    session[CSRF_SESSION_KEY] = secrets.token_urlsafe(32)


def clear_login():
    """Clear authentication and CSRF data from the session."""
    session.clear()


def get_csrf_token():
    """Return the current session token, creating one when necessary."""
    token = session.get(CSRF_SESSION_KEY)

    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token

    return token


def validate_csrf_token(token=None):
    """Validate a CSRF token using constant-time comparison."""
    expected = session.get(CSRF_SESSION_KEY)

    if token is None:
        token = request.headers.get(CSRF_HEADER_NAME)

    if not isinstance(expected, str) or not isinstance(token, str):
        return False

    return hmac.compare_digest(expected, token)


def authentication_required_response():
    """Return a consistent API response or redirect a browser to login."""
    if request.path.startswith("/api/") or request.path.startswith("/ioc-investigation"):
        return jsonify({
            "status": "error",
            "message": "Authentication required.",
        }), 401

    return redirect(url_for("auth.login", next=request.path))


def csrf_rejected_response():
    """Return a generic CSRF validation error without leaking token data."""
    return jsonify({
        "status": "error",
        "message": "CSRF validation failed.",
    }), 400


def secret_key_from_environment():
    """Read the application signing key without inventing a fallback."""
    return os.environ.get(AUTH_SECRET_KEY_ENV)


def authentication_configuration_ready():
    """Return whether signing key and login credentials are configured."""
    secret_key = secret_key_from_environment()
    return bool(
        isinstance(secret_key, str)
        and len(secret_key) >= 32
        and credentials_configured()
    )


def secure_cookie_setting():
    """Read an explicit deployment setting for HTTPS-only session cookies."""
    value = os.environ.get("CLOUDSENTINEL_COOKIE_SECURE", "false")
    return value.strip().lower() in {"1", "true", "yes", "on"}


def csrf_enabled():
    """Allow tests to opt out explicitly; enabled by default."""
    return current_app.config.get("CLOUDSENTINEL_CSRF_ENABLED", True)
