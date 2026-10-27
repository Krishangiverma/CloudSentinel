"""Login and logout routes for CloudSentinel."""

from urllib.parse import urlsplit

from flask import (
    Blueprint,
    current_app,
    redirect,
    render_template,
    request,
    url_for,
)

from src.api.auth import (
    clear_login,
    credentials_configured,
    establish_login,
    get_csrf_token,
    validate_csrf_token,
    verify_credentials,
)


auth_bp = Blueprint("auth", __name__)


def _safe_local_destination(value):
    """Accept only relative paths on this application."""
    if not isinstance(value, str) or not value.startswith("/"):
        return None

    if value.startswith("//") or "\\" in value:
        return None

    parsed = urlsplit(value)

    if parsed.scheme or parsed.netloc:
        return None

    return value


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Render the login form and authenticate configured credentials."""
    error = None

    if request.method == "POST":
        submitted_token = request.form.get("csrf_token")

        if not validate_csrf_token(submitted_token):
            error = "Your session expired or the form was invalid. Please try again."
            current_app.logger.warning("Rejected login request with invalid CSRF token.")
            return render_template(
                "login.html",
                csrf_token=get_csrf_token(),
                error=error,
                credentials_ready=credentials_configured(),
            ), 400

        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if not credentials_configured():
            error = "Login is not configured. Contact the administrator."
            return render_template(
                "login.html",
                csrf_token=get_csrf_token(),
                error=error,
                credentials_ready=False,
            ), 503

        if not verify_credentials(username, password):
            error = "Invalid username or password."
            current_app.logger.warning("Rejected CloudSentinel login attempt.")
            return render_template(
                "login.html",
                csrf_token=get_csrf_token(),
                error=error,
                credentials_ready=True,
            ), 401

        establish_login(username)

        destination = _safe_local_destination(
            request.form.get("next", "")
        )

        return redirect(destination or url_for("dashboard"))

    return render_template(
        "login.html",
        csrf_token=get_csrf_token(),
        error=error,
        credentials_ready=credentials_configured(),
    )


@auth_bp.route("/logout", methods=["POST"])
def logout():
    """End the current session after validating its CSRF token."""
    if not validate_csrf_token(request.form.get("csrf_token")):
        return "CSRF validation failed.", 400

    clear_login()
    return redirect(url_for("auth.login"))
