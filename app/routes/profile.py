"""
Profile routes - VULNERABLE VERSION (CSRF).

--------------------------------------------------------------------
WHY IS THIS VULNERABLE?
--------------------------------------------------------------------
The email-change form below submits a plain POST request with no
CSRF token anywhere - neither a hidden form field nor any other
anti-CSRF mechanism. The route that handles it, update_email(),
authenticates the request using ONLY the session cookie:

    if "user_id" not in session:
        return redirect(url_for("auth.login"))

This is the exact anti-pattern that enables CSRF. Browsers
automatically attach cookies to requests based on the TARGET domain,
regardless of which site the request originated from. So if a logged
-in victim visits a completely unrelated, attacker-controlled page
that contains a hidden auto-submitting form pointed at this app's
/profile/update endpoint, the browser will still send the victim's
valid session cookie along with it. From the server's point of view,
the request looks exactly like a legitimate one made by the victim -
because, technically, the victim's own authenticated browser sent it.

Flask does NOT provide CSRF protection automatically (unlike some
other frameworks) - it must be explicitly added, typically via
Flask-WTF's CSRFProtect extension. This app deliberately never
initializes it, in either app/__init__.py or here.

--------------------------------------------------------------------
DEMONSTRATION
--------------------------------------------------------------------
See docs/testing/TC-CSRF-01.md for the full documented test scenario.
A minimal proof-of-concept malicious page is provided at
docs/testing/csrf_poc_email_change.html - opening that file directly
in a browser (as a local file, completely outside this Flask app)
while logged in here is enough to trigger the unwanted email change,
demonstrating that the attack works from a page the application never
served and has no control over.
"""

from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from app.db import get_db

profile_bp = Blueprint("profile", __name__)


@profile_bp.route("/profile")
def profile():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    db = get_db()
    user = db.execute(
        "SELECT id, username, email FROM users WHERE id = ?",
        (session["user_id"],),
    ).fetchone()
    return render_template("auth/profile.html", user=user)


@profile_bp.route("/profile/update", methods=["POST"])
def update_email():
    """
    VULNERABLE: no CSRF token is checked here. The only thing this
    route verifies is that SOME valid session cookie is present -
    it never confirms the request actually originated from this
    application's own /profile page.
    """
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    new_email = request.form.get("email", "").strip()
    if not new_email:
        flash("Email cannot be empty.")
        return redirect(url_for("profile.profile"))

    db = get_db()
    db.execute(
        "UPDATE users SET email = ? WHERE id = ?",
        (new_email, session["user_id"]),
    )
    db.commit()
    flash("Email updated successfully.")
    return redirect(url_for("profile.profile"))
