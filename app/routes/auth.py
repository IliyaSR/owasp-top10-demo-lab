"""
Authentication routes - VULNERABLE VERSION.

This module intentionally contains a classic SQL Injection
vulnerability in the login query, for demonstration purposes as part
of a university thesis. Registration itself is NOT vulnerable (it
uses parameterized queries) - the injection is scoped narrowly to the
login flow, so the experiment isolates one clear, well-understood
vulnerability rather than scattering bugs everywhere.

--------------------------------------------------------------------
WHY IS THIS VULNERABLE?
--------------------------------------------------------------------
The user-lookup query is built by directly interpolating (f-string)
the raw, unsanitized `username` form field into the SQL statement:

    query = f"SELECT * FROM users WHERE username = '{username}'"

The password itself is NOT part of the SQL query - it is verified
separately in Python via `check_password_hash()`, exactly as a
correctly-written app would do. This is a deliberate design choice:
it keeps password hashing correct in BOTH the vulnerable and secure
branches (the thesis is not about weak password storage), while
still leaving a genuine, exploitable SQL Injection point in the
lookup query.

Because `username` becomes part of the SQL statement's *text* rather
than being treated as *data*, this still enables real attacks:

1. Comment-based existence/row disclosure:
     ' OR '1'='1' --
   returns the first row in the `users` table (whoever that may be),
   which an attacker can use to enumerate valid usernames.

2. UNION-based full authentication bypass:
     nonexistent' UNION SELECT 1, 'attacker', '<hash of "attacker-password">', 'x@x.com', NULL --
   The attacker pre-computes a password hash for a password they
   know (offline, using the same hashing function), embeds it in a
   UNION SELECT, and the query returns a synthetic "user" row whose
   password_hash the attacker controls. `check_password_hash()` then
   succeeds, because - from the application's point of view - the
   hash and the submitted password legitimately match. This is a
   complete authentication bypass with no credential guessing
   required, and it is the primary payload used in the documented
   test scenario.

See docs/testing/TC-SQL-01.md for the full documented test scenario
and payloads (created in a later step).
"""

from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from app.db import get_db

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        email = request.form["email"]
        db = get_db()

        error = None
        if not username or not password or not email:
            error = "All fields are required."

        if error is None:
            try:
                # Registration uses a parameterized query even in the
                # vulnerable branch - this is intentional, see module
                # docstring above.
                db.execute(
                    "INSERT INTO users (username, password_hash, email) "
                    "VALUES (?, ?, ?)",
                    (username, generate_password_hash(password, method="pbkdf2:sha256"), email),
                )
                db.commit()
            except db.IntegrityError:
                error = f"User '{username}' is already registered."
            else:
                flash("Registration successful. Please log in.")
                return redirect(url_for("auth.login"))

        flash(error)

    return render_template("auth/register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        db = get_db()

        # --------------------------------------------------------------
        # VULNERABLE QUERY - DO NOT USE THIS PATTERN IN REAL CODE.
        #
        # `username` is concatenated directly into the SQL string via
        # an f-string, instead of being passed as a bound parameter.
        # This is the exact anti-pattern that enables SQL Injection.
        # The password is deliberately NOT part of this query - see
        # the module docstring for why, and for the UNION-based
        # bypass this enables.
        # --------------------------------------------------------------
        query = f"SELECT * FROM users WHERE username = '{username}'"
        cursor = db.execute(query)
        user = cursor.fetchone()

        # Password verification itself is done correctly (hashed,
        # constant-time comparison via werkzeug). The vulnerability is
        # entirely in how `user` was looked up above.
        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Incorrect username or password.")
        else:
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("auth.dashboard"))

    return render_template("auth/login.html")


@auth_bp.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))
    return render_template("auth/dashboard.html", username=session.get("username"))


@auth_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
