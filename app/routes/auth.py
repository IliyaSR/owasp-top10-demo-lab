"""
Authentication routes - SECURE VERSION.

This module fixes the SQL Injection vulnerability that exists in the
`vulnerable` branch's login query. Registration was never vulnerable
(it has always used parameterized queries) - only the login lookup
query has changed here.

--------------------------------------------------------------------
WHY IS THIS SECURE?
--------------------------------------------------------------------
The user-lookup query now uses a parameterized (bound) placeholder
instead of directly interpolating the raw `username` form field into
the SQL statement text:

    query = "SELECT * FROM users WHERE username = ?"
    cursor = db.execute(query, (username,))

The `?` is a placeholder that sqlite3 binds separately from the SQL
statement itself, so `username` is always treated as *data* to
compare against, never as *SQL syntax* to be parsed and executed.
Even if an attacker submits a value like:

    ' OR '1'='1' --

it is bound as a literal string and compared verbatim against the
`username` column - it can no longer break out of the string literal,
inject a UNION SELECT, or otherwise alter the query's structure. This
closes both attack paths documented on the `vulnerable` branch:
comment-based row disclosure (`' OR '1'='1' --`) and full
authentication bypass via a UNION SELECT with an attacker-controlled
password hash.

The password itself is NOT part of the SQL query - it is verified
separately in Python via `check_password_hash()`, exactly as before.
Password hashing correctness is unchanged between the vulnerable and
secure branches; the SQL Injection fix is scoped entirely to the
lookup query above.

See docs/testing/TC-SQL-01.md for the corresponding vulnerable-branch
test scenario and payloads this fix defeats.
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
        # SECURE QUERY - parameterized / bound placeholder.
        #
        # `username` is passed as a bound parameter (`?`) instead of
        # being concatenated into the SQL string. sqlite3 binds it as
        # data, not as SQL syntax, so it can never alter the query's
        # structure - this is what prevents the SQL Injection that
        # works against the `vulnerable` branch's f-string-built query.
        # The password is deliberately NOT part of this query - see
        # the module docstring for why.
        # --------------------------------------------------------------
        query = "SELECT * FROM users WHERE username = ?"
        cursor = db.execute(query, (username,))
        user = cursor.fetchone()

        # Password verification is done correctly (hashed,
        # constant-time comparison via werkzeug), exactly as on the
        # vulnerable branch - the only difference from that branch is
        # the parameterized lookup query above.
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

    from app.routes.comments import get_comments
    comments = get_comments()

    return render_template(
        "auth/dashboard.html", username=session.get("username"), comments=comments
    )


@auth_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
