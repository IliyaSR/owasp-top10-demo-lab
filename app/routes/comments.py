"""
Comments routes - VULNERABLE VERSION (Stored XSS).

--------------------------------------------------------------------
WHY IS THIS VULNERABLE?
--------------------------------------------------------------------
User-submitted comment content is rendered back into the page using
Jinja2's `| safe` filter, which explicitly disables Jinja2's default
auto-escaping for that value:

    {{ comment.content | safe }}

Normally, Jinja2 auto-escapes all variables by default (converting
`<` to `&lt;`, etc.), which is itself a strong built-in XSS defense.
The `| safe` filter is a deliberate opt-out of that protection - it
tells Jinja2 "trust this string completely, render it as raw HTML".

Because comment content comes directly from user input and is stored
verbatim in the database, an attacker can submit a comment containing
a <script> tag. Every time ANY user (not just the attacker) later
views the comments page, that script executes in THEIR browser, in
THEIR authenticated session - this is what makes it "Stored" XSS,
as opposed to "Reflected" XSS (which only affects the single request
that carries the payload).

--------------------------------------------------------------------
DEMONSTRATION ENDPOINT: /debug/collector
--------------------------------------------------------------------
`collector()` below is NOT part of a normal application. It exists
only so the thesis experiment can demonstrate cookie exfiltration
without needing a real external attacker-controlled server - it
simply logs whatever it receives to the console, standing in for
"data arriving at the attacker's server". It must be removed (or at
minimum clearly marked and disabled) outside the lab environment.

See docs/testing/TC-XSS-01.md for the full documented test scenarios
and payloads (created in a later step).
"""

from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from app.db import get_db

comments_bp = Blueprint("comments", __name__)

# In-memory store for the lab-only "attacker collector" demo below.
# Deliberately simple (not persisted to the database) - this is a
# throwaway demonstration aid, not part of the application's real
# data model.
_collected_data = []


@comments_bp.route("/comments", methods=["POST"])
def add_comment():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    content = request.form.get("content", "").strip()
    if not content:
        flash("Comment cannot be empty.")
        return redirect(url_for("auth.dashboard"))

    db = get_db()
    # Storing the comment itself uses a parameterized query - the
    # vulnerability is NOT in how data is written to the database,
    # it is in how it is rendered back out (see comments.html).
    db.execute(
        "INSERT INTO comments (user_id, content) VALUES (?, ?)",
        (session["user_id"], content),
    )
    db.commit()
    return redirect(url_for("auth.dashboard"))


def get_comments():
    """Helper used by the dashboard route to fetch all comments with
    the posting user's username, most recent first."""
    db = get_db()
    return db.execute(
        "SELECT comments.id, comments.content, comments.created_at, "
        "users.username FROM comments "
        "JOIN users ON comments.user_id = users.id "
        "ORDER BY comments.created_at DESC"
    ).fetchall()


@comments_bp.route("/debug/collector")
def collector():
    """
    LAB-ONLY demonstration endpoint. Simulates an attacker-controlled
    server receiving exfiltrated data (e.g. a stolen session cookie)
    via a query parameter. Logs to the console; stores nothing.

    In a real attack, this would be a server the attacker owns,
    completely outside the victim's application - it is included
    here only so the exfiltration step can be demonstrated end-to-end
    within the isolated lab environment, without any external network
    calls leaving localhost.
    """
    stolen_data = request.args.get("data", "")
    print(f"[XSS-DEMO] Collector endpoint received: {stolen_data}")
    _collected_data.append(stolen_data)
    return "", 204


@comments_bp.route("/debug/collector-log")
def collector_log():
    """
    LAB-ONLY view of everything the simulated collector endpoint has
    received so far. In a real attack this would be private to the
    attacker (their own server's logs) - here it's just a plain page
    so you can visually confirm the exfiltration worked, for
    screenshots and documentation purposes.
    """
    return render_template("auth/capture_log.html", entries=_collected_data)
