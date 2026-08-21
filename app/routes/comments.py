"""
Comments routes - SECURE VERSION (Stored + Reflected XSS).

--------------------------------------------------------------------
WHY IS THIS SECURE?
--------------------------------------------------------------------
Comment content is now rendered as a plain Jinja2 variable, with no
`| safe` filter, in app/templates/auth/dashboard.html:

    {{ comment.content }}

Jinja2's default auto-escaping is therefore active for this value
(converting `<` to `&lt;`, etc.), so a comment containing a <script>
tag is rendered as literal, inert text rather than being parsed and
executed as HTML/JS. This directly fixes the Stored XSS vulnerability
from the `vulnerable` branch, where the same value was rendered with
`| safe`, disabling that protection.

The reflected variant (`search_comments()` below) is fixed the same
way - see its docstring for details.

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


@comments_bp.route("/comments/search")
def search_comments():
    """
    SECURE: Reflected XSS fix.

    Unlike add_comment()/get_comments() above (Stored XSS - the
    payload would be saved in the database and affect every future
    visitor), the `vulnerable` branch's version of this route
    demonstrated the OTHER classic XSS variant: the `q` query
    parameter echoed straight back into the page, unescaped, in the
    SAME response, never persisted anywhere.

    Here, `query` is rendered as a plain Jinja2 variable, with no
    `| safe` filter, in app/templates/auth/search_results.html:

        {{ query }}

    Jinja2's default auto-escaping is therefore active, so a `q`
    value like `<script>...</script>` is rendered as literal text
    instead of being parsed and executed by the browser - a request
    such as:

        http://127.0.0.1:5000/comments/search?q=<script>...</script>

    no longer executes anything in the victim's browser. This
    directly fixes the reflected XSS from the `vulnerable` branch.

    See docs/testing/TC-XSS-02.md for the vulnerable-branch test
    scenario and payloads this fix defeats.
    """
    query = request.args.get("q", "")

    results = []
    if query:
        db = get_db()
        # The search itself is done safely (parameterized LIKE query) -
        # the vulnerability is purely in how `query` is echoed back
        # into the page heading below, not in how it is used here.
        results = db.execute(
            "SELECT comments.id, comments.content, comments.created_at, "
            "users.username FROM comments "
            "JOIN users ON comments.user_id = users.id "
            "WHERE comments.content LIKE ? "
            "ORDER BY comments.created_at DESC",
            (f"%{query}%",),
        ).fetchall()

    # `query` is passed to the template and rendered with `| safe`
    # there (see search_results.html) - that is the actual injection
    # point for this vulnerability.
    return render_template("auth/search_results.html", query=query, results=results)


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
