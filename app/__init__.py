"""
Flask application factory.

This file is intentionally kept simple and identical between the
`vulnerable` and `secure` branches - all the interesting differences
live inside app/routes/*.py, so that a `git diff vulnerable secure`
shows exactly and only the security-relevant changes.
"""

from __future__ import annotations

import os
from typing import Optional

from flask import Flask


def create_app(test_config: Optional[dict] = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)

    app.config.from_mapping(
        SECRET_KEY="dev-secret-key-change-me",
        DATABASE=os.path.join(app.instance_path, "lab.sqlite"),
    )

    if test_config is not None:
        app.config.update(test_config)

    os.makedirs(app.instance_path, exist_ok=True)

    from . import db
    db.init_app(app)

    from .routes.auth import auth_bp
    app.register_blueprint(auth_bp)

    from .routes.comments import comments_bp
    app.register_blueprint(comments_bp)

    from .routes.profile import profile_bp
    app.register_blueprint(profile_bp)

    @app.route("/")
    def index():
        from flask import session, redirect, url_for
        if "user_id" in session:
            return redirect(url_for("auth.dashboard"))
        return redirect(url_for("auth.login"))

    return app
