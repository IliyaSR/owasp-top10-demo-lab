"""
Seed script: populates the database with two test users for manual
testing and for the SQL Injection / XSS / CSRF demonstrations.

Run with:
    flask --app app init-db
    python -m app.seed

Passwords are hashed with werkzeug even in the vulnerable branch -
weak password storage is not one of the three vulnerabilities this
thesis focuses on, so credential handling is done correctly in both
versions.
"""

from werkzeug.security import generate_password_hash

from app import create_app
from app.db import get_db

SEED_USERS = [
    ("alice", "password123", "alice@example.com"),
    ("bob", "password123", "bob@example.com"),
]


def seed() -> None:
    app = create_app()
    with app.app_context():
        db = get_db()
        for username, password, email in SEED_USERS:
            db.execute(
                "INSERT OR IGNORE INTO users (username, password_hash, email) "
                "VALUES (?, ?, ?)",
                (username, generate_password_hash(password, method="pbkdf2:sha256"), email),
            )
        db.commit()
        print(f"Seeded {len(SEED_USERS)} users.")


if __name__ == "__main__":
    seed()
