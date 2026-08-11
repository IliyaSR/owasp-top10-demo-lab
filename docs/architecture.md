# Architecture of the Experimental Web Application

## 1. Project structure

```
secweb-thesis/
├── app/
│   ├── __init__.py        # Flask app factory
│   ├── db.py               # DB connection, helper functions
│   ├── schema.sql          # Database schema
│   ├── seed.py              # Seed/test data
│   ├── routes/
│   │   ├── auth.py          # login / logout / register (-> SQL Injection)
│   │   ├── comments.py      # post/display comments (-> XSS)
│   │   └── profile.py       # profile data update (-> CSRF)
│   ├── templates/           # Jinja2 templates
│   └── static/               # CSS / JS
├── tests/                     # Manual and automated test scripts
├── docs/                      # Architecture docs, diagrams, ZAP reports
├── requirements.txt
└── schema.sql
```

## 2. Git branch strategy

The repository uses two main branches:

- **`vulnerable`** — contains the intentionally vulnerable variants of
  the three features (login, comments, profile).
- **`secure`** — a clone of `vulnerable`, in which ONLY the vulnerable
  functions are replaced with their hardened equivalents. Everything
  else (templates, styling, DB schema, unrelated logic) stays
  identical, so that the before/after comparison is valid.

`git diff vulnerable secure -- app/routes/` produces an exact,
documented list of changes — used directly as material in Chapter 4.

## 3. Confirmed technology stack

| Layer | Technology | Rationale |
|---|---|---|
| Backend | Python 3 + Flask | Lightweight, well documented, explicit route logic without hidden "magic" |
| CSRF protection | Flask-WTF | Standard, widely recognized library for token generation/validation |
| Database | SQLite | File-based DB, zero configuration, sufficient for a lab-scale project |
| Frontend | HTML/CSS/JS (no framework) | Keeps focus on the security logic, not UI complexity |
| Security scanning | OWASP ZAP | Standard tool for automated testing in an academic context |

## 4. STRIDE mapping of the three threats (summary for Chapter 3)

| Feature | Vulnerability | STRIDE category | Rationale |
|---|---|---|---|
| Login (`auth.py`) | SQL Injection | Tampering, Elevation of Privilege | Manipulating the WHERE clause to bypass authentication |
| Comments (`comments.py`) | Stored XSS | Tampering, Information Disclosure | An injected script is stored and executed in other users' browsers, potentially stealing session data |
| Profile (`profile.py`) | CSRF | Spoofing of an action | A request is sent without the authenticated user's knowledge, riding on an existing session |

## 5. Authentication model (applies to both versions)

- Passwords: `werkzeug.security.generate_password_hash` /
  `check_password_hash` (bcrypt-based). This is **not** part of the
  demonstrated vulnerabilities — passwords are handled correctly in
  both versions, so the focus stays on the three selected attacks.
- Sessions: Flask `session` (signed cookie), standard configuration.
  The vulnerable/secure difference is only in the CSRF protection of
  sensitive operations, not in the session mechanism itself.
