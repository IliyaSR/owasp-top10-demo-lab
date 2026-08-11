# OWASP Top 10 Demo Lab

> Master's thesis — Plovdiv University "Paisii Hilendarski",
> Information Security program.
> Topic: **Analysis and Protection of Web Applications Against OWASP Top 10 Attacks**

## ⚠️ Important — Lab use only

This repository contains an **intentionally vulnerable** web application
(`vulnerable` branch), built solely for educational and research purposes
as part of an academic thesis.

- The application is meant to run **locally only**, in an isolated lab
  environment (localhost).
- The vulnerabilities present (SQL Injection, Stored XSS, CSRF) are
  **not accidental bugs** — they are deliberately and documentedly
  introduced in order to be demonstrated, analyzed, and subsequently
  fixed.
- **Do not deploy this application to a publicly accessible server**,
  and do not use the techniques contained here against systems you do
  not own or do not have explicit permission to test.

## Project goal

Develop a single, connected experimental web application in two
versions — vulnerable and secure — through which three specific OWASP
Top 10 attacks are demonstrated, their impact analyzed, and matching
defense mechanisms implemented and tested.

| Feature | Vulnerability | Defense |
|---|---|---|
| Login | SQL Injection | Prepared statements / parameterized queries |
| Comments | Stored XSS | Output encoding, CSP |
| Profile update | CSRF | CSRF tokens (Flask-WTF) |

## Repository structure

- `main` — base project structure, documentation, database schema
- `vulnerable` — intentionally vulnerable version of the three features
- `secure` — hardened version of the same features

See [`docs/architecture.md`](docs/architecture.md) for the full
architecture documentation and rationale behind the technology choices.

## Tech stack

Python 3 · Flask · Flask-WTF · SQLite · OWASP ZAP (for automated
security testing)

## Running locally

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m app.seed          # load seed data
flask --app app run --debug
```

## Author

Master's thesis, supervised by [supervisor name],
Plovdiv University "Paisii Hilendarski", 2026.
