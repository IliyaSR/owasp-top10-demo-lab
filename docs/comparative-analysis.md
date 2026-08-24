# Comparative Analysis: Vulnerable vs. Secure

This document consolidates the results from manual testing
(`docs/testing/TC-*.md`) and automated scanning
(`docs/testing/zap-report-vulnerable.html`,
`docs/testing/zap-report-secure.html`) into a single before/after
comparison, as material for Chapter 5 of the thesis.

## 1. Manual test results (per vulnerability)

| Test Case | Vulnerability | Vulnerable branch result | Secure branch result | Fix applied |
|---|---|---|---|---|
| TC-SQL-01 | SQL Injection (login) | UNION-based payload achieves full authentication bypass as a synthetic identity | Payload rejected — "Incorrect username or password"; no bypass possible | Parameterized query (`?` placeholder) replaces f-string interpolation |
| TC-XSS-01 | Stored XSS (comments) | `<script>` payload persists and executes for every visitor; demonstrated keylogging and credential-phishing impact | Payload rendered as literal, inert text; no script execution | Removed `\| safe` filter — Jinja2 auto-escaping restored |
| TC-XSS-02 | Reflected XSS (search) | `<script>` payload in URL executes on page load for whoever opens the link | Payload rendered as literal text; no execution | Removed `\| safe` filter — Jinja2 auto-escaping restored |
| TC-CSRF-01 | CSRF (profile email change) | Cross-origin forged request (from a genuinely separate attacker server) silently changes victim's email | Forged request rejected — HTTP 400, "The CSRF token is missing" | Flask-WTF `CSRFProtect` enabled; per-session token required on all state-changing forms |
| TC-IDOR-01 | IDOR (user profile lookup) | Any authenticated user can view any other user's profile by changing the URL's numeric id | Request for another user's id rejected — HTTP 403 Forbidden | Explicit authorization check (`user_id == session["user_id"]`) added |

## 2. Automated scan results (OWASP ZAP)

| Metric | Vulnerable branch | Secure branch | Change |
|---|---|---|---|
| Total alerts | 13 | 10 | −3 |
| SQL Injection | Present (2 instances: `/login`, `/register` — see note below) | **Absent** | Resolved |
| Cross Site Scripting (Reflected) | Present | **Absent** | Resolved |
| Cross Site Scripting (DOM Based) | Present | **Absent** | Resolved |
| Absence of Anti-CSRF Tokens | Present (5 instances) | **Absent** | Resolved |
| Content Security Policy Header Not Set | Present | Replaced by a minor "CSP: Failure to Define Directive with No Fallback" notice — confirms the CSP header is now present, with a small tuning suggestion | Improved |
| Missing Anti-clickjacking Header | Present (1) | Still present (4) | Not addressed — outside primary scope |
| Cookie without SameSite Attribute | Present | Still present | Not addressed — outside primary scope |
| Server Leaks Version Information | Present | Still present | Not addressed — outside primary scope |
| X-Content-Type-Options Header Missing | Present | Still present | Not addressed — outside primary scope |
| User Controllable HTML Element Attribute (Potential XSS) | Present | Still present | Low-confidence/informational; not confirmed exploitable in manual testing |
| GET for POST | Not flagged | Newly flagged | Informational; unrelated to the four target vulnerabilities |

**Note on the `/register` SQL Injection alert (vulnerable scan):**
manual verification (see TC-SQL-01.md and the `register()` function's
source code, which uses a parameterized `INSERT` statement in both
branches) indicates this is a **false positive** — `/register` was
never actually vulnerable. This is documented explicitly here as a
methodological finding: automated scanners can produce false
positives, which is precisely why the project's primary evidence
rests on the manually verified scenarios in the TC-*.md documents,
with ZAP serving as a secondary, independent check rather than the
sole source of truth (as stated in the original project brief).

## 3. Summary

All four primary vulnerabilities targeted by this thesis — SQL
Injection, Cross-Site Scripting (both Stored and Reflected), CSRF,
and IDOR — were confirmed exploitable on the `vulnerable` branch
through both manual testing and, for three of the four (SQLi, XSS,
CSRF; IDOR is not part of ZAP's default active scan rules), automated
scanning. All four were confirmed fixed on the `secure` branch
through the same manual test scenarios, with the automated scan
independently corroborating the resolution of SQLi, XSS, and CSRF
(IDOR's fix was verified manually only, per TC-IDOR-01.md, since it
is an application-specific authorization check rather than a generic
scanner-detectable pattern).

Several lower-severity, informational findings (missing
`X-Content-Type-Options`, missing `SameSite` cookie attribute, server
version disclosure, missing anti-clickjacking header) remain present
on both branches. These are noted as opportunities for further
hardening but fall outside the four vulnerabilities this thesis
specifically targets and demonstrates; they are discussed briefly in
Chapter 6 (Conclusions and Future Work) rather than treated as
primary findings.
