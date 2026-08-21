# TC-SQL-01: SQL Injection — Login Authentication Bypass

## Identifier
TC-SQL-01

## Objective
Verify whether the login functionality (`/login`) is vulnerable to
SQL Injection via the `username` field, and whether an attacker can
achieve full authentication bypass without knowledge of any valid
user's real password.

## Preconditions
- Application running locally (`flask run`), database initialized
  and seeded (`flask init-db`, `python -m app.seed`).
- Seeded users: `alice` / `password123`, `bob` / `password123`.
- Tester has no prior knowledge of any user's real password.

## Test Environment
- Branch under test: `vulnerable` (baseline) and `secure` (post-fix
  verification)
- Tool: browser (manual), curl (scripted verification)

---

## Sub-scenario A — Baseline: normal login (control test)

**Input:** username=`alice`, password=`password123`

**Expected result:** Successful login, redirect to `/dashboard`,
page displays "Welcome, alice".

**Actual result (vulnerable branch):** As expected — successful
login.

**Actual result (secure branch):** As expected — successful login
(confirms the fix does not break normal functionality).

---

## Sub-scenario B — Comment-based injection (partial effect)

**Input:** username=`' OR '1'='1' --`, password=`anything`

**Expected result (vulnerable branch):** The injected `OR '1'='1'`
condition, combined with the trailing `--` comment, causes the
query to return the first row in the `users` table regardless of
the WHERE clause. However, because password verification is
performed separately in Python via `check_password_hash()` (not as
part of the SQL query), the login still fails unless the submitted
password happens to match that row's real password hash.

**Actual result (vulnerable branch):** Login fails with "Incorrect
username or password" — confirms the injection point exists and
alters the query's row-selection behavior, but does not by itself
grant a full bypass in this implementation.

**Actual result (secure branch):** Login fails identically — the
parameterized query treats the entire string `' OR '1'='1' --` as a
literal (and non-existent) username value, so no row is returned at
all.

**Conclusion:** This sub-scenario demonstrates that the presence of
an injection point does not automatically equal full compromise —
impact depends on how the rest of the authentication logic is
structured.

---

## Sub-scenario C — UNION-based full authentication bypass

**Preparation:** Attacker computes, offline, a valid password hash
for a password they choose:
**Input:**
- username: `nope' UNION SELECT 1, 'attacker', '<computed-hash>', 'a@a.com', NULL --`
- password: `hack123`

**Expected result (vulnerable branch):** The UNION SELECT causes the
query to return a synthetic row entirely controlled by the attacker,
including the `password_hash` column. Because `check_password_hash()`
then compares the submitted password against a hash the attacker
generated themselves, verification succeeds.

**Actual result (vulnerable branch):** **Confirmed.** Login succeeds,
session is established with `username="attacker"`, dashboard
displays "Welcome, attacker" — a fully synthetic identity with no
corresponding row ever written to the database.

**Actual result (secure branch):** Login fails with "Incorrect
username or password". The parameterized query
(`db.execute("SELECT * FROM users WHERE username = ?", (username,))`)
treats the entire UNION payload as a single literal string being
compared against the `username` column — no such username exists,
so the query returns zero rows and `user is None`.

**Conclusion:** SQL Injection via the login form is fully mitigated
on the `secure` branch by parameterizing the query. No functional
regression observed for legitimate logins.

---

## Sub-scenario D — Column-count enumeration (methodology note)

**Input (sequential):** username=`nope' ORDER BY 1 --`, then `ORDER
BY 2 --`, ... incrementing until an error is returned.

**Expected result:** SQLite returns a syntax/range error once N
exceeds the actual column count (5, per `schema.sql`), confirming
the schema shape to an attacker without any prior knowledge of the
source code.

**Actual result (vulnerable branch):** Confirmed — `ORDER BY 6 --`
produces an `OperationalError`, `ORDER BY 5 --` does not, correctly
revealing the 5-column structure used in Sub-scenario C.

**Actual result (secure branch):** N/A — the parameterized query
never allows attacker-supplied SQL syntax to be parsed at all, so
this enumeration technique has no effect (username is always treated
as literal data).

---

## Overall Conclusion

The `vulnerable` branch's login query, built via f-string
interpolation of the `username` field, is exploitable via UNION-based
SQL Injection, achieving complete authentication bypass with no
knowledge of any real user's password. Impact is limited to the
lookup query itself — password verification via
`check_password_hash()` remains correct in both branches, meaning
simpler injection payloads (Sub-scenario B) do not achieve full
bypass on their own; only the UNION technique, which lets the
attacker control the compared hash directly, succeeds.

The `secure` branch's fix — replacing string interpolation with a
parameterized query (`?` placeholder + bound tuple) — eliminates all
tested attack paths (B, C, D) while preserving normal login
functionality (A). No further SQL Injection surface was identified
in this route during testing.
