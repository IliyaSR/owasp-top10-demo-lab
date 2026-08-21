# TC-IDOR-01: Insecure Direct Object Reference — User Profile Lookup

## Identifier
TC-IDOR-01

## Objective
Verify whether the user profile lookup route (`/users/<id>`) properly
restricts access to only the requesting user's own data, or whether
any authenticated user can view arbitrary other users' profile
information by directly manipulating the `id` value in the URL.

## Preconditions
- Application running locally, database initialized and seeded.
- Two distinct seeded users available: `alice` (id=1) and `bob`
  (id=2).
- Tester logged in as `bob`, with no legitimate access to `alice`'s
  account.

## Test Environment
- Branch under test: `vulnerable` (baseline) and `secure` (post-fix
  verification)
- Tool: browser (manual), curl (scripted verification)

---

## Sub-scenario A — Baseline: viewing one's own profile (control test)

**Input:** Logged in as `bob`, navigate to `/users/2` (bob's own id).

**Expected result:** Profile page displays bob's own username and
email.

**Actual result (vulnerable branch):** As expected.

**Actual result (secure branch):** As expected — no regression.

---

## Sub-scenario B — Accessing another user's profile by id manipulation

**Input:** Logged in as `bob`, navigate to `/users/1` (alice's id,
not bob's).

**Expected result (vulnerable branch):** The route's only
authorization check is "is someone logged in at all" — it never
verifies that the requested `user_id` matches the session's own
`user_id`. The database query
(`SELECT id, username, email, created_at FROM users WHERE id = ?`)
is itself safe (parameterized) but is executed for **any** id an
authenticated user requests, without restriction.

**Actual result (vulnerable branch):** **Confirmed.** Bob
successfully viewed alice's full profile, including her real email
address (`alice@example.com`), despite having no legitimate
relationship to her account. The page additionally displayed a
lab-added warning banner noting the access was to a non-owned
profile, for demonstration clarity — this banner is a diagnostic aid
for this thesis, not a real application feature.

**Actual result (secure branch):** Request returns **HTTP 403
Forbidden**. The added check
(`if user_id != session["user_id"]: abort(403)`) rejects the request
before any database query for the target user is even executed.

---

## Sub-scenario C — Enumeration implications (methodology note)

**Observation (vulnerable branch):** Because `user_id` is a small,
sequential integer (auto-incremented by SQLite), an attacker does not
need to guess or discover valid ids through any sophisticated means —
simply iterating `/users/1`, `/users/2`, `/users/3`, ... is sufficient
to enumerate and harvest every registered user's profile data,
without needing SQL Injection, XSS, or any other separate
vulnerability.

**Actual result (secure branch):** The same sequential-id
enumeration attempt now returns 403 for every id other than the
requester's own, regardless of how many ids are tried.

**Conclusion:** This sub-scenario highlights that IDOR vulnerabilities
are often trivially exploitable at scale — no injection payload
crafting or social engineering is required, only systematic id
iteration — which is part of why Broken Access Control (the OWASP
Top 10 category this vulnerability belongs to) affects such a large
proportion of real-world applications in practice.

---

## Overall Conclusion

The `vulnerable` branch's `/users/<id>` route is exploitable via
IDOR: the server correctly authenticates *who* is making the request
(via the session cookie) but never authorizes *which* specific
user's data that requester is permitted to access, allowing any
authenticated user to enumerate and read every other user's profile
information.

The `secure` branch's fix adds an explicit authorization check
comparing the requested `user_id` against `session["user_id"]`,
rejecting mismatched requests with 403 Forbidden. This is the
general pattern for correctly fixing IDOR: authentication alone
(confirming *who* is asking) is never sufficient — a separate,
explicit authorization check (confirming *what* that specific
identity may access) is required for every object reference derived
from user-controllable input.
