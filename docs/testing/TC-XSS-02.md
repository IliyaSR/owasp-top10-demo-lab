# TC-XSS-02: Reflected Cross-Site Scripting — Comment Search

## Identifier
TC-XSS-02

## Objective
Verify whether the comment search feature (`/comments/search`) is
vulnerable to Reflected XSS, and confirm that — unlike Stored XSS
(TC-XSS-01) — the injected payload does not persist and only affects
a victim who opens a specifically crafted URL.

## Preconditions
- Application running locally, database initialized and seeded.
- Tester logged in as a normal user.

## Test Environment
- Branch under test: `vulnerable` (baseline) and `secure` (post-fix
  verification)
- Tool: browser (manual)

---

## Sub-scenario A — Baseline: normal search (control test)

**Input:** `q=hello`

**Expected result:** Page displays "Search results for: hello" plus
any matching comments.

**Actual result (vulnerable branch):** As expected.

**Actual result (secure branch):** As expected — no regression.

---

## Sub-scenario B — Proof of concept via URL parameter

**Input URL:**
```
http://127.0.0.1:5000/comments/search?q=<script>alert('reflected')</script>
```

**Expected result (vulnerable branch):** The `q` parameter is
rendered into the page heading via `{{ query | safe }}`, disabling
auto-escaping. The browser executes the embedded script the moment
the page loads.

**Actual result (vulnerable branch):** **Confirmed.** An
`alert('reflected')` dialog fires immediately on page load.

**Actual result (secure branch):** The `| safe` filter was removed;
the payload is rendered as literal, inert text
(`<script>alert('reflected')</script>` visible as plain text on the
page). No dialog fires.

---

## Sub-scenario C — Confirming "Reflected" (non-persistent) behavior

**Step 1:** Submit the payload URL from Sub-scenario B; confirm the
dialog fires.

**Step 2:** Reload `/comments/search` **without** the `q` parameter
(i.e. navigate to `/comments/search` directly, or `/dashboard`).

**Step 3:** Query the database directly for any comment containing
the string `reflected`:
```python
import sqlite3
conn = sqlite3.connect('instance/lab.sqlite')
print(conn.execute("SELECT COUNT(*) FROM comments WHERE content LIKE '%reflected%'").fetchone())
```

**Expected result:** No alert fires on the plain reload (Step 2), and
zero rows are found in the database (Step 3) — confirming the
payload was never written anywhere and only affected the single
response to the crafted URL.

**Actual result (vulnerable branch):** **Confirmed.** Step 2 produced
no dialog; Step 3 returned `(0,)` — zero matching comments in the
database, despite the payload having executed successfully in
Sub-scenario B. This is the defining distinction from Stored XSS
(TC-XSS-01), where the payload persists and affects every subsequent
visitor.

**Conclusion:** This vulnerability requires an attacker to deliver a
crafted link to a victim (e.g. via chat, email, or a clickable link
disguised as something else) for each individual attack attempt — it
cannot passively affect visitors the way Stored XSS does, which is a
meaningfully different (generally lower, though still serious) risk
profile from an attacker-effort perspective.

---

## Overall Conclusion

The `vulnerable` branch's search feature is exploitable via Reflected
XSS through the unescaped `q` URL parameter. Unlike the Stored XSS
vulnerability in TC-XSS-01, this attack does not persist in the
database and requires the victim to open a specifically crafted URL
for each exploitation attempt, making it a distinct vulnerability
class with a different delivery mechanism and risk profile, despite
sharing the same root cause (missing output escaping via `| safe`).

The `secure` branch's fix — removing `| safe` from the search results
template — closes this attack path using the same underlying
mechanism (Jinja2 auto-escaping) as the Stored XSS fix, plus the same
CSP defense-in-depth header applied application-wide.
