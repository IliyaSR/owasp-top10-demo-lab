"""
Standalone "attacker server" for the CSRF demonstration - LAB USE ONLY.

This is a tiny, completely separate HTTP server (not part of the
Flask lab app in any way) that serves attacker_site/index.html. Its
entire purpose is to simulate a real attacker-controlled website
living at its own address, distinct from the lab app - so the CSRF
demonstration involves genuinely separate origins (two different
ports on localhost), not just a local file opened directly.

--------------------------------------------------------------------
HOW TO RUN THE FULL DEMONSTRATION
--------------------------------------------------------------------
You will need TWO servers running at the same time, in two separate
terminals:

  Terminal 1 (the lab app - the "victim" site):
      export FLASK_APP=app
      flask run
      -> serves the real app at http://127.0.0.1:5000

  Terminal 2 (this script - the "attacker" site):
      python docs/testing/attacker_server.py
      -> serves the fake prize page at http://127.0.0.1:8080

Then, in your browser:
  1. Go to http://127.0.0.1:5000/login and log in as the VICTIM
     (e.g. bob / password123). Open /profile in that same tab and
     confirm the current email address.
  2. Open a NEW TAB (same browser, same session) and navigate to:
         http://127.0.0.1:8080
     This is the "attacker's" page - notice its address bar clearly
     shows a different origin (port 8080) than the lab app (5000).
  3. The page displays a fake prize/giveaway message. The instant it
     finishes loading, it silently submits the hidden form in the
     background - no click on anything required.
  4. Switch back to the first tab and reload /profile on the lab app
     (port 5000). The email has changed, even though you never
     submitted anything on the lab app's own /profile page.
"""

import http.server
import os
import socketserver

PORT = 8080
DIRECTORY = os.path.join(os.path.dirname(__file__), "attacker_site")


class AttackerSiteHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)


if __name__ == "__main__":
    with socketserver.TCPServer(("127.0.0.1", PORT), AttackerSiteHandler) as httpd:
        print(f"[attacker-server] Simulated attacker site running at http://127.0.0.1:{PORT}")
        print("[attacker-server] This is NOT part of the lab app - a separate origin, on purpose.")
        httpd.serve_forever()
