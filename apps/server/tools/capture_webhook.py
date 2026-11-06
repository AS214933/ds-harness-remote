#!/usr/bin/env python3
"""Capture the real webhook payload shape from a live Logto.

Builds a webhook pointing at a local receiver, triggers User.Deleted and
User.SuspensionStatus.Updated, and prints the exact bodies. This settles the
payload shape by observation instead of by reading docs that may be stale.
"""
import base64
import http.server
import json
import socketserver
import subprocess
import threading
import urllib.error
import urllib.parse
import urllib.request

BASE = "http://localhost:3001"
RESOURCE = "https://default.logto.app/api"
CID = "cpu562vas8h3t2yzaqlxo"
CSEC = "oCorhvnR1546Rp1jIN6O8zj9zCiPYu4h"
SIGNING_KEY = "capture-signing-key"
RECEIVER_PORT = 8899
RECEIVER_HOST = "172.28.167.140"

PG = ["psql", "-h", "127.0.0.1", "-U", "postgres", "-d", "logto", "-tAq"]
captured: list[bytes] = []


def sql(q):
    env = {"PGPASSWORD": "logto_lab_pw", "PATH": "/usr/bin:/bin"}
    p = subprocess.run(PG + ["-c", q], capture_output=True, text=True, env=env)
    return (p.stdout or p.stderr).strip()


def req(method, path, *, body=None, headers=None, form=None):
    hdrs = dict(headers or {})
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        hdrs["Content-Type"] = "application/json"
    r = urllib.request.Request(BASE + path, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(r, timeout=25) as resp:
            raw = resp.read().decode() or ""
            return resp.status, (json.loads(raw) if raw.strip() else None)
    except urllib.error.HTTPError as e:
        raw = e.read().decode() or ""
        try:
            return e.code, (json.loads(raw) if raw.strip() else None)
        except Exception:
            return e.code, raw


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("content-length", 0))
        body = self.rfile.read(length)
        captured.append(body)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def log_message(self, *args):
        pass


def main():
    basic = base64.b64encode(f"{CID}:{CSEC}".encode()).decode()
    st, tok = req("POST", "/oidc/token", headers={"Authorization": "Basic " + basic},
                  form={"grant_type": "client_credentials",
                        "resource": RESOURCE, "scope": "all"})
    if st != 200:
        raise SystemExit(f"token {st} {tok}")
    auth = {"Authorization": "Bearer " + tok["access_token"]}

    # Local receiver. Logto requires publicly reachable HTTPS for real use, but
    # for a lab capture on the same host http://127.0.0.1 is accepted.
    server = socketserver.TCPServer(("0.0.0.0", RECEIVER_PORT), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://{RECEIVER_HOST}:{RECEIVER_PORT}/hook"
    print(f"receiver on {url}")

    # Clean up any previous capture webhook.
    st, hooks = req("GET", "/api/hooks", headers=auth)
    for hook in hooks if isinstance(hooks, list) else []:
        if hook.get("name") == "payload-capture":
            req("DELETE", f"/api/hooks/{hook['id']}", headers=auth)

    st, hook = req("POST", "/api/hooks", headers=auth, body={
        "name": "payload-capture",
        "events": ["User.Deleted", "User.SuspensionStatus.Updated"],
        "config": {"url": url, "retries": 0},
        "signingKey": SIGNING_KEY,
    })
    print(f"create hook -> {st}")
    if st not in (200, 201):
        print(json.dumps(hook)[:400])
        server.shutdown()
        return 1

    # Create a throwaway user, then suspend and delete it.
    st, user = req("POST", "/api/users", headers=auth,
                   body={"primaryEmail": "capture-me@example.com", "name": "capture"})
    if st not in (200, 201):
        st2, users = req("GET", "/api/users?" + urllib.parse.urlencode(
            {"search.primaryEmail": "capture-me@example.com", "mode.primaryEmail": "exact"}),
            headers=auth)
        user = users[0]
    uid = user["id"]
    print(f"user {uid}")

    req("PATCH", f"/api/users/{uid}/is-suspended", headers=auth, body={"isSuspended": True})
    req("DELETE", f"/api/users/{uid}", headers=auth)

    import time
    for _ in range(40):
        if len(captured) >= 2:
            break
        time.sleep(0.25)

    print(f"\ncaptured {len(captured)} payload(s)")
    for i, raw in enumerate(captured):
        print(f"\n--- payload {i + 1} ---")
        try:
            print(json.dumps(json.loads(raw), indent=2)[:1500])
        except Exception:
            print(raw[:400])

    req("DELETE", f"/api/hooks/{hook['id']}", headers=auth)
    server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
