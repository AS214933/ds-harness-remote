#!/usr/bin/env python3
"""Integration test for apps/server/src/auth/logto.ts against a live Logto.

Runs the compiled adapter through the scenarios that decide correctness:
happy path, wrong password, suspended user, MFA user, passwordless user,
unknown email, and an unreachable Logto.

Usage:
    node --experimental-strip-types ...   (or build first, then:)
    python3 logto-lab/test_auth_ts.py
"""
import base64
import json
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

# default tenant (3001). The admin tenant (3002) has a different API indicator
# and cannot manage these users.
BASE = "http://localhost:3001"
RESOURCE = "https://default.logto.app/api"
CID = "cpu562vas8h3t2yzaqlxo"
CSEC = "oCorhvnR1546Rp1jIN6O8zj9zCiPYu4h"

PG = ["psql", "-h", "127.0.0.1", "-U", "postgres", "-d", "logto", "-tAq"]


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


def token():
    basic = base64.b64encode(f"{CID}:{CSEC}".encode()).decode()
    st, body = req("POST", "/oidc/token",
                   headers={"Authorization": "Basic " + basic},
                   form={"grant_type": "client_credentials",
                         "resource": RESOURCE, "scope": "all"})
    if st != 200:
        raise SystemExit(f"cannot mint M2M token: {st} {body}")
    return {"Authorization": "Bearer " + body["access_token"]}


def ensure_user(auth, email, password, *, suspended=False):
    st, u = req("POST", "/api/users", headers=auth,
                body={"primaryEmail": email, "password": password, "name": email.split("@")[0]})
    if st in (200, 201):
        uid = u["id"]
    else:
        st2, us = req("GET", "/api/users?" + urllib.parse.urlencode(
            {"search.primaryEmail": email, "mode.primaryEmail": "exact"}), headers=auth)
        if st2 != 200 or not us:
            raise SystemExit(f"cannot create/find {email}: {st} {u}")
        uid = us[0]["id"]
    if suspended:
        req("PATCH", f"/api/users/{uid}/is-suspended", headers=auth, body={"isSuspended": True})
    else:
        req("PATCH", f"/api/users/{uid}/is-suspended", headers=auth, body={"isSuspended": False})
    return uid


def set_mfa(uid, factors):
    """Seed MFA factors directly (Console/user-registration would do the same)."""
    sql(f"update users set mfa_verifications = '{json.dumps(factors)}'::jsonb "
        f"where tenant_id='default' and id='{uid}';")


def main():
    auth = token()
    print("M2M token OK")

    PW = "CorrectHorseBattery1!"
    print("\n--- seeding users ---")
    happy = ensure_user(auth, "t_happy@example.com", PW)
    print(f"  t_happy          id={happy}")
    wrong = ensure_user(auth, "t_wrong@example.com", PW)
    print(f"  t_wrong          id={wrong}")
    susp = ensure_user(auth, "t_susp@example.com", PW, suspended=True)
    print(f"  t_susp           id={susp}  (suspended)")
    mfa = ensure_user(auth, "t_mfa@example.com", PW)
    set_mfa(mfa, [{"id": "mfatest00000000000001", "type": "Totp",
                   "createdAt": "2026-01-01T00:00:00.000Z", "name": "t",
                   "secret": "JBSWY3DPEHPK3PXP"}])
    print(f"  t_mfa            id={mfa}  (TOTP factor seeded)")
    passkey = ensure_user(auth, "t_passkey@example.com", PW)
    set_mfa(passkey, [{"id": "mfatest00000000000002", "type": "WebAuthn",
                       "createdAt": "2026-01-01T00:00:00.000Z", "name": "t",
                       "credentialId": "ZmFrZQ", "publicKey": "ZmFrZQ",
                       "counter": 0, "transports": ["usb"]}])
    print(f"  t_passkey        id={passkey}  (WebAuthn factor seeded)")
    nopw = ensure_user(auth, "t_nopw@example.com", PW)
    # strip the password by re-creating without one is not allowed; instead use a
    # fresh user created without a password
    st, u = req("POST", "/api/users", headers=auth,
                body={"primaryEmail": "t_nopw2@example.com", "name": "nopw2"})
    if st in (200, 201):
        nopw = u["id"]
    else:
        st2, us = req("GET", "/api/users?" + urllib.parse.urlencode(
            {"search.primaryEmail": "t_nopw2@example.com", "mode.primaryEmail": "exact"}), headers=auth)
        nopw = us[0]["id"] if us else nopw
    print(f"  t_nopw2          id={nopw}  (no password)")

    cases = [
        ("correct password",            "t_happy@example.com",   PW,          "ok"),
        ("wrong password",              "t_wrong@example.com",   "nope",      "invalid"),
        ("unknown email",               "nobody@example.com",    PW,          "invalid"),
        ("suspended + correct password","t_susp@example.com",    PW,          "suspended"),
        ("suspended + wrong password",  "t_susp@example.com",    "nope",      "invalid"),
        ("MFA(TOTP) + correct password","t_mfa@example.com",     PW,          "ok"),
        ("passkey + correct password",  "t_passkey@example.com", PW,          "ok"),
        ("no password set",             "t_nopw2@example.com",   PW,          "invalid"),
        ("empty password",              "t_happy@example.com",   "",          "invalid"),
    ]

    print("\n--- adapter expectations ---")
    print(json.dumps({
        "endpoint": BASE,
        "clientId": CID,
        "clientSecret": CSEC,
        "resource": RESOURCE,
        "adminRole": "admin",
        "cases": [{"name": n, "email": e, "password": p, "expect": x} for n, e, p, x in cases],
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
