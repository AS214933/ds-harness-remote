#!/usr/bin/env python3
"""Can the Logto Management API's `all` scope be narrowed?

Tries every mechanism that could plausibly carve the built-in resource into
finer permissions, and reports what Logto actually does. Measured, not assumed.
"""
import base64
import json
import subprocess
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
    st, body = req("POST", "/oidc/token", headers={"Authorization": "Basic " + basic},
                   form={"grant_type": "client_credentials",
                         "resource": RESOURCE, "scope": "all"})
    if st != 200:
        raise SystemExit(f"token {st} {body}")
    return {"Authorization": "Bearer " + body["access_token"]}


def main():
    auth = token()
    print("=== 1. 内置 resource 到底有几个 scope ===")
    print("  ", sql("select string_agg(id, ',') from scopes where tenant_id='default' "
                    "and resource_id='management-api';"))

    print("\n=== 2. 能否给内置 resource 新增一个更细的 scope ===")
    st, body = req("POST", "/api/resources/management-api/scopes", headers=auth,
                   body={"name": "users:verify", "description": "probe"})
    print(f"  POST /api/resources/management-api/scopes -> {st} {str(body)[:120]}")

    print("\n=== 3. 能否直接改内置 resource（比如改名/换 indicator） ===")
    st, body = req("PATCH", "/api/resources/management-api", headers=auth,
                   body={"name": "renamed"})
    print(f"  PATCH /api/resources/management-api -> {st} {str(body)[:120]}")

    print("\n=== 4. 请求一个不存在的 scope，会不会被降级而不是报错 ===")
    basic = base64.b64encode(f"{CID}:{CSEC}".encode()).decode()
    for scope in ["users:read", "password:verify", "all", ""]:
        st, body = req("POST", "/oidc/token", headers={"Authorization": "Basic " + basic},
                       form={"grant_type": "client_credentials",
                             "resource": RESOURCE, "scope": scope})
        got = body.get("scope") if isinstance(body, dict) else body
        print(f"  scope={scope!r:20s} -> {st}  granted={got!r}")

    print("\n=== 5. 自建一个新 API resource 能否替代 Management API ===")
    st, created = req("POST", "/api/resources", headers=auth,
                      body={"name": "dsh-self", "indicator": "https://dsh.local/api"})
    print(f"  POST /api/resources -> {st}")
    if st in (200, 201):
        print(f"    id={created['id']} indicator={created['indicator']}")
        print("    （能建，但它保护的是我们自己的 API，不是 Logto 的 Management API）")
        req("DELETE", f"/api/resources/{created['id']}", headers=auth)

    print("\n=== 6. 保留结论：用 all token 调一次写操作，确认权限没有变窄 ===")
    victim = sql("select id from users where tenant_id='default' "
                 "and primary_email='t_wrong@example.com' limit 1;")
    st, _ = req("PATCH", f"/api/users/{victim}/is-suspended", headers=auth,
                body={"isSuspended": False})
    print(f"  PATCH user is-suspended -> {st}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
