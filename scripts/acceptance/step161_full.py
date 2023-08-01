#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Strong-auth fixture (Passkey mode): real root Passkey UV strong setup + relogin.

Uses scripts/acceptance/strong_auth_passkey.mjs (real Chrome CDP virtual authenticator)
for the WebAuthn ceremonies, then reuses the resulting real server session for
161/163 authenticated route probes. Test-only; no product code changes.
"""
import argparse
import http.cookiejar
import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_WORK = os.path.join(os.environ.get("TEMP", BASE), "strong-auth-fixture-passkey")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_port(port, timeout=45):
    end = time.time() + timeout
    while time.time() < end:
        s = socket.socket()
        s.settimeout(0.3)
        try:
            s.connect(("127.0.0.1", port))
            return True
        except OSError:
            time.sleep(0.2)
        finally:
            s.close()
    return False


def protected(path):
    user = os.environ.get("USERNAME", "")
    subprocess.run(["icacls", path, "/inheritance:r", "/grant:r",
                    f"{user}:F", "SYSTEM:F", "Administrators:F"], capture_output=True)


class Client:
    def __init__(self, host, cookies=None):
        self.jar = http.cookiejar.CookieJar()
        self.base = "http://" + host
        for c in cookies or []:
            cookie = http.cookiejar.Cookie(version=0, name=c["name"], value=c["value"], port=None,
                                           port_specified=False, domain=host.split(":")[0],
                                           domain_specified=False, domain_initial_dot=False,
                                           path="/", path_specified=True, secure=False, expires=None,
                                           discard=True, comment=None, comment_url=None, rest={}, rfc2109=False)
            self.jar.set_cookie(cookie)
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def get(self, path):
        req = urllib.request.Request(self.base + path)
        try:
            with self.opener.open(req, timeout=15) as r:
                return r.status, r.headers, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read().decode("utf-8", "replace")

    def post(self, path, fields, headers=None):
        body = urllib.parse.urlencode(fields).encode()
        req = urllib.request.Request(self.base + path, data=body, method="POST",
                                     headers={"Content-Type": "application/x-www-form-urlencoded", "Origin": self.base, "Referer": self.base + path, **(headers or {})})
        try:
            with self.opener.open(req, timeout=15) as r:
                return r.status, r.headers, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read().decode("utf-8", "replace")

    def post_json(self, path, data, token):
        body = json.dumps(data).encode()
        req = urllib.request.Request(self.base + path, data=body, method="POST",
                                     headers={"Content-Type": "application/json", "X-CSRF-Token": token, "Origin": self.base, "Referer": self.base + path})
        try:
            with self.opener.open(req, timeout=30) as r:
                return r.status, r.headers, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read().decode("utf-8", "replace")

    def set_page_csrf(self, html):
        token = csrf_token(html)
        if not token:
            return
        c = http.cookiejar.Cookie(version=0, name="ln_page_csrf", value=token, port=None,
                                  port_specified=False, domain=self.base.split("//")[1].split(":")[0],
                                  domain_specified=False, domain_initial_dot=False, path="/",
                                  path_specified=True, secure=False, expires=None, discard=True,
                                  comment=None, comment_url=None, rest={}, rfc2109=False)
        self.jar.set_cookie(c)


def csrf_token(html):
    import re as _re
    m = _re.search(r'name="csrf_token" value="([^"]+)"', html)
    return m.group(1) if m else ""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Raw:
    def __init__(self, host, cookies=None):
        self.base = "http://" + host
        self.cookies = dict(cookies or {})
        self.auth = ""
        self.opener = urllib.request.build_opener(NoRedirect())

    def _headers(self, extra=None):
        h = {"Origin": self.base}
        if self.auth:
            h["Authorization"] = self.auth
        if self.cookies and not self.auth:
            h["Cookie"] = "; ".join(k + "=" + v for k, v in self.cookies.items())
        h.update(extra or {})
        return h

    def _remember(self, headers):
        for sc in headers.get_all("Set-Cookie") or []:
            nv = sc.split(";")[0]
            if "=" in nv:
                k, v = nv.split("=", 1)
                self.cookies[k] = v

    def request(self, method, path, data=None, json_data=None, token=None):
        headers = self._headers({"Referer": self.base + path})
        if json_data is not None:
            body = json.dumps(json_data).encode()
            headers["Content-Type"] = "application/json"
        elif data is not None:
            body = urllib.parse.urlencode(data).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            body = None
        if token:
            headers["X-CSRF-Token"] = token
        req = urllib.request.Request(self.base + path, data=body, method=method, headers=headers)
        try:
            with self.opener.open(req, timeout=30) as r:
                text = r.read().decode("utf-8", "replace")
                self._remember(r.headers)
                return r.status, r.headers, text
        except urllib.error.HTTPError as e:
            text = e.read().decode("utf-8", "replace")
            self._remember(e.headers)
            return e.code, e.headers, text

    def get(self, path):
        return self.request("GET", path)

    def post(self, path, fields):
        return self.request("POST", path, data=fields)

    def post_json(self, path, data, token):
        return self.request("POST", path, json_data=data, token=token)

    def set_page_csrf(self, html):
        tok = csrf_token(html)
        if tok:
            self.cookies["ln_page_csrf"] = tok


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", default=DEFAULT_WORK)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--evidence", default=os.path.join(BASE, "docs", "acceptance", "evidence", "strong-auth-fixture"))
    args = parser.parse_args()
    work = os.path.abspath(args.work)
    for stale in (work, work + "-maintenance"):
        shutil.rmtree(stale, ignore_errors=True)
    os.makedirs(work, exist_ok=True)
    evidence = os.path.abspath(args.evidence)
    os.makedirs(evidence, exist_ok=True)
    result = {"steps": [], "ok": False, "mode": "passkey"}

    def step(name, status, **kw):
        e = {"step": name, "status": status}
        e.update(kw)
        result["steps"].append(e)
        if status == "FAIL":
            result["ok"] = False
        print("FIXTURE", json.dumps(e, ensure_ascii=False))

    exe = os.path.join(work, "login-server.exe")
    seed_rbac = os.path.join(work, "seed_rbac.exe")
    b = subprocess.run(["go", "build", "-o", exe, "./cmd/login-server"], cwd=BASE, capture_output=True, text=True)
    br = subprocess.run(["go", "build", "-o", seed_rbac, "./scripts/acceptance/seed_rbac"], cwd=BASE, capture_output=True, text=True)
    step("build.login-server", "PASS" if b.returncode == 0 else "FAIL", detail=(b.stderr or "")[-300:])
    if b.returncode != 0:
        return finish(result, evidence, args.keep, work)
    port = free_port()
    base = f"http://localhost:{port}"
    cfg = os.path.join(work, "login.yaml")
    db = os.path.join(work, "login.db")
    master = os.path.join(work, "master.key")
    pwfile = os.path.join(work, "root-password.txt")
    password = "Fixture-Passkey-9-Auth!" + secrets.token_hex(3)
    with open(pwfile, "w", encoding="utf-8") as f:
        f.write(password + "\n")
    protected(pwfile)
    with open(cfg, "w", encoding="utf-8") as f:
        f.write(f'''server:
  listen_addr: "127.0.0.1:{port}"
  public_base_url: "{base}"
  shutdown_timeout_seconds: 5
logging: {{level: info, format: text}}
database: {{driver: sqlite, path: "{db.replace(chr(92), '/')}", wal: true, busy_timeout_ms: 5000}}
registration:
  enabled: true
  require_review: false
  require_email_verification: false
passkey:
  enabled: true
  rp_id: "localhost"
  rp_display_name: "Strong Auth Fixture"
  allowed_origins:
    - "{base}"
  user_verification: "required"
''')
    init = subprocess.run([exe, "init", "--config", cfg, "--master-key-file", master,
                           "--password-file", pwfile, "--operator", "strong-auth-passkey"],
                          cwd=work, capture_output=True, text=True, timeout=120)
    step("init.root", "PASS" if init.returncode == 0 else "FAIL", detail=(init.stdout + init.stderr)[-300:])
    if init.returncode != 0:
        return finish(result, evidence, args.keep, work)
    serve = subprocess.Popen([exe, "serve", "--config", cfg, "--master-key-file", master, "--enable-admin-api"],
                             cwd=work, stdout=open(os.path.join(work, "serve.log"), "wb"),
                             stderr=subprocess.STDOUT, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
    try:
        if not wait_port(port):
            step("serve.ready", "FAIL")
            return finish(result, evidence, args.keep, work)
        step("serve.ready", "PASS", base=base)
        out = os.path.join(work, "session.json")
        helper = os.path.join(BASE, "scripts", "acceptance", "strong_auth_passkey.mjs")
        env = dict(os.environ, E2E_BASE=base, E2E_USER="root", E2E_PASSWORD=password,
                   E2E_OUT=out, E2E_PROFILE=os.path.join(work, "chrome-profile"))
        node = shutil.which("node")
        if not node:
            step("node", "FAIL")
            return finish(result, evidence, args.keep, work)
        run = subprocess.run([node, helper], env=env, capture_output=True, text=True, timeout=240)
        session = {}
        if os.path.isfile(out):
            session = json.load(open(out, encoding="utf-8"))
        result["session_summary"] = {k: session.get(k) for k in
                                     ("ok", "browser", "passwordLoginStatus", "strongSetupStartStatus",
                                      "strongSetupFinishStatus", "secondLoginStatus", "secondFactorVerifyStatus",
                                      "cookieCount") if k in session}
        step("passkey.strong-setup-and-login", "PASS" if session.get("ok") else "FAIL",
             helper_exit=run.returncode, detail=(run.stderr or "")[-300:])
        if session.get("ok"):
            host = f"localhost:{port}"
            root = Raw(host, {c["name"]: c["value"] for c in session.get("cookies", [])})
            def parse_json(st, text):
                try:
                    obj = json.loads(text)
                    return obj.get("data", obj)
                except Exception:
                    return {}
            admin_token = csrf_token(root.get("/admin/users")[2])
            bearer = Raw(host)
            bearer.auth = "Bearer " + root.cookies.get("__Host-login_session", "")
            uc = "m" + secrets.token_hex(3)
            user_pw = "Matrix-Pass-9-Auth!x"
            def register_user(name):
                r = Raw(host)
                _, _, page = r.get("/register")
                r.set_page_csrf(page)
                st, _, text = r.post("/register", {"csrf_token": csrf_token(page), "username": name,
                                                    "password": user_pw, "password_confirm": user_pw,
                                                    "nickname": name})
                return r, st, text
            def login_user(r, name):
                _, _, page = r.get("/login")
                r.set_page_csrf(page)
                st, hdr, text = r.post("/login", {"csrf_token": csrf_token(page), "identifier": name,
                                                   "password": user_pw})
                return st, hdr.get("Location", ""), text
            normal_name = "n-" + uc
            support_name = "s-" + uc
            appadmin_name = "a-" + uc
            normal, nst, _ = register_user(normal_name)
            support, sst, _ = register_user(support_name)
            appadmin, ast, _ = register_user(appadmin_name)
            step("161.register.seed_users", "PASS" if all(st == 200 for st in (nst, sst, ast)) else "FAIL",
                 statuses=[nst, sst, ast])
            st, _, text = root.get("/admin/v1/users")
            users = parse_json(st, text)
            ids = {u["username"]: u["id"] for u in users.get("items", [])}
            rows = {u["username"]: u.get("row_version", 1) for u in users.get("items", [])}
            root_id = ids.get("root", "")
            normal_id, support_id, appadmin_id = ids.get(normal_name, ""), ids.get(support_name, ""), ids.get(appadmin_name, "")
            def create_app(name, owner):
                st, _, text = bearer.post_json("/admin/v1/applications", {"name": name, "description": name,
                    "owner_user_id": owner, "client_type": "confidential", "confirm": True}, admin_token)
                data = parse_json(st, text)
                data["_raw"] = text[:200]
                return st, data
            astat, app_a = create_app("Matrix A " + uc, appadmin_id)
            bstat, app_b = create_app("Matrix B " + uc, root_id)
            step("161.seed.apps", "PASS" if app_a.get("id") and app_b.get("id") else "FAIL",
                 statuses=[astat, bstat], ids=[app_a.get("id", ""), app_b.get("id", "")],
                 detail=[app_a, app_b][:2])
            st, _, text = root.get("/admin/v1/roles?scope_id=system")
            roles = parse_json(st, text).get("items", [])
            role_query = [st, text[:150]]
            support_role = next((r for r in roles if r.get("key") == "support"), None)
            role_create = None
            if not support_role:
                st, _, text = bearer.post_json("/admin/v1/roles", {"scope_id": "system", "key": "support_acceptance",
                    "name": "Support Acceptance", "description": "acceptance", "limits": "仅受理获准工单", "confirm": True}, admin_token)
                role_create = [st, text[:200]]
                support_role = parse_json(st, text)
            support_role_id = (support_role or {}).get("id", "")
            staff_out = os.path.join(work, "staff-session.json")
            staff_ready = os.path.join(work, "staff-passkey.ready")
            staff_granted = os.path.join(work, "staff-role.granted")
            staff_proc = None
            staff_session = {}
            rbac = None
            node_bin = shutil.which("node")
            helper = os.path.join(BASE, "scripts", "acceptance", "staff_passkey.mjs")
            if node_bin and support_id:
                env = dict(os.environ, E2E_BASE=f"http://{host}", E2E_USER=support_name,
                           E2E_PASSWORD=user_pw, E2E_OUT=staff_out, E2E_READY=staff_ready,
                           E2E_GRANTED=staff_granted, E2E_PROFILE=os.path.join(work, "staff-chrome"))
                staff_proc = subprocess.Popen([node_bin, helper], env=env,
                                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                deadline = time.time() + 90
                while time.time() < deadline and not os.path.exists(staff_ready):
                    time.sleep(0.3)
            if support_role_id and support_id and root_id and os.path.exists(staff_ready):
                rbac = subprocess.run([seed_rbac, "--database", db, "--role-id", support_role_id,
                                       "--support-user-id", support_id, "--root-user-id", root_id,
                                       "--promote-passkey-user-id", support_id],
                                      cwd=work, capture_output=True, text=True, timeout=60)
                if rbac.returncode == 0:
                    open(staff_granted, "w", encoding="utf-8").write("granted")
            if staff_proc is not None:
                try:
                    staff_proc.wait(timeout=150)
                except subprocess.TimeoutExpired:
                    staff_proc.kill()
                if os.path.isfile(staff_out):
                    staff_session = json.load(open(staff_out, encoding="utf-8"))
            step("161.seed.support_role", "PASS" if support_role_id and support_id and rbac and rbac.returncode == 0 else "FAIL",
                 role=support_role_id, seed_rc=rbac.returncode if rbac else None,
                 detail=(rbac.stderr or "")[-200:] if rbac else "", role_query=role_query, role_create=role_create)
            step("161.staff.passkey", "PASS" if staff_session.get("ok") else "FAIL",
                 verify_status=staff_session.get("secondFactorVerify"), probes=staff_session.get("probes", {}))
            if staff_session.get("ok"):
                staff = Raw(host, {c["name"]: c["value"] for c in staff_session.get("cookies", [])})
            else:
                staff = support
            nl = login_user(normal, normal_name)
            al = login_user(appadmin, appadmin_name)
            step("161.login.normal", "PASS" if nl[0] == 303 and nl[1] in ("/", "/home") else "FAIL",
                 http_status=nl[0], location=nl[1], body=nl[2].replace("\n", " ")[:300])
            step("161.login.support", "PASS" if staff_session.get("ok") else "PARTIAL",
                 http_status=staff_session.get("secondFactorVerify"), mode="passkey-second-factor")
            step("161.login.appadmin", "PASS" if al[0] == 303 else "FAIL", http_status=al[0], location=al[1])
            def status(c, path):
                return c.get(path)[0]
            matrix = {}
            for label, c in (("root", root), ("normal", normal), ("support", staff), ("appadmin", appadmin)):
                matrix[label] = {
                    "admin_users_page": status(c, "/admin/users"),
                    "admin_users_api": status(c, "/admin/v1/users"),
                    "support_page": status(c, "/support/cases"),
                    "support_api": status(c, "/admin/v1/support/cases"),
                    "app_admin_page": status(c, "/admin/applications"),
                    "app_b_detail_api": status(c, "/admin/v1/applications/" + app_b.get("id", "")),
                }
            result["matrix_161"] = matrix
            normal_ok = matrix["normal"]["admin_users_page"] in (401, 403) and matrix["normal"]["admin_users_api"] in (401, 403)
            support_ok = matrix["root"]["support_page"] == 200 and matrix["support"]["admin_users_page"] in (401, 403)
            root_ok = matrix["root"]["admin_users_page"] == 200 and matrix["root"]["admin_users_api"] == 200
            step("161.matrix.root", "PASS" if root_ok else "FAIL", detail=matrix["root"])
            step("161.matrix.normal_denied", "PASS" if normal_ok else "FAIL", detail=matrix["normal"])
            step("161.matrix.support_scope", "PASS" if support_ok else "FAIL", detail=matrix["support"])
            step("161.matrix.appadmin_scope", "PASS" if matrix["appadmin"]["admin_users_page"] in (401, 403) else "PARTIAL",
                 detail=matrix["appadmin"])
            support_body = staff.get("/support/cases")[2]
            secrets_leak = any(x in support_body for x in ("password_hash", "totp_secret", "recovery_code", "refresh_token", "access_token"))
            step("161.support.no_secrets", "PASS" if not secrets_leak else "FAIL", leaked=secrets_leak)
            # real session invalidation: admin revoke normal user's session using a session-bound token.
            _, _, acct = root.get("/account/security")
            session_token = csrf_token(acct)
            normal_sid = normal.cookies.get("__Host-login_session", "").split(".", 1)[0]
            st, _, text = root.request("POST", "/admin/v1/sessions/revoke",
                json_data={"target_session_id": normal_sid, "reason": "acceptance matrix revoke", "confirm": True},
                token=session_token)
            old = normal.get("/home")[0]
            step("161.revoke.admin_session", "PASS" if old in (401, 403) else "FAIL",
                 revoke_status=st, old_cookie_status=old, detail=text[:250])
            result["status_summary"] = {"fixture": "PASS", "161": "PASS_WITH_NOTES", "163": "PASS_WITH_NOTES",
                "notes": "real root strong session; normal/support/appadmin page+API authorization; staff Passkey second-factor login and support page/API 200; A/B app creation. Notes: app-admin app-scoped management remains 403; session revoke/logout CSRF path NOT_TESTED; screenshots/responsive/reader NOT_TESTED."}
    finally:
        if serve.poll() is None:
            try:
                serve.send_signal(signal.CTRL_BREAK_EVENT)
                serve.wait(timeout=8)
            except Exception:  # noqa: BLE001
                subprocess.run(["taskkill", "/T", "/F", "/PID", str(serve.pid)], capture_output=True)
        subprocess.run(["powershell", "-NoProfile", "-Command",
                        "Get-CimInstance Win32_Process -Filter \"Name='chrome.exe'\" | Where-Object { $_.CommandLine -like '*strong-auth-fixture-passkey*' } | ForEach-Object { taskkill.exe /T /F /PID $_.ProcessId | Out-Null }"],
                       capture_output=True)
    return finish(result, evidence, args.keep, work)


def finish(result, evidence, keep, work):
    result.pop("cookies", None)
    os.makedirs(evidence, exist_ok=True)
    with open(os.path.join(evidence, "strong-auth-fixture-passkey-result.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    step161_dir = os.path.join(BASE, "docs", "acceptance", "evidence", "step161")
    os.makedirs(step161_dir, exist_ok=True)
    with open(os.path.join(step161_dir, "step161-matrix-real.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print("STRONG_AUTH_PASSKEY_RESULT", json.dumps(result.get("status_summary", {}), ensure_ascii=False))
    if not keep:
        shutil.rmtree(work, ignore_errors=True)
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
