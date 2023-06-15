#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""可复用验收夹具：真实 login-server init + serve + 预置真实 TOTP 强因素。

- 临时 SQLite、回环端口、合成 root 密码；
- 用 scripts/acceptance/seed_totp 在临时库写入真实 active TOTP 绑定（fixture-only，
  不进入产品），并标记临时 root 初始化完成；
- 通过真实登录表单完成 root 密码 + TOTP 第二因素，取得真实会话 Cookie；
- 输出脱敏证据与 161/163 管理路由可达性；不伪造认证、不降级 MFA。
"""
import argparse
import re
import hashlib
import hmac
import http.cookiejar
import json
import os
import secrets
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_WORK = os.path.join(os.environ.get("TEMP", BASE), "strong-auth-fixture")


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


def protected_file(path):
    user = os.environ.get("USERNAME", "")
    subprocess.run(["icacls", path, "/inheritance:r", "/grant:r",
                    f"{user}:F", "SYSTEM:F", "Administrators:F"], capture_output=True)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), NoRedirect)

    def request(self, method, url, data=None):
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        req = urllib.request.Request(url, method=method, data=body,
                                     headers={"Content-Type": "application/x-www-form-urlencoded",
                                              "Origin": BASE_URL, "Referer": url})
        try:
            with self.opener.open(req, timeout=15) as resp:
                return resp.status, resp.headers, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.headers, exc.read().decode("utf-8", "replace")

    def get(self, path):
        return self.request("GET", BASE_URL + path)

    def post(self, path, data):
        return self.request("POST", BASE_URL + path, data)


def csrf(html):
    marker = 'name="csrf_token" value="'
    i = html.find(marker)
    if i < 0:
        return ""
    j = html.find('"', i + len(marker))
    return html[i + len(marker):j]


def set_page_csrf(client, html):
    token = csrf(html)
    if not token:
        return
    cookie = http.cookiejar.Cookie(version=0, name="ln_page_csrf", value=token, port=None,
                                   port_specified=False, domain="127.0.0.1", domain_specified=False,
                                   domain_initial_dot=False, path="/", path_specified=True,
                                   secure=False, expires=None, discard=True, comment=None,
                                   comment_url=None, rest={}, rfc2109=False)
    client.jar.set_cookie(cookie)


def hidden_fields(html):
    import re
    fields = {}
    for m in re.finditer(r'name="([^"]+)" value="([^"]*)"', html):
        fields[m.group(1)] = m.group(2)
    return fields


def totp(secret_b32, at=None):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    bits = 0
    value = 0
    out = bytearray()
    for ch in secret_b32.upper():
        value = (value << 5) | alphabet.index(ch)
        bits += 5
        if bits >= 8:
            out.append((value >> (bits - 8)) & 0xFF)
            bits -= 8
    counter = int((at or time.time()) // 30)
    digest = hmac.new(bytes(out), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % 1000000).zfill(6)


def main():
    global BASE_URL
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", default=DEFAULT_WORK)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--evidence", default=os.path.join(BASE, "docs", "acceptance", "evidence", "strong-auth-fixture"))
    args = parser.parse_args()
    work = os.path.abspath(args.work)
    for stale in (work, work + "-maintenance"):
        if os.path.isdir(stale):
            shutil.rmtree(stale, ignore_errors=True)
    os.makedirs(work, exist_ok=True)
    evidence_dir = os.path.abspath(args.evidence)
    os.makedirs(evidence_dir, exist_ok=True)
    result = {"steps": [], "ok": True, "work_retained": bool(args.keep)}

    def step(name, status, **kw):
        entry = {"step": name, "status": status}
        entry.update(kw)
        result["steps"].append(entry)
        if status == "FAIL":
            result["ok"] = False
        print("FIXTURE", json.dumps(entry, ensure_ascii=False))

    exe = os.path.join(work, "login-server.exe")
    seed_exe = os.path.join(work, "seed_totp.exe")
    build = subprocess.run(["go", "build", "-o", exe, "./cmd/login-server"], cwd=BASE, capture_output=True, text=True)
    seed_build = subprocess.run(["go", "build", "-o", seed_exe, "./scripts/acceptance/seed_totp"], cwd=BASE, capture_output=True, text=True)
    step("build", "PASS" if build.returncode == 0 and seed_build.returncode == 0 else "FAIL",
         detail=(build.stderr + seed_build.stderr)[-300:])
    if build.returncode != 0 or seed_build.returncode != 0:
        return finish(result, evidence_dir, args.keep, work)

    port = free_port()
    BASE_URL = f"http://127.0.0.1:{port}"
    cfg = os.path.join(work, "login.yaml")
    db = os.path.join(work, "login.db")
    master = os.path.join(work, "master.key")
    password_file = os.path.join(work, "root-password.txt")
    password = "Fixture-Strong-9-Auth!" + secrets.token_hex(3)
    with open(password_file, "w", encoding="utf-8") as f:
        f.write(password + "\n")
    protected_file(password_file)
    with open(cfg, "w", encoding="utf-8") as f:
        f.write(f'''server:
  listen_addr: "127.0.0.1:{port}"
  public_base_url: "{BASE_URL}"
  shutdown_timeout_seconds: 5
logging: {{level: info, format: text}}
database: {{driver: sqlite, path: "{db.replace(chr(92), '/')}", wal: true, busy_timeout_ms: 5000}}
''')
    init = subprocess.run([exe, "init", "--config", cfg, "--master-key-file", master,
                           "--password-file", password_file, "--operator", "strong-auth-fixture"],
                          cwd=work, capture_output=True, text=True, timeout=120)
    step("init.root", "PASS" if init.returncode == 0 else "FAIL", detail=(init.stdout + init.stderr)[-300:])
    if init.returncode != 0:
        return finish(result, evidence_dir, args.keep, work)

    secret_file = os.path.join(work, "root-totp.json")
    seed = subprocess.run([seed_exe, "--database", db, "--master-key", master,
                           "--username", "root", "--out", secret_file, "--mark-ready"],
                          cwd=work, capture_output=True, text=True, timeout=120)
    step("seed.real-totp-factor", "PASS" if seed.returncode == 0 else "FAIL",
         detail=(seed.stdout + seed.stderr)[-300:])
    if seed.returncode != 0:
        return finish(result, evidence_dir, args.keep, work)
    secret = json.load(open(secret_file, encoding="utf-8"))["secret"]

    serve_log = open(os.path.join(work, "serve.log"), "wb")
    serve = subprocess.Popen([exe, "serve", "--config", cfg, "--master-key-file", master, "--enable-admin-api"],
                             cwd=work, stdout=serve_log, stderr=subprocess.STDOUT,
                             creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
    try:
        if not wait_port(port):
            step("serve.ready", "FAIL", detail=open(os.path.join(work, "serve.log"), encoding="utf-8", errors="replace").read()[-500:])
            return finish(result, evidence_dir, args.keep, work)
        step("serve.ready", "PASS", base=BASE_URL)

        client = Client()
        status, _, login_page = client.get("/login")
        set_page_csrf(client, login_page)
        status, headers, login_result = client.post("/login", {"csrf_token": csrf(login_page),
                                                               "identifier": "root", "password": password})
        step("login.root.password", "PASS" if status == 303 else "FAIL",
             http_status=status, location=headers.get("Location", ""), detail=re.sub(r'<[^>]+>', ' ', login_result)[:500])
        second_path = headers.get("Location", "")
        if "second-factor" not in second_path:
            step("login.root.second-factor", "FAIL", detail=login_result[:200])
            return finish(result, evidence_dir, args.keep, work)
        status, _, second_page = client.get(second_path)
        set_page_csrf(client, second_page)
        step("second-factor.page", "PASS" if status == 200 else "FAIL", http_status=status)
        fields = hidden_fields(second_page)
        code = totp(secret)
        payload = {k: v for k, v in fields.items() if k not in ("code",)}
        payload["code"] = code
        status, headers, verified = client.post(second_path, payload)
        step("login.root.totp", "PASS" if status == 303 and headers.get("Location") == "/home" else "FAIL",
             http_status=status, location=headers.get("Location", ""), detail=verified[:150])
        result["session"] = {"cookie_names": [c.name for c in client.jar], "authenticated": status == 303}

        # authenticated admin route probes
        probes = {}
        for path in ["/home", "/account/security", "/admin", "/admin/users", "/admin/applications",
                     "/admin/roles", "/admin/audit", "/admin/reports", "/admin/v1/users",
                     "/admin/v1/applications", "/admin/v1/audit/events", "/admin/v1/audit/retention",
                     "/admin/v1/reports", "/admin/v1/backups", "/admin/v1/notifications", "/admin/v1/sessions"]:
            st, _, text = client.get(path)
            probes[path] = {"status": st, "snippet": text.replace("\n", " ")[:120]}
        result["probes_authenticated"] = probes
        anon = Client()
        unauth = {}
        for path in ["/admin", "/admin/users", "/admin/v1/users", "/admin/v1/audit/events"]:
            st, _, _ = anon.get(path)
            unauth[path] = st
        result["probes_anonymous"] = unauth
        admin_ok = all(probes[p]["status"] == 200 for p in ["/admin/users", "/admin/applications", "/admin/roles"])
        anon_ok = all(unauth[p] in (302, 303, 401, 403) for p in ["/admin", "/admin/users", "/admin/v1/users"])
        step("161.authenticated_admin_routes", "PASS" if admin_ok else "FAIL",
             detail={p: probes[p]["status"] for p in ["/admin/users", "/admin/applications", "/admin/roles"]})
        step("161.anonymous_denied", "PASS" if anon_ok else "FAIL", detail=unauth)
        audit_ok = probes["/admin/v1/audit/events"]["status"] == 200
        reports_ok = probes["/admin/v1/reports"]["status"] in (200, 403)
        step("163.strong_session_audit_route", "PASS" if audit_ok else "FAIL", http_status=probes["/admin/v1/audit/events"]["status"])
        step("163.strong_session_report_route", "PASS" if reports_ok else "FAIL", http_status=probes["/admin/v1/reports"]["status"])
        result["status_summary"] = {
            "fixture": "PASS" if result["ok"] else "FAIL",
            "161": "PARTIAL" if admin_ok and anon_ok else "FAIL",
            "163": "PARTIAL" if audit_ok and reports_ok else "FAIL",
            "note": "161 role x app/CSRF write matrix and 163 report generation/restore chains require additional fixtures; route reachability only.",
        }
    finally:
        if serve.poll() is None:
            try:
                serve.send_signal(signal.CTRL_BREAK_EVENT)
                serve.wait(timeout=8)
            except Exception:  # noqa: BLE001
                subprocess.run(["taskkill", "/T", "/F", "/PID", str(serve.pid)], capture_output=True)
        serve_log.close()
    return finish(result, evidence_dir, args.keep, work)


def finish(result, evidence_dir, keep, work):
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "strong-auth-fixture-result.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print("STRONG_AUTH_FIXTURE_RESULT", json.dumps(result.get("status_summary", {}), ensure_ascii=False))
    if not keep and os.path.isdir(work):
        shutil.rmtree(work, ignore_errors=True)
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001
        print("STRONG_AUTH_FIXTURE_FAIL", repr(exc))
        sys.exit(2)
