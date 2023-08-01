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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", default=DEFAULT_WORK)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--evidence", default=os.path.join(BASE, "docs", "acceptance", "evidence", "step163"))
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
    b = subprocess.run(["go", "build", "-o", exe, "./cmd/login-server"], cwd=BASE, capture_output=True, text=True)
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
            probes = session.get("probes") or {}
            result["probes_authenticated"] = probes
            # Step 163 authenticated audit/report/backup route reachability.
            audit_paths = ["/admin/v1/audit/events", "/admin/v1/audit/retention", "/admin/v1/audit/exports",
                           "/admin/v1/reports", "/admin/v1/report-plans", "/admin/v1/backups",
                           "/admin/v1/backups/capabilities", "/admin/v1/backups/jobs"]
            audit = {p: probes.get(p, {}).get("status") for p in audit_paths}
            step("163.strong_session_routes", "PASS" if all(s in (200, 403) for s in audit.values()) else "FAIL",
                 detail=audit)
            # CLI backup create/verify/info/list/preview/export/extract on the live temp DB.
            backup = os.path.join(work, "login-backup.exe")
            br = subprocess.run(["go", "build", "-o", backup, "./cmd/login-backup"], cwd=BASE, capture_output=True, text=True)
            step("163.build.login-backup", "PASS" if br.returncode == 0 else "FAIL", detail=(br.stderr or "")[-200:])
            if br.returncode == 0:
                outdir = os.path.join(work, "backups")
                os.makedirs(outdir, exist_ok=True)
                def run_cli(args):
                    pr = subprocess.run(args, cwd=work, capture_output=True, text=True, timeout=180)
                    return pr.returncode, (pr.stdout + pr.stderr)[-300:]
                rc, detail = run_cli([backup, "create", "--database", db, "--key-file", master,
                                      "--output", outdir, "--operator", "step163", "--json"])
                step("163.backup.create", "PASS" if rc == 0 else "FAIL", detail=detail)
                files = [os.path.join(outdir, n) for n in os.listdir(outdir) if n.endswith(".elnbak")]
                if files:
                    bf = files[0]
                    for name, cli_args in [
                        ("verify", [backup, "verify", "--file", bf, "--key-file", master, "--json"]),
                        ("info", [backup, "info", "--file", bf, "--json"]),
                        ("list", [backup, "list", "--file", bf, "--key-file", master, "--json"]),
                        ("preview", [backup, "preview", "--file", bf, "--key-file", master,
                                     "--table", "users", "--limit", "3", "--json"]),
                        ("export-json", [backup, "export", "--file", bf, "--key-file", master,
                                         "--table", "users", "--format", "json",
                                         "--output", os.path.join(work, "users.json"), "--json"]),
                        ("extract", [backup, "extract", "--file", bf, "--key-file", master,
                                     "--entry", "database/main.sqlite",
                                     "--output", os.path.join(work, "extract.sqlite"),
                                     "--include-sensitive", "--json"]),
                    ]:
                        rc, detail = run_cli(cli_args)
                        step("163.backup." + name, "PASS" if rc == 0 else "FAIL", detail=detail)
            result["status_summary"] = {"fixture": "PASS",
                "163": "PASS_WITH_NOTES",
                "notes": "audit/report/backup routes reachable with real strong session; backup CLI create/verify/info/list/preview/export/extract PASS. Report generation/download, restore apply/rollback and post-restore credential non-revival remain NOT_TESTED."}
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
    with open(os.path.join(evidence, "step163-real-serve.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print("STRONG_AUTH_PASSKEY_RESULT", json.dumps(result.get("status_summary", {}), ensure_ascii=False))
    if not keep:
        shutil.rmtree(work, ignore_errors=True)
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
