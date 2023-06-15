#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""步骤 161 可达部分冒烟：真实 login-server serve（临时 SQLite/回环）+ 未认证
页面/API 边界，并用系统 Chrome/Playwright 打开公开页面记录浏览器路径。
角色×应用矩阵因缺少受控强认证管理会话夹具，标记 NOT_TESTED（见验收文档）。"""
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(BASE, "..", ".."))
WORK = os.path.join(os.environ.get("TEMP", ROOT), "step161-smoke")
EVIDENCE = os.path.join(ROOT, "docs", "acceptance", "evidence")
RESULT = {"steps": [], "ok": True}


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


def request(url, method="GET", headers=None):
    req = urllib.request.Request(url, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")[:300]
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")[:300]
    except Exception as exc:  # noqa: BLE001
        return 0, str(exc)


def main():
    if os.path.isdir(WORK):
        shutil.rmtree(WORK)
    os.makedirs(WORK, exist_ok=True)
    exe = os.path.join(WORK, "login-server.exe")
    build = subprocess.run(["go", "build", "-o", exe, "./cmd/login-server"], cwd=ROOT,
                           capture_output=True, text=True)
    if build.returncode != 0:
        print("BUILD_FAIL", build.stderr[-500:])
        RESULT["ok"] = False
        return 1
    port = free_port()
    cfg = os.path.join(WORK, "login.yaml")
    db = os.path.join(WORK, "login.db").replace("\\", "/")
    with open(cfg, "w", encoding="utf-8") as f:
        f.write(f'''server:
  listen_addr: "127.0.0.1:{port}"
  public_base_url: "http://127.0.0.1:{port}"
  shutdown_timeout_seconds: 5
logging: {{level: info, format: text}}
database: {{driver: sqlite, path: "{db}", wal: true, busy_timeout_ms: 5000}}
''')
    master = os.path.join(WORK, "master.key")
    password = os.path.join(WORK, "password.txt")
    with open(password, "w", encoding="utf-8") as f:
        f.write("V7q!Lm2#Rp9@Kx4$")
    user = os.environ.get("USERNAME", "")
    subprocess.run(["icacls", password, "/inheritance:r", "/grant:r",
                    f"{user}:F", "SYSTEM:F", "Administrators:F"], capture_output=True)
    init = subprocess.run([exe, "init", "--config", cfg, "--master-key-file", master,
                           "--password-file", password, "--operator", "step161"],
                          cwd=WORK, capture_output=True, text=True, timeout=120)
    if init.returncode != 0:
        print("INIT_FAIL", (init.stdout + init.stderr)[-700:])
        RESULT["ok"] = False
        return 1
    serve = subprocess.Popen([exe, "serve", "--config", cfg, "--master-key-file", master,
                              "--enable-admin-api"], cwd=WORK,
                             stdout=open(os.path.join(WORK, "serve.out.log"), "wb"),
                             stderr=open(os.path.join(WORK, "serve.err.log"), "wb"),
                             creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
    try:
        if not wait_port(port):
            print("SERVE_FAIL", open(os.path.join(WORK, "serve.err.log"), encoding="utf-8", errors="replace").read()[-700:])
            RESULT["ok"] = False
            return 1
        base = f"http://127.0.0.1:{port}"
        checks = {
            "healthz": request(base + "/healthz"),
            "login_page": request(base + "/login"),
            "register_page": request(base + "/register"),
            "admin_users_page_unauth": request(base + "/admin/users"),
            "admin_api_users_unauth": request(base + "/admin/v1/users"),
        }
        for name, (status, body) in checks.items():
            RESULT["steps"].append({"step": name, "status": status, "snippet": body[:120]})
            print("HTTP", name, status)
        if checks["healthz"][0] != 200 or checks["login_page"][0] != 200:
            RESULT["ok"] = False
        if checks["admin_api_users_unauth"][0] != 401:
            RESULT["ok"] = False
        # 浏览器路径（系统 Chrome + Playwright；仅公开页面，登录后矩阵 NOT_TESTED）。
        node_path = os.environ.get("PLAYWRIGHT_NODE_PATH", r"B:\TMP\_npx\e41f203b7505f1fb\node_modules")
        node = shutil.which("node")
        if node:
            js = r'''
const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch({ headless: true, executablePath: 'C:/Program Files/Google/Chrome/Application/chrome.exe' });
  const page = await browser.newPage({ viewport: { width: 1024, height: 768 } });
  const out = [];
  for (const path of ['/login', '/register']) {
    const resp = await page.goto(process.env.E2E_BASE + path, { waitUntil: 'networkidle' });
    out.push({ path, status: resp ? resp.status() : 0, title: await page.title(),
      hasForm: await page.locator('form').count() > 0 });
  }
  console.log(JSON.stringify(out));
  await browser.close();
})();
'''
            env = dict(os.environ, NODE_PATH=node_path, E2E_BASE=base)
            browser = subprocess.run([node, "-e", js], capture_output=True, text=True, timeout=90, env=env)
            browser_ok = browser.returncode == 0
            browser_data = []
            if browser_ok:
                try:
                    browser_data = json.loads(browser.stdout.strip().splitlines()[-1])
                except Exception:  # noqa: BLE001
                    browser_ok = False
            RESULT["steps"].append({"step": "browser_public_pages", "ok": browser_ok,
                                    "pages": browser_data,
                                    "stderr": (browser.stderr or "")[-200:]})
            print("BROWSER", browser_ok, browser_data)
        else:
            RESULT["steps"].append({"step": "browser_public_pages", "ok": False,
                                    "reason": "node not available"})
    finally:
        if serve.poll() is None:
            try:
                serve.send_signal(signal.CTRL_BREAK_EVENT)
                serve.wait(timeout=8)
            except Exception:  # noqa: BLE001
                subprocess.run(["taskkill", "/T", "/F", "/PID", str(serve.pid)], capture_output=True)
        time.sleep(0.3)
    return 0 if RESULT["ok"] else 1


if __name__ == "__main__":
    code = 2
    try:
        code = main()
    except Exception as exc:  # noqa: BLE001
        RESULT["ok"] = False
        RESULT["error"] = repr(exc)
    try:
        os.makedirs(EVIDENCE, exist_ok=True)
        with open(os.path.join(EVIDENCE, "step161-real-serve-smoke.json"), "w", encoding="utf-8") as f:
            json.dump(RESULT, f, ensure_ascii=False, indent=2)
    except OSError:
        pass
    print("STEP161_SMOKE_RESULT", json.dumps(RESULT, ensure_ascii=False))
    sys.exit(code)
