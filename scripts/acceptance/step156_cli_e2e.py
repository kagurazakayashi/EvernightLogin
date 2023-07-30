#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""步骤 156 真实 CLI 写 E2E 套件（供 strong-auth 夹具复用）。

前置：真实 login-server 已运行且提供强认证管理会话 secret；本模块构建真实
loginctl 二进制，通过同一管理 API 验证：只读、用户/组/角色/应用写、版本冲突、
强制下线、客服、托管策略读、过期强认证拒绝；所有写请求服务端仍重新授权。
"""
import json
import os
import sqlite3
import subprocess
import time

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def build_cli(work):
    exe = os.path.join(work, "loginctl-step156.exe")
    proc = subprocess.run(["go", "build", "-o", exe, "./cmd/loginctl"], cwd=BASE,
                          capture_output=True, text=True)
    return exe if proc.returncode == 0 else "", (proc.stderr or "")[-300:]


def protected(path):
    user = os.environ.get("USERNAME", "")
    subprocess.run(["icacls", path, "/inheritance:r", "/grant:r",
                    f"{user}:F", "SYSTEM:F", "Administrators:F"], capture_output=True)


def run_suite(base_url, session_secret, work, cli_bin, db_path=""):
    session_file = os.path.join(work, "step156-session.secret")
    with open(session_file, "w", encoding="utf-8") as f:
        f.write(session_secret)
    protected(session_file)
    env = {k: v for k, v in os.environ.items()
           if k.lower() not in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")}
    results = {}

    def cli(args, expect_zero=True):
        proc = subprocess.run([cli_bin] + args + ["--server", base_url,
                              "--session-file", session_file, "--json"],
                              cwd=work, capture_output=True, text=True, timeout=60, env=env)
        payload = {}
        try:
            payload = json.loads(proc.stdout)
        except Exception:
            start = proc.stdout.find("{")
            if start >= 0:
                try: payload = json.loads(proc.stdout[start:])
                except Exception: pass
        ok = (proc.returncode == 0) == expect_zero
        return ok, proc.returncode, payload, (proc.stderr or proc.stdout)[-200:]

    def record(name, ok, **kw):
        entry = {"ok": bool(ok)}
        entry.update(kw)
        results[name] = entry

    if not cli_bin:
        record("cli.build", False, detail="loginctl build failed")
        return results
    ok, code, payload, detail = cli(["admin", "users"])
    record("users.list", ok, exit=code, detail=detail)
    ok, code, created, detail = cli(["admin", "write", "users", "--body", json.dumps(
        {"username": "step156user", "nickname": "156", "language": "zh-CN",
         "timezone": "Asia/Shanghai"}), "--confirm", "ADMIN-WRITE"])
    user_id = str(((created.get("data") or {}).get("id", ""))) if isinstance(created, dict) else ""
    record("users.create", ok and bool(user_id), exit=code, detail=detail)
    ok, code, created, detail = cli(["admin", "write", "groups", "--body", json.dumps(
        {"scope_id": "system", "group_key": "step156group", "name": "step156 group",
         "description": "e2e"}), "--confirm", "ADMIN-WRITE"])
    record("group.create", ok, exit=code, detail=detail)
    ok, code, created, detail = cli(["admin", "write", "roles", "--body", json.dumps(
        {"scope_id": "system", "key": "step156role", "name": "step156 role",
         "description": "step156 e2e role", "limits": "step156 e2e limits"}), "--confirm", "ADMIN-WRITE"])
    record("role.create", ok, exit=code, detail=detail)
    ok, code, app, detail = cli(["admin", "write", "applications", "--body", json.dumps(
        {"name": "step156 app", "description": "e2e", "client_type": "public",
         "owner_user_id": user_id}), "--confirm", "ADMIN-WRITE"])
    app_id = str(((app.get("data") or {}).get("id", ""))) if isinstance(app, dict) else ""
    row_version = int(((app.get("data") or {}).get("row_version", 0) or 0)) if isinstance(app, dict) else 0
    record("application.create", ok and bool(app_id), exit=code, detail=detail)
    if app_id:
        ok, code, state, detail = cli(["admin", "write", "applications/" + app_id + "/state",
                                        "--body", json.dumps({"enable": True,
                                        "expected_row_version": row_version}), "--confirm", "ADMIN-WRITE"])
        record("application.enable", ok, exit=code, detail=detail)
        ok, code, current, detail = cli(["admin", "application", app_id])
        owner_value = user_id
        if isinstance(current, dict):
            data = current.get("data") or {}
            row_version = int(data.get("row_version", row_version) or row_version)
            owner_value = str(data.get("owner_user_id", "") or "")
        record("application.read-after-enable", ok, exit=code, detail=detail,
               data=(current.get("data") if isinstance(current, dict) else None))
        ok, code, updated, detail = cli(["admin", "write", "applications/" + app_id, "--method", "PUT", "--body",
            json.dumps({"name": "step156 app v2", "description": "e2e",
                        "owner_user_id": owner_value, "expected_row_version": row_version}),
            "--confirm", "ADMIN-WRITE"])
        record("application.update", ok, exit=code, detail=detail)
        ok, code, stale, detail = cli(["admin", "write", "applications/" + app_id, "--method", "PUT", "--body",
            json.dumps({"name": "step156 app stale", "description": "e2e",
                        "owner_user_id": owner_value, "expected_row_version": row_version}),
            "--confirm", "ADMIN-WRITE"], expect_zero=False)
        record("application.version-conflict", ok, exit=code, detail=detail)
        ok, code, policy, detail = cli(["admin", "application", app_id, "managed-policy"])
        record("managed-policy.read", ok, exit=code, detail=detail)
        policy_put = json.dumps({"allowed": ["documents.read"], "service_allowed": [],
                                 "expected_row_version": int(((policy.get("data") or {}).get("row_version", 0) or 0)) if isinstance(policy, dict) else 0,
                                 "policy_digest": "unknown"})
        ok, code, put, detail = cli(["admin", "write", "applications/" + app_id + "/managed-policy",
                                     "--method", "PUT", "--body", policy_put,
                                     "--confirm", "ADMIN-WRITE"], expect_zero=False)
        record("managed-policy.write", ok, exit=code, detail=detail,
               note="requires page/reauth one-time binding; if rejected must remain fail-closed")
    if user_id:
        ok, code, revoked, detail = cli(["session", "admin-revoke", "--user", user_id,
            "--reason", "step156 e2e", "--confirm", "ADMIN-REVOKE"])
        record("session.admin-revoke", ok, exit=code, detail=detail)
        ok, code, case, detail = cli(["admin", "write", "support/cases", "--body", json.dumps(
            {"target_user_id": user_id, "reason": "e2e support"}), "--confirm", "ADMIN-WRITE"])
        record("support.case-create", ok, exit=code, detail=detail,
               note="target may lack verified email; failure recorded, not fabricated")
    # 过期强认证：更新当前强会话时间戳，CLI 写必须被拒绝；随后恢复。
    if db_path and os.path.isfile(db_path):
        conn = sqlite3.connect(db_path)
        try:
            row = conn.execute("SELECT id,strong_auth_verified_at_ms FROM sessions WHERE revoked_at_ms IS NULL ORDER BY created_at_ms DESC LIMIT 1").fetchone()
            if row:
                conn.execute("UPDATE sessions SET strong_auth_verified_at_ms=0 WHERE id=?", (row[0],))
                conn.commit()
                ok, code, payload, detail = cli(["admin", "users"], expect_zero=False)
                record("session.expired-strong-auth", ok and code != 0, exit=code, detail=detail)
                conn.execute("UPDATE sessions SET strong_auth_verified_at_ms=? WHERE id=?", (row[1], row[0]))
                conn.commit()
        finally:
            conn.close()
    record("ordinary-user-deny", False, note="NOT_TESTED: fixture lacks loginable ordinary-user password credential")
    return results
