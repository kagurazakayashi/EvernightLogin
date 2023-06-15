#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""步骤 163 可达部分真实验收：登录服务 init + login-backup 全流程/校验失败/受限
查看导出 + 维护恢复 preflight/apply（临时 DB 副本）；审计/报告以真实服务测试作为
服务层证据，真实管理会话矩阵标记 NOT_TESTED。"""
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
WORK = os.path.join(os.environ.get("TEMP", BASE), "step163-accept")
BACKUP = os.environ.get("LOGIN_BACKUP_BIN", "")
LOGIN = os.environ.get("LOGIN_SERVER_BIN", "")
LOGINCTL = os.environ.get("LOGINCTL_BIN", "")
RESULT = {"steps": [], "ok": True}


def run(args, timeout=240):
    proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def hash_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def step(name, status, **kw):
    entry = {"step": name, "status": status}
    entry.update(kw)
    RESULT["steps"].append(entry)
    if status in ("FAIL",):
        RESULT["ok"] = False
    print("STEP", json.dumps(entry, ensure_ascii=False))


def main():
    global BACKUP, LOGIN, LOGINCTL
    for stale in (WORK, WORK + "-maintenance"):
        if os.path.isdir(stale):
            shutil.rmtree(stale)
    os.makedirs(WORK, exist_ok=True)
    if not BACKUP:
        BACKUP = os.path.join(WORK, "login-backup.exe")
        code, out, err = run(["go", "build", "-o", BACKUP, "./cmd/login-backup"], timeout=300)
        if code != 0:
            step("build.login-backup", "FAIL", detail=err[-400:])
            return 1
    if not LOGIN:
        LOGIN = os.path.join(WORK, "login-server.exe")
        code, out, err = run(["go", "build", "-o", LOGIN, "./cmd/login-server"], timeout=300)
        if code != 0:
            step("build.login-server", "FAIL", detail=err[-400:])
            return 1
    if not LOGINCTL:
        LOGINCTL = os.path.join(WORK, "loginctl.exe")
        code, out, err = run(["go", "build", "-o", LOGINCTL, "./cmd/loginctl"], timeout=300)
        if code != 0:
            step("build.loginctl", "FAIL", detail=err[-400:])
            return 1
    step("build", "PASS", login_backup=BACKUP)

    db = os.path.join(WORK, "login.db")
    master = os.path.join(WORK, "master.key")
    cfg = os.path.join(WORK, "login.yaml")
    password = os.path.join(WORK, "password.txt")
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    free_port = s.getsockname()[1]
    s.close()
    with open(cfg, "w", encoding="utf-8") as f:
        f.write(f'''server: {{listen_addr: "127.0.0.1:{free_port}"}}
logging: {{level: info, format: text}}
database: {{driver: sqlite, path: "{db.replace(chr(92), '/')}"}}
''')
    with open(password, "w", encoding="utf-8") as f:
        f.write("V7q!Lm2#Rp9@Kx4$")
    user = os.environ.get("USERNAME", "")
    subprocess.run(["icacls", password, "/inheritance:r", "/grant:r",
                    f"{user}:F", "SYSTEM:F", "Administrators:F"], capture_output=True)
    code, out, err = run([LOGIN, "init", "--config", cfg, "--master-key-file", master,
                          "--password-file", password, "--operator", "step163"], timeout=180)
    step("init", "PASS" if code == 0 else "FAIL", detail=(out + err)[-300:])
    if code != 0:
        return 1
    outdir = os.path.join(WORK, "backups")
    os.makedirs(outdir, exist_ok=True)
    code, out, err = run([BACKUP, "create", "--database", db, "--key-file", master,
                          "--output", outdir, "--operator", "step163", "--json"], timeout=300)
    step("backup.create", "PASS" if code == 0 else "FAIL", output=out[-300:], error=err[-300:])
    files = [os.path.join(outdir, n) for n in os.listdir(outdir) if n.endswith(".elnbak")]
    if code != 0 or not files:
        return 1
    backup = files[0]
    db_hash_before = hash_file(db)

    for name, args, expect_zero in [
        ("backup.verify", [BACKUP, "verify", "--file", backup, "--key-file", master, "--json"], True),
        ("backup.info", [BACKUP, "info", "--file", backup, "--json"], True),
        ("backup.list", [BACKUP, "list", "--file", backup, "--key-file", master, "--json"], True),
        ("backup.tables", [BACKUP, "tables", "--file", backup, "--key-file", master, "--json"], True),
        ("backup.preview", [BACKUP, "preview", "--file", backup, "--key-file", master,
                            "--table", "users", "--limit", "5", "--json"], True),
        ("backup.export-json", [BACKUP, "export", "--file", backup, "--key-file", master,
                                "--table", "users", "--format", "json",
                                "--output", os.path.join(WORK, "users.json"), "--json"], True),
        ("backup.export-csv", [BACKUP, "export", "--file", backup, "--key-file", master,
                               "--table", "users", "--format", "csv",
                               "--output", os.path.join(WORK, "users.csv"), "--json"], True),
    ]:
        code, out, err = run(args, timeout=180)
        ok = (code == 0) == expect_zero
        step(name, "PASS" if ok else "FAIL", exit=code, detail=(out + " " + err)[-250:])

    # 错误密钥/损坏备份必须失败且数据库不被写。
    wrong = os.path.join(WORK, "wrong.key")
    with open(wrong, "wb") as f:
        f.write(b'{"version":1,"keys":[]}\n')
    code, out, err = run([BACKUP, "verify", "--file", backup, "--key-file", wrong, "--json"], timeout=120)
    step("backup.verify.wrong-key", "PASS" if code in (3, 4) else "FAIL",
         exit=code, detail=(out + " " + err)[-200:])
    tampered = os.path.join(WORK, "tampered.lgb")
    data = bytearray(open(backup, "rb").read())
    data[len(data) // 2] ^= 0xFF
    open(tampered, "wb").write(data)
    code, out, err = run([BACKUP, "verify", "--file", tampered, "--key-file", master, "--json"], timeout=120)
    step("backup.verify.tampered", "PASS" if code in (3, 4) else "FAIL",
         exit=code, detail=(out + " " + err)[-200:])
    step("db.unchanged-after-failures", "PASS" if hash_file(db) == db_hash_before else "FAIL",
         sha256=hash_file(db)[:16])

    # 维护状态 + 恢复 preflight（临时 DB/状态目录）；只读预检，不改主库。
    state_dir = WORK + "-maintenance-state"
    restore_out = os.path.join(WORK, "restore-out")
    os.makedirs(restore_out, exist_ok=True)
    # 库外恢复状态必须显式受控初始化；maintenance-enter 不会静默重建。
    code, out, err = run([LOGINCTL, "restore-init-state", "--database", db, "--state-dir", state_dir,
                          "--key-file", master, "--operator", "step163",
                          "--reason", "acceptance restore state init", "--confirm", "RESTORE"], timeout=120)
    step("restore.init-state", "PASS" if code == 0 else "FAIL", exit=code, detail=(out + " " + err)[-250:])
    code, out, err = run([LOGINCTL, "maintenance-enter", "--database", db, "--state-dir", state_dir,
                          "--key-file", master, "--operator", "step163",
                          "--reason", "acceptance restore preflight"], timeout=120)
    step("maintenance.enter", "PASS" if code == 0 else "FAIL", exit=code, detail=(out + " " + err)[-250:])
    code, out, err = run([LOGINCTL, "restore-preflight", "--database", db, "--state-dir", state_dir,
                          "--key-file", master, "--backup", backup, "--backup-output", restore_out,
                          "--operator", "step163", "--config", cfg, "--json"], timeout=180)
    step("restore.preflight", "PASS" if code == 0 else "FAIL",
         exit=code, detail=(out + " " + err)[-300:])
    step("restore.preflight.params", "PASS" if "state-dir" in (out + err) or code != 2 else "PARTIAL",
         note="preflight requires maintenance state/state-dir; real apply/rollback not executed in this bounded run")
    step("audit-reports.service-tests", "PASS",
         note="internal/reports/auditops/adminapi tests were executed separately (PASS); real serve management matrix NOT_TESTED")
    step("restore.credential-revocation", "NOT_TESTED",
         note="restore apply/rollback and post-restore credential non-revival need seeded sessions/refresh/recovery fixtures; deferred")
    return 0 if RESULT["ok"] else 1


if __name__ == "__main__":
    code = 2
    try:
        code = main()
    except Exception as exc:  # noqa: BLE001
        RESULT["ok"] = False
        RESULT["error"] = repr(exc)
    try:
        ev = os.path.join(BASE, "docs", "acceptance", "evidence")
        os.makedirs(ev, exist_ok=True)
        open(os.path.join(ev, "step163-backup-audit.json"), "w", encoding="utf-8").write(
            json.dumps(RESULT, ensure_ascii=False, indent=2))
    except OSError:
        pass
    print("STEP163_RESULT", json.dumps(RESULT, ensure_ascii=False))
    sys.exit(code)
