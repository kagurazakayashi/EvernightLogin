# scripts/acceptance — Login stage acceptance drafts

This directory is for **draft/skeleton acceptance tooling for the parent
EvernightLogin project** (not the EvernightMail submodule, whose own acceptance
scripts live under `EvernightMail/scripts/acceptance/`).

## Current contents

| File | Purpose |
|---|---|
| `step158-matrix.ps1` | Draft step 158 Windows + SQLite account/permission E2E matrix runner. **Dry-run only by default**; `-Execute` currently refuses with exit 3. |
| `step158-cases.json` | Machine-readable draft matrix (stages, entries, dependencies, NOT_TESTED risks). |
| `step159-163-matrix.ps1` | Draft per-step matrix planner for 159–163. **Dry-run only**; `-Execute` refuses (exit 3). |
| `step162_mail_faults.py` | 步骤 162 真实 login-server + EvernightMail 故障投递 E2E（临时数据/端口；不作为发布脚本） |
| `step159-163-cases.json` | Machine-readable draft matrix for 159–163 (assets/stages/dependencies/NOT_TESTED). |

## Safety

- The skeleton performs **no destructive action** and starts no process unless
  `-Execute` is explicitly passed; that mode is intentionally not implemented
  while step 157 and 138–156 are unfinished.
- Read-only prerequisite check: `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\acceptance\step158-matrix.ps1 -CheckPrereqs`
  (reports Go/toolchain and source presence; calls only read-only `git` queries).
- Do not point it at the repository database or real secrets. Execution (when
  implemented) must use a throw-away temp directory, a protected password file,
  a loopback random port, and full cleanup.
- No Git write operations; no product code changes.

## When can step 158 actually run?

Blocked on:
1. step 157 complete (requirement matrix closed) — no report yet;
2. step 138 final support (currently Phase A DONE / Phase B PARTIAL);
3. step 139 completion and security recheck (current `SEC_VERDICT: FAIL`, mail env
   vars not implemented);
4. steps 140–156 dev/audit closure for HTTP registration/email verification,
   authorization/managed APIs, management pages, CLI/API consistency;
5. a clean committed baseline for reproducible acceptance.

See `.ai/lead/reports/step157-158-prep.md` for the full inventory, matrix draft,
dependencies and NOT_TESTED risks.

## 2026-11-21 实际执行状态

步骤 158 已在 Windows+SQLite 执行：e2e 48 PASS/0 FAIL/5 NOT_TESTED，TestStep91 6/6 PASS，CLI 临时库读取/建组与迁移状态证据已产出；HTTP 管理强认证/浏览器/Passkey/在线审计仍为 PARTIAL/NOT_TESTED。详见 `docs/acceptance/步骤158：Windows 与 SQLite 初始化、账户与权限端到端验收记录（2026-11-21）.md`。

## 步骤 159 执行状态

2026-11-21 已用 Windows Chrome 157 CDP + WebAuthn 虚拟认证器对真实 login-server 执行。真实注册/登录与安全页渲染 PASS；Passkey 注册/TOTP 绑定/恢复代码生成均被真实服务端 REAUTH_REQUIRED/MFA_REQUIRED 拒绝，登记 FAIL/阻塞并给出根因；真实硬件/Windows Hello/读屏/非 Windows NOT_TESTED。详见 step159-dev.md 与 docs/acceptance/evidence/step159/。
