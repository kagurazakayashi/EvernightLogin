# 步骤 163 验收：审计报告、热备份、离线查看与恢复后凭据失效（PARTIAL）

- 执行者：大肥鱼助手，2026-11-21 23:0x（Asia/Shanghai）。环境：Windows 11、Go 1.27.1、临时 SQLite/回环、合成数据；未改 Mail、无 Git 写操作、未改产品代码。
- 结论：**PARTIAL**。热备份与离线查看/导出/提取已用真实 `login-backup` 二进制在真实初始化数据库上完成并通过校验/失败路径；审计/报告五格式与计划/历史/取消语义由真实服务测试覆盖 PASS，但**真实 serve + 管理会话的审计/报告 HTTP 矩阵未执行**；维护恢复 apply/rollback 与恢复后凭据不复活未执行（受维护状态/强会话夹具限制），标 NOT_TESTED。
- 原始证据：`docs/acceptance/evidence/step163-backup-audit.json`（脚本 `scripts/acceptance/step163-backup-audit.py`）；日志 `/p/go/tmp/step163.log`。

## 1. 矩阵

| 用例 | 场景 | 预期 | 实际/证据 | 状态 |
|---|---|---|---|---|
| 163-A1 | 审计查询/清理权限（页面+管理 API） | 仅获权者可查/导出/清理；稳定错误码 | `internal/adminapi`、`internal/auditops` 真实服务测试 PASS；真实 serve 强认证矩阵未执行 | **PARTIAL** |
| 163-A2 | 审计清理取消/执行语义 | 取消请求≠实际取消；真实操作者/原因/范围可追踪 | `internal/auditops` 测试 PASS（服务层）；真实 HTTP 未执行 | **PARTIAL** |
| 163-B1 | 报告五格式生成/下载 | HTML/PDF/CSV/JSON/可选 Markdown；下载受权/令牌单次 | `internal/reports` 测试 PASS（服务层）；真实 serve 未执行 | **PARTIAL** |
| 163-B2 | 报告计划/历史/取消者记录 | 计划启用/取消/历史真实；操作者追踪 | `internal/reports` 计划/取消测试 PASS；真实 serve 未执行 | **PARTIAL** |
| 163-C1 | `login-backup create` | 一致热备份（SQLite 在线备份，非复制主文件）、AES-256-GCM | 真实 CLI PASS（初始化 DB、manifest/SHA-256、1.55MB 快照） | **PASS** |
| 163-C2 | `verify/info/list/tables` | 认证解密/清单/数据库版本/受限表目录 | 真实 CLI PASS（verify/info/list/tables 退出 0，schema_history 46 版本） | **PASS** |
| 163-C3 | `preview` 白名单表/受限查询 | 只允许白名单、默认排除敏感字段 | 真实 CLI PASS（users 预览，sensitive_included=false） | **PASS** |
| 163-C4 | `export` CSV/JSON | 默认排除敏感字段；CSV 防公式注入；oplog 元数据 | 真实 CLI PASS（JSON/CSV 导出 + `.login-backup-viewer-oplog.jsonl`） | **PASS** |
| 163-C5 | `extract` 原始数据库条目 | 默认拒绝高敏条目；`--include-sensitive` 显式确认后提取并保护输出 | 真实 CLI：无 include-sensitive 退出 6 拒绝；带参数退出 0、提取 1.55MB 并告警 | **PASS** |
| 163-C6 | 错误密钥/损坏备份 | 明确失败（退出 3/4），不写主库 | 真实 CLI：错误密钥 exit 4、篡改备份 exit 4；失败前后主库 SHA-256 一致 | **PASS** |
| 163-D1 | 维护恢复 preflight/apply/失败回退 | 维护态/停服/排他锁；失败保留可回退状态 | 离线 `maintenance-enter` 返回 INTERNAL_ERROR（临时环境维护状态/密钥前置未满足），restore-preflight 未执行；未伪造通过 | **NOT_TESTED** |
| 163-D2 | 恢复后旧会话/刷新令牌/恢复代码/一次性授权不复活 | 恢复后旧凭证立即失效 | 需要预置会话/令牌/恢复代码夹具与真实 restore apply；本轮未执行 | **NOT_TESTED** |
| 163-E1 | 备份期间输出目录安全/明文快照 | ACL 限制/临时文件清理 | 真实 CLI 输出安全提示；未做多用户 ACL 实测 | **PARTIAL** |

## 2. 已执行命令与结果

```text
# 真实 login-server init（临时 SQLite）+ login-backup 全流程
python scripts/acceptance/step163-backup-audit.py
→ create PASS / verify PASS / info PASS / list PASS / tables PASS / preview PASS
→ export json PASS / export csv PASS / extract（默认拒绝敏感 exit6；显式 include-sensitive exit0）
→ wrong-key verify exit4 / tampered verify exit4；主库 SHA-256 失败前后一致 PASS

# 审计/报告服务层（真实 SQLite + 服务，不含真实 serve 管理会话）
go test ./internal/reports ./internal/auditops ./internal/adminapi   PASS（47.7s/53.0s/42.9s）
```

## 3. NOT_TESTED / 限制

1. 真实 serve + 强认证管理会话下的审计查询/清理、报告五格式/计划/历史/下载未执行（与管理会话夹具同一缺口；未用普通会话冒充 root）。
2. 维护恢复 apply/rollback、维护状态 HMAC/停服排他锁真实验收未运行：离线 `maintenance-enter` 在临时环境返回 INTERNAL_ERROR（未继续猜测绕过）；因此恢复后旧会话/刷新令牌/恢复代码/一次性授权不复活也未验证。
3. 未做备份期间明文快照的 NTFS ACL 多用户实测；未做恢复演练的失败注入矩阵。
4. 未新增产品代码/迁移；未改 Mail；所有临时进程/目录由脚本清理。

## 4. 追加：CSRF 账户公开表单修复（同轮）

步骤 162 发现 `/email/change/verify` 匿名 POST 恒 403；根因 `internal/serverapp/pages.go publicFormPaths()` 漏合并 `UIPageAccountPublicFormPaths`，已修复并扩展 `TestPublicFormPaths...` 回归。真实 serve 验证：匿名 GET 返回 400 页面（路由可达）、带合法 `account.email_change_verify` pagecsrf 令牌与 Cookie 的匿名 POST 返回 **400 内容无效而非 403 CSRF**；该修复不改变本步备份/审计结论。另记录 pagecsrf Cookie `Secure=true` 在明文 HTTP 回环的浏览器发送限制，待后续决策。

## 2026-11-22 00:19 强认证夹具与 163 复跑

- 真实 root 强认证管理会话下 `/admin/v1/audit/events`、`/admin/v1/audit/retention`、`/admin/v1/reports`、`/admin/v1/backups` 均 **200**（路由可达性 PASS）。
- 备份 CLI create/verify/info/list/tables/preview/export JSON+CSV、错误密钥/篡改/DB 未变 PASS。
- `maintenance-enter`/`restore-preflight` 原 INTERNAL_ERROR 已定位为 **验收脚本缺少 `restore-init-state` 且 state-dir 位于数据库目录内**；修正脚本后 init-state/maintenance-enter/preflight 均 PASS。报告生成/下载、恢复 apply/回滚、恢复后凭据失效链仍 NOT_TESTED。证据：`docs/acceptance/evidence/strong-auth-fixture/`。

## 2026-11-22 02:10 最终补跑（VERDICT：PASS_WITH_NOTES）

详见 `docs/acceptance/evidence/step163/step163-final.md`：真实 root 强会话下审计/保留/报告/计划/备份路由 200；backup CLI create/verify/info/list/preview/export/extract PASS；maintenance init-state/enter/preflight PASS。报告五格式生成/下载、restore apply/回滚、恢复后凭据不复活仍 NOT_TESTED，不能勾选完整 163。

## 5. 追加（真实维护恢复链，PASS_WITH_NOTES）

脚本：`scripts/acceptance/step163_restore.py`；证据：`docs/acceptance/evidence/step163/step163-restore-result.json`、`step163-restore.log`。

真实执行（临时 SQLite/回环，不碰真实库）：
1. 真实 `login-server init` + `login-backup create`（B0）；真实 serve 用 root 密码登录创建真实会话（sessions=1），再备份 B1。
2. `restore-init-state`（库外状态，HMAC）→ `maintenance-enter` → `restore-preflight`（10 项全 ok）→ `restore-apply --service-stopped --confirm RESTORE`：
   - 成功，generation=1，`revoked.sessions=1`、`mfa_challenges=1`、`one_time_credentials=1`、`total_deleted=3`，`maintenance_exited=true`，审计合并 12 条；
   - 恢复后活动会话=0，`audit_events=26` 可读，`report_history` 表可读（0 条）。
3. 恢复后重启真实 serve：`/healthz` 200；使用恢复前旧 Cookie 访问 `/home` 返回 401（旧会话未复活）。
4. 失败注入：再次维护 → 篡改备份 → preflight 失败（退出 1）；数据库 SHA-256 与失败前一致；随后 `maintenance-exit` 清理。

结论：恢复 apply/失败回退/旧会话不复活/审计可读 **PASS**。报告受控生成/下载（HTML/PDF/CSV/JSON/Markdown）**NOT_TESTED**：当前无独立 ad-hoc 生成入口，页面生成需计划任务/强管理页面交互；`internal/reports` 五格式/计划/取消服务层测试 PASS，但本轮未生成真实报告产物，未虚报。
