# 步骤196 验收：备份恢复后旧凭据失效与失败审计（PASS_WITH_NOTES）

- 执行者：代码编写团队 并行主力程序员 zfyhelper9，2026-11-23 03:0x–03:1x（Asia/Shanghai）。
- 环境：Windows 11、Go 1.27.4（amd64，`GOMAXPROCS=2`/`-p 2`）；**真实临时 SQLite**（testutil 临时目录，全部迁移）、真实 `internal/backup`（SQLite 在线快照 + 认证加密）与真实 `internal/restore`（维护模式/回退备份/切换/凭证失效/审计合并）；**未触碰 `database/login.db`**。
- 结论：**PASS_WITH_NOTES**。备份内已存在的会话、刷新令牌、授权码、恢复代码、重置链接、一封验证/一次性凭证在恢复后均不可用；恢复走产品真实流程（维护模式→预演→回退备份→切换→同事务凭证失效→审计合并→退出维护），未用“直接改安全版本字段”代替；恢复删除签名密钥使旧 Access Token 失效；恢复失败保持维护并留失败审计、审计合并失败可重试、切换后回滚不复活凭据；恢复代际/库外审计日志不在被回滚数据库内。**未发现需要修改的产品缺陷**——本步以新增验收测试 + 文档固化证据，不改产品逻辑（避免与备份链其他在研改动冲突）。

## 1. 执行命令与结果

| 命令（仓库根） | 退出码 | 结果 |
|---|---|---|
| `gofmt -l internal/restore/step196_acceptance_test.go` | 0 | 空输出 |
| `go build ./...` | 0 | 通过 |
| `go test ./internal/restore/ -count=1 -v` | 0 | **12 PASS / 0 FAIL / 0 SKIP**（含本步新增 `TestRestoreDoesNotRevivePreBackupCredentials`，2.79s；单跑 6.75s） |
| `go test ./internal/restore/ -run 'TestRestoreDoesNotRevivePreBackupCredentials' -count=1 -v` | 0 | PASS |

全量 restore 套件逐条：`TestRehearseStructuredChecksAndCapacity`、`TestRestoreRejectsWrongKey`、`TestRestoreRejectsIncompatibleDatabaseVersion`、`TestRestoreInterruptBeforeSwitchKeepsDatabase`、`TestRestoreInterruptAfterSwitchRollsBack`、`TestRestoreAuditMergeFailureKeepsMaintenanceAndRetries`、`TestRestoreRequiresRestoreLock`、`TestRestoreRequiresRootOrLocalAdmin`、`TestOutsideStateAndJournalAnchorsFailClosed`、`TestInitStateAdoptJournal`、`TestRestoreReplacesDatabaseAndRevokesCredentials`、`TestRestoreDoesNotRevivePreBackupCredentials`。

## 2. 判据与证据矩阵

| 判据 | 证据 | 结果 |
|---|---|---|
| 恢复后**会话**旧凭据拒绝 | 真实 `session.Service` 签发会话并在备份前 `Validate` 成功；真实恢复后同一秘密 `Validate` 返回错误（`TestRestoreDoesNotRevivePreBackupCredentials`） | PASS |
| 恢复后**刷新令牌**拒绝 | 备份前按产品同一 SHA-256 摘要查询路径（`oauthflow/sqlite.Store.GetRefreshTokenByHash`）可查到；恢复后查不到，无法再兑换 | PASS |
| 恢复后**授权码**拒绝 | 备份前 `GetAuthorizationCodeByHash` 可查到；恢复后查不到，无法再兑换；`TestRestoreReplacesDatabaseAndRevokesCredentials` 亦断言恢复删除授权码计数 | PASS |
| 恢复后**恢复代码**拒绝 | 真实 restore 事务清空 `recovery_codes`/`recovery_code_groups`/`recovery_attempts`，计数断言 + 恢复后逐表为 0（明文摘要由密钥派生，见 §5 限制） | PASS |
| 恢复后**重置链接/邮件验证链接**拒绝 | 真实 restore 事务清空 `password_reset_requests`/`email_verification_tickets`/`email_change_requests`，恢复后逐表为 0 | PASS |
| 恢复后**一次性凭证**拒绝 | 真实 `credential.Service` 签发邮件验证令牌，备份前 `Peek` 成功；备份后消费，恢复旧备份后同一令牌 `VerifyAndConsume` 返回错误 | PASS |
| **离线 JWT 因签名密钥删除失效** | 真实 `token.Service`（client_credentials 系统签发）在备份前签发的 Access Token 可 `VerifyAccessToken`；恢复后同一令牌验证失败，且恢复后 `KeyInfos` 不再包含旧 `kid`（签名私钥/密钥记录已被删除） | PASS |
| 客户端缓存 **JWKS** 边界 | 旧公钥可能仍在客户端缓存中，但服务端已无对应密钥记录与私钥；旧 JWT 无法再被本服务验证通过（见 §5 与指南 5.1） | 已文档化 |
| **恢复失败保持维护 + 失败审计** | `TestRestoreAuditMergeFailureKeepsMaintenanceAndRetries`、`TestRestoreInterruptBeforeSwitchKeepsDatabase`、`TestRestoreInterruptAfterSwitchRollsBack` | PASS |
| **审计合并失败可重试** | 同上（合并失败保持维护，修复后重试成功合并） | PASS |
| **回滚数据库不复活已撤销凭证** | `TestRestoreInterruptAfterSwitchRollsBack`：切换后中断回退到恢复前快照，但维护状态与库外锚点使流程不视为完成；只有再次成功恢复才退出维护（重新执行凭证失效） | PASS |
| **恢复代际/密钥撤销机制不在被回滚库内** | `TestOutsideStateAndJournalAnchorsFailClosed`（库外状态/日志锚点缺失即 fail-closed）；本步测试断言恢复后库外状态目录非空、库外恢复日志序号连续，库内 `restore_generation` 与结果一致 | PASS |
| **不得用直接改安全版本字段代替产品恢复流程** | 全部断言走真实 `restore.Service.Execute`（预演/维护/回退备份/切换/后处理/审计合并），测试未改写 `security_version` 等字段 | PASS |

## 3. 本次新增验收测试覆盖的真实操作序列

1. 真实临时 SQLite 迁移 + 种子数据；插入格式合法（`usr_`+32 hex）测试账户，删除不可解密的占位签名密钥。
2. 备份前真实签发：系统 Access Token（真实签名密钥）、普通会话（真实会话服务）、一次性邮件验证令牌（真实凭证服务）；把种子刷新令牌/授权码摘要改为已知明文的 SHA-256，便于恢复后走产品同一条摘要查询路径。
3. 真实加密备份（SQLite 在线快照）。
4. 备份后撤销/消费：真实 `Logout` 撤销会话、真实 `VerifyAndConsume` 消费一次性令牌、刷新令牌置 revoked（模拟“恢复旧快照会复活”的风险窗口）。
5. 恢复旧备份：真实 `restore.Execute` → 维护模式、回退备份、切换、同事务删除 25 类一次性/会话材料与签名密钥、写恢复运行记录/暂停清单、审计合并、退出维护；断言代际=1、`Revoked.SigningKeys≥1`。
6. 恢复后逐类真实尝试并断言拒绝（会话/刷新/授权码/一次性凭证/JWT），逐表为 0，库外状态与日志锚点仍在。

## 4. 恢复删除的凭据材料（实现事实核对）

`internal/restore/postrestore.go` 在同事务删除：`refresh_tokens`、`refresh_token_families`、OAuth 授权码/请求、恢复尝试/恢复代码/恢复代码组、邮箱验证、找回密码、邮箱变更、扫码登录、设备授权、MFA 挑战、WebAuthn 仪式、重认证审批/挑战、邀请/接受、人工恢复执行/审批/请求、注册审核、`sessions`、`one_time_credentials`、`token_signing_keys`；提交前 `verifyNoLiveCredentials` 再次核对，任一仍有存活材料即按 fail-closed 回滚事务。密码哈希/MFA 因素/Passkey/OAuth 客户端密钥属被恢复账户安全状态，不在“一次性凭据复活”范围（设计注释已说明）。

## 5. 未测项与限制

1. **刷新令牌/授权码**：真实恢复删除 + 产品摘要查询路径已断言；未装配完整 `oauthflow` 授权码/刷新流程做“发行→兑换”端到端回放（装配需客户端认证、会话、令牌签发与授权确认多依赖）。这属于“服务层查询路径已证实拒绝”，不是完整协议端点验收。
2. **恢复代码/重置链接/邮件验证**：明文摘要由密钥派生或对应流程发行，测试无法逆推；以真实恢复事务删除计数 + 逐表为 0 覆盖，未做对应流程的明文回放。
3. **真实 HTTP/CLI**：`loginctl restore-preflight/restore-apply` 与 `login-backup` 的真实命令调用未在本步重跑（服务层真实流程已覆盖；CLI 参数与退出码属装配层）。
4. **非 Windows** 未运行；未做长时间/压力测试；备份/恢复使用合成密钥环与临时目录，未接真实生产密钥材料。
5. 回退备份、明文快照的安全擦除等既有“未提供”限制不变（指南第 5 节）。
6. 本步未改产品代码（`git status` 仅新增验收测试与文档）。

## 6. 复现命令

```powershell
$repo = 'P:\go\src\github.com\kagurazakayashi\EvernightLogin'
cd $repo
$env:GOMAXPROCS='2'; $env:GOFLAGS='-p=2'
go build ./...
go test ./internal/restore/ -run 'TestRestoreDoesNotRevivePreBackupCredentials' -count=1 -v
go test ./internal/restore/ -count=1 -v
```
