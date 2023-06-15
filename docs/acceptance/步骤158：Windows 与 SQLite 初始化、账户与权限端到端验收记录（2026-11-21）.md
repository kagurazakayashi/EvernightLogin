# 步骤 158：Windows 与 SQLite 初始化、账户与权限端到端验收记录（2026-11-21）

- 平台：Windows 11；Go 1.27.1 windows/amd64；SQLite（父项目唯一实测数据库）
- 执行者：中肥鱼；时间：2026-11-21 22:40–22:50（Asia/Shanghai）
- 基线：父仓库 HEAD `200bfac`、工作树为并行交付候选（未提交，脏树）；`go version`/HEAD 见 `docs/acceptance/evidence/step158/baseline.txt`
- 所有进程/端口/数据库均在空临时目录与回环地址；未读取/修改 `database/login.db`；未做 Git 写操作；未真实外发邮件/访问公网。
- 结论：**PASS（已测范围 48/48 真实 e2e 检查 + 6/6 TestStep91 场景），PARTIAL/NOT_TESTED 项明确列出，不把 Go 级复用结果冒充 HTTP 管理/浏览器证据。**

## 1. 验收命令与环境

| 项 | 值 |
|---|---|
| 构建 | `scripts/e2e-login-server.ps1` 内部 `go build`（login-server/loginctl/loginte2e/process-harness） |
| 真实进程脚本 | `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/e2e-login-server.ps1 -KeepArtifacts -TimeoutSeconds 600` |
| 账户/权限真实 SQLite 场景 | `GOMAXPROCS=4 CGO_ENABLED=0 go test -count=1 -p 1 -timeout 280s -run 'TestStep91' -v .` |
| CLI 证据 | 从 e2e 临时工作目录运行 `loginctl user list/get`、`group create/list`、`role list`、`app list`、`permission list`、`migrate status` |
| 证据目录 | `docs/acceptance/evidence/step158/`（e2e result/log、TestStep91 log、CLI JSON/err、baseline） |

## 2. 端到端矩阵

| ID | 场景 | 真实入口/证据 | 状态 | 说明 |
|---|---|---|---|---|
| S0 | 基线/构建 | e2e build 阶段；`build.login-server/loginctl/loginte2e/process-harness` PASS；`baseline.txt` | **PASS** | 候选脏树基线；不宣称可复现提交 |
| S1 | 空临时目录/受保护秘密/init root | e2e `config.protected-password-file`、`init.first-run`、`init.no-password-echo`、`init.repeat-rejected` PASS；CLI `migrate status` applied/embedded=`0046` current=true | **PASS** | root 密码在受保护临时文件，不打印；重复 init 拒绝；SQLite 46 条迁移 |
| S2 | 真实 serve + HTTP 表面（normal/protocol/admin/maintenance） | e2e `serve.*`、`health/openapi/login`、`protocol.discovery/jwks`、`admin-api.disabled-404/anonymous-401`、maintenance 503、access log、single-instance | **PASS** | 48 PASS/0 FAIL/5 NOT_TESTED；端口/进程清理断言 PASS |
| S3 | root 强因素绑定（TOTP/Passkey） | e2e 不绑定强因素；TestStep91 不覆盖真实强因素 ceremony | **PARTIAL / NOT_TESTED（浏览器/硬件归 159）** | root 初始化后仍按规定受强认证约束；真实 TOTP/Passkey 绑定与浏览器流程未在本步执行 |
| S4 | 注册/审核/管理员建用户 | `TestStep91RegistrationInviteAndReview` PASS（真实 SQLite/领域服务）；CLI `user list` 仅 root；HTTP 注册/审核/管理建用户未在本步跑 | **PARTIAL** | Go 级真实服务 PASS；真实 HTTP 注册/审核/管理建用户 **NOT_TESTED**（无强认证管理会话；浏览器/页面归 159） |
| S5 | 资料/改名/邮箱变更 | `TestStep91ProfileAndEmailChange` PASS；真实 HTTP 页面流程未跑 | **PARTIAL** | Go 级真实服务 PASS；HTTP 页面 **NOT_TESTED** |
| S6 | 组/角色/权限 + 两应用隔离 | `TestStep91PermissionMatrixAcrossApps`、`TestStep91SelfEscalationAndCrossAppDenied` PASS；CLI `group create`/`group list` PASS（真实 SQLite）；`role list`/`app list` 为空（未创建）；`permission list` 50 项 PASS | **PARTIAL** | 领域/CLI 真实 SQLite PASS；真实角色/应用创建管理 HTTP **NOT_TESTED**（管理强认证会话缺失）；两应用隔离由真实领域服务矩阵覆盖 |
| S7 | 禁用/启用/旧会话失效/强制下线 | `TestStep91AccountLifecycleAndSessionInvalidation` PASS（真实 SQLite）；e2e 负向会话/管理 API；管理员强制下线 HTTP/CLI 未跑 | **PARTIAL** | Go 级生命周期/会话失效 PASS；真实 HTTP 管理强制下线 **NOT_TESTED**（151 范围） |
| S8 | 拒绝/越权路径 | e2e：admin API 匿名 401、disabled 404、maintenance 503、single-instance、fake session；TestStep91：自我提权/跨应用拒绝 PASS | **PASS（已测范围）** | 未认证/错误会话/禁用/维护/越权均有真实拒绝；管理强认证成功路径见 S4/S6 的 NOT_TESTED |
| S9 | 审计/清理 | TestStep91 审计断言 PASS；e2e `hygiene.no-child-processes`、`hygiene.port-released`、`repo.database-untouched`、`hygiene.no-secret-in-captured-output` PASS；CLI audit events（需在线强认证会话）未跑 | **PARTIAL** | 真实进程清理与仓库 DB 未变 PASS；在线审计查询 **NOT_TESTED**（缺管理强认证会话） |

## 3. 真实证据摘要

### 3.1 e2e（48 PASS/0 FAIL/5 NOT_TESTED）
- 构建四组件 PASS；受保护密码文件、首次 init、重复 init 拒绝、无密码回显 PASS。
- 正常 serve：healthz/openapi/login、双实例 DB 锁拒绝、Ctrl+Break 有界关闭、端口释放、访问日志、仓库 DB 未改 PASS。
- protocol/admin 启用：OIDC discovery、JWKS、loginte2e discovery/JWKS、admin API 匿名 401、CLI 无/伪造会话拒绝 PASS。
- maintenance：enter/health 200/业务页 503/protocol 503/admin 503/exit/ready PASS。
- 5 项 NOT_TESTED：真实强认证管理会话、authcode/token/device/QR 套件、TLS/mTLS/反代、真实邮件/Webhook、Windows CTRL_CLOSE/SIGTERM。
- 证据：`docs/acceptance/evidence/step158/e2e-run.log`、`e2e-result.json`（pass 48/fail 0/not_tested 5）。

### 3.2 TestStep91（真实 SQLite + 真实领域服务）
`TestStep91AccountLifecycleAndSessionInvalidation`、`RegistrationInviteAndReview`、`ProfileAndEmailChange`、`PermissionMatrixAcrossApps`、`SelfEscalationAndCrossAppDenied`、`SupportRecoveryFlow` 全部 PASS（6/6 顶格 Test）。
证据：`docs/acceptance/evidence/step158/teststep91.log`。

### 3.3 CLI（真实临时 SQLite）
- `user list`：root 用户（`usr_...`，security_version=2）。
- `group create`/`group list`：真实创建并读回 `grp_...`（system scope）。
- `role list`/`app list`：空（未通过 CLI 创建；CLI 不开放这些写入口）。
- `permission list`：50 项预设权限。
- `migrate status`：applied/embedded=`0046`，current=true。
证据：`docs/acceptance/evidence/step158/cli-*.json`。

## 4. NOT_TESTED / PARTIAL 原因

1. **真实浏览器/强因素绑定**：本步没有浏览器/CDP 与 Windows Hello/安全密钥 ceremony；root 初始化后强认证约束未以真实 TOTP/Passkey 绑定验证（159 范围）。
2. **真实 HTTP 管理写入**：管理 JSON API 的强认证管理会话未在本步构造；注册/审核/管理建用户/角色/应用/强制下线只做了 Go 级真实服务与 e2e 负向路径，未把领域矩阵冒充 HTTP 成功证据。
3. **CLI 在线审计/组角色写**：CLI 只开放本地读取与受控建组；角色/应用/权限写与在线审计查询需要管理 API 强认证会话，本步未执行。
4. **非 Windows/非 SQLite**：按项目约定不实测；仅本机 Windows+SQLite。
5. **脏树基线**：当前工作树为并行步骤候选且未提交，不能称干净可复现发布基线；用户提交后应重跑 e2e/158 作为最终证据。

## 5. 清洁与边界

- e2e 工作目录在 `C:\Users\yashi\AppData\Local\Temp\...\login-e2e-*`，证据已复制到仓库 `docs/acceptance/evidence/step158/` 后删除；无残留 login-server 进程/监听端口（e2e hygiene PASS）。
- 未读取/修改仓库 `database/login.db`（e2e `repo.database-untouched` PASS）；未改 Mail 子模块；无 Git 写操作；临时密码/会话秘密未进入证据。
- CLI 在临时数据库创建了一个合成组 `step158-readers`，只存在已删除的临时目录，不进入仓库。
