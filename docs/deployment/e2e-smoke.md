# login-server 端到端冒烟测试（真实进程 + 真实 SQLite）

本文说明可复用测试器 `scripts/e2e-login-server.ps1` 的用途、前置条件、运行方式、
覆盖矩阵、输出与真实现状。测试器面向**真实 `login-server` 进程**：真实编译、真实
`init`、真实监听回环随机端口、真实临时 SQLite、真实管理 CLI 与协议套件调用，用于
发布前验收与回归。

## 1. 用途与定位

- 验证独立服务装配：`init` 首次初始化、`serve` 启动/关闭、内置页面、健康检查与
  OpenAPI、协议端点开关、管理 JSON API 开关、维护模式、单实例数据库锁、访问日志。
- 验证命令行边界：`loginctl config validate`、`diag health`、`diag ready`、
  `maintenance-enter`/`maintenance-exit`、在线命令（`tasks get`）的稳定退出码。
- 以 `tools/loginte2e` 的真实套件验证 `discovery` 与 `jwks` 协议契约。
- 每次运行生成结构化 `result.json` 与终端摘要；可直接作为发布前门禁（退出码 0/1）。

**不做什么**：不修改仓库、不调用 Git、不读写仓库 `database/login.db`、不连接外部
网络（仅 `127.0.0.1`）、不真实外发邮件/Webhook、不打印密码或会话秘密。

## 2. 前置条件

| 条件 | 说明 |
|---|---|
| 操作系统 | Windows 11（当前实现；依赖 Windows 控制台进程组与 ACL 检查） |
| PowerShell | Windows PowerShell 5.1 或 PowerShell 7（脚本为纯 ASCII，兼容两者） |
| Go 工具链 | 用当前 `PATH` 中的 `go` 构建 `login-server`、`loginctl`、`loginte2e`；需要可写 `GOCACHE`/`GOTMPDIR`（沿用环境） |
| 权限 | 当前用户可创建临时目录、对临时文件设置 DACL（`icacls`）；无需管理员 |
| 网络 | 仅需回环；脚本显式忽略代理环境变量并清理 MSYS2 的大小写重复环境变量 |
| 仓库 | 在仓库根目录执行（脚本按 `$PSScriptRoot` 定位仓库，不依赖当前目录） |

并发约束：脚本设置 `GOMAXPROCS=floor(逻辑处理器/2)`、`CGO_ENABLED=0`，并对 Go 构建
使用 `-p 3`；同一时间只运行一个测试实例即可。

## 3. 运行方式

```bat
:: 仓库根目录；默认 300 秒总超时
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\e2e-login-server.ps1

:: 保留临时产物（成功也保留）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\e2e-login-server.ps1 -KeepArtifacts

:: 自定义总超时（30～1800 秒）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\e2e-login-server.ps1 -TimeoutSeconds 600
```

参数：

| 参数 | 默认 | 说明 |
|---|---|---|
| `-KeepArtifacts` | 关闭 | 成功时也保留临时工作目录（含 `result.json` 与原始进程日志） |
| `-TimeoutSeconds` | `300` | 全流程墙钟上限；超时记为失败并进入清理 |

退出码：`0` = 没有 FAIL（允许存在 NOT_TESTED）；`1` = 至少一个 FAIL，或总超时/提前中止。

默认清理策略：通过时删除临时目录；失败时保留临时目录作为最小脱敏证据并打印路径，
确认后可手动删除（其中含测试数据库、随机测试密码文件与日志，均为临时内容）。

## 4. 测试环境与安全边界

每次运行在 `%TEMP%` 下创建唯一目录（例如 `login-e2e-<时间>-<随机>`），其中：

- 临时 SQLite：`data/login.db`；库外维护状态 `data-maintenance/`（默认位置规则）。
- 主密钥环：`secrets/master.key`，由 `init` 以平台受保护权限生成。
- root 密码：随机生成，写入仅当前用户/SYSTEM/Administrators 可访问的临时文件后交给
  `init --password-file`；**从不打印、不进入命令行、不写日志**，运行结束随目录清理。
- 配置：回环随机端口、TLS 关闭、Passkey 关闭、注册关闭、邮件/Webhook 本地禁用；
  `protocol.issuer` 指向本次回环地址，通过 `--enable-protocol`/`--enable-admin-api`
  控制开关（因此“未启用 404”与“启用后行为”是同一配置的真实对照）。
- 访问日志：`logs/access-*.log`（文件模式，验证真实写入且不含测试秘密）。
- 进程控制：脚本在临时目录内生成一个仅用标准库的 Go 助手 `e2e-proc.exe`，用于
  `CREATE_NEW_PROCESS_GROUP` + Ctrl+Break 的有界优雅关闭验证；助手随临时目录删除。

安全断言：仓库 `database/login.db` 运行前后 SHA-256/存在性不变；所有捕获输出扫描
随机密码与测试会话秘密，出现即失败。

## 5. 覆盖矩阵（check id）

共 53 项：**48 PASS / 0 FAIL / 5 NOT_TESTED**（2026-11-21 本机实测；JWKS 启动预引导修复后复跑，退出码 0，见第 8 节）。

| 阶段 | check id | 断言 |
|---|---|---|
| 环境/构建 | `env.normalized`、`build.login-server`、`build.loginctl`、`build.loginte2e`、`build.process-harness` | 环境隔离；三个真实二进制与临时进程助手构建成功 |
| 配置/初始化 | `config.protected-password-file`、`init.first-run`、`init.no-password-echo`、`init.repeat-rejected` | 受保护随机密码文件；`init` 创建唯一 root 并进入 `setup_verified`；不回显密码；重复 `init` 被拒绝 |
| 正常模式 | `serve.start-normal`、`http.healthz`、`http.openapi`、`ui.login-page`、`protocol.disabled-404`、`admin-api.disabled-404`、`cli.config-validate`、`cli.diag-health`、`single-instance.rejected`、`access-log.written`、`shutdown.ctrl-break-normal` | 真实监听就绪；健康/文档/登录页；协议与管理 API 未启用时 404；CLI 本地命令；同库第二实例被拒；访问日志；Ctrl+Break 有界关闭并释放端口 |
| 协议/管理 API | `serve.start-protocol-admin`、`protocol.discovery`、`protocol.jwks-reachable`、`protocol.jwks-signing-key`、`loginte2e.discovery`、`loginte2e.jwks`、`admin-api.anonymous-401`、`cli.online-missing-session`、`cli.online-invalid-session-file`、`cli.online-fake-session`、`access-log.protocol-run`、`shutdown.ctrl-break-protocol` | Discovery issuer/端点一致；JWKS 可解析且含签名公钥；loginte2e 套件；管理 API 匿名 401；在线 CLI 稳定退出码（缺参数=2、无效/伪造会话文件=4）；访问日志；优雅关闭 |
| 维护模式 | `maintenance.enter`、`serve.start-maintenance`、`maintenance.healthz`、`maintenance.login-503`、`maintenance.protocol-503`、`maintenance.admin-api-503`、`shutdown.ctrl-break-maintenance`、`maintenance.exit`、`maintenance.ready-after-exit` | 受控进入维护；维护下健康 200（`mode=maintenance`）、页面/协议/管理 API 一律 503；优雅关闭；退出维护后 `diag ready` 为 ok |
| 维护后恢复 | `serve.start-after-maintenance`、`serve.post-maintenance-endpoints`、`shutdown.ctrl-break-final` | 退出维护后可正常启动；协议 200、管理 API 401 证明回到正常装配；再次优雅关闭 |
| 限制登记 | `admin-api.strong-auth-session`、`protocol.authcode-token-device-qr`、`tls.mtls-and-proxy`、`notifications.external-delivery`、`shutdown.sigterm-ctrl-close` | NOT_TESTED，原因见第 7 节 |
| 资源卫生 | `hygiene.no-child-processes`、`hygiene.port-released`、`hygiene.no-secret-in-captured-output`、`repo.database-untouched` | 无残留进程、端口释放、输出不含测试秘密、仓库数据库未触碰 |

## 6. 输出与证据

- 终端：每项 `[PASS]/[FAIL]/[NOT_TESTED] <id> - <说明>`，末尾打印 PASS/FAIL/NOT_TESTED
  计数、失败清单、NOT_TESTED 清单与产物路径。
- 临时目录：`result.json`（结构化：`host`、`config`、`summary`、`checks[]`、
  `failed_checks[]`、`limitations[]`、`duration_ms`）与 `logs/` 下每个子进程的
  stdout/stderr/退出码 JSON。证据字段已脱敏并截断，不含密码与会话秘密。
- 失败时默认保留上述目录；成功时默认删除（`-KeepArtifacts` 可保留）。

## 7. 已知限制（NOT_TESTED 与设计边界）

1. **管理会话强认证**：管理 JSON API 只验证“未启用 404 / 匿名 401 / 维护 503”；
   真实强认证（Passkey/MFA）会话无法无人值守取得，管理写操作未测。
2. **协议套件范围**：`authcode`/`token`/`device`/`qr` 需要已登记 OAuth 客户端与真实
   浏览器会话 Cookie；当前版本没有无人值守的客户端登记入口，故未纳入。
3. **TLS/mTLS/反向代理**：本测试使用回环明文；TLS、mTLS、可信代理与证书轮换未测。
4. **真实通知投递**：邮件发送器在产品内为显式“未配置”，脚本从不外发；Webhook 端点
   管理入口未开放，未测真实出站。
5. **Windows 信号语义**：脚本通过 Ctrl+Break 验证有界优雅关闭（Go 运行时映射为
   `os.Interrupt`，与 SIGINT/SIGTERM 使用同一取消上下文）；CTRL_CLOSE/SIGTERM 需要
   关闭控制台窗口，会连带影响测试控制台，故未直接触发。
6. **端口选择**：先取空闲回环端口再启动；极小概率被并发抢占会以启动失败告真相，
   不自动重试。
7. **平台**：脚本为 Windows 专用（进程组/ACL/icacls）；Linux/macOS 未提供等价脚本。

## 8. 真实运行现状（2026-11-21，Windows 11 / amd64 / Go 1.27.1）

命令：`powershell -NoProfile -ExecutionPolicy Bypass -File scripts\e2e-login-server.ps1 -TimeoutSeconds 420`

结果：**PASS=48 / FAIL=0 / NOT_TESTED=5 / 总计 53**，退出码 **0**（本机实测，含 4 次
Go 构建，约 40 秒级）；PASS 运行结束时脚本按默认策略删除临时目录。

修复前后对照（同一脚本、同一主机）：

| 阶段 | 结果 | 说明 |
|---|---|---|
| 修复前基线（首次真实运行） | 45 PASS / 3 FAIL / 5 NOT_TESTED，退出码 1 | `protocol.jwks-signing-key`（`/jwks` 200 但 `{"keys":[]}`，`keys=0`）、`loginte2e.discovery`（`fail=1`：`jwks_reachable=JWKS 不含任何公钥`）、`loginte2e.jwks`（`fail=1`：`jwks_document=JWKS 不含任何公钥`） |
| 修复后（当前工作树复跑） | **48 PASS / 0 FAIL / 5 NOT_TESTED，退出码 0** | `protocol.jwks-signing-key` PASS（JWKS 非空）；`loginte2e.discovery`、`loginte2e.jwks` PASS（session 相关用例按工具文档跳过） |

缺口与修复（**已关闭**）：全新实例此前在首次令牌签发前 JWKS 为空，因为签名密钥只在
首次签发时懒引导（`internal/token` 的 `ensureActiveKey`）。后续修复新增了
`internal/token.EnsureSigningKey`（幂等、系统主体审计），并在
`internal/serverapp/protocol_domains.go` 的协议装配启动阶段预引导，使**启动即发布
非空 JWKS**；`tools/loginte2e` 的 `discovery`/`jwks` 套件对全新实例随之为 PASS。
回归价值：如果后续改动移除启动预引导，本测试器的 `protocol.jwks-signing-key`、
`loginte2e.discovery`、`loginte2e.jwks` 三项会立即重新变红。

另注：任务简报期望“无 `--session-file` 时在线命令退出码 4”，实际实现把“缺少必需
参数”归类为用法错误（稳定退出码 2，见 `internal/managecli/online.go` 的
`onlineTarget`）；无效/伪造会话文件才是 4。脚本按真实契约断言为 2，并在该项 evidence
中记录实际值。

48 项 PASS 覆盖第 5 节全部主要路径，包括 4 次 Ctrl+Break 有界优雅关闭（正常模式、
协议+管理 API 模式、维护模式、维护后模式，均退出码 0 且端口释放）、同库第二实例被拒
（退出码 1）、维护模式 503、访问日志写入、仓库数据库零改动。

## 9. 清理与排障

- 通过时脚本自动删除临时目录；失败时保留并打印路径。确认后可手动删除该目录。
- 若怀疑有残留进程/端口：`Get-Process login-server`、
  `Get-NetTCPConnection -State Listen`；脚本结束会强制清理自己启动的子进程。
- 失败时优先看临时目录 `result.json` 的 `failed_checks` 与 `logs/proc-*.err`；
  `logs/bootstrap-*` 是构建阶段的输出。
