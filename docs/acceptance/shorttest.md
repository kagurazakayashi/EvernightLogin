# 无人值守短测试统一入口（scripts/shorttest.ps1）

本文件说明第 10 轮步骤 203 建立的**统一短测试入口**与**机器可读能力清单**。两者都是
开发/验收工具，不进入发布包，不改变产品运行时行为。

- 统一入口：`scripts/shorttest.ps1` + 场景注册表 `scripts/shorttest/scenarios.json`
  + 场景 Go 程序 `scripts/shorttest/scenario/<id>/`；
- 能力清单：生成器 `scripts/capabilities/` + 声明 `scripts/capabilities/catalog.json`，
  产物 `docs/acceptance/capability-matrix.json` 与 `capability-matrix.md`。

## 1. 为什么需要统一入口

后续领域测试（找回、MFA、公开门面、分页等）都需要同样的资源纪律。若每个步骤各写一套
脚本，容易出现：临时目录/端口/子进程残留、总超时失控、结果格式不一致、临时秘密进入
日志。统一入口把这些横切约束集中到一处，场景只实现业务步骤与检查项：

| 入口职责 | 实现方式 |
|---|---|
| 临时数据目录 | `%TEMP%\evernight-shorttest-<时间>-<随机>` 唯一目录；默认结束删除（`-KeepArtifacts` 保留） |
| 动态回环端口 | 场景绑定 `127.0.0.1:0` 取得端口；入口在结束后验证端口可重新绑定 |
| 合成用户/秘密 | 场景内随机生成（本步场景为合成 root 密码）；入口与结果 JSON 不含秘密值 |
| 总超时 | `-TimeoutSeconds`（默认 180，范围 5～1800）覆盖构建+运行+清理；超时结束整棵子进程树 |
| 子进程退出与清理 | 记录退出码/超时/剩余进程；只终止入口自己启动的进程 |
| 结构化结果 | stdout 单行 JSON（`evernight.shorttest.result/v1`），`-Out` 可落盘 |
| 并发预算 | 读取本机逻辑处理器数，`floor(N/2)`（本机 4 → 2），设置 `GOMAXPROCS` 与 `go build -p` |

每个运行都会校验并写入结果 JSON 的 `cleanup` 段：`workdir_removed`、`port_released`、
`tracked_processes`、`processes_remaining`。清理校验失败时即便场景本身 PASS 也判 FAIL。

## 2. 使用

```powershell
# 列出已登记场景（JSON）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\shorttest.ps1 -List

# 真实 login-server 初始化 + 监听 + 失败关闭拒绝路径（本步实际跑通的真实短场景）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\shorttest.ps1 `
  -Scenario login-server-smoke -TimeoutSeconds 240 `
  -Out docs\acceptance\evidence\step203\shorttest-login-server-smoke.json

# 入口自身超时/终止/清理自检（预期 TIMEOUT，退出码 1；不是产品测试）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\shorttest.ps1 `
  -Scenario harness-timeout -TimeoutSeconds 20 `
  -Out docs\acceptance\evidence\step203\shorttest-harness-timeout.json
```

退出码：`0`=场景 PASS；`1`=FAIL/TIMEOUT；`2`=参数错误/未知场景；`3`=注册表/构建/环境错误。
参数拒绝与未知场景也会输出结构化 JSON（`status=ERROR`），不会误判为 PASS。

## 3. 场景契约与新增方式

`scenarios.json` 每项字段：

| 字段 | 说明 |
|---|---|
| `id` | 场景标识（命令行 `-Scenario`） |
| `title` | 人类可读名称 |
| `program` | 场景 Go 包路径（`go build` 目标，须为 `package main`） |
| `needs_server_binary` | 是否需要入口先构建 `./cmd/login-server` |
| `timeout_seconds` | 场景自身超时上限（入口还会受 `-TimeoutSeconds` 总预算约束） |
| `arguments` | 参数模板，支持 `{workdir}`/`{server}`/`{timeout}`/`{result}` 占位 |
| `covers` | 覆盖的能力 id（与 `scripts/capabilities/catalog.json` 对应，便于交叉核对） |
| `notes` | 边界与限制说明 |

场景程序必须：把数据只写到 `-workdir`；秘密只进受保护临时文件且不打印；结束前删除
自己创建的临时文件；向 stdout 只输出一行结构化 JSON（`evernight.shorttest.scenario-result/v1`），
失败时以非零退出码传播；可用 `-result` 同时落盘。入口不把"无输出"当成功。

新增领域测试时：在 `scripts/shorttest/scenario/` 下新增 `package main`，在
`scenarios.json` 登记，并在能力声明/验收记录中引用 `covers`。不要复制第二套临时目录、
端口、超时与清理逻辑。

## 4. 本步实际运行边界（2026-11-25，Windows 11）

- 已跑通：`login-server-smoke`（14 项检查全 PASS，wall 约 9.3s；含成功路径与
  admin API/协议端点未启用时 404 fail-closed 拒绝路径、重复 init 拒绝、端口释放、
  临时秘密删除、临时目录清理）。
- 已跑通（拒绝/失败路径）：未知场景、非法超时参数均返回 exit 2 + `status=ERROR`；
  `harness-timeout` 在入口超时后被强制终止并清理（`status=TIMEOUT`，exit 1）。
- **未测**：Linux/macOS 上运行（本步只做 Windows 实测）；真实浏览器/读屏；真实硬件
  Passkey；长时间并发/压力。能力清单中的测试证据只证明"定向测试函数存在"，不证明
  当前全部通过；通过性需按能力清单的测试路径另跑 `go test`（本轮由审计员做全量回归）。

## 5. 机器可读能力清单

```powershell
$env:GOTOOLCHAIN='local'; $env:GOMAXPROCS='2'
go run ./scripts/capabilities -strict
```

产出 `docs/acceptance/capability-matrix.json`（机器可读）与同名 `.md`（同数据生成）。
状态由"声明面是否在源码中真实解析到"决定：`implemented` / `implemented_untested` /
`missing` / `unimplemented`；反向覆盖段列出未被任何能力声明覆盖的生产面。`-strict`
时有 missing 或未覆盖项会返回退出码 3，可作为后续步骤的回归门禁。

## 6. 场景：embedded-minimal-selftest（步骤 240）

`embedded-minimal-selftest` 由步骤 240 登记，用于验证"最小嵌入示例"这一外部
Module 的真实可运行性；示例本身在 `examples/embedded-minimal/`（独立 go.mod，
只导入公开包 `login` 与 `app`，不导入 `internal/`）。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\shorttest.ps1 `
  -Scenario embedded-minimal-selftest -TimeoutSeconds 180 `
  -Out docs\acceptance\evidence\step240\shorttest-embedded-minimal.json
```

场景行为：在入口临时目录内 `go build` 外部示例 Module → 运行示例
`-self-test -json`（示例自己用真实临时 SQLite 与 127.0.0.1 动态端口，覆盖打开
实例、受控初始化、注册、登录成功/拒绝、会话校验与撤销、HTTP/UI 页面与 CSRF/401/
403、宿主受保护路由、显式启停与清理）→ 解析示例 JSON，断言 15 项检查全部 PASS，
并**独立核验**：示例临时数据目录已删除、动态端口已释放、场景构建产物已删除、
入口临时目录无残留文件。任一断言失败或清理校验失败都返回非零退出码。

预期：`status=PASS`、`exit_code=0`；结果 JSON 中 `checks[]` 是场景检查，
`example_result` 是示例自身结构化结果，`cleanup` 是场景独立清理证据。

## 7. 场景：custom-pages-profile-sync-selftest（步骤 241）

`custom-pages-profile-sync-selftest` 由步骤 241 登记，验证"宿主自定义页面与资料
同步示例"这一外部 Module 的真实可运行性；示例在
`examples/custom-pages-profile-sync/`（独立 go.mod，只导入公开包）。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\shorttest.ps1 `
  -Scenario custom-pages-profile-sync-selftest -TimeoutSeconds 240 `
  -Out docs\acceptance\evidence\step241\shorttest-custom-pages-profile-sync.json
```

场景行为：在入口临时目录内 `go build` 外部示例 Module → 运行示例
`-self-test -json`（示例自己用真实临时 SQLite、127.0.0.1 动态端口与进程内本地邮件
捕获器，覆盖宿主自定义页面并存挂载、匿名 CSRF 拒绝、注册→邮箱验证邮件→登录、
资料读取/白名单更新、受控改名与业务投影按稳定 UserID 同步、跨用户修改拒绝、找回
密码→重置→旧会话失效→新密码登录、MFA 受限会话不建立宿主会话、显式启停与清理）→
解析示例 JSON，断言 **23 项检查**全部 PASS，并**独立核验**：示例临时数据目录已删除、
HTTP 动态端口已释放、本地邮件捕获器端口已释放、场景构建产物已删除、入口临时目录
无残留文件。任一断言失败或清理校验失败都返回非零退出码。

预期：`status=PASS`、`exit_code=0`；`cleanup` 段含 `port_released`、
`mail_port_released`、`workdir_removed`、`processes_remaining` 等清理证据。

## 8. 场景：app-delegation-support-selftest（步骤 242）

`app-delegation-support-selftest` 由步骤 242 登记，验证“应用委派管理与客服示例”
这一外部 Module 的真实可运行性；示例在 `examples/app-delegation-support/`
（独立 go.mod，只导入公开包）。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\shorttest.ps1 `
  -Scenario app-delegation-support-selftest -TimeoutSeconds 120 `
  -Out docs\acceptance\evidence\step242\shorttest-app-delegation-support.json
```

场景行为：在入口临时目录内 `go build` 外部示例 Module → 运行示例
`-self-test -json`（示例使用真实临时 SQLite/主密钥，不监听端口/不访问网络；覆盖
两个应用共享账户但成员/权限隔离、应用范围权限/角色、委派资格授予/撤回与跨 scope
拒绝、confidential OAuth 客户端一次性秘密、业务投影稳定 UserID/CreatedAt≠LinkedAt、
客服工单在无真实客服会话时 fail-closed、人工恢复制度只读、跨应用/错误版本资料更新
拒绝）→ 解析示例 JSON，断言至少 10 项检查全部 PASS，并独立核验示例临时数据目录与
场景构建产物已删除。预期 `status=PASS`、`exit_code=0`。
