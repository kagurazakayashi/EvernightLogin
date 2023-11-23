# 最小嵌入示例（embedded-minimal）

这是一个**真实外部 Go Module** 的最小可运行示例：只导入公开包
`github.com/kagurazakayashi/EvernightLogin`（包名 `login`）与 `.../app`，不导入
仓库的 `internal/`。本目录有自己的 `go.mod`，通过 `replace ../..` 指向本地仓库。
Go 的 internal 规则禁止模块外导入 `internal/`，所以本示例能编译、能运行本身就证明
公开装配 API 没有泄漏内部类型。

它演示的最小链路：

1. 打开实例（`app.Open`，只构造、不监听、不启动后台任务，状态 `new`）；
2. 受控本地初始化管理员（`Runtime.Bootstrap().EnsureRoot`，不经任何 HTTP 参数）；
3. 通过公开注册接口创建合成用户（`Runtime.Users().Create`）；
4. 登录成功/失败（`Runtime.Auth().Login`，失败返回稳定 `AUTH_FAILED`）；
5. 会话校验（`Runtime.Sessions().Validate`）与撤销（`Runtime.Sessions().Revoke`）；
6. 把 HTTP/UI 挂到宿主自己的 `http.ServeMux` 与 `http.Server`（`Runtime.Mount`）：
   登录/注册页面、CSRF 拒绝、未认证管理页 401、普通用户管理页 403；
7. 宿主受保护业务路由：用公开 `Sessions.Validate` 在宿主 HTTP 边界校验会话，
   未认证 401、有效会话 200、撤销后 401；
8. 显式 `Runtime.Start`、`Ready`、重复 `Start` 拒绝、幂等 `Close`；
9. 关闭并删除临时数据目录（真实临时 SQLite，动态 127.0.0.1 端口，不污染旧数据）。

## 运行方式

```powershell
# 有界自检：stdout 只输出一行 JSON，退出码 0=全部通过、1=失败
cd examples/embedded-minimal
go run . -self-test -json

# 有界自检：人类可读摘要
go run . -self-test

# 显式启动演示（默认 127.0.0.1 动态端口；Ctrl+C 或 -duration 到期后自动清理）
go run . -demo
go run . -demo -duration 30s

# 独立编译与测试（嵌套 module 需要在本目录执行）
go build ./...
go vet ./...
go test ./...
```

一键自检（推荐；统一入口负责临时目录、总超时、子进程退出与清理校验，并输出
结构化 JSON）：

```powershell
# 在仓库根执行
pwsh -NoProfile -File scripts/shorttest.ps1 -Scenario embedded-minimal-selftest
```

退出码与结果：0=`PASS`，1=`FAIL/TIMEOUT`，2=参数错误，3=环境/构建错误；结果 JSON
的 `checks[]` 列出每个检查项，`cleanup` 段给出临时目录/端口/进程清理证据。

## 演示模式会打印什么

- EvernightLogin 登录页/注册页地址（`/idp/login`、`/idp/register`）；
- 宿主自己的 `/healthz` 与受保护路由 `/api/whoami`；
- 临时数据目录路径；
- 演示账户名与**临时凭据文件**路径（密码只写在该文件，不打印到日志；文件与
  数据目录一起在退出时删除，`-keep-data` 可保留用于排查）。

演示模式不会常驻后台，也不会把本地管理员（`LocalAdmin`）暴露给任何 HTTP 请求；
受保护路由只接受宿主自己 Cookie 里的会话秘密并经公开 `Sessions.Validate` 校验。

## 预期输出（自检 JSON 节选）

```json
{
  "schema": "evernight.embedded-minimal.selftest/v1",
  "status": "PASS",
  "mode": "self-test",
  "listen_addr": "127.0.0.1:52341",
  "port": 52341,
  "http_prefix": "/idp",
  "data_dir": "C:\\Users\\<user>\\AppData\\Local\\Temp\\evernightlogin-embedded-minimal-123456",
  "data_dir_removed": true,
  "checks": [
    {"id": "runtime.opened", "status": "PASS", "detail": "state=new; http_prefix=/idp; listen=127.0.0.1:52341"},
    {"id": "bootstrap.root", "status": "PASS", "detail": "root_user_id=usr_..."},
    {"id": "registration.user_created", "status": "PASS", "detail": "user_id=usr_... username=embedded-user status=active"},
    {"id": "login.bad_password_rejected", "status": "PASS"},
    {"id": "login.success", "status": "PASS"},
    {"id": "session.validate", "status": "PASS"},
    {"id": "http.ui.page", "status": "PASS"},
    {"id": "http.ui.csrf_reject", "status": "PASS", "detail": "缺 token=403; 跨来源=403"},
    {"id": "http.ui.login_submit", "status": "PASS", "detail": "login=303 home=200 admin=403"},
    {"id": "http.ui.admin_unauthorized", "status": "PASS", "detail": "未认证管理页=401"},
    {"id": "host.protected_route", "status": "PASS"},
    {"id": "lifecycle.start_ready", "status": "PASS"},
    {"id": "session.revoke", "status": "PASS"},
    {"id": "lifecycle.close_idempotent", "status": "PASS"},
    {"id": "cleanup.temp_data_removed", "status": "PASS"}
  ],
  "duration_ms": 1234
}
```

端口、用户 ID、临时目录与耗时每次都不同，上例仅为格式示意。

## 已知范围（不夸大）

- 只覆盖密码登录与无第二因素场景；TOTP/Passkey/MFA、找回密码、邮件、多实例、
  真实浏览器交互不在本示例范围内（其他示例/测试覆盖）。
- 只实测 Windows amd64 / Go 1.27.4 / `CGO_ENABLED=0`；未做非 Windows、`-race`、
  反向代理/TLS 部署实测。
- 示例的 Cookie 只是本地演示写法，真实宿主应使用 HTTPS、`HttpOnly`、`SameSite`
  等属性；受保护路由只做会话有效校验，业务操作还应调用 `Sessions.Authorize`
  检查应用绑定与所需权限。
