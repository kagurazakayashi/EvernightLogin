# 宿主自定义页面与用户资料同步示例（custom-pages-profile-sync）

这是第二个自包含嵌入示例：**宿主自己的登录/注册/邮箱验证/找回/重置/资料页面**与
EvernightLogin 内置页面在同一站点并存，业务侧按**稳定 UserID** 同步资料投影。

- 真实外部 Go Module：本目录有自己的 `go.mod`，通过 `replace ../..` 指向本地仓库；
  只导入公开包 `github.com/kagurazakayashi/EvernightLogin`（包名 `login`）与
  `.../app`，不导入仓库的 `internal/`；
- 真实资源：临时 SQLite、`127.0.0.1` 动态端口、进程内本地邮件捕获器（明文回环
  SMTP，仅本示例自检/演示使用）；不访问外网、不需要前端工具链；
- 宿主页面只调用公开 Go 接口：`Auth().Login`、`Registration().RegisterAccount/
  VerifyEmail`、`PasswordReset().Request/ValidateTokenWithSource/Complete`、
  `Profile().GetProfile/UpdateProfile/ChangeUsername`、`Sessions().Validate/
  ValidateCSRF/Revoke`。

## 覆盖内容

1. **页面并存挂载**：宿主页面注册在 Evernight 固定前缀下的精确路径（`/idp/login`、
   `/idp/register`、`/idp/email/verify`、`/idp/login/forgot-password`、
   `/idp/login/reset-password`），精确模式优先于挂载的内置前缀子树；其余内置页面
   （如 `/idp/home`、`/idp/403`）仍由 Evernight 提供，路由不冲突。
2. **认证安全不绕过**：宿主页面自行实现同源校验 + 匿名表单双提交 CSRF；已登录表单
   用公开 `Sessions.ValidateCSRF` 校验与会话绑定的令牌。密码校验、失败限制与审计
   仍由 EvernightLogin 领域层执行；启用第二因素的账户只得到受限会话，宿主页面
   **不建立会话**（不绕过 MFA）。
3. **邮箱验证与找回**：注册走公开注册接口并触发真实验证邮件；自检从本地邮件捕获器
   解析一次性验证/找回链接，经宿主验证页/重置页调用公开接口完成；找回遵循防枚举
   文案，重置成功后旧会话与旧密码失效。
4. **资料公开接口**：资料读取、白名单字段更新（昵称/简介/语言/时区）、受控改名
   （当前密码再次认证 + 冷却/保留名由领域判定）；错误密码与过期资料版本被稳定拒绝。
5. **业务资料投影**：业务记录只按稳定 UserID 关联；`username` 是只读同步展示值，
   更名不换身份；清楚区分账户 `CreatedAt`（来自公开资料视图）、业务 `LinkedAt`
   （业务首次关联时间）与业务 `BusinessUpdatedAt`（业务侧最近同步时间，未同步时
   显示“未同步”，不虚构账户上不存在的业务字段）。
6. **跨用户拒绝**：普通用户不能修改他人资料，也不能用普通会话冒充管理员；
   Bob 修改本人资料不影响 Alice。
7. **清理**：显式 `Start/Ready`、幂等 `Close`；关闭 HTTP 服务、运行时、本地邮件
   捕获器，释放 HTTP/邮件端口并删除临时数据目录。

宿主会话设计：浏览器只持有随机 `host_session` Cookie（HttpOnly/SameSite=Lax），
Evernight 会话秘密与 CSRF 令牌只保存在宿主进程内存，不写入 Cookie、日志或文件；
页面没有前端脚本，不使用 localStorage。

## 运行方式

```powershell
cd examples/custom-pages-profile-sync

# 有界自检：stdout 只输出一行 JSON，退出码 0=全部通过、1=失败
go run . -self-test -json

# 有人类可读摘要
go run . -self-test

# 显式启动演示（默认 127.0.0.1 动态端口；Ctrl+C 或 -duration 到期后自动清理）
go run . -demo
go run . -demo -duration 60s

# 独立编译、静态检查与测试（嵌套 module 需要在本目录执行）
go build ./...
go vet ./...
go test ./...
```

一键自检（统一短测试入口负责临时目录、总超时、子进程退出与清理校验，并输出
结构化 JSON）：

```powershell
# 在仓库根执行
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\shorttest.ps1 `
  -Scenario custom-pages-profile-sync-selftest -TimeoutSeconds 240
```

演示模式下额外注册一个**仅演示可用**的本地信报页 `/dev/mailbox`：展示被本地邮件
捕获器接收的邮件（含一次性验证/找回链接），仅用于本机手动走通注册/找回流程；
自检模式下该路由不存在（404），生产代码不应注册它。

## 预期输出（自检 JSON 节选）

```json
{
  "schema": "evernight.custom-pages-profile-sync.selftest/v1",
  "status": "PASS",
  "mode": "self-test",
  "listen_addr": "127.0.0.1:52341",
  "port": 52341,
  "http_prefix": "/idp",
  "mail_sink_addr": "127.0.0.1:52340",
  "data_dir": "C:\\Users\\<user>\\AppData\\Local\\Temp\\evernightlogin-custom-pages-123456",
  "data_dir_removed": true,
  "checks": [
    {"id": "host.pages_coexist", "status": "PASS"},
    {"id": "host.csrf_anonymous_reject", "status": "PASS", "detail": "缺 token=403；跨来源=403；缺 Cookie=403"},
    {"id": "registration.via_host_page", "status": "PASS"},
    {"id": "email.verification_mail", "status": "PASS"},
    {"id": "email.verify_via_host_page", "status": "PASS"},
    {"id": "login.wrong_password_rejected", "status": "PASS"},
    {"id": "login.success", "status": "PASS"},
    {"id": "profile.update_whitelist_and_sync", "status": "PASS"},
    {"id": "rename.success_stable_user_id", "status": "PASS"},
    {"id": "cross_user.modification_denied", "status": "PASS"},
    {"id": "forgot_password.via_host_page", "status": "PASS"},
    {"id": "reset_password.via_host_page", "status": "PASS"},
    {"id": "mfa.restricted_not_bypassed", "status": "PASS"},
    {"id": "no_secrets_in_result", "status": "PASS"},
    {"id": "cleanup.temp_data_removed", "status": "PASS"}
  ],
  "duration_ms": 2600
}
```

端口、用户 ID、临时目录与耗时每次都不同，上例仅为格式示意；共 23 项检查。

## 生产集成注意（示例不是生产代码）

- 示例用 LocalAdmin 创建一个 **system 范围的示例自助权限角色**（`self.profile.read`/
  `self.profile.update`/`self.credentials.manage`）并分配给合成用户，仅为让自包含
  示例可运行；真实部署应使用产品内置角色/预设与正式管理流程，不要在宿主代码里
  手工建权限。
- 宿主页面替换了内置路径后，**Evernight HTTP 中间件不再覆盖这些路径**：宿主必须
  自行实现同源/CSRF 防护（本示例用双提交 Cookie + `Sessions.ValidateCSRF`）并继续
  经公开 Go 接口执行认证与审计；不要在这些页面里自行校验密码或跳过领域判定。
- 示例会话存储是进程内内存实现，重启即失效；生产应使用宿主自己的会话/缓存设施，
  服务端保存 Evernight 会话秘密，浏览器只持有随机 ID。
- 本示例只覆盖密码登录与“启用第二因素后受限”的拒绝路径；未实现第二步表单
  （TOTP/Passkey ceremony）、找回后的 MFA 重绑闭环由产品页面/服务覆盖。
- 本地邮件捕获器只是测试夹具：明文回环、无 AUTH/TLS、不持久化。真实邮件投递需
  配置产品邮件传输（SMTP）；示例不访问外网，也不发送真实邮件。

## 已知范围（不夸大）

- 只实测 Windows 11 amd64 / Go 1.27.4 / `CGO_ENABLED=0`；未做 Linux/macOS、
  `-race`、真实浏览器、TLS/反向代理、真实 SMTP 服务器实测。
- 未覆盖 TOTP 第二步表单、Passkey、多实例、找回后的 MFA 重绑，也未验证产品页面
  与宿主页面混用时的全部组合。
