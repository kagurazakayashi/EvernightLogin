# 步骤 211 验收：新公开找回接口的外部消费回归

- 执行者：中肥鱼（zhongfeiyu10）
- 日期：2026-11-25（Asia/Shanghai）
- 依赖基线：204 `adeff19`、205 `088cf1a`、206 `5d44573`、208 `8ac8400`、212 `26e7b2f`（均已提交）
- 结果：**PASS_WITH_NOTES**（`pass=31 fail=0 not_tested=1`）
- 复核更新（211 审计 F1 修复后）：连续 2 次复跑均 `PASS_WITH_NOTES（31/0/1）`；此前审计独立复跑 3 次中 1 次的 `enumerate.unknown_identifier` 假失败已定位为采样竞态（详见 §6）
- 机器可读证据（本地、gitignored）：`docs/acceptance/evidence/step211/password-reset-consumer.json`（含逐项检查与只读审计诊断行）与同目录 `.log`

## 1. 被测对象

`examples/password-reset-consumer/` 是**真正独立的 Go Module**
（`example.com/evernightlogin-password-reset-consumer`，仅 `replace` 到父模块），
只使用公开包与公开入口：

- 公开 Go 门面：`app.Open`、`Registration`、`Auth`、`Sessions`、`Security`、`PasswordReset`；
- 真实嵌入式 HTTP：宿主自己的 `http.Server` 挂载 `Runtime.Handler()`，使用真实页面表单
  （同源 Origin + CSRF）；
- 真实 EvernightMail 子进程：随机回环 SMTP/HTTP 端口、临时数据目录；从 Mail 已提交的
  `.eml + .json` 成对文件读取邮件（校验 size/sha256，MIME 传输解码后提取一次性链接）；
- 只读审计诊断：外部模块用自己的 `modernc.org/sqlite` 以只读方式读取临时库
  `password.reset_*` 审计行，不写认证状态、不冒充管理接口。

## 2. 复现命令（Windows 11 / go1.27.4 / `CGO_ENABLED=0` / `GOMAXPROCS=2`）

EvernightMail 子模块正被 237 链在途修改，因此按审计员做法用**干净 HEAD** 构建二进制：

```bash
git -C EvernightMail archive HEAD | tar -x -C .ai/tmp/mail-head
cd .ai/tmp/mail-head && GOTOOLCHAIN=local CGO_ENABLED=0 GOMAXPROCS=2 \
  GOFLAGS=-mod=mod GOPROXY=off go build -o ../mail-head-bin/evernightmail.exe ./cmd/evernightmail
```

运行外部回归（最终一次，不带 `-keep`，临时目录自动清理）：

```bash
cd examples/password-reset-consumer
GOTOOLCHAIN=local GOFLAGS=-mod=mod GOPROXY=off CGO_ENABLED=0 GOMAXPROCS=2 \
  go run . -mail "<干净 HEAD 的 evernightmail.exe>" -timeout 10m \
  -out "../../docs/acceptance/evidence/step211/password-reset-consumer.json"
```

退出码 0 并输出 `PASS_WITH_NOTES`。定向单测：

```bash
go test -count=1 -run 'TestBuildMailURLs|TestMailURLConfigCombinations|TestValidateMailRegistration' ./internal/serverapp/
```

## 3. 覆盖结果（31 PASS / 0 FAIL / 1 NOT_TESTED）

| 分组 | 检查项（全部 PASS） |
|---|---|
| 启动与装配 | 真实 Mail 子进程就绪；`app.Open+Start` 使用公开包完成临时 SQLite/邮件/页面装配（前缀 `/idp`） |
| 注册/邮箱验证 | 公开注册页提交合成账户（CSRF+同源 Origin）并收到邮件；从真实 Mail 提取验证链接并提交验证页 |
| 204 预检查 | 预检查连续两次通过且不消费 token；弱密码被拒绝后同一链接仍可预检查（`reset.weak_password_does_not_burn`） |
| 205 找回完成 | 强密码完成找回成功，旧会话撤销、要求重新登录；已消费 token 的完成/预检查均拒绝；旧密码登录拒绝；新密码 + 原 TOTP 重新登录成功（MFA 未清除） |
| 206 安全变更失效 | 账户页改密后，先前未使用的找回链接失效；通过账户页申请并验证新邮箱后，先前未使用的找回链接同样失效 |
| 防枚举/配置/失败路径 | 未知账户、root（无已验证邮箱）、待审核账户申请返回统一成功外形且不发信；邮件关闭时公开找回返回 `CONFIG_INVALID`；SMTP 不可达时公开申请仍返回统一外形（失败只进受控状态/审计） |
| 208 限流/编号 | 同一来源限额内 10 次申请返回统一成功外形；超限返回稳定 `RATE_LIMITED` 且不再受理；未知账户与可用账户在受限来源返回相同 `RATE_LIMITED`（不可枚举）；限额内实际投递 5 封（≤10，邮箱级与来源级限流叠加），超限后不再新增；审计可辨别 `rate_limited`，且至少一条受理/拒绝审计行携带调用方生成的请求编号 |
| 诊断分离 | 公开响应防枚举，同时管理/审计只读诊断保留成功与拒绝原因；只读读取 19 条 `password.reset_*` 审计行 |

**NOT_TESTED（1 项，原因如实）**：`enumerate.disabled_passwordless` —— 公开 app 门面当前
没有“创建禁用账户/无密码账户”的入口，无法仅用公开入口构造该状态；该状态由内部测试覆盖，
外部公开入口未测。

## 4. 本步顺带修复的外部消费问题（均在示例模块内，不改生产实现）

1. Mail 邮件正文是 base64 传输编码：原读取逻辑直接在原始 `.eml` 上找链接会得到密文。
   改为最小 MIME 解码（base64 / quoted-printable / multipart），修复后验证/找回/邮箱变更
   链接均可提取。
2. 邮箱验证页 CSRF：必须从带 `uid/cid/token` 的验证页本身提取隐藏 CSRF，不能无查询串
   重新打开（会 400）。
3. TOTP 时间步：绑定/登录验证不能复用同一 30s 时间步（服务端防重放）；测试改用下一时间步。
4. 账户页会话 Cookie `__Host-` 前缀（Secure/Path=/ 且无 Domain）：本地站点改为自签名临时
   证书的 **HTTPS** 宿主；账户页会话由公开认证门面（密码 + TOTP 第二步）真实签发后注入
   测试浏览器 Cookie，不伪造会话、不绕过第二因素。
5. 208 语义校正：超限返回的是稳定的 `RATE_LIMITED`（调用方配额事实，对未知账户同样返回，
   不构成账户枚举差异）；邮件数为“≤ 来源上限且超限后不新增”，不虚构精确封数。

## 5. 边界与未测（不夸大）

- 仅 Windows 11 + SQLite 运行验证；MySQL/PostgreSQL/SQL Server 未运行。
- 真实邮箱的最终送达/用户已读不保证也不宣称；只验证“Mail 子进程 SMTP 接受并落盘”。
- 邮件公开地址 × `path_prefix` 的合法/非法组合由 `internal/serverapp` 定向单测覆盖
  （`TestBuildMailURLs` / `TestMailURLConfigCombinations` / `TestValidateMailRegistration`）；
  端到端只覆盖 `https://<loopback>/idp` 一种部署形态。
- 页面仅 `httptest`/真实 HTTP 表单路径，不含真实浏览器/读屏验证。
- 禁用/无密码账户的外部公开入口尚未提供（见 NOT_TESTED）。
- 能力矩阵/文档索引的刷新不在本步写域；`docs/acceptance/README.md` 等如需列入需在后续步骤同步。
- 临时资源：最终运行使用系统临时目录并自动删除；未保留 Mail/HTTP 进程或监听端口。

## 6. 211 审计 F1 修复（采样竞态，非产品枚举泄漏）

审计独立复跑 3 次中 1 次在 `enumerate.unknown_identifier` 失败：原断言比较“申请前后
立即读取的 Mail 已提交邮件总数差值”，未等待异步投递队列稳定，前序邮箱切换等异步邮件
可能落入采样窗口，造成**假失败**；审计未发现产品泄漏证据。

修复（仅示例验收脚本，不改产品实现）：

1. 防枚举断言改为**按收件人 + 一次性链接路径精确过滤**（只统计发给该 identifier 且
   含 `/login/reset-password` 的邮件），注册验证/其他场景邮件不会混入；
2. 读取前**有界等待异步队列静默**（计数稳定 1.5s 或最多 8s 超时），超时仍按当前精确
   计数断言，不无限等待；
3. 同口径修正 `enumerate.root` 与 `enumerate.pending_account`（后者真正风险是注册验证
   邮件晚到，不等于找回入口发信）。

修复后连续 2 次真实 E2E 复跑均 `PASS_WITH_NOTES（pass=31 fail=0 not_tested=1）`。
诚实边界：这只证明修复后两次复跑通过，不宣称“永不 flaky”；若未来仍出现假失败，应
按同一根因（异步/窗口采样）继续收敛，而非放宽断言。
