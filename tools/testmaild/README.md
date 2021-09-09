# testmaild：本地测试邮件服务器

`testmaild` 是登录项目自带的**仅供测试**的本地 SMTP 接收服务器工具，底层使用
`internal/testmail`。它把收到的邮件保存在内存中，**不投递、不中继、不连接任何外部
邮件服务**，默认只监听 `127.0.0.1` 的随机端口；`cmd/login-server` 等生产入口不会
装配它，生产邮件发送实现必须另行编写（见 `internal/mailer`）。

典型用途：

- 手工验证登录项目的邮件相关功能（验证邮件、邀请邮件、安全告知等）；
- 用固定的 SMTP 地址、模拟账户与预置限制反复测试邮件客户端行为；
- 观察收到的完整邮件内容（信封、全部头部、正文）与会话级 SMTP 命令轨迹。

> 本工具不是产品能力，也不能替代 `internal/mailer` 的真实投递实现；它只做本地
> 内存捕获。

## 快速开始

在项目根目录执行（默认回环随机端口，启动后打印实际地址）：

```bat
go run .\tools\testmaild
```

使用带中文注释的示例配置（固定端口 2525、两个模拟账户、detail 输出）：

```bat
go run .\tools\testmaild -config .\tools\testmaild\config.example.yaml
```

示例配置里的 `listen.addr` 固定为 `127.0.0.1:2525`；端口被占用或被系统限制时，
请修改 `listen.addr`，或加 `-addr 127.0.0.1:0` 改用随机回环端口。

启动 STARTTLS 并添加一个命令行测试账户：

```bat
go run .\tools\testmaild -addr 127.0.0.1:0 -starttls -auth tester:test-pass -require-auth
```

打开详细输出与 SMTP 命令轨迹：

```bat
go run .\tools\testmaild -addr 127.0.0.1:0 -output debug -print-body
```

按 `Ctrl+C` 或发送 SIGTERM 优雅关闭，打印共接收的邮件数并释放端口。

## 优先级与配置来源

优先级：**命令行参数 > 配置文件 > 内置默认值**。

- 每个配置文件字段都可省略，省略时使用内置默认值；
- 命令行显式给出的参数覆盖同名配置；未显式给出的参数不会覆盖配置文件
  （工具通过 `flag` 的 `fs.Visit` 判断“是否显式给出”）；
- 命令行 `-auth user:password` 一旦出现，会**整体替换**配置文件中的
  `auth.accounts`（不做合并，避免半合并歧义）；
- STARTTLS 来源优先级：命令行 `-tls-cert`/`-tls-key` 证书对 > 命令行 `-starttls`
  > 配置文件 `starttls`；`-tls-cert` 与 `-tls-key` 必须同时给出；
- 配置采用严格解析：未知字段、重复键、类型错误、时长格式错误都会直接报错，并带
  文件路径、字段名与中文说明，不会静默忽略拼写错误。

## 配置文件字段

示例文件：`tools/testmaild/config.example.yaml`（逐字段中文注释，可直接复制修改）。

| 字段 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `listen.addr` | string | `127.0.0.1:0` | 监听地址 `host:port`；`0` 端口表示随机分配 |
| `listen.hostname` | string | `testmail.local` | SMTP 问候语与 EHLO 响应中的主机名 |
| `listen.allow_non_loopback` | bool | `false` | 显式允许监听非回环地址；仍只做本地捕获 |
| `limits.max_message_bytes` | int | `262144` | 单条消息字节上限（1～16777216），超限返回 552 |
| `limits.max_recipients` | int | `50` | 单条消息收件人上限（1～1000），超限返回 452 |
| `limits.max_connections` | int | `32` | 最大并发连接数（1～1024），超出直接 421 |
| `limits.max_messages` | int | `500` | 内存中保留消息数上限（1～100000），满后返回 452 |
| `limits.read_timeout` | duration | `30s` | 单次读取超时（50ms～1h） |
| `limits.session_timeout` | duration | `5m` | 单连接总时长上限（50ms～1h） |
| `starttls.enabled` | bool | `false` | 启用 STARTTLS；无证书文件时生成一次性自签测试证书 |
| `starttls.cert_file` | string | 空 | 自定义证书 PEM 路径（与 `key_file` 必须同时给出） |
| `starttls.key_file` | string | 空 | 自定义私钥 PEM 路径 |
| `auth.require_auth` | bool | `false` | 要求先 AUTH 才能发信（未认证的 MAIL FROM 返回 530） |
| `auth.accounts[].username` | string | 无 | 模拟账户用户名，不能为空、不能重复 |
| `auth.accounts[].password` | string | 无 | 模拟账户测试密码，不能为空 |
| `output.level` | string | `summary` | 输出级别：`summary`、`detail`、`debug` |
| `output.print_body` | bool | `false` | 是否打印邮件正文 |
| `output.max_body_bytes` | int | `4096` | 正文最多打印字节数，`0` 表示不限制 |
| `output.trace_smtp` | bool | `false` | 是否打印会话级 SMTP 命令轨迹 |

时长字段使用 Go 时长字符串（如 `30s`、`5m`、`500ms`），不要写纯数字。相对路径按
运行工具时的当前目录解析。配置解析错误示例：

```text
testmaild: 配置文件 "x.yaml" 解析失败：yaml: unmarshal errors:
  line 3: field unknown_option not found in type main.listenSection
请对照 tools/testmaild/config.example.yaml 检查字段名、缩进与取值类型
```

## 模拟邮件账户

- 在 `auth.accounts` 中配置多个“用户名 + 测试密码”的模拟账户，或用命令行
  `-auth user:password`（可重复）临时添加；
- `auth.require_auth: true` 时，未认证的 `MAIL FROM` 返回 `530 5.7.0`；
- 支持 AUTH PLAIN 与 AUTH LOGIN；
- 启动 banner 会打印**模拟账户清单**，明确标注「测试专用、非真实凭据」：配置文件
  来源的测试密码会被回显并逐行标注「本地测试凭据、仅回环使用」，命令行来源的
  密码不回显（只显示用户名）；
- 安全风险：配置文件中的密码会出现在启动输出里，便于本地连接测试；它们只是测试
  凭据，**不要复用任何真实密码**。若启用了 `allow_non_loopback`，任何能连接到本
  端口的人都可以看到并使用这些测试凭据（告警会在账户/密码清单之前输出）。
- 如不想让测试密码出现在启动输出，可改用命令行 `-auth user:password`（不落盘、
  不回显），或把含密码的配置文件放在不纳入版本控制的位置。

## 启动输出（连接参数）

启动后除监听地址与限制外，还会打印客户端连接参数，例如：

```text
testmaild: 监听 127.0.0.1:2525
testmaild: 主机名 testmail.local
testmaild: 限制 消息=262144字节 收件人=50 连接=32 保留=500
testmaild: AUTH 已启用，测试用户 [tester tester2]（要求先认证=false）
testmaild: 配置来源 配置文件 config.example.yaml（命令行显式参数优先）
testmaild: 输出 级别=detail 正文=true 正文上限=8192字节 SMTP轨迹=false
testmaild: 模拟账户清单（测试专用、非真实凭据）:
testmaild: 警告 以下为本地测试凭据、仅回环使用；不要复用任何真实账户密码
testmaild:   - 用户名=tester 密码=test-pass  [本地测试凭据、仅回环使用]
testmaild: ── 客户端连接参数（供手工测试邮件）──
testmaild:   SMTP 地址（host:port）: 127.0.0.1:2525
（实际输出还包含 EHLO 主机名、加密方式、AUTH 状态、swaks 示例与产品配置片段）
```

连接参数包含：

- SMTP 地址 `host:port`、EHLO 主机名；
- 是否需要 STARTTLS：自签测试证书的 CN/SAN（`CN=testmail.local`，覆盖
  `localhost`、`127.0.0.1`、`::1`，有效期 24 小时），客户端需显式信任或临时跳过
  校验；
- AUTH 是否启用、是否强制、可用用户名；
- `swaks` 示例命令（自签证书时带 `--tls`；swaks 默认不校验证书，需要校验时显式
  使用 `--tls-verify` 并信任证书）；
- `openssl s_client -starttls smtp -crlf -connect host:port` 示例；
- 产品配置片段样例（`smtp.host` / `smtp.port` / `smtp.username` /
  `smtp.password` / `smtp.starttls`；无模拟账户时省略 username/password，但仍给出
  `starttls` 字段）。当前仓库根配置尚未提供 SMTP 节，宿主可用
  `internal/mailer.SMTPOptions` 指向上面的地址（明文连接需
  `AllowPlaintextLocal=true` 且目标为回环地址）。

## 详细输出与 SMTP 轨迹

输出级别（`output.level` 或 `-output`）：

| 级别 | 内容 |
|---|---|
| `summary` | 默认值，每条消息一行摘要：`id`/`from`/`to`/`subject`/`size`/`tls`/`auth`，与旧版工具行为一致 |
| `detail` | 摘要 + 完整信封（MAIL FROM / RCPT TO）、全部头部原始值（保留折行）、解析出的 Subject/Date/Message-ID、TLS 与 AUTH 用户、字节数（总大小/正文/头部）、可选正文 |
| `debug` | `detail` + 默认开启会话级 SMTP 命令轨迹 |

正文打印由 `output.print_body` / `-print-body` 控制；`output.max_body_bytes` /
`-body-limit` 控制最多打印的字节数（默认 4096，`0` 表示不限制），超出时按 UTF-8
字符边界截断并输出明确提示：

```text
testmaild:     第一行正文
testmaild:     …（已截断：正文共 58 字节，仅显示前 15 字节；调整 output.max_body_bytes 或 -body-limit 查看完整内容，0 表示不限制）
```

正文、头部原始值、Subject/Message-ID 与 SMTP 轨迹中的终端控制字符（例如 ESC
`0x1b`、BEL）会被转义成 `\x1b`、`\x07` 形式后再输出，避免可疑邮件构造终端转义
序列影响本地终端；制表符与普通文本保持不变。

会话级轨迹（`output.trace_smtp` / `-trace-smtp` 或 `-output debug`）会打印连接建立、
客户端命令（`C:`）、服务器应答（`S:`）、STARTTLS 握手、认证成功与连接关闭：

```text
testmaild: SMTP 轨迹 [会话 1 127.0.0.1:55308] C: EHLO localhost
testmaild: SMTP 轨迹 [会话 1 127.0.0.1:55308] S: 250 testmail.local | SIZE 262144 | AUTH PLAIN LOGIN
testmaild: SMTP 轨迹 [会话 1 127.0.0.1:55308] C: AUTH PLAIN [凭据已脱敏]
testmaild: SMTP 轨迹 [会话 1 127.0.0.1:55308] 认证成功: tester
```

轨迹中的 AUTH 命令参数只保留机制名，AUTH 客户端响应内容与邮件正文不会进入轨迹
（`-trace-smtp` 下也不会出现密码或 base64 凭据）；不要在调试输出里寻找密码。

## 命令行参数

| 参数 | 说明 |
|---|---|
| `-config <path>` | YAML 配置文件路径 |
| `-addr` | 监听地址（默认 `127.0.0.1:0`） |
| `-hostname` | 问候语主机名（默认 `testmail.local`） |
| `-allow-non-loopback` | 显式允许监听非回环地址 |
| `-max-message-bytes` / `-max-recipients` / `-max-connections` / `-max-messages` | 资源限制 |
| `-read-timeout` / `-session-timeout` | 超时 |
| `-starttls` | 生成自签测试证书并启用 STARTTLS |
| `-tls-cert` / `-tls-key` | 自定义证书与私钥 PEM 文件（必须同时给出） |
| `-auth user:password` | 添加测试账户（可重复） |
| `-require-auth` | 要求先认证才能发信 |
| `-output summary\|detail\|debug` | 输出级别 |
| `-print-body` | 打印正文 |
| `-body-limit` | 正文最多打印字节数（默认 4096，0 表示不限制） |
| `-trace-smtp` | 打印会话级 SMTP 命令轨迹（AUTH 凭据不会进入轨迹） |

`-addr :0` 这类空主机名不会被当作回环地址，必须显式写 `127.0.0.1:0` 或加
`-allow-non-loopback`。

## 在 Go 测试中复用

Go 测试直接使用 `internal/testmail` 即可，不需要启动本工具：

```go
srv, err := testmail.New(testmail.Options{
    Auth: &testmail.AuthOptions{Users: map[string]string{"tester": "test-pass"}},
    // 可选：调试轨迹钩子（AUTH 参数已脱敏）。
    OnSessionEvent: func(ev testmail.SessionEvent) { t.Logf("%s %s", ev.Kind, ev.Command) },
})
if err != nil { return err }
if err := srv.Start(); err != nil { return err }
defer srv.Close()

msgs, err := srv.Wait(ctx, testmail.Query{To: "user@example.test"})
// 信封在 EnvelopeFrom/EnvelopeTo，原始字节在 Data，正文在 Body()，
// 头部在 Headers 与 Header()/HeaderValues()，Subject/Date 为解析结果。
```

## 限制与安全提示

- 不投递、不中继、不外部拨号；收件人域名是外部域名时也只在本地内存保存。该约束
  有源码级测试守护（`internal/testmail/isolation_test.go`）。
- 默认只监听回环地址；监听非回环地址必须显式 `allow_non_loopback`/
  `-allow-non-loopback`。即使开启也不会外发，但网络上的其他人可以连接并使用
  模拟测试凭据。
- 未启用 STARTTLS 时，AUTH 凭据会明文传输；只建议在回环地址上使用。启用 STARTTLS
  时使用自签测试证书，客户端需显式信任或临时跳过校验。
- 测试凭据只来自配置文件或命令行，不读取环境变量、凭证库或真实秘密；请勿复用
  任何真实密码。日志与轨迹不会打印 `AUTH` 凭据；banner 会回显配置文件中的模拟
  测试密码并明确标注其测试用途。如不希望密码出现在启动输出，可改用命令行
  `-auth user:password`（不落盘、不回显），或把含密码的配置文件放在不纳入版本
  控制的位置。
- 内存占用上限约为 `max_message_bytes × max_messages`（默认约 128 MiB），
  `max_connections` 还会叠加并发缓冲；高负载或长时间测试请调低这些参数。
- 该工具是测试基础设施，不得导入 `cmd/login-server` 或其他生产装配路径；生产邮件
  发送请使用 `internal/mailer`。

## 验证命令

在项目根目录（Windows amd64 实测）：

```bat
go test -count=1 -p 1 .\internal\testmail\
go test -count=1 -p 1 .\tools\testmaild\
go build -o %TEMP%\testmaild.exe .\tools\testmaild
del %TEMP%\testmaild.exe
go vet .\tools\testmaild\ .\internal\testmail\
```

构建命令显式用 `-o` 输出到临时目录，避免在仓库根目录留下 `testmaild.exe`。
```
