# testmaild：本地测试邮件服务器

`testmaild` 是登录项目自带的**仅供测试**的本地邮件服务器工具，底层使用
`internal/testmail`。它提供 SMTP 收信，并可选择开启**只读 IMAP/POP3 收件箱**，
让 Thunderbird、Outlook、Foxmail 等真实邮件客户端连接查看模拟账户收到的测试邮件。
收到的邮件只保存在内存中，**不投递、不中继、不连接任何外部邮件服务**，默认只监听
`127.0.0.1` 的随机端口；`cmd/login-server` 等生产入口不会装配它，生产邮件发送实现
必须另行编写（见 `internal/mailer`）。

典型用途：

- 手工验证登录项目的邮件相关功能（验证邮件、邀请邮件、安全告知等）；
- 用固定的 SMTP 地址、模拟账户与预置限制反复测试邮件客户端行为；
- 观察收到的完整邮件内容（信封、全部头部、正文）与会话级 SMTP 命令轨迹；
- 用真实邮件客户端（Thunderbird/Outlook/Foxmail）连接只读 IMAP/POP3 收件箱，
  像检查真实邮箱一样查看模拟账户收到的测试邮件（按账户隔离，不泄露他人邮件）。

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

同时开启只读 IMAP 与 POP3 收件箱（随机回环端口，启动信息会打印实际端口）：

```bat
go run .\tools\testmaild -addr 127.0.0.1:0 -auth tester:test-pass -imap -pop3
```

只想固定端口时显式指定（示例 1143/1110 为常见测试端口，需确认本机空闲）：

```bat
go run .\tools\testmaild -addr 127.0.0.1:0 -auth tester:test-pass -imap -imap-addr 127.0.0.1:1143 -pop3 -pop3-addr 127.0.0.1:1110
```

`config.example.yaml` 已默认启用 IMAP/POP3（回环随机端口）并提供两个模拟账户，
直接运行上面的示例配置命令即可用邮件客户端连接（端口看启动 banner）。

按 `Ctrl+C` 或发送 SIGTERM 优雅关闭，打印共接收的邮件数并释放 SMTP/IMAP/POP3 端口。

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
| `imap.enabled` | bool | `false` | 启用只读 IMAP 收件箱；需要 `auth.accounts` 或 `-auth` |
| `imap.addr` | string | `127.0.0.1:0` | IMAP 监听地址；明文只允许回环地址 |
| `imap.tls` | bool | `false` | IMAP 使用隐式 TLS（复用 STARTTLS 证书或自签证书） |
| `pop3.enabled` | bool | `false` | 启用只读 POP3 收件箱；需要模拟账户 |
| `pop3.addr` | string | `127.0.0.1:0` | POP3 监听地址；明文只允许回环地址 |
| `pop3.tls` | bool | `false` | POP3 使用隐式 TLS（证书来源同 `imap.tls`） |

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
- **配置文件权限**：配置文件里可能包含明文测试密码，请放在受控位置并限制访问权限
  （POSIX 建议 `chmod 600`；Windows 建议只给当前用户读写权限），不要提交到版本
  控制、不要放在共享目录或会被同步到云端的路径；这些密码虽然不是真实账户秘密，
  但仍不应被其他本机用户或日志收集器读到。
- **命令行 `-auth` 的暴露面**：`-auth user:password` 的参数会出现在进程命令行中，
  同一台机器上的其他用户/进程管理工具（任务管理器、WMI、审计日志）可能读到它，也
  可能留在 shell 历史里；只建议使用一次性测试密码，并优先选择“受控位置的配置文件”。
  两种来源都只用于本地回环测试，不要填写任何真实账户密码。

## 只读 IMAP/POP3 收件箱（邮件客户端连接）

测试服务器可以把通过 SMTP 捕获的邮件按模拟账户映射成只读收件箱，供真实邮件客户端
查看。协议实现是 `internal/testmail` 内手写的最小只读子集，不引入第三方 IMAP/POP3
库，**不投递、不中继、不连接外部服务器**。

### 支持的命令子集

- IMAP4rev1：`CAPABILITY`、`NOOP`、`LOGIN`、`LIST`/`LSUB`（只有 INBOX）、
  `SELECT`/`EXAMINE`（INBOX，返回 `[READ-ONLY]`）、`FETCH`/`UID FETCH`
  （支持 `UID`、`FLAGS`、`INTERNALDATE`、`SIZE`/`RFC822.SIZE`、`BODY[]`、
  `BODY.PEEK[]`、`RFC822`、`BODY[HEADER]`、`RFC822.HEADER`、`BODY[TEXT]`、
  `RFC822.TEXT`、`BODY[HEADER.FIELDS (...)]`、`ENVELOPE`，宏 `FAST`/`ALL`）、
  `STATUS`、`CLOSE`、`LOGOUT`。
- POP3：`USER`/`PASS`、`STAT`、`LIST`、`RETR`、`TOP`、`DELE`（仅本会话隐藏）、
  `RSET`、`NOOP`、`QUIT`、`CAPA`。
- 未支持的命令或参数返回标准 `BAD`/`NO`（IMAP）或 `-ERR`（POP3），连接保持可用，
  服务端不会崩溃。`BODYSTRUCTURE`、`BODY[1]` 等高级 FETCH 项**未实现**，请求时会
  得到 BAD；客户端可能因此不显示附件结构，但正文与常用头部可以正常查看。

### 账户与收件箱映射

- IMAP/POP3 与 SMTP 共用 `auth.accounts` 中的模拟账户；启用前必须至少配置一个账户；
- 邮件按收件人映射到账户：SMTP 信封收件人（RCPT TO）或头部 `To`/`Cc`/`Bcc` 中
  任一地址的本地部分（`@` 之前）等于账户用户名时，该账户可见；
- 没有命中的账户完全看不到这封邮件（EXISTS/STAT/RETR/FETCH 都不含），测试多个账户
  时不会互相泄露内容；
- 只有 `INBOX` 一个邮箱；`UIDVALIDITY` 固定为 1，UID 即服务内单调递增的消息编号，
  `UIDNEXT` 为下一个将要分配的编号；`SELECT` 后新到达的邮件不会主动推送，重新
  `SELECT`/`EXAMINE` 或重新登录后可见（不实现 IDLE）；
- 服务端不维护 `\Seen` 等标记：`FLAGS ()`，`PERMANENTFLAGS ()`，只读。

### 只读语义

- IMAP 的 `STORE`、`EXPUNGE`、`APPEND`、`COPY`、`MOVE`、`UID STORE`、`UID EXPUNGE`
  等写操作一律返回 `NO [READ-ONLY]`，不会修改共享内存仓库；
- POP3 的 `DELE` **只在本会话内隐藏**该邮件（本次会话的 STAT/LIST/RETR 不再返回），
  `QUIT` 或断开连接后消息仍在共享内存仓库中，其他会话与 IMAP 客户端仍能看到，
  不会真正删除；`RSET` 可取消本会话的删除标记；
- 邮件内容不会被转发、投递或写入磁盘。

### 客户端配置步骤（以 Thunderbird 为例）

1. 启动工具（例如 `-auth tester:test-pass -imap -pop3`），记下 banner 中
   `IMAP 地址（host:port）` / `POP3 地址（host:port）` 的主机与端口；
2. Thunderbird → 账户设置 → 添加邮件账户 → 手动配置，协议选 `IMAP`（或 `POP3`），
   服务器填 `127.0.0.1`，端口填 banner 显示的端口；
3. 连接安全性：明文模式下选「无」；`imap.tls`/`pop3.tls` 开启时选「SSL/TLS」
   （隐式 TLS），并接受自签证书例外（见下一节）；
4. 认证方式选「普通密码」，用户名填 `auth.accounts` 中的模拟用户名，密码填对应
   测试密码（banner 会提示用户名；配置文件来源的测试密码会回显并标注
   「本地测试凭据、仅回环使用」，命令行 `-auth` 来源的密码不回显，需要你自己记得）；
5. Outlook/Foxmail：账户类型选 IMAP 或 POP3，接收服务器填 `127.0.0.1`、端口与
   加密方法按 banner 的「Outlook/Foxmail 设置」行填写，用户名/密码同第 4 步。

#### 自签证书信任

`imap.tls`/`pop3.tls` 开启时默认使用一次性自签测试证书（CN=testmail.local，覆盖
localhost/127.0.0.1/::1，有效期 24 小时）；也可以把自备测试证书放在 `starttls.cert_file`
与 `starttls.key_file` 复用。客户端会提示证书不受信任：在只用于本地测试的客户端
配置中可临时接受例外/关闭证书校验；**不要**把该证书或其信任配置用于任何真实服务。

### 常见问题

- 客户端连不上：确认协议已启用（banner 有对应地址行）、端口抄对、客户端与工具在
  同一台机器；明文协议只允许回环地址，非回环必须 `tls: true` 并在
  `listen.allow_non_loopback` 显式允许；
- 收件箱为空：邮件是否真的投递给了该账户（检查信封 RCPT TO 与 To/Cc/Bcc 本地部分
  是否等于用户名）；另外 `SELECT` 之后的快照不会自动刷新，重新选择邮箱再看；
- 附件显示异常：`BODYSTRUCTURE` 未实现属于已知限制，本工具用于验证收发内容而非
  完整 MIME 渲染。

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
| `-imap` / `-imap-addr` / `-imap-tls` | 启用 IMAP 收件箱 / 监听地址 / 隐式 TLS |
| `-pop3` / `-pop3-addr` / `-pop3-tls` | 启用 POP3 收件箱 / 监听地址 / 隐式 TLS |

`-addr :0` 这类空主机名不会被当作回环地址，必须显式写 `127.0.0.1:0` 或加
`-allow-non-loopback`。

## 在 Go 测试中复用

Go 测试直接使用 `internal/testmail` 即可，不需要启动本工具：

```go
srv, err := testmail.New(testmail.Options{
    Auth: &testmail.AuthOptions{Users: map[string]string{"tester": "test-pass"}},
    // 可选：只读 IMAP/POP3 收件箱（真实邮件客户端可连接）。
    IMAP: &testmail.IMAPOptions{},
    POP3: &testmail.POP3Options{},
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
- IMAP/POP3 收件箱是**只读**能力：拒绝标记/删除/追加/复制，POP3 的 DELE 只在本会话
  隐藏消息；收件箱按模拟账户隔离，非收件账户看不到邮件内容；
- 明文 IMAP/POP3 只允许回环地址；监听非回环必须启用隐式 TLS 并显式
  `allow_non_loopback`。未启用 TLS 时登录凭据会明文传输，只建议本机测试；
- 每个协议监听器各自使用 `max_connections` 并发额度（SMTP/IMAP/POP3 互不占用），
  读取超时与单连接总时长上限复用 `limits.read_timeout` / `limits.session_timeout`；
- 不使用 BODYSTRUCTURE 等高级 IMAP 扩展；仅支持 INBOX，不实现 IDLE 推送。
- 会话级调试轨迹（`-trace-smtp` / `output.trace_smtp`）只覆盖 SMTP；IMAP/POP3 的
  协议应答使用标准英文（`BAD`/`NO`/`-ERR` 等，POP3 惯例），中文说明以本文档与
  启动 banner 为准。
- 内存占用上限约为 `max_message_bytes × max_messages`（默认约 128 MiB），
  `max_connections` 还会叠加并发缓冲；高负载或长时间测试请调低这些参数。
- 含测试密码的配置文件应限制访问权限（POSIX `chmod 600`；Windows 仅当前用户），
  不要提交到版本控制、共享目录或云端同步路径；命令行 `-auth user:password` 的密码会
  出现在进程命令行与 shell 历史中，仅建议一次性测试密码。
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
