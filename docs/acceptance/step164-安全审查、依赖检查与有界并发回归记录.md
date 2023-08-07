# 步骤 164 安全审查、依赖检查与有界并发回归记录（2026-11-21）

- 执行者：小肥鱼；时间：2026-11-21 23:1x–23:2x；任务：安全审查/依赖检查/有界并发与故障回归。
- 基线：HEAD `200bfac`，dirty **290 项**（并行在途）；**不是干净发布基线**，本记录不能替代 166 最终干净基线验收。
- 环境：Windows 11、Go 1.27.1、SQLite；所有命令 `GOMAXPROCS=4`、`-p 1/2`、有界超时；未压测、未长跑；未改产品代码/Mail、无 Git 写操作。

## 1. 静态与依赖检查（真实执行）

| 检查 | 结果 |
|---|---|
| 父项目 `gofmt -l`（排除 EvernightMail/.git） | **0 文件** |
| `go mod verify` | **all modules verified** |
| `go build ./...` | **PASS** |
| `go vet ./...` | **PASS** |
| 依赖数量 | `go list -m all` **74 行**（含主模块） |
| `govulncheck` | **本机不可用/未安装**；无网络更新漏洞库；**未执行漏洞库扫描，不能写成 0 漏洞** |
| `gosec` | **本机不可用**；仅人工静态审查与既有测试 |
| SBOM/产物签名 | 未生成；166 发布候选需补或明确不提供 |

## 2. 代码级安全审查（按变更面）

| 领域 | 检查/证据 | 结论 |
|---|---|---|
| 身份来源 | 可信边界构造 Caller（用户/本地管理员/系统）；`internal/managecli`、`adminapi`、`serverapp` 测试；152/154/156 审计 | 未发现参数自称 root/系统；管理 API 强会话/CSRF 未放宽 |
| 授权交集 | `internal/tokenauthz`、144/145 dev/审计；资源服务/客户端/权限联合校验测试 | 144/145 真实 HTTP 黑盒仍未完成（见 157 矩阵 G157-02/03），本步不冒充通过 |
| CSRF | 162 真实 serve 发现 `/email/change/verify` 公开表单白名单漏项 → 403；修复后 `TestPublicFormPathsIncludeMFAAndPasswordReset` **PASS**，162 复跑邮箱变更 200 | **发现并关闭 1 个真实产品缺陷**；无其他公开表单漏项证据 |
| XSS | 页面使用 `html/template` 自动转义，无通用 `raw_html`；报告 SVG 仅由内部数据构造；不接受用户 HTML | 未发现新增未转义路径；真实浏览器 XSS E2E 未做（NOT_TESTED） |
| SSRF | `internal/netguard`/Webhook/头像抓取测试；TLS 不提供 `InsecureSkipVerify`；Mail 仅本地回环 | 未发现关闭校验/任意 URL 抓取；真实外部攻防未做 |
| 路径/解压 | 备份查看、头像、导出路径测试（`viewer_test`/`avatar`/`backup` 路径穿越用例） | 既有防护测试在；GB/硬链接/Windows DACL 对抗未测 |
| 备份/恢复/旧凭证 | 步骤 94/152 测试；恢复后旧会话/刷新/恢复码失效用例 | SQLite 域通过；152 MFA 真实双操作员执行链路仍 NOT_TESTED |
| 秘密/日志 | 配置秘密来源 env/file、诊断脱敏、邮件密码不落普通日志；静态 grep 未发现新增明文日志 | 未发现新增秘密泄露；19xx 低项（Secret 副本不可清零等）保留历史登记 |
| 邮件故障边界 | 162 真实 Mail 故障：认证/TLS/拒收/断连/延迟均如实失败；`injected=true` 证据 | 故障不绕过鉴权；Mail duplicate Copier 未装配为 Mail 侧限制（PARTIAL） |

## 3. 有界并发/故障回归（真实执行）

| 测试 | 结果 |
|---|---|
| `go test -run 'TestStep94' -count=1 -p 1 -timeout 240s .` | **PASS 29.859s**（并发/取消/故障/备份恢复受控演练） |
| `go test -run 'Concurrent|Revok|Replay|CSRF' -p 2 -timeout 240s ./internal/session ./internal/token ./internal/reports ./internal/netguard` | **PASS**（session 45.446s / token 40.788s / reports 39.648s；netguard 无匹配测试） |
| `go test ./internal/serverapp -run 'TestPublicForm'` | **PASS 40.631s**（CSRF 账户公开表单回归） |
| `CGO_ENABLED=1 go test -race ./internal/session` | **FAIL（环境）**：`runtime/cgo: stddef.h: No such file or directory`；**race NOT_TESTED**，不是产品失败 |
| 并发预算/清理 | 均 GOMAXPROCS=4、`-p≤2`、timeout；无压测/长跑；无本步残留进程/监听 |

## 4. 发现与结论

1. **已发现并关闭**：`/email/change/verify` 公开 CSRF 白名单缺失（162 发现，大肥鱼助手修复，serverapp 回归 + 162 真实复跑 PASS）。
2. **未关闭/限制**：
   - `govulncheck`/`gosec` 本机不可用且无网络更新 → 依赖漏洞扫描 **NOT_TESTED**；`go mod verify` 只证明校验和完整，不是漏洞结论。
   - `-race` 缺 C 工具链 → NOT_TESTED。
   - 144/145 真实 HTTP 黑盒、162 的 Mail duplicate Copier/找回/MFA 队列证据仍 PARTIAL；支持恢复/真实外部部署 NOT_TESTED。
   - 真实浏览器 XSS/点击劫持/读屏、公网反代/mTLS 未做。
3. **VERDICT：PASS_WITH_NOTES**：未发现新的高危可复现问题；CSRF 缺陷已修复；静态零告警不等于安全认证，依赖扫描/race/真实部署为明确未测项。166 最终验收必须在用户提交后的干净基线复核；本 dirty 记录不得当最终发布安全证明。
