package loginte2e

import (
	"fmt"
	"strings"
	"time"
)

// 套件名称常量。命令行为 `loginte2e <suite>`，这些字面值是稳定契约。
const (
	// SuiteDiscovery 核对 Discovery 文档与真实端点。
	SuiteDiscovery = "discovery"
	// SuiteJWKS 拉取公钥并独立验证 ID Token。
	SuiteJWKS = "jwks"
	// SuiteAuthCode 授权码 + PKCE S256 授权流程。
	SuiteAuthCode = "authcode"
	// SuiteToken 令牌端点、UserInfo、刷新轮换、撤销与状态查询。
	SuiteToken = "token"
	// SuiteDevice 设备码流程（RFC 8628）。
	SuiteDevice = "device"
	// SuiteQR 扫码登录流程。
	SuiteQR = "qr"
	// SuiteTokenAuthz 扩展 Token+当前权限联合判定端点契约。
	SuiteTokenAuthz = "tokenauthz"
	// SuiteIntrospect 标准 RFC 7662 状态查询契约。
	SuiteIntrospect = "introspect"
	// SuiteAdminAPI 管理 JSON API 只读契约。
	SuiteAdminAPI = "adminapi"
	// SuiteAll 按固定顺序运行全部套件。
	SuiteAll = "all"
)

// 稳定退出码。调用脚本可以据此区分“测试失败”“用法/配置错误”“环境不可用”。
const (
	// ExitPass 表示没有失败用例（允许存在 skip）。
	ExitPass = 0
	// ExitFail 表示至少一个用例失败。
	ExitFail = 1
	// ExitUsage 表示命令行参数/配置/受保护文件读取错误（测试未真正开始）。
	ExitUsage = 2
	// ExitUnavailable 表示测试目标不可达（连接/TLS/非 JSON 响应），或全部用例
	// 都因缺少前置条件被跳过。
	ExitUnavailable = 3
)

// 结果状态。StatusPass/StatusFail/StatusSkip 是报告里唯一允许出现的取值。
const (
	StatusPass = "pass"
	StatusFail = "fail"
	StatusSkip = "skip"
)

// Result 是一条用例结果。字段与命令 --json 输出一致：{suite,case,ok,detail}，
// 额外 status 字段区分 pass/fail/skip（ok 只在 pass 时为 true）。
//
// Detail 是供人排障的安全文本：只包含状态码、稳定错误码、公开消息与端点路径，
// 绝不包含令牌、授权码、设备码、短码、领取绑定、会话秘密、Cookie 或带查询串的 URL。
type Result struct {
	Suite  string `json:"suite"`
	Case   string `json:"case"`
	OK     bool   `json:"ok"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// Summary 是报告汇总。
type Summary struct {
	Pass int `json:"pass"`
	Fail int `json:"fail"`
	Skip int `json:"skip"`
}

// Report 是一次套件运行的完整报告。Results 顺序与用例执行顺序一致。
type Report struct {
	Tool       string   `json:"tool"`
	Server     string   `json:"server"`
	Suite      string   `json:"suite"`
	StartedAt  string   `json:"started_at"`
	DurationMS int64    `json:"duration_ms"`
	Results    []Result `json:"results"`
	Summary    Summary  `json:"summary"`
}

// newReport 构造空报告（工具名与服务器地址由 Runner 填充）。
func newReport(server, suite string, started time.Time) *Report {
	return &Report{Tool: "loginte2e", Server: server, Suite: suite,
		StartedAt: started.UTC().Format(time.RFC3339), Results: []Result{}}
}

// add 追加一条结果并维护汇总。
func (r *Report) add(result Result) {
	r.Results = append(r.Results, result)
	switch result.Status {
	case StatusPass:
		r.Summary.Pass++
	case StatusFail:
		r.Summary.Fail++
	case StatusSkip:
		r.Summary.Skip++
	}
}

// finish 记录总耗时。
func (r *Report) finish(now time.Time) {
	started, err := time.Parse(time.RFC3339, r.StartedAt)
	if err == nil {
		r.DurationMS = now.Sub(started).Milliseconds()
	}
}

// ExitCode 把报告映射为稳定退出码：有失败 → ExitFail；全部用例都被跳过 →
// ExitUnavailable；其余（含全部通过、通过+跳过混合）→ ExitPass。
func (r *Report) ExitCode() int {
	if r == nil {
		return ExitUnavailable
	}
	if r.Summary.Fail > 0 {
		return ExitFail
	}
	if len(r.Results) == 0 || r.Summary.Pass == 0 {
		return ExitUnavailable
	}
	return ExitPass
}

// Successful 报告是否没有失败用例。
func (r *Report) Successful() bool { return r != nil && r.Summary.Fail == 0 }

// skipError 表示用例因环境/前置条件不满足被跳过（不是测试失败）。
type skipError struct{ reason string }

// Error 实现 error。
func (e *skipError) Error() string { return e.reason }

// skipf 构造一个 skip 错误；reason 必须是安全文本（不含秘密）。
func skipf(format string, args ...any) error {
	return &skipError{reason: fmt.Sprintf(format, args...)}
}

// isSkip 判断错误是否为跳过。
func isSkip(err error) bool {
	_, ok := err.(*skipError)
	return ok
}

// safeDetail 把错误转成报告用文本：去掉可能的换行与控制字符，并截断长度，
// 防止把服务端大段正文或意外内容写进报告。
func safeDetail(err error) string {
	if err == nil {
		return ""
	}
	text := err.Error()
	text = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, text)
	if len(text) > 600 {
		text = text[:600] + "…"
	}
	return text
}
