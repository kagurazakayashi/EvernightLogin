package loginte2e

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// orderedSuites 是 all 套件的固定顺序：先核对声明，再验证签名与授权码，最后令牌
// 与管理 API。顺序稳定便于比对历史报告。
var orderedSuites = []string{
	SuiteDiscovery, SuiteJWKS, SuiteAuthCode, SuiteToken,
	SuiteDevice, SuiteQR, SuiteTokenAuthz, SuiteIntrospect, SuiteAdminAPI,
}

// KnownSuites 返回所有合法套件名（含 all）。
func KnownSuites() []string {
	result := append([]string(nil), orderedSuites...)
	return append(result, SuiteAll)
}

// IsKnownSuite 判断套件名是否合法（大小写不敏感）。
func IsKnownSuite(name string) bool {
	normalized := strings.ToLower(strings.TrimSpace(name))
	for _, suite := range KnownSuites() {
		if suite == normalized {
			return true
		}
	}
	return false
}

// Runner 是单次运行的用例记录器：一条用例一个 Result，顺序稳定。
type Runner struct {
	client    *Client
	report    *Report
	suite     string
	discovery *DiscoveryDocument
}

// Run 执行一个套件并返回报告。返回的 error 只表示**无法继续**的系统性问题
// （目标不可达、配置非法）；用例级失败已经记录在报告里，不通过 error 表达。
// 对 all 套件，中途不可达时返回已收集的部分报告 + 错误。
func (c *Client) Run(ctx context.Context, suiteName string) (*Report, error) {
	normalized := strings.ToLower(strings.TrimSpace(suiteName))
	if !IsKnownSuite(normalized) {
		return nil, fmt.Errorf("%w: 未知套件 %q（可用：%s）", ErrConfigInvalid,
			suiteName, strings.Join(KnownSuites(), ", "))
	}
	if ctx == nil {
		ctx = context.Background()
	}
	report := newReport(c.ServerBase(), normalized, c.nowTime())
	if normalized == SuiteAll {
		for _, suite := range orderedSuites {
			runner := &Runner{client: c, report: report, suite: suite}
			if err := runner.dispatch(ctx); err != nil {
				report.finish(c.nowTime())
				return report, err
			}
		}
		report.finish(c.nowTime())
		return report, nil
	}
	runner := &Runner{client: c, report: report, suite: normalized}
	if err := runner.dispatch(ctx); err != nil {
		report.finish(c.nowTime())
		return report, err
	}
	report.finish(c.nowTime())
	return report, nil
}

// dispatch 按套件名分派；未知套件在 Run 里已拦截，这里只做穷尽分支。
func (r *Runner) dispatch(ctx context.Context) error {
	switch r.suite {
	case SuiteDiscovery:
		return r.runDiscoverySuite(ctx)
	case SuiteJWKS:
		return r.runJWKSSuite(ctx)
	case SuiteAuthCode:
		return r.runAuthCodeSuite(ctx)
	case SuiteToken:
		return r.runTokenSuite(ctx)
	case SuiteDevice:
		return r.runDeviceSuite(ctx)
	case SuiteQR:
		return r.runQRSuite(ctx)
	case SuiteTokenAuthz:
		return r.runTokenAuthzSuite(ctx)
	case SuiteIntrospect:
		return r.runIntrospectSuite(ctx)
	case SuiteAdminAPI:
		return r.runAdminSuite(ctx)
	default:
		return fmt.Errorf("%w: 未知套件 %q", ErrConfigInvalid, r.suite)
	}
}

// run 执行一条用例：nil → pass；skipError → skip；其他 → fail（细节已脱敏）。
func (r *Runner) run(caseName string, fn func() error) {
	result := Result{Suite: r.suite, Case: caseName}
	err := fn()
	switch {
	case err == nil:
		result.Status = StatusPass
		result.OK = true
	case isSkip(err):
		result.Status = StatusSkip
		result.Detail = safeDetail(err)
	default:
		result.Status = StatusFail
		result.Detail = safeDetail(err)
	}
	r.report.add(result)
}

// skipSuite 记录一条覆盖整个套件的 skip（缺少前置条件时使用，只记一条，不刷屏）。
func (r *Runner) skipSuite(reason string) {
	r.report.add(Result{Suite: r.suite, Case: "suite", Status: StatusSkip,
		Detail: safeDetail(skipf("%s", reason))})
}

// document 返回并缓存 Discovery 文档；获取失败视为系统性错误（套件无法继续）。
func (r *Runner) document(ctx context.Context) (*DiscoveryDocument, error) {
	if r.discovery != nil {
		return r.discovery, nil
	}
	document, err := r.client.fetchDiscovery(ctx)
	if err != nil {
		return nil, err
	}
	r.discovery = document
	return document, nil
}

// requireClient 检查 client_id 前置条件；缺失返回 skip 错误。
func (r *Runner) requireClient() error {
	if strings.TrimSpace(r.client.cfg.ClientID) == "" {
		return skipf("缺少 --client-id：该套件需要已登记客户端")
	}
	return nil
}

// requireRedirect 检查授权码回调前置条件。
func (r *Runner) requireRedirect() error {
	if err := r.requireClient(); err != nil {
		return err
	}
	if strings.TrimSpace(r.client.cfg.RedirectURI) == "" {
		return skipf("缺少 --redirect-uri：授权码流程需要登记的回调地址")
	}
	return nil
}

// requireSession 检查已登录会话前置条件。
func (r *Runner) requireSession() error {
	if strings.TrimSpace(r.client.cfg.SessionSecret) == "" {
		return skipf("缺少已登录会话：用 --session-cookie-file 提供受保护的会话 Cookie/秘密文件")
	}
	return nil
}

// requireAdminSession 检查管理会话前置条件。
func (r *Runner) requireAdminSession() error {
	if strings.TrimSpace(r.client.cfg.AdminSessionSecret) == "" {
		return skipf("缺少管理会话：用 --admin-session-file 提供受保护的管理会话秘密文件")
	}
	return nil
}

// resourceList 返回授权请求的 resource 参数：未显式配置时使用 issuer（UserInfo
// 的 audience），保证 Access Token 可用于 UserInfo。
func (r *Runner) resourceList() []string {
	if len(r.client.cfg.Resources) > 0 {
		return append([]string(nil), r.client.cfg.Resources...)
	}
	if r.discovery != nil && r.discovery.Issuer != "" {
		return []string{r.discovery.Issuer}
	}
	return nil
}

// isUnavailable 判断错误链里是否包含“目标不可达”。
func isUnavailable(err error) bool { return errors.Is(err, ErrUnavailable) }

// sleepContext 在可取消的等待中暂停（轮询间隔）。
func sleepContext(ctx context.Context, duration time.Duration) error {
	if duration <= 0 {
		return nil
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return fmt.Errorf("%w: 等待被取消", ErrUnavailable)
	case <-timer.C:
		return nil
	}
}
