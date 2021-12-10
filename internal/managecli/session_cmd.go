// 本文件实现 `loginctl session` 命令：操作者用真实会话秘密文件查看/撤销本人会话。
//
// 认证与安全边界：
//   - 会话秘密只从受保护文件读取（绝对值、普通文件、非符号链接、大小受限、
//     通过 internal/secrets.CheckProtectedFile 的平台权限检查）；不接受命令行参数、
//     环境变量明文或标准输入回显，也从不打印秘密。
//   - 认证判定完全复用 internal/session 的 Validate/ListSessions/RevokeSession：
//     会话有效期、账户状态、安全版本、应用成员失效等由服务层重新读取数据库判定。
//   - 管理强制下线需要已完成强认证的管理会话；本项目的 MFA/管理强认证尚未实现，
//     因此不提供 admin-revoke，避免用本地参数冒充管理认证。
package managecli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	sessionsqlite "github.com/kagurazakayashi/EvernightLogin/internal/session/sqlite"
)

// sessionCommandUsage 是 session 组帮助。
const sessionCommandUsage = `用法：
  loginctl session whoami --session-file <f> --keyring-file <f> [--config <file>] [--json]
  loginctl session list --session-file <f> --keyring-file <f> [--page N] [--page-size N] \
[--config <file>] [--json]
  loginctl session revoke <session_id> --session-file <f> --keyring-file <f> [--config <file>] [--json]

安全说明：
  - 会话秘密只从 --session-file 读取；该文件必须是受保护普通文件，不接受命令行明文。
  - --keyring-file 是主密钥环文件（与备份/会话摘要分离保管），不会写入输出。
  - revoke 只能撤销本人名下会话；管理强制下线需要已完成强认证的管理会话，本步不提供。`

// maxSessionSecretFileBytes 是会话秘密文件大小上限，避免误读大文件。
const maxSessionSecretFileBytes = 64 << 10

// sessionOutput 是会话摘要的公开投影（绝不含会话秘密）。
type sessionOutput struct {
	ID                string `json:"id"`
	UserID            string `json:"user_id"`
	AppID             string `json:"app_id,omitempty"`
	Kind              string `json:"kind"`
	Reason            string `json:"reason,omitempty"`
	CreatedAt         string `json:"created_at,omitempty"`
	LastSeenAt        string `json:"last_seen_at,omitempty"`
	IdleExpiresAt     string `json:"idle_expires_at,omitempty"`
	AbsoluteExpiresAt string `json:"absolute_expires_at,omitempty"`
	Current           bool   `json:"current,omitempty"`
}

// runSession 分派 session 子命令。
func (r *runner) runSession(args []string) int {
	r.usageText = sessionCommandUsage
	if len(args) == 0 {
		return r.helpText("session", sessionCommandUsage)
	}
	subcommand, rest := args[0], args[1:]
	r.command = "session " + subcommand
	switch subcommand {
	case "whoami":
		return r.runSessionWhoami(rest)
	case "list":
		return r.runSessionList(rest)
	case "revoke":
		return r.runSessionRevoke(rest)
	case "admin-revoke":
		return r.fail("MANAGEMENT_STRONG_AUTH_UNAVAILABLE", ExitForbidden,
			"管理强制下线需要已完成强认证的管理会话；当前项目未实现 MFA/管理强认证，"+
				"本地参数不能冒充管理认证", nil)
	case "help", "-h", "--help":
		return r.helpText("session", sessionCommandUsage)
	default:
		return r.usage("未知的 session 子命令 %q（可用：whoami/list/revoke）", subcommand)
	}
}

// sessionFlags 返回 session 命令的公共参数定义。
func sessionFlags(extra ...flagDef) []flagDef {
	definitions := []flagDef{
		{name: "config", value: true}, {name: "json"},
		{name: "session-file", value: true}, {name: "keyring-file", value: true},
	}
	return append(definitions, extra...)
}

// runSessionWhoami 校验会话秘密并输出会话信息。
func (r *runner) runSessionWhoami(args []string) int {
	values, positional, err := parseFlags(args, sessionFlags())
	if err != nil {
		return r.flagError(err)
	}
	if len(positional) != 0 {
		return r.usage("session whoami 不接受位置参数")
	}
	r.json = boolFlag(values, "json")
	sessionService, secret, exit := r.sessionServiceAndSecret(values)
	if exit != ExitOK {
		return exit
	}
	defer sessionService.close()
	current, err := sessionService.service.Validate(r.ctx, secret)
	if err != nil {
		return r.sessionFailure("读取当前会话", err)
	}
	output := sessionOutput{ID: current.ID, UserID: current.UserID, AppID: current.AppID,
		Kind: string(current.Kind), Reason: string(current.Reason),
		CreatedAt:         formatTime(current.CreatedAt),
		LastSeenAt:        formatTime(current.LastSeenAt),
		IdleExpiresAt:     formatTime(current.IdleExpiresAt),
		AbsoluteExpiresAt: formatTime(current.AbsoluteExpiresAt)}
	if r.json {
		return r.succeed(output)
	}
	fmt.Fprintf(r.stdout, "当前用户：%s\n会话：%s（类别 %s）\n",
		output.UserID, output.ID, output.Kind)
	if output.AppID != "" {
		fmt.Fprintf(r.stdout, "应用上下文：%s\n", output.AppID)
	}
	fmt.Fprintf(r.stdout, "创建：%s；最后活动：%s；空闲到期：%s；绝对到期：%s\n",
		valueOrDash(output.CreatedAt), valueOrDash(output.LastSeenAt),
		valueOrDash(output.IdleExpiresAt), valueOrDash(output.AbsoluteExpiresAt))
	return ExitOK
}

// sessionListOutput 是设备列表输出。
type sessionListOutput struct {
	Page     int             `json:"page"`
	PageSize int             `json:"page_size"`
	Total    int64           `json:"total"`
	HasMore  bool            `json:"has_more"`
	Sessions []sessionOutput `json:"sessions"`
}

// runSessionList 列出本人当前活动会话。
func (r *runner) runSessionList(args []string) int {
	values, positional, err := parseFlags(args, sessionFlags(
		flagDef{name: "page", value: true}, flagDef{name: "page-size", value: true}))
	if err != nil {
		return r.flagError(err)
	}
	if len(positional) != 0 {
		return r.usage("session list 不接受位置参数")
	}
	r.json = boolFlag(values, "json")
	page, err := parseIntFlag(values, "page", 1)
	if err != nil || page < 1 {
		return r.usage("--page 必须是正整数")
	}
	pageSize, err := parseIntFlag(values, "page-size", 20)
	if err != nil || pageSize < 1 || pageSize > 50 {
		return r.usage("--page-size 必须在 1～50 之间")
	}
	sessionService, secret, exit := r.sessionServiceAndSecret(values)
	if exit != ExitOK {
		return exit
	}
	defer sessionService.close()
	result, err := sessionService.service.ListSessions(r.ctx, secret,
		session.ListOptions{Page: page, PageSize: pageSize})
	if err != nil {
		return r.sessionFailure("读取会话列表", err)
	}
	output := sessionListOutput{Page: result.Page, PageSize: result.PageSize,
		Total: result.Total, HasMore: result.HasMore}
	for _, item := range result.Sessions {
		output.Sessions = append(output.Sessions, sessionOutput{ID: item.ID,
			UserID: "", AppID: item.AppID, Kind: string(item.Kind),
			Reason: string(item.Reason), CreatedAt: formatTime(item.CreatedAt),
			LastSeenAt:        formatTime(item.LastSeenAt),
			IdleExpiresAt:     formatTime(item.IdleExpiresAt),
			AbsoluteExpiresAt: formatTime(item.AbsoluteExpiresAt), Current: item.Current})
	}
	if r.json {
		return r.succeed(output)
	}
	if len(output.Sessions) == 0 {
		fmt.Fprintln(r.stdout, "没有活动会话。")
		return ExitOK
	}
	for _, item := range output.Sessions {
		marker := ""
		if item.Current {
			marker = "（当前）"
		}
		fmt.Fprintf(r.stdout, "%s  %s  app=%s  created=%s%s\n", item.ID, item.Kind,
			valueOrDash(item.AppID), valueOrDash(item.CreatedAt), marker)
	}
	if output.HasMore {
		fmt.Fprintln(r.stdout, "（还有更多会话，请使用 --page）")
	}
	return ExitOK
}

// runSessionRevoke 撤销本人名下的指定会话。
func (r *runner) runSessionRevoke(args []string) int {
	values, positional, err := parseFlags(args, sessionFlags())
	if err != nil {
		return r.flagError(err)
	}
	if len(positional) != 1 {
		return r.usage("用法：loginctl session revoke <session_id> --session-file <f> " +
			"--keyring-file <f> [--config <file>] [--json]")
	}
	r.json = boolFlag(values, "json")
	targetID := strings.TrimSpace(positional[0])
	sessionService, secret, exit := r.sessionServiceAndSecret(values)
	if exit != ExitOK {
		return exit
	}
	defer sessionService.close()
	revoked, err := sessionService.service.RevokeSession(r.ctx, secret, targetID)
	if err != nil {
		return r.sessionFailure("撤销会话", err)
	}
	output := map[string]any{"revoked": revoked, "session_id": targetID,
		"message": "目标不存在、已失效或不属于当前用户时按幂等成功返回 revoked=false"}
	if r.json {
		return r.succeed(output)
	}
	if revoked {
		fmt.Fprintf(r.stdout, "已撤销会话 %s。\n", targetID)
	} else {
		fmt.Fprintf(r.stdout, "未撤销：会话 %s 不存在、已失效或不属于当前用户（幂等成功）。\n",
			targetID)
	}
	return ExitOK
}

// sessionServiceBundle 是一次会话命令构造的服务与资源。
type sessionServiceBundle struct {
	service *session.Service
	store   interface{ Close() error }
}

// close 释放数据库连接；服务本身不拥有连接。
func (b *sessionServiceBundle) close() {
	if b != nil && b.store != nil {
		_ = b.store.Close()
	}
}

// sessionServiceAndSecret 读取并校验受保护文件，构造会话服务。
func (r *runner) sessionServiceAndSecret(values map[string]string) (*sessionServiceBundle,
	string, int) {
	sessionFile := stringFlag(values, "session-file")
	keyringFile := stringFlag(values, "keyring-file")
	if sessionFile == "" || keyringFile == "" {
		return nil, "", r.usage("--session-file 与 --keyring-file 必填")
	}
	secret, err := readProtectedSecret(sessionFile, "会话秘密文件")
	if err != nil {
		return nil, "", r.fail("SESSION_FILE_INVALID", ExitUnauthenticated, err.Error(), nil)
	}
	config, exit := r.loadEffectiveConfig(values)
	if exit != ExitOK {
		return nil, "", exit
	}
	raw, exit := r.openDatabase(config)
	if exit != ExitOK {
		return nil, "", exit
	}
	provider, err := secrets.NewFileProvider(strings.TrimSpace(keyringFile))
	if err != nil {
		_ = raw.Close()
		return nil, "", r.fail("KEYRING_UNAVAILABLE", ExitError, "主密钥环文件路径无效", nil)
	}
	ring, err := secrets.LoadKeyring(r.ctx, provider)
	if err != nil {
		_ = raw.Close()
		return nil, "", r.fail("KEYRING_UNAVAILABLE", ExitError,
			"主密钥环文件无法加载（错误详情已省略）", nil)
	}
	auditStore, err := auditsqlite.New(raw)
	if err != nil {
		_ = raw.Close()
		return nil, "", r.fail("AUDIT_STORE_UNAVAILABLE", ExitError, "无法构造审计存储", nil)
	}
	recorder, err := audit.New(auditStore, audit.Options{Now: r.options.Now})
	if err != nil {
		_ = raw.Close()
		return nil, "", r.fail("AUDIT_STORE_UNAVAILABLE", ExitError, "无法构造审计写入器", nil)
	}
	sessionStore, err := sessionsqlite.New(raw)
	if err != nil {
		_ = raw.Close()
		return nil, "", r.fail("SESSION_STORE_UNAVAILABLE", ExitError, "无法构造会话存储", nil)
	}
	service, err := session.New(sessionStore, session.Options{Store: sessionStore,
		Audit: recorder, Keyring: ring, Now: r.options.Now})
	if err != nil {
		_ = raw.Close()
		return nil, "", r.fail("SESSION_STORE_UNAVAILABLE", ExitError,
			"无法构造会话服务（配置或密钥环不可用）", nil)
	}
	return &sessionServiceBundle{service: service, store: raw}, secret, ExitOK
}

// readProtectedSecret 从受保护普通文件读取秘密，做大小上限与常量时间非空检查。
// 返回的错误与调用方输出都不包含秘密内容。
func readProtectedSecret(path, label string) (string, error) {
	absolute, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return "", fmt.Errorf("%s路径无效", label)
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return "", fmt.Errorf("%s不存在", label)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%s不能是符号链接", label)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s必须是普通文件", label)
	}
	if info.Size() <= 0 || info.Size() > maxSessionSecretFileBytes {
		return "", fmt.Errorf("%s大小不合法（必须非空且不超过 %d 字节）", label,
			maxSessionSecretFileBytes)
	}
	if err := secrets.CheckProtectedFile(absolute); err != nil {
		return "", fmt.Errorf("%s未按平台要求保护（仅允许当前用户访问）", label)
	}
	data, err := os.ReadFile(absolute)
	if err != nil {
		return "", fmt.Errorf("%s无法读取", label)
	}
	secret := strings.TrimSpace(string(data))
	if secret == "" {
		return "", fmt.Errorf("%s内容为空", label)
	}
	return secret, nil
}

// sessionFailure 把会话领域错误映射为稳定错误码/退出码。
func (r *runner) sessionFailure(operation string, err error) int {
	code := string(session.CodeOf(err))
	if code == "" {
		code = "INTERNAL_ERROR"
	}
	exitCode := ExitError
	switch {
	case errors.Is(err, session.ErrSessionInvalid), errors.Is(err, session.ErrAccountNotEligible),
		errors.Is(err, session.ErrRotationFailed), errors.Is(err, session.ErrConcurrentLimit):
		exitCode = ExitUnauthenticated
	case errors.Is(err, session.ErrRestrictedSession), errors.Is(err, session.ErrStrongAuthRequired),
		errors.Is(err, session.ErrAccessDenied), errors.Is(err, session.ErrRecoveryNotAllowed),
		errors.Is(err, session.ErrLoginGrantDenied):
		exitCode = ExitForbidden
	case errors.Is(err, session.ErrInvalidRequest):
		exitCode = ExitUsage
	}
	return r.fail(code, exitCode, operation+"失败："+err.Error(), nil)
}
