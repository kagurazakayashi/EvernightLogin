// Package rootrecovery 实现 root 密码与两步验证的本地应急重置（步骤 48）。
//
// 使用场景与信任边界：
//   - 本包只服务于**本地服务器管理员**在 root 无法在线登录时的应急流程；它必须由
//     本地 CLI（cmd/loginctl root-recover）以维护停机方式调用，不暴露 HTTP 路由、
//     不提供远程匿名入口，也不会在程序启动时自动执行恢复。
//   - 调用前必须确认服务已停止或处于维护状态（由调用者的显式确认与本地 CLI 参数
//     表达），并且本包会在数据库目录创建并独占锁定 lock 文件：同一数据库同一时刻
//     只允许一次恢复；进程内重入与跨进程并发都拒绝。
//   - 数据库必须是本项目的实例：库文件存在、schema_history 与当前内嵌迁移的版本和
//     校验和完全一致、唯一 root 账户存在且 active、root 初始化记录匹配。错误库/旧版本
//     库/非本项目数据库在写入前拒绝，且拒绝路径不修改数据库（包括不写失败审计，避免
//     对未知数据库产生任何写入；原因由 CLI 输出给本地操作者）。
//   - 新密码只能通过交互式隐藏输入取得（cmd/loginctl 使用 golang.org/x/term 关闭
//     回显），绝不来自命令行参数、环境变量或明文日志；密码策略复用 internal/authn。
//   - 密码重置、MFA 重置与主登录 Passkey 撤销是分别选择的范围；Passkey 默认保留，
//     仅当显式选择撤销时才撤销。每次恢复还需要一次明确的整体确认，取消确认不产生
//     任何修改。
//   - 重置成功后：在同一审计事务内递增 root security_version、撤销其全部会话、作废
//     一次性凭证与恢复代码、按选择重置密码/MFA/Passkey，并把 root 初始化状态置回
//     setup_verified（必须重新配置强认证的受限状态）；审计失败整体回滚，绝不出现
//     “半完成但安全版本/session 未生效”的状态。主登录 Passkey 默认保留不违反
//     “重置 MFA 不等于删除 Passkey”的约束。
//   - 恢复操作记录与待补发通知写入 0028 的 root_recovery_events（outbox）；记录只
//     含本地操作者/机器/原因/范围/计数/时间，不含密码、哈希、种子或恢复代码。宿主
//     或下次启动应读取 pending 通知并补发，再把状态标记为 delivered/failed。
//
// 未实现（不宣称）：在线管理端点、完整 CLI 其它命令、自动通知消费者；Windows 实测
// 之外的平台仅编译检查。
package rootrecovery

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"strings"
	"time"
	"unicode"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
)

const (
	// MaxReasonRunes 是恢复原因的最大字符数（与迁移 CHECK 一致）。
	MaxReasonRunes = 500
	// MaxOperatorIDBytes 是本地操作者标识的字节上限。
	MaxOperatorIDBytes = 128
	// MaxMachineBytes 是机器名标识的字节上限。
	MaxMachineBytes = 128
	// LockFileName 是数据库目录内的恢复排他锁文件名（隐藏文件）；另外按数据库
	// 底层文件身份（卷/索引或 dev/inode）在系统临时目录加身份锁，使同一文件的
	// 符号链接/硬链接路径共享互斥。
	LockFileName = ".root-recovery.lock"
	// MaxNotificationAttempts 是恢复安全告知补发的最大尝试次数；达到后 outbox 事件
	// 进入 failed 终态，避免无限重试。补发为至少一次语义，宿主必须按事件 ID 幂等。
	MaxNotificationAttempts = 5
)

// 领域错误哨兵。错误文本不包含密码、哈希、令牌或数据库内容。
var (
	ErrOptionsInvalid       = errors.New("root 应急恢复选项无效")
	ErrInvalidRequest       = errors.New("root 应急恢复请求无效")
	ErrMaintenanceRequired  = errors.New("必须停止服务或进入维护状态后才能执行 root 应急恢复")
	ErrLocked               = errors.New("该数据库已有正在进行的 root 应急恢复")
	ErrInvalidDatabase      = errors.New("所选数据库不是可恢复的本项目实例")
	ErrRootNotFound         = errors.New("数据库中不存在可恢复的 root 账户")
	ErrRootNotEligible      = errors.New("root 账户状态不允许应急恢复")
	ErrConfirmationDeclined = errors.New("操作者取消确认，未做任何修改")
	ErrPasswordPolicy       = errors.New("新密码不满足密码策略")
	ErrStoreUnavailable     = errors.New("root 应急恢复存储暂时不可用")
	ErrAuditUnavailable     = errors.New("关键操作未能可靠记录")
	ErrNoAction             = errors.New("至少需要选择密码重置或 MFA 重置之一")
)

// ErrorCode 是 root 应急恢复领域对根包错误码注册表的投影（只复用既有码）。
type ErrorCode string

const (
	CodeReqInvalid                 ErrorCode = "REQ_INVALID"
	CodeAccessDenied               ErrorCode = "ACCESS_DENIED"
	CodeConflict                   ErrorCode = "CONFLICT"
	CodeRestoreMaintenanceRequired ErrorCode = "RESTORE_MAINTENANCE_REQUIRED"
	CodeDBUnavailable              ErrorCode = "DB_UNAVAILABLE"
	CodeAuditWriteFailed           ErrorCode = "AUDIT_WRITE_FAILED"
	CodeInternalError              ErrorCode = "INTERNAL_ERROR"
)

// CodeOf 把 root 应急恢复领域错误映射为根包已登记错误码。
func CodeOf(err error) ErrorCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrOptionsInvalid),
		errors.Is(err, ErrPasswordPolicy), errors.Is(err, ErrNoAction):
		return CodeReqInvalid
	case errors.Is(err, ErrMaintenanceRequired):
		return CodeRestoreMaintenanceRequired
	case errors.Is(err, ErrLocked):
		return CodeConflict
	case errors.Is(err, ErrConfirmationDeclined), errors.Is(err, ErrRootNotFound),
		errors.Is(err, ErrRootNotEligible):
		return CodeAccessDenied
	case errors.Is(err, ErrInvalidDatabase), errors.Is(err, ErrStoreUnavailable):
		return CodeDBUnavailable
	case errors.Is(err, ErrAuditUnavailable):
		return CodeAuditWriteFailed
	default:
		return CodeInternalError
	}
}

// Operator 是本地应急操作者的审计身份（操作系统用户与机器名，不含秘密）。
type Operator struct {
	// ID 是稳定操作者标识，建议 "os:<用户>@<机器>"；只用于审计与恢复记录。
	ID string
	// Machine 是机器名标识。
	Machine string
}

// Validate 校验操作者标识长度与非空（不做主机名真实性承诺，本地信任边界）。
func (o Operator) Validate() error {
	if strings.TrimSpace(o.ID) == "" || strings.TrimSpace(o.Machine) == "" {
		return fmt.Errorf("%w: 操作者标识与机器名不能为空", ErrOptionsInvalid)
	}
	if len(o.ID) > MaxOperatorIDBytes || len(o.Machine) > MaxMachineBytes {
		return fmt.Errorf("%w: 操作者标识或机器名过长", ErrOptionsInvalid)
	}
	for _, value := range []string{o.ID, o.Machine} {
		if strings.ContainsFunc(value, unicode.IsControl) {
			return fmt.Errorf("%w: 操作者标识不能包含控制字符", ErrOptionsInvalid)
		}
	}
	return nil
}

// LocalOperator 从操作系统环境推导本地操作者身份；失败时使用保守占位标识。
func LocalOperator() Operator {
	username := "local-admin"
	if current, err := user.Current(); err == nil && strings.TrimSpace(current.Username) != "" {
		username = current.Username
	}
	machine := "unknown-host"
	if hostname, err := os.Hostname(); err == nil && strings.TrimSpace(hostname) != "" {
		machine = hostname
	}
	operator := Operator{ID: "os:" + username + "@" + machine, Machine: machine}
	if err := operator.Validate(); err != nil {
		// 极端环境（主机名/用户名含非法字符或过长）退化为固定标识，仍可由本地
		// 管理员从上下文识别；不把无法校验的数据写入审计。
		return Operator{ID: "os:local-admin@unknown-host", Machine: "unknown-host"}
	}
	return operator
}

// Request 是一次 root 应急恢复请求；操作范围由调用者显式选择。
type Request struct {
	// Reason 是本地操作者填写的恢复原因（必填、不含控制字符）。
	Reason string
	// ResetPassword 表示重置 root 正式密码（需要交互式隐藏输入新密码两次）。
	ResetPassword bool
	// ResetMFA 表示重置 root 两步验证因素（邮件因素、TOTP 绑定与待处理挑战）。
	ResetMFA bool
	// RevokeLoginPasskeys 表示同时撤销 root 的主登录 Passkey；默认 false（保留）。
	RevokeLoginPasskeys bool
	// ServiceStopped 是操作者显式确认“服务已停止或处于维护状态”；必须为 true。
	ServiceStopped bool
	// RequestID 是可选的请求编号，用于关联审计与恢复记录。
	RequestID string
}

// ScopeSummary 是恢复前展示给操作者的范围摘要（不含任何秘密）。
type ScopeSummary struct {
	DatabasePath        string
	Operator            Operator
	RootUsername        string
	ResetPassword       bool
	ResetMFA            bool
	RevokeLoginPasskeys bool
	CurrentState        string
}

// Prompter 是交互式确认与隐藏密码输入契约；生产实现见 cmd/loginctl（x/term）。
// 取消确认必须返回 (false, nil)，绝不能把取消当作成功。
type Prompter interface {
	// ConfirmRecovery 展示范围摘要并要求操作者明确确认；返回 false 表示取消。
	ConfirmRecovery(scope ScopeSummary) (bool, error)
	// ReadNewPassword 读取一次新密码（隐藏输入，返回字节切片）；调用方会调用
	// 两次并要求一致，使用后尽力清零。Go 无法保证 string 转换不产生副本，密码
	// 的驻留期仍受 GC 与运行时限制（README 已声明）。
	ReadNewPassword() ([]byte, error)
	// ConfirmPasskeyRevocation 在显式选择撤销主登录 Passkey 时要求二次确认。
	ConfirmPasskeyRevocation() (bool, error)
}

// AuditRecorder 是安全审计写入契约；实现必须 fail-closed。
type AuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
	RecordFailure(ctx context.Context, event audit.Event) error
	ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error
}

// Result 是一次成功恢复的结果（不含秘密）。
type Result struct {
	EventID                   string
	RootUserID                string
	SecurityVersionAfter      int64
	SessionsRevoked           int64
	FactorsDisabled           int64
	RecoveryCodeGroupsRevoked int64
	PasskeysRevoked           int64
	CompletedAt               time.Time
}

// Notification 是一条待补发的 root 恢复安全告知（outbox）。
type Notification struct {
	ID              string
	RootUserID      string
	OperatorID      string
	OperatorMachine string
	Reason          string
	PasswordReset   bool
	MFAReset        bool
	PasskeysRevoked bool
	CreatedAt       time.Time
	Attempts        int
}

// faultStage 允许测试注入事务中途失败（仅测试路径使用，生产为 nil）。
const (
	faultAfterPassword   = "after_password"
	faultAfterFactors    = "after_factors"
	faultAfterSessions   = "after_sessions"
	faultBeforeAuditDone = "before_audit_done"
)

func validReason(reason string) (string, error) {
	trimmed := strings.TrimSpace(reason)
	if trimmed == "" || len([]rune(trimmed)) > MaxReasonRunes {
		return "", fmt.Errorf("%w: 原因不能为空且最多 %d 个字符",
			ErrInvalidRequest, MaxReasonRunes)
	}
	for _, character := range trimmed {
		if unicode.IsControl(character) {
			return "", fmt.Errorf("%w: 原因不能包含控制字符", ErrInvalidRequest)
		}
	}
	// 原因只进入审计/恢复记录；限制字符集避免日志注入与格式破坏。
	for index := 0; index < len(trimmed); index++ {
		character := trimmed[index]
		if character < 0x20 || character == 0x7f {
			return "", fmt.Errorf("%w: 原因包含不可打印字符", ErrInvalidRequest)
		}
	}
	return trimmed, nil
}

// checkPasswordPolicy 复用 internal/authn 的密码策略校验（root 用户名作为标识）。
func checkPasswordPolicy(policy authn.PasswordPolicy, password, username string) error {
	if err := policy.Check(password, []string{username, "root"}); err != nil {
		return fmt.Errorf("%w: %v", ErrPasswordPolicy, err)
	}
	return nil
}
