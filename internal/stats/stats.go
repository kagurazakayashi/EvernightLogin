// Package stats 实现可重复计算的统计后端（步骤 75）：按固定时区与时间窗口聚合
// 成功认证活跃用户、错误原始次数与去重失败请求/任务数，并采集服务健康等已可得
// 状态；同时为步骤 76 的看板与后续报告提供稳定、可机器判读的统计上下文。
//
// 设计边界与安全不变量：
//   - 数据来源可信：活跃用户只统计服务端审计事实中的“完整成功认证”（会话签发
//     的 session_kind=normal，或可信登录批准后的扫码登录会话签发）；等待第二
//     因素、等待授权、正常拒绝、主动取消与故障不计入活跃。业务活动必须由应用
//     服务端以系统身份显式上报，并同时通过应用白名单与注入的用户存在/成员关系
//     校验，单独计数、另标口径，绝不与登录活跃相加，也不接受浏览器/普通请求参数
//     自报；幂等键绑定应用，跨应用同键互不吞事件。业务活动表当前没有自动清理
//     任务，宿主需按自身保留策略账删（本步不实现清理，属于已知限制）。
//   - 时间语义固定：所有窗口都是左闭右开区间 [Start, End)，按调用者选定的 IANA
//     时区划分自然日/自然周（周一起始）/自然月；事件按 UTC 毫秒参与比较，避免
//     跨午夜重复/漏计。窗口结束时间不晚于服务器当前观测时刻，进行中的末桶显式
//     标记，不把当前未完成桶当作完整桶。
//   - 原始次数与去重数量分开：原始事件次数按审计行计数；去重失败请求/任务数按
//     稳定 request_id/task_id 去重（缺失关联编号时以事件自身 ID 计一个逻辑请求/
//     任务），事件重试、同一失败请求的多条日志与任务重试不会重复计数。行级与
//     全局去重数分别计算，页面上不得把行级数量相加当作全局总数。
//   - 缺失不等于零：保留期不足、采样空档、来源截断、权限裁剪与未启用模块都通过
//     完整性结构显式表达；本包从不把未知值填充为 0，也不伪造“健康”状态。
//   - 聚合遵守调用者范围：每次查询都通过注入的 Authorizer 重新授权（权限键
//     reports.read），数据范围在 SQL WHERE 子句生效，不先读全量再内存过滤；root
//     通过显式 root 检查放行，不经过普通权限引擎。
//   - 本包不启动常驻服务、不自行创建后台协程；健康采样由调用方显式调用 RunOnce，
//     单实例并发受控，采样数量、保留期与清理批次都有硬上限。
package stats

import (
	"errors"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// 领域错误哨兵。调用方用 errors.Is 判断；装配层可映射到根包既有错误码：
//   - ErrInvalidRequest -> REQ_INVALID
//   - ErrAccessDenied   -> ACCESS_DENIED
//   - ErrStoreUnavailable -> DB_UNAVAILABLE
//   - 完整性不足以数据字段表达，对应 REPORT_DATA_INCOMPLETE，不作为查询失败。
var (
	// ErrOptionsInvalid 表示服务或依赖构造参数不合法。
	ErrOptionsInvalid = errors.New("统计服务选项无效")
	// ErrInvalidRequest 表示查询参数、时间窗口或上报字段不合法。
	ErrInvalidRequest = errors.New("统计请求无效")
	// ErrAccessDenied 表示调用者缺少权限或超出数据范围；对外不泄露目标是否存在。
	ErrAccessDenied = errors.New("无权查看统计数据")
	// ErrStoreUnavailable 表示统计存储不可用（读取或写入失败）。
	ErrStoreUnavailable = errors.New("统计存储暂不可用")
)

// 权限键：复用 preset 目录已登记的 reports.read，不新增权限。
const PermissionRead = "reports.read"

// ScopeSystem 是系统范围的稳定 ID。
const ScopeSystem = "system"

// 硬上限：限制单次查询/采样的资源与存储增长，超出即拒绝而不是静默截断。
const (
	// MaxBucketCount 是单次窗口允许的最大时间桶数量。
	MaxBucketCount = 400
	// MaxWindowDays 是单次窗口允许的最大自然跨度（天）。
	MaxWindowDays = 3 * 366
	// DefaultRangeDays 是未指定时间范围时的默认跨度（最近 7 天）。
	DefaultRangeDays = 7
	// MaxFactRows 是单次活跃聚合允许读取的认证事实行数上限；达到上限时结果
	// 显式标记 FactTruncated，不把截断后的数量当成完整值。
	MaxFactRows = 100_000
	// MaxErrorGroups 是错误聚合分组数上限；超出时显式标记截断。
	MaxErrorGroups = 5_000
	// DefaultErrorLimit/MaxErrorLimit 是错误排序表单页条数边界。
	DefaultErrorLimit = 100
	MaxErrorLimit     = 500
	// MaxOffset 限制深分页，避免统计接口变成全量导出通道。
	MaxOffset = 100_000
	// DefaultSampleRetentionDays/MaxSampleRetentionDays 是健康采样保留天数。
	DefaultSampleRetentionDays = 30
	MaxSampleRetentionDays     = 365
	// DefaultMaxSamplesPerRun 是单次采样最多写入的样本行数。
	DefaultMaxSamplesPerRun = 512
	// MaxPruneBatch 是单次清理最多删除的采样行数。
	MaxPruneBatch = 5_000
	// MaxBusinessActivityRows 是业务活动聚合允许读取的行数上限。
	MaxBusinessActivityRows = 100_000
	// MaxAppIDBytes/MaxUserIDBytes/MaxActivityKeyBytes/MaxDedupeKeyBytes 是业务
	// 活动上报的字段边界。
	MaxAppIDBytes       = 64
	MaxUserIDBytes      = 128
	MaxActivityKeyBytes = 64
	MaxDedupeKeyBytes   = 128
)

// SourceAppServer 是可信业务活动来源稳定标识：只有应用服务端使用系统身份显式
// 上报才使用它；普通浏览器请求、用户会话与匿名调用不能自称该来源。
const SourceAppServer = "app_server"

// Category 是统计口径中的事件类别。它把“等待授权/正常拒绝/主动取消/警告/故障”
// 分开，避免把安全保护生效（正常拒绝）误当故障，也避免把取消与超时混为失败。
type Category string

const (
	// CategoryPending 是等待授权/等待处理的流程状态（如扫码登录待确认、人工恢复
	// 待审批）。等待不是故障，也不是成功活跃。
	CategoryPending Category = "pending"
	// CategoryDenied 是正常权限拒绝/策略拒绝：保护按预期生效。
	CategoryDenied Category = "denied"
	// CategoryCancelled 是主动取消或已确认的取消结果；取消请求与取消成功分开由
	// 动作/错误码区分，统计中不再当作故障。
	CategoryCancelled Category = "cancelled"
	// CategoryWarning 是数据质量警告（如报告数据不完整）或非故障告警。
	CategoryWarning Category = "warning"
	// CategoryFailure 是系统故障/未预期失败。
	CategoryFailure Category = "failure"
	// CategoryUnknown 是未登记错误码或无法分类的事件。
	CategoryUnknown Category = "unknown"
)

// Valid 报告类别是否已定义。
func (c Category) Valid() bool {
	switch c {
	case CategoryPending, CategoryDenied, CategoryCancelled, CategoryWarning,
		CategoryFailure, CategoryUnknown:
		return true
	default:
		return false
	}
}

// Severity 是统计口径中的影响程度。它是统计字典（用于聚合与排序），不替代根包
// 错误码注册表的分类，也不改变任何错误码含义。
type Severity string

const (
	// SeverityInfo 表示信息级：正常拒绝、等待、取消等流程事件。
	SeverityInfo Severity = "info"
	// SeverityWarning 表示告警级：任务结果、限流、通知投递失败、数据质量等。
	SeverityWarning Severity = "warning"
	// SeverityError 表示故障级：未分类失败、备份/报告/内部错误等。
	SeverityError Severity = "error"
	// SeverityCritical 表示严重级：安全审计、权限判定或数据库等基础保障不可用。
	SeverityCritical Severity = "critical"
	// SeverityUnknown 表示未知（未登记错误码），不能按 0 或 info 处理。
	SeverityUnknown Severity = "unknown"
)

// Valid 报告严重度是否已定义。
func (s Severity) Valid() bool {
	switch s {
	case SeverityInfo, SeverityWarning, SeverityError, SeverityCritical, SeverityUnknown:
		return true
	default:
		return false
	}
}

// Rank 返回严重度数值（越大越严重），用于稳定排序；unknown 不参与严重度排序。
func (s Severity) Rank() int {
	switch s {
	case SeverityInfo:
		return 1
	case SeverityWarning:
		return 2
	case SeverityError:
		return 3
	case SeverityCritical:
		return 4
	default:
		return 0
	}
}

// pendingActions 是“等待授权/待处理”动作登记表。只有这些成功动作会计入 pending
// 类别；登记表是稳定白名单，新增动作必须同步测试与说明，不能由错误码前缀推测。
var pendingActions = map[string]bool{
	"app_qr_login.request_created": true,
	"manual_recovery.requested":    true,
	"support.case.reset_requested": true,
}

// cancelledActions 是“主动取消/已取消”动作登记表。取消请求、取消成功与取消被
// 拒绝分别由不同动作/错误码表达，本表只登记已确认的取消或取消请求本身。
var cancelledActions = map[string]bool{
	"app_qr_login.cancelled":            true,
	"audit.export.cancel":               true,
	"audit.purge.cancel":                true,
	"email.change.cancel":               true,
	"invitation.cancel":                 true,
	"manual_recovery.cancelled":         true,
	"password.reset_requests_cancelled": true,
	"recovery.cancelled":                true,
	"webhook.delivery.cancelled":        true,
}

// warningCodes 是数据质量/非故障警告错误码。它们不是失败，统计中单列 warning。
var warningCodes = map[string]bool{
	"REPORT_DATA_INCOMPLETE": true,
}

// criticalCodes 是基础保障不可用的错误码：审计、权限判定或数据库不可用会直接
// 影响安全与可用性，统计中标为 critical 供运维优先处理。
var criticalCodes = map[string]bool{
	"AUDIT_WRITE_FAILED": true,
	"AUTHZ_UNAVAILABLE":  true,
	"DB_UNAVAILABLE":     true,
}

// warningImpactCodes 是故障类别下影响较轻、应作为告警跟踪的错误码。
var warningImpactCodes = map[string]bool{
	"RATE_LIMITED":             true,
	"TASK_TIMEOUT":             true,
	"TASK_CANCEL_CONFLICT":     true,
	"MAIL_DELIVERY_FAILED":     true,
	"WEBHOOK_DELIVERY_FAILED":  true,
	"REPORT_GENERATION_FAILED": true,
	"CONFIG_INVALID":           true,
}

// Classification 是单条事件的统计分类结果。
type Classification struct {
	// Category 是分开的类别。
	Category Category
	// Severity 是统计字典严重度。
	Severity Severity
	// Counted 表示该事件是否进入错误/异常聚合（失败、拒绝、取消、警告、等待）。
	// 普通成功动作不计入错误统计。
	Counted bool
}

// ClassifyEvent 把审计事件结果、错误码与动作映射为统计类别与严重度。规则固定且
// 有稳定顺序，测试逐项覆盖：
//  1. 数据质量警告码始终归 warning（不是故障，也不被取消动作吞掉）；
//  2. 失败结果优先于动作类别：审计/权限/数据库等 critical 不可用码即使动作属于
//     取消登记表也计为 failure/critical，失败请求/任务计数不得丢失；“取消失败”
//     （取消动作但失败结束）同样按失败计，不归入取消；
//  3. 只有错误码 TASK_CANCELLED 的失败结果与成功结束的取消动作归 cancelled/info；
//  4. 结果为 denied -> denied/info（正常拒绝是保护生效）；
//  5. 其余失败按错误码字典区分 critical/warning/error；空/未登记错误码保留
//     unknown/unknown，不静默并入故障；
//  6. 成功动作只有“等待授权/待处理”登记表计入 pending/info，其余不计入。
func ClassifyEvent(outcome audit.Outcome, errorCode, action string) Classification {
	if warningCodes[errorCode] {
		return Classification{Category: CategoryWarning, Severity: SeverityWarning, Counted: true}
	}
	if outcome == audit.OutcomeFailure {
		if criticalCodes[errorCode] {
			// 基础保障不可用必须留痕并计入失败，不因动作是取消类而被吞。
			return Classification{Category: CategoryFailure, Severity: SeverityCritical, Counted: true}
		}
		if errorCode == "TASK_CANCELLED" {
			return Classification{Category: CategoryCancelled, Severity: SeverityInfo, Counted: true}
		}
		// 取消动作以失败结果结束属于“取消失败”，按失败统计（保留请求/任务去重）。
		severity := SeverityError
		if warningImpactCodes[errorCode] {
			severity = SeverityWarning
		}
		category := CategoryFailure
		if errorCode == "" || !isRegisteredCode(errorCode) {
			// 空/未登记错误码不能被悄悄当作已知故障分类；保留在 unknown 供排查。
			category = CategoryUnknown
			severity = SeverityUnknown
		}
		return Classification{Category: category, Severity: severity, Counted: true}
	}
	switch outcome {
	case audit.OutcomeDenied:
		return Classification{Category: CategoryDenied, Severity: SeverityInfo, Counted: true}
	case audit.OutcomeSuccess:
		if cancelledActions[action] {
			return Classification{Category: CategoryCancelled, Severity: SeverityInfo, Counted: true}
		}
		if pendingActions[action] {
			return Classification{Category: CategoryPending, Severity: SeverityInfo, Counted: true}
		}
	}
	return Classification{Category: CategoryUnknown, Severity: SeverityUnknown, Counted: false}
}

// registeredCodes 是根包 48 个设计错误码的稳定副本，用于区分“已登记故障”与
// “未登记错误码”。它必须与根包注册表保持一致，根包测试会逐项核验覆盖。
var registeredCodes = map[string]bool{
	"REQ_INVALID": true, "AUTH_FAILED": true, "TOKEN_INVALID": true,
	"TOKEN_EXPIRED": true, "TOKEN_REVOKED": true, "TOKEN_AUDIENCE_MISMATCH": true,
	"CLIENT_AUTH_FAILED": true, "CLIENT_DISABLED": true, "USER_DISABLED": true,
	"APP_MEMBERSHIP_REQUIRED": true, "PERMISSION_REQUIRED": true,
	"PERMISSION_DISABLED": true, "PERMISSION_UNKNOWN": true,
	"APP_SCOPE_MISMATCH": true, "RESOURCE_FORBIDDEN": true, "ACCESS_DENIED": true,
	"REAUTH_REQUIRED": true, "MFA_REQUIRED": true, "MFA_REBIND_REQUIRED": true,
	"CHALLENGE_INVALID": true, "REFRESH_REUSE_DETECTED": true, "RATE_LIMITED": true,
	"SUPPORT_IDENTITY_UNVERIFIED": true, "SUPPORT_TARGET_PROTECTED": true,
	"RECOVERY_APPROVAL_REQUIRED": true, "RECOVERY_SELF_APPROVAL_DENIED": true,
	"CONFLICT": true, "AUTHZ_UNAVAILABLE": true, "DB_UNAVAILABLE": true,
	"AUDIT_WRITE_FAILED": true, "MAIL_DELIVERY_FAILED": true, "BACKUP_FAILED": true,
	"BACKUP_CANCEL_FORBIDDEN": true, "TASK_CANCEL_CONFLICT": true,
	"TASK_CANCELLED": true, "TASK_TIMEOUT": true, "BACKUP_INVALID": true,
	"BACKUP_DECRYPT_FAILED": true, "BACKUP_VERSION_UNSUPPORTED": true,
	"RESTORE_MAINTENANCE_REQUIRED": true, "EXPORT_PATH_UNSAFE": true,
	"REPORT_GENERATION_FAILED": true, "REPORT_DATA_INCOMPLETE": true,
	"REPORT_ACCESS_DENIED": true, "CONFIG_INVALID": true, "INTERNAL_ERROR": true,
	"WEBHOOK_DELIVERY_FAILED": true, "WEBHOOK_ENDPOINT_BLOCKED": true,
}

// isRegisteredCode 报告错误码是否属于根包已登记的设计码。
func isRegisteredCode(code string) bool { return registeredCodes[code] }

// IsRegisteredErrorCode 报告统计字典是否覆盖该已登记错误码。根包测试用它核验
// 统计分类与错误码注册表同步，避免新增错误码后统计静默归入未知。
func IsRegisteredErrorCode(code string) bool { return isRegisteredCode(code) }

// NonFailureCodes 返回不应计入“失败请求/任务”的错误码：任务取消与数据质量警告
// 是流程状态/警告，不是故障。取消类动作若以失败结果结束仍按失败计数（见
// ClassifyEvent），因此不能按动作排除。正常拒绝保留原始次数但不冒充失败。
func NonFailureCodes() []string {
	codes := make([]string, 0, len(warningCodes)+1)
	codes = append(codes, "TASK_CANCELLED")
	for code := range warningCodes {
		codes = append(codes, code)
	}
	return codes
}

// StatisticallyRelevantActions 返回参与统计分类（等待授权/取消）的动作登记表
// 副本，供存储层做 SQL 粗筛；最终分类仍由 ClassifyEvent 统一判定。
func StatisticallyRelevantActions() []string {
	actions := make([]string, 0, len(pendingActions)+len(cancelledActions))
	for action := range pendingActions {
		actions = append(actions, action)
	}
	for action := range cancelledActions {
		actions = append(actions, action)
	}
	return actions
}

// StatisticallyRelevantCodes 返回参与统计分类的错误码副本（数据质量警告等）。
// 供存储层做 SQL 粗筛，避免漏掉以 success 结果记录的警告事件。
func StatisticallyRelevantCodes() []string {
	codes := make([]string, 0, len(warningCodes))
	for code := range warningCodes {
		codes = append(codes, code)
	}
	return codes
}

// RegisteredErrorCodes 返回统计字典覆盖的已登记错误码副本（稳定顺序不保证）。
func RegisteredErrorCodes() []string {
	codes := make([]string, 0, len(registeredCodes))
	for code := range registeredCodes {
		codes = append(codes, code)
	}
	return codes
}

// Module 是健康/状态模块稳定标识。
type Module string

const (
	// ModuleService 是服务健康（进程/监听/自检）。
	ModuleService Module = "service"
	// ModuleRequestsErrors 是请求与错误当前窗口状态。
	ModuleRequestsErrors Module = "requests_errors"
	// ModuleTasksNotifications 是后台任务与通知（邮件/Webhook）状态。
	ModuleTasksNotifications Module = "tasks_notifications"
	// ModuleDatabase 是数据库可用性与延迟。
	ModuleDatabase Module = "database"
	// ModuleCertificate 是证书状态与到期时间。
	ModuleCertificate Module = "certificate"
	// ModuleBackup 是备份指标；当前没有备份实现，按“未启用”如实呈现。
	ModuleBackup Module = "backup"
)

// RequiredModules 返回健康快照必须表达的模块顺序。缺少真实来源的模块以未知或
// 未启用呈现，不省略、不默认健康。
func RequiredModules() []Module {
	return []Module{ModuleService, ModuleRequestsErrors, ModuleTasksNotifications,
		ModuleDatabase, ModuleCertificate, ModuleBackup}
}

// ModuleState 是模块当前观测状态。
type ModuleState string

const (
	// StateHealthy 表示该模块当前观测正常。
	StateHealthy ModuleState = "healthy"
	// StateDegraded 表示降级/有告警但仍可用。
	StateDegraded ModuleState = "degraded"
	// StateUnavailable 表示不可用/故障。
	StateUnavailable ModuleState = "unavailable"
	// StateUnknown 表示没有可用观测，未知不等于健康。
	StateUnknown ModuleState = "unknown"
	// StateNotEnabled 表示该模块当前未启用/未实现（例如未来备份指标）。
	StateNotEnabled ModuleState = "not_enabled"
)

// Valid 报告模块状态是否已定义。
func (s ModuleState) Valid() bool {
	switch s {
	case StateHealthy, StateDegraded, StateUnavailable, StateUnknown, StateNotEnabled:
		return true
	default:
		return false
	}
}

// HealthSample 是一个模块在某个观测时刻的状态样本。
type HealthSample struct {
	Module     Module
	State      ModuleState
	Severity   Severity
	Enabled    bool
	ObservedAt time.Time
	// Source 是状态来源稳定标识（如 database/certificate/task_queue），用于说明
	// 数据的可信出处，不包含连接串或凭据。
	Source string
	// Detail 是有界的脱敏补充信息（如延迟毫秒数、到期时间文本）。
	Detail map[string]string
}

// validateHealthSample 校验样本的稳定字段与有界性。
func validateHealthSample(sample HealthSample) error {
	if !validToken(string(sample.Module), 64) {
		return fmt.Errorf("%w: 健康模块标识无效", ErrInvalidRequest)
	}
	if !sample.State.Valid() {
		return fmt.Errorf("%w: 模块状态未定义", ErrInvalidRequest)
	}
	if sample.Severity != "" && !sample.Severity.Valid() {
		return fmt.Errorf("%w: 严重度未定义", ErrInvalidRequest)
	}
	if sample.ObservedAt.IsZero() {
		return fmt.Errorf("%w: 观测时间不能为空", ErrInvalidRequest)
	}
	if !validToken(sample.Source, 64) {
		return fmt.Errorf("%w: 状态来源标识无效", ErrInvalidRequest)
	}
	if len(sample.Detail) > 16 {
		return fmt.Errorf("%w: 状态补充字段过多", ErrInvalidRequest)
	}
	for key, value := range sample.Detail {
		if !validToken(key, 64) {
			return fmt.Errorf("%w: 状态补充字段名无效", ErrInvalidRequest)
		}
		if len(value) > 256 {
			return fmt.Errorf("%w: 状态补充字段值过长", ErrInvalidRequest)
		}
	}
	return nil
}

// validToken 校验稳定标识：非空、长度受限、只含 ASCII 字母/数字与 . _ -。
func validToken(value string, max int) bool {
	if value == "" || len(value) > max {
		return false
	}
	for index := 0; index < len(value); index++ {
		c := value[index]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}
