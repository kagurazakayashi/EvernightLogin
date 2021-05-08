// Package app 实现应用登记、资料管理与应用作用范围一致性。
//
// 本包是内部领域包，不直接暴露 HTTP 端点：调用方只能通过可信 Caller 与
// Authorizer 调用。应用 ID 由服务生成且创建后不可变；创建应用时在同一数据库
// 事务中写入 applications 行与唯一对应的 application scope，避免出现“有应用
// 无作用范围”或“有作用范围无应用”的半状态。
//
// 边界：
//   - 本包只处理应用记录、展示资料与启停状态；不实现 OAuth 客户端凭证、回调/
//     授权端点或 Web 页面（后续步骤）。
//   - 展示字段（名称/描述/图标引用/主页/联系方式）与可信客户端配置分开：客户端
//     类型只在创建时确定，资料更新白名单不包含它；应用 ID 也不可修改。
//   - 负责人变更只改 owner_user_id，不会自动转移任何管理权限；应用管理员分配由
//     授权器/后续权限模块维护。
//   - 应用停用写入状态与可靠审计事件；依赖方必须检查应用状态，令牌/会话模块
//     以后才能消费该失效信号（本步不实现令牌）。
//   - 应用成员关系与应用专属资料按应用隔离：成员状态只影响指定应用，不能禁用
//     全局账户或影响其他应用；加入既有账户必须经过可信 Authorizer 的受控调用，
//     仅知道用户名/邮箱不能认领账户，成员关系不自动授予任何业务功能权限。
//   - 成员添加/资料更新/启停在审计事务中与成功审计一致提交；成员移除写可靠审计
//     事件。未来令牌/会话模块必须消费成员移除/停用与应用停用事件，并在每次授权
//     时读取当前成员状态；本包没有会话/令牌表，不声称撤销全链路已完成。
//   - 本步不提供应用删除：删除会级联应用 scope、角色/权限关系与成员关系，必须在
//     后续步骤先定义审计保留、数据移交与受保护应用策略；停用不等于删除。
package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/netpolicy"
)

const (
	// MaxNameRunes 是应用名称的字符上限。
	MaxNameRunes = 64
	// MaxDescriptionRunes 是应用描述的字符上限。
	MaxDescriptionRunes = 1000
	// MaxIconRefBytes 是图标引用长度上限。
	MaxIconRefBytes = 256
	// MaxHomepageBytes 是主页 URL 长度上限。
	MaxHomepageBytes = 2048
	// MaxContactInfoRunes 是联系方式字符上限。
	MaxContactInfoRunes = 256
	// DefaultListLimit/MaxListLimit 是应用列表的默认与最大每页数量。
	DefaultListLimit = 20
	MaxListLimit     = 100
	// MaxListOffset 限制列表偏移量，避免深分页放大数据库开销。
	MaxListOffset = 1_000_000
	// applicationIDPrefix/applicationIDRandomBytes 定义应用 ID 格式：app_ + 128 位随机数。
	applicationIDPrefix      = "app_"
	applicationIDRandomBytes = 16
)

// Status 是应用全局状态，与 applications 表 CHECK 约束一致。
type Status string

const (
	// StatusActive 表示应用已启用。
	StatusActive Status = "active"
	// StatusDisabled 表示应用已停用；应用相关令牌/会话模块必须检查该状态。
	StatusDisabled Status = "disabled"
)

// Valid 报告状态是否已定义。
func (s Status) Valid() bool {
	return s == StatusActive || s == StatusDisabled
}

// ClientType 是可信客户端类型（公开/保密），只在创建时确定。
type ClientType string

const (
	// ClientTypePublic 表示公开客户端（如移动 App/SPA，不能保存密钥）。
	ClientTypePublic ClientType = "public"
	// ClientTypeConfidential 表示保密客户端（服务端可安全保存凭证）。
	ClientTypeConfidential ClientType = "confidential"
)

// Valid 报告客户端类型是否已定义。
func (c ClientType) Valid() bool {
	return c == ClientTypePublic || c == ClientTypeConfidential
}

// SortField 是应用列表允许的排序字段白名单。
type SortField string

const (
	SortCreatedAt SortField = "created_at"
	SortUpdatedAt SortField = "updated_at"
	SortName      SortField = "name"
	SortID        SortField = "id"
)

// Valid 报告排序字段是否在白名单内。
func (s SortField) Valid() bool {
	switch s {
	case SortCreatedAt, SortUpdatedAt, SortName, SortID:
		return true
	default:
		return false
	}
}

// Application 是应用记录快照。ScopeID 是同一事务创建的应用作用范围 ID。
type Application struct {
	ID          string
	Name        string
	Description string
	IconRef     string
	Homepage    string
	OwnerUserID string
	ContactInfo string
	Status      Status
	ClientType  ClientType
	ScopeID     string
	RowVersion  int64
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// CreateRequest 是应用登记白名单。应用 ID、状态与 row_version 由服务生成/默认值
// 决定；它不包含 OAuth 凭证、回调地址等可信客户端秘密字段。
type CreateRequest struct {
	Name        string
	Description string
	IconRef     string
	Homepage    string
	OwnerUserID string
	ContactInfo string
	ClientType  ClientType
}

// UpdateRequest 是应用资料更新白名单。它不包含 ID、client_type、status 与
// row_version 以外的可信配置：应用 ID 不可修改，客户端类型只在创建时确定，
// 状态通过独立启停命令变更。
type UpdateRequest struct {
	Name               string
	Description        string
	IconRef            string
	Homepage           string
	OwnerUserID        string
	ContactInfo        string
	ExpectedRowVersion int64
}

// StatusRequest 是应用启停请求。
type StatusRequest struct {
	ApplicationID      string
	ExpectedRowVersion int64
}

// StatusResult 是应用启停结果。Changed=false 表示已处于目标状态（幂等成功）。
type StatusResult struct {
	Application Application
	Changed     bool
}

// ListRequest 是应用列表请求；Status 为空表示不过滤。
type ListRequest struct {
	Limit      int
	Offset     int
	Status     Status
	Sort       SortField
	Descending bool
}

// ListResult 是应用列表结果。
type ListResult struct {
	Applications []Application
	HasMore      bool
}

// 领域错误哨兵；调用方用 errors.Is 判断，并用 CodeOf 映射已登记错误码。
var (
	ErrOptionsInvalid      = errors.New("应用服务选项无效")
	ErrInvalidRequest      = errors.New("应用请求无效")
	ErrApplicationNotFound = errors.New("应用不存在")
	ErrAccessDenied        = errors.New("未获准执行该操作")
	ErrStateConflict       = errors.New("应用数据已被其他操作修改")
	ErrInvalidTransition   = errors.New("当前应用状态不允许该操作")
	ErrStoreUnavailable    = errors.New("应用存储暂时不可用")
	ErrAuditUnavailable    = errors.New("关键操作未能可靠记录")
)

// ErrorCode 是与根包错误码注册表一致的字面值；根包测试核对登记状态。
type ErrorCode string

const (
	CodeReqInvalid       ErrorCode = "REQ_INVALID"
	CodeConflict         ErrorCode = "CONFLICT"
	CodeAccessDenied     ErrorCode = "ACCESS_DENIED"
	CodeClientDisabled   ErrorCode = "CLIENT_DISABLED"
	CodeUserDisabled     ErrorCode = "USER_DISABLED"
	CodeDBUnavailable    ErrorCode = "DB_UNAVAILABLE"
	CodeAuditWriteFailed ErrorCode = "AUDIT_WRITE_FAILED"
	CodeInternalError    ErrorCode = "INTERNAL_ERROR"
)

// CodeOf 把应用领域错误映射到已登记错误码。
func CodeOf(err error) ErrorCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrInvalidRequest),
		errors.Is(err, ErrApplicationNotFound),
		errors.Is(err, ErrMemberNotFound),
		errors.Is(err, ErrTargetUserNotFound):
		return CodeReqInvalid
	case errors.Is(err, ErrStateConflict), errors.Is(err, ErrInvalidTransition),
		errors.Is(err, ErrMemberExists):
		return CodeConflict
	case errors.Is(err, ErrAccessDenied):
		return CodeAccessDenied
	case errors.Is(err, ErrApplicationInactive):
		return CodeClientDisabled
	case errors.Is(err, ErrUserNotEligible):
		return CodeUserDisabled
	case errors.Is(err, ErrStoreUnavailable):
		return CodeDBUnavailable
	case errors.Is(err, ErrAuditUnavailable):
		return CodeAuditWriteFailed
	default:
		return CodeInternalError
	}
}

// NewApplicationID 生成 app_ + 128 位随机数的稳定应用 ID。
func NewApplicationID(random io.Reader) (string, error) {
	if random == nil {
		random = rand.Reader
	}
	buffer := make([]byte, applicationIDRandomBytes)
	if _, err := io.ReadFull(random, buffer); err != nil {
		return "", fmt.Errorf("无法生成应用 ID: %w", err)
	}
	return applicationIDPrefix + hex.EncodeToString(buffer), nil
}

// ValidApplicationID 报告应用 ID 是否符合本包生成的固定格式。
func ValidApplicationID(id string) bool {
	if len(id) != len(applicationIDPrefix)+2*applicationIDRandomBytes ||
		!strings.HasPrefix(id, applicationIDPrefix) {
		return false
	}
	_, err := hex.DecodeString(id[len(applicationIDPrefix):])
	return err == nil
}

// ScopeID 返回应用对应的作用范围 ID；当前约定与应用 ID 相同（1:1、稳定）。
func ScopeID(applicationID string) string {
	return applicationID
}

// normalizeText 做 NFKC 规范化、去首尾空白并校验 UTF-8；rejectNewlines 为 true
// 时拒绝换行/制表符，允许单行文本字段使用。
func normalizeText(raw string, maxRunes int, rejectNewlines bool) (string, error) {
	value := strings.TrimSpace(norm.NFKC.String(strings.TrimSpace(raw)))
	if value == "" {
		return "", nil
	}
	if !utf8.ValidString(value) {
		return "", fmt.Errorf("%w: 文本不是合法 UTF-8", ErrInvalidRequest)
	}
	count := 0
	for _, character := range value {
		count++
		if character == '\n' || character == '\t' {
			if rejectNewlines {
				return "", fmt.Errorf("%w: 文本字段不能包含换行或制表符", ErrInvalidRequest)
			}
			continue
		}
		if unicode.IsControl(character) || unicode.Is(unicode.Cf, character) ||
			unicode.Is(unicode.Zl, character) || unicode.Is(unicode.Zp, character) {
			return "", fmt.Errorf("%w: 文本包含不允许的控制或格式字符", ErrInvalidRequest)
		}
	}
	if count > maxRunes {
		return "", fmt.Errorf("%w: 文本超过 %d 个字符", ErrInvalidRequest, maxRunes)
	}
	return value, nil
}

// normalizeIconRef 校验图标引用：只允许相对存储引用，不允许绝对 URL、协议、
// 反斜杠、查询串或 .. 路径段，避免展示字段变成外部资源抓取入口。
func normalizeIconRef(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil
	}
	if len(value) > MaxIconRefBytes {
		return "", fmt.Errorf("%w: 图标引用过长", ErrInvalidRequest)
	}
	if strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") ||
		strings.ContainsAny(value, "\\?#") || strings.Contains(value, "://") {
		return "", fmt.Errorf("%w: 图标引用必须是受控相对存储引用", ErrInvalidRequest)
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "", fmt.Errorf("%w: 图标引用包含非法路径段", ErrInvalidRequest)
		}
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' ||
			character == '_' || character == '-' || character == '/' {
			continue
		}
		return "", fmt.Errorf("%w: 图标引用包含不允许的字符", ErrInvalidRequest)
	}
	return value, nil
}

// normalizeHomepage 校验主页 URL：只允许 http/https 绝对地址，必须带合法主机，
// 不允许用户信息、控制字符与超长值。服务端不抓取该地址。
func normalizeHomepage(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil
	}
	if len(value) > MaxHomepageBytes {
		return "", fmt.Errorf("%w: 主页地址过长", ErrInvalidRequest)
	}
	for _, character := range value {
		if character <= 0x20 || character == 0x7f {
			return "", fmt.Errorf("%w: 主页地址包含空白或控制字符", ErrInvalidRequest)
		}
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("%w: 主页地址不是合法 URL", ErrInvalidRequest)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("%w: 主页地址必须使用 http 或 https", ErrInvalidRequest)
	}
	if parsed.Host == "" || parsed.User != nil {
		return "", fmt.Errorf("%w: 主页地址必须带主机且不能包含用户信息", ErrInvalidRequest)
	}
	if _, err := netpolicy.ParseRequestHost(parsed.Host); err != nil {
		return "", fmt.Errorf("%w: 主页主机名无效", ErrInvalidRequest)
	}
	return value, nil
}

// normalizeContactInfo 校验联系方式：单行纯文本，拒绝控制/格式字符，不解释为
// 可执行内容；日志与审计不得输出完整值。
func normalizeContactInfo(raw string) (string, error) {
	return normalizeText(raw, MaxContactInfoRunes, true)
}

// validateOwnerUserID 校验可选负责人 ID 的格式；存在性与状态由服务查询数据库。
func validateOwnerUserID(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil
	}
	if !account.ValidUserID(value) {
		return "", fmt.Errorf("%w: 负责人用户 ID 格式无效", ErrInvalidRequest)
	}
	return value, nil
}

// Action 是应用操作动作。
type Action string

const (
	ActionCreateApplication  Action = "application.create"
	ActionGetApplication     Action = "application.get"
	ActionListApplications   Action = "application.list"
	ActionUpdateApplication  Action = "application.update"
	ActionEnableApplication  Action = "application.enable"
	ActionDisableApplication Action = "application.disable"
	// 应用成员动作；全部要求显式 ApplicationID，授权器按应用分配判权。
	ActionAddApplicationMember           Action = "application.member.add"
	ActionGetApplicationMember           Action = "application.member.get"
	ActionListApplicationMembers         Action = "application.member.list"
	ActionUpdateApplicationMemberProfile Action = "application.member.profile.update"
	ActionEnableApplicationMember        Action = "application.member.enable"
	ActionDisableApplicationMember       Action = "application.member.disable"
	ActionRemoveApplicationMember        Action = "application.member.remove"
)

// Valid 报告动作是否已定义。
func (a Action) Valid() bool {
	switch a {
	case ActionCreateApplication, ActionGetApplication, ActionListApplications,
		ActionUpdateApplication, ActionEnableApplication, ActionDisableApplication,
		ActionAddApplicationMember, ActionGetApplicationMember, ActionListApplicationMembers,
		ActionUpdateApplicationMemberProfile, ActionEnableApplicationMember,
		ActionDisableApplicationMember, ActionRemoveApplicationMember:
		return true
	default:
		return false
	}
}

// Caller 是可信操作者上下文；字段不导出，只能由构造器生成。
type Caller struct {
	actor     audit.Actor
	requestID string
}

// LocalBootstrapCaller 构造受限本地初始化操作者（local_admin）。
func LocalBootstrapCaller(operatorID string) (Caller, error) {
	return newCaller(audit.ActorLocalAdmin, operatorID)
}

// SystemCaller 构造系统组件操作者（system）；必须有显式系统操作者白名单。
func SystemCaller(componentID string) (Caller, error) {
	return newCaller(audit.ActorSystem, componentID)
}

// UserCaller 构造应用管理员用户操作者（user）；权限仍由 Authorizer 判定。
func UserCaller(userID string) (Caller, error) {
	return newCaller(audit.ActorUser, userID)
}

func newCaller(kind audit.ActorKind, id string) (Caller, error) {
	actor := audit.Actor{Type: kind, ID: id}
	if err := actor.Validate(); err != nil {
		return Caller{}, fmt.Errorf("%w: 操作者标识无效", ErrInvalidRequest)
	}
	return Caller{actor: actor}, nil
}

// WithRequestID 返回带请求编号的调用者副本。
func (c Caller) WithRequestID(requestID string) (Caller, error) {
	if requestID != "" {
		if len(requestID) > 64 {
			return Caller{}, fmt.Errorf("%w: 请求编号过长", ErrInvalidRequest)
		}
		for index := 0; index < len(requestID); index++ {
			character := requestID[index]
			if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
				(character >= '0' && character <= '9') || character == '.' ||
				character == '_' || character == '-' {
				continue
			}
			return Caller{}, fmt.Errorf("%w: 请求编号包含非法字符", ErrInvalidRequest)
		}
	}
	c.requestID = requestID
	return c, nil
}

// Authorizer 判定可信调用者是否可执行应用操作。ApplicationID 为空表示创建/列表
// 等无单一目标的操作。实际权限引擎未完成前只提供 StaticAuthorizer。
type Authorizer interface {
	Authorize(ctx context.Context, caller Caller, action Action, applicationID string) error
	// ApplicationScope 返回调用者可管理的应用：all=true 表示可管理全部应用；
	// 否则返回显式应用 ID 列表（用于列表过滤）。
	ApplicationScope(ctx context.Context, caller Caller) (all bool, applicationIDs []string, err error)
}

// AuthorizerOptions 是 StaticAuthorizer 的显式配置。
type AuthorizerOptions struct {
	// LocalAdminIDs 是受限本地初始化操作者 ID，可管理全部应用。
	LocalAdminIDs []string
	// SystemIDs 是允许创建/管理应用的系统组件 ID。
	SystemIDs []string
	// ApplicationAdmins 按应用 ID 配置应用管理员用户 ID（只读/改资料/启停已分配
	// 应用，不能创建应用或改负责人）。
	ApplicationAdmins map[string][]string
}

// StaticAuthorizer 是权限引擎未完成前的显式白名单授权器。它只根据构造时给定的
// 系统/本地操作者与应用管理员映射判权，不读取请求参数自称的身份；不是完整权限
// 引擎，不能替代后续角色/权限模型。
type StaticAuthorizer struct {
	mu          sync.RWMutex
	localAdmins map[string]struct{}
	systems     map[string]struct{}
	appAdmins   map[string]map[string]struct{}
}

// NewStaticAuthorizer 构造显式白名单授权器并校验所有者 ID。
func NewStaticAuthorizer(options AuthorizerOptions) (*StaticAuthorizer, error) {
	if len(options.LocalAdminIDs) == 0 && len(options.SystemIDs) == 0 {
		return nil, fmt.Errorf("%w: 至少需要一个本地管理员或系统操作者", ErrOptionsInvalid)
	}
	authorizer := &StaticAuthorizer{
		localAdmins: make(map[string]struct{}, len(options.LocalAdminIDs)),
		systems:     make(map[string]struct{}, len(options.SystemIDs)),
		appAdmins:   make(map[string]map[string]struct{}, len(options.ApplicationAdmins)),
	}
	for _, id := range options.LocalAdminIDs {
		actor := audit.Actor{Type: audit.ActorLocalAdmin, ID: id}
		if err := actor.Validate(); err != nil {
			return nil, fmt.Errorf("%w: 本地管理员标识无效", ErrOptionsInvalid)
		}
		authorizer.localAdmins[id] = struct{}{}
	}
	for _, id := range options.SystemIDs {
		actor := audit.Actor{Type: audit.ActorSystem, ID: id}
		if err := actor.Validate(); err != nil {
			return nil, fmt.Errorf("%w: 系统操作者标识无效", ErrOptionsInvalid)
		}
		authorizer.systems[id] = struct{}{}
	}
	for appID, userIDs := range options.ApplicationAdmins {
		if !ValidApplicationID(appID) {
			return nil, fmt.Errorf("%w: 应用管理员配置中的应用 ID 无效", ErrOptionsInvalid)
		}
		admins := make(map[string]struct{}, len(userIDs))
		for _, userID := range userIDs {
			actor := audit.Actor{Type: audit.ActorUser, ID: userID}
			if err := actor.Validate(); err != nil {
				return nil, fmt.Errorf("%w: 应用管理员用户 ID 无效", ErrOptionsInvalid)
			}
			admins[userID] = struct{}{}
		}
		authorizer.appAdmins[appID] = admins
	}
	return authorizer, nil
}

// AssignApplicationAdmin 显式给应用分配一名管理员用户。它由宿主/后续权限模块
// 在受控流程中调用，不会因为负责人变更自动触发；应用管理员自身没有该能力。
func (a *StaticAuthorizer) AssignApplicationAdmin(applicationID, userID string) error {
	if a == nil {
		return ErrOptionsInvalid
	}
	if !ValidApplicationID(applicationID) {
		return fmt.Errorf("%w: 应用 ID 无效", ErrInvalidRequest)
	}
	actor := audit.Actor{Type: audit.ActorUser, ID: userID}
	if err := actor.Validate(); err != nil {
		return fmt.Errorf("%w: 应用管理员用户 ID 无效", ErrInvalidRequest)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	admins, ok := a.appAdmins[applicationID]
	if !ok {
		admins = make(map[string]struct{})
		a.appAdmins[applicationID] = admins
	}
	admins[userID] = struct{}{}
	return nil
}

// Authorize 实现 Authorizer。
func (a *StaticAuthorizer) Authorize(_ context.Context, caller Caller, action Action, applicationID string) error {
	if a == nil || !action.Valid() {
		return ErrAccessDenied
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if caller.actor.Type == audit.ActorLocalAdmin {
		if _, ok := a.localAdmins[caller.actor.ID]; ok {
			return nil
		}
		return ErrAccessDenied
	}
	if caller.actor.Type == audit.ActorSystem {
		if _, ok := a.systems[caller.actor.ID]; !ok {
			return ErrAccessDenied
		}
		return nil
	}
	if caller.actor.Type == audit.ActorUser {
		if action == ActionListApplications {
			// 列表范围由 ApplicationScope 过滤；不在此按单个应用判权。
			return nil
		}
		if action == ActionCreateApplication || applicationID == "" {
			return ErrAccessDenied
		}
		admins, ok := a.appAdmins[applicationID]
		if !ok {
			return ErrAccessDenied
		}
		if _, ok := admins[caller.actor.ID]; !ok {
			return ErrAccessDenied
		}
		return nil
	}
	return ErrAccessDenied
}

// ApplicationScope 实现 Authorizer。
func (a *StaticAuthorizer) ApplicationScope(_ context.Context, caller Caller) (bool, []string, error) {
	if a == nil {
		return false, nil, ErrAccessDenied
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	switch caller.actor.Type {
	case audit.ActorLocalAdmin:
		if _, ok := a.localAdmins[caller.actor.ID]; ok {
			return true, nil, nil
		}
	case audit.ActorSystem:
		if _, ok := a.systems[caller.actor.ID]; ok {
			return true, nil, nil
		}
	case audit.ActorUser:
		values := make([]string, 0, len(a.appAdmins))
		for appID, admins := range a.appAdmins {
			if _, ok := admins[caller.actor.ID]; ok {
				values = append(values, appID)
			}
		}
		sort.Strings(values)
		return false, values, nil
	}
	return false, nil, ErrAccessDenied
}
