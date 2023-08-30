package app

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"strconv"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
	"github.com/kagurazakayashi/EvernightLogin/internal/securityevent"
)

// AuditRecorder 是应用服务依赖的安全审计写入契约，生产实现为 *audit.Recorder。
type AuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
	RecordFailure(ctx context.Context, event audit.Event) error
	ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error
}

// UpdateRecord 是已通过校验的条件资料更新；仓储映射固定 SQL 字段。
type UpdateRecord struct {
	ApplicationID      string
	ExpectedRowVersion int64
	Name               string
	Description        string
	IconRef            string
	Homepage           string
	OwnerUserID        string
	ContactInfo        string
	Now                time.Time
}

// StatusChange 是已通过状态机校验的条件启停更新。
type StatusChange struct {
	ApplicationID      string
	ExpectedRowVersion int64
	ExpectedStatus     Status
	NewStatus          Status
	Now                time.Time
}

// ListQuery 是已校验的应用列表查询参数。
type ListQuery struct {
	Limit           int
	Offset          int
	Status          Status
	Sort            SortField
	Descending      bool
	AllApplications bool
	ApplicationIDs  []string
	// IncludeDeleted 为 true 时包含已逻辑删除的应用（默认只返回未删除应用）。
	IncludeDeleted bool
}

// DeletionChange 是已通过状态机与行版本校验的逻辑删除条件更新。
type DeletionChange struct {
	ApplicationID      string
	ExpectedRowVersion int64
	Now                time.Time
}

// Store 是应用持久化契约，由 internal/app/sqlite 提供生产实现。
//
// CreateApplication 必须在调用方给出的 audit.Tx 中同时写入 applications 行与
// 对应的 scopes(id=app_id, kind='application', app_id) 行；任一步失败整体回滚。
type Store interface {
	CreateApplication(ctx context.Context, tx audit.Tx, application Application) error
	GetApplication(ctx context.Context, id string) (Application, error)
	ListApplications(ctx context.Context, query ListQuery) ([]Application, bool, error)
	UpdateApplication(ctx context.Context, tx audit.Tx, update UpdateRecord) error
	ApplyStatus(ctx context.Context, tx audit.Tx, change StatusChange) error
	// MarkApplicationDeleted 以行版本为条件标记逻辑删除（deleted_at_ms 非空），
	// 同一 UPDATE 内不物理删除任何关联数据。
	MarkApplicationDeleted(ctx context.Context, tx audit.Tx, change DeletionChange) error
	// DeletionImpact 读取删除前影响预览的真实计数（成员/角色/权限/会话/客户端/
	// 授权/凭证/邀请/Webhook/审计），用于页面预览与审计记录。
	DeletionImpact(ctx context.Context, applicationID string) (DeletionImpact, error)
	// PurgeApplication 在调用方审计事务中物理清理已逻辑删除的应用及其外键级联数据
	// （作用范围/成员/角色/权限/组/会话/客户端/授权/凭证/邀请/Webhook 配置/托管策略），
	// 并显式清理无外键的刷新令牌族；共享账户与安全审计记录不在清理范围。
	PurgeApplication(ctx context.Context, tx audit.Tx, applicationID string) error
	// UserEligibleAsOwner 报告用户是否存在且处于 active 状态；负责人变更只允许
	// 指向仍可用账户，不做任何权限转移。
	UserEligibleAsOwner(ctx context.Context, userID string) (bool, error)

	// 应用成员持久化：所有方法都必须以 ApplicationID + UserID 为范围，仓储不得
	// 提供跨应用读取或写入。成员资料只存 profile_json，不写回全局用户资料。
	GetMembership(ctx context.Context, applicationID, userID string) (Membership, error)
	ListMemberships(ctx context.Context, query MemberListQuery) ([]Membership, bool, error)
	// CreateMembership 必须在调用方审计事务中写入成员关系；重复加入返回
	// ErrMemberExists，不覆盖已有成员资料。
	CreateMembership(ctx context.Context, tx audit.Tx, membership Membership) error
	// UpdateMembershipProfile 只更新 profile_json 与 row_version。
	UpdateMembershipProfile(ctx context.Context, tx audit.Tx, update MemberProfileUpdate) error
	// ApplyMembershipStatus 以状态与行版本为条件更新应用内成员状态。
	ApplyMembershipStatus(ctx context.Context, tx audit.Tx, change MemberStatusChange) error
	// RemoveMembership 以行版本为条件删除成员关系；只影响指定应用，不删除用户。
	RemoveMembership(ctx context.Context, tx audit.Tx, remove MemberRemove) error
	// LookupUserState 返回全局账户状态、root 标记与是否存在；加入/启用成员前
	// 必须要求 active 且非 root。root 只能通过受保护本地通道管理，不能成为
	// 应用成员；删除/停用成员关系时允许清理非 active 账户。
	LookupUserState(ctx context.Context, userID string) (status account.Status, isRoot bool, found bool, err error)
	// ListMemberEffectivePermissionIDs 在调用方事务内读取该用户在该应用范围内
	// 通过直接角色与用户组角色当前会生效的权限 ID（角色/权限启用且非 root_only）。
	// 加入/重新启用成员会让这些权限恢复生效，写前必须做可转授检查。
	ListMemberEffectivePermissionIDs(ctx context.Context, tx audit.Tx, applicationID, userID string) ([]string, error)
}

// MaxManageableApplicationScopes 是可管理应用候选枚举的硬上限（分页泄漏与查询
// 资源保护）：超过上限时返回错误而不是静默截断，避免“看不到但存在”的越权误判。
const MaxManageableApplicationScopes = 256

// ScopeCandidateLister 是应用存储的可选能力：枚举用户在应用范围内拥有**启用角色**
// 的候选应用 ID。它只用于缩小候选集合，最终授权仍必须由权限引擎逐应用判定；
// 不得把候选列表直接当作已授权应用返回给调用方。
type ScopeCandidateLister interface {
	// ListUserApplicationScopes 返回去重排序后的应用 ID（稳定顺序）；
	// 数量超过 MaxManageableApplicationScopes 时返回错误（fail-closed）。
	ListUserApplicationScopes(ctx context.Context, userID string) ([]string, error)
}

// Options 是构造应用服务的显式依赖。
type Options struct {
	Store      Store
	Audit      AuditRecorder
	Authorizer Authorizer
	Transfers  delegation.Guard
	// Events 是可选的安全事件通知契约（步骤 59 Webhook）；nil 表示未启用通知，
	// 不影响成员关系变更。事件在审计事务提交后发出，失败只记日志。
	Events securityevent.Emitter
	// PurgeRetention 是逻辑删除后允许物理清理的最小保留期；0 使用
	// DefaultPurgeRetention（30 天），负数拒绝构造。保留期内只能逻辑删除，不能清理。
	PurgeRetention time.Duration
	Now            func() time.Time
	Random         io.Reader
	Logger         *slog.Logger
}

// DefaultPurgeRetention 是逻辑删除到物理清理的默认保留期。
const DefaultPurgeRetention = 30 * 24 * time.Hour

// Service 是应用领域服务。构造后不可变，可被多个 goroutine 并发使用；不启动
// 后台协程、不提供 HTTP 端点。
type Service struct {
	events         securityevent.Emitter
	store          Store
	audit          AuditRecorder
	authorizer     Authorizer
	transfers      delegation.Guard
	now            func() time.Time
	random         io.Reader
	logger         *slog.Logger
	purgeRetention time.Duration
}

// New 校验依赖并构造应用服务；缺少 Store/Audit/Authorizer 返回 ErrOptionsInvalid。
func New(options Options) (*Service, error) {
	if isNil(options.Store) {
		return nil, fmt.Errorf("%w: 应用存储为空", ErrOptionsInvalid)
	}
	if isNil(options.Audit) {
		return nil, fmt.Errorf("%w: 安全审计写入器为空", ErrOptionsInvalid)
	}
	if isNil(options.Authorizer) {
		return nil, fmt.Errorf("%w: 授权器为空", ErrOptionsInvalid)
	}
	if isNil(options.Transfers) {
		return nil, fmt.Errorf("%w: 可转授权限检查器为空", ErrOptionsInvalid)
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	purgeRetention := options.PurgeRetention
	if purgeRetention < 0 {
		return nil, fmt.Errorf("%w: 物理清理保留期不能为负数", ErrOptionsInvalid)
	}
	if purgeRetention == 0 {
		purgeRetention = DefaultPurgeRetention
	}
	random := options.Random
	if random == nil {
		random = rand.Reader
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
	}
	return &Service{store: options.Store, audit: options.Audit, authorizer: options.Authorizer,
		transfers: options.Transfers, events: options.Events, now: now, random: random,
		logger: logger, purgeRetention: purgeRetention}, nil
}

// CreateApplication 登记应用，并在同一审计事务中创建唯一对应的应用作用范围。
// 应用 ID 由服务生成且不可变；创建状态为 disabled，资料变更后通过显式启停启用。
// 客户端类型只在创建时确定，资料更新请求不能修改它。
func (s *Service) CreateApplication(ctx context.Context, caller Caller, request CreateRequest) (Application, error) {
	if err := s.authorize(ctx, caller, ActionCreateApplication, ""); err != nil {
		return Application{}, err
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return Application{}, err
	}
	application, err := s.buildNewApplication(ctx, request)
	if err != nil {
		return Application{}, err
	}
	id, err := NewApplicationID(s.random)
	if err != nil {
		return Application{}, fmt.Errorf("%w: %v", ErrStoreUnavailable, err)
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	application.ID = id
	application.ScopeID = ScopeID(id)
	application.Status = StatusDisabled
	application.RowVersion = 1
	application.CreatedAt = now
	application.UpdatedAt = now
	event := audit.Event{
		Actor:     caller.actor,
		Action:    string(ActionCreateApplication),
		Target:    audit.Target{Type: "application", ID: application.ID},
		RequestID: caller.requestID,
		Changes: []audit.FieldChange{
			{Field: "name", After: application.Name},
			{Field: "status", After: string(application.Status)},
			{Field: "client_type", After: string(application.ClientType)},
			{Field: "scope_id", After: application.ScopeID},
		},
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: "application.create_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.store.CreateApplication(txCtx, tx, application)
	})
	if err != nil {
		return Application{}, mapCriticalError(err)
	}
	s.logger.Info("应用已登记", "application_id", application.ID, "status", string(application.Status))
	return application, nil
}

// buildNewApplication 校验登记资料白名单并返回未赋 ID 的应用。
func (s *Service) buildNewApplication(ctx context.Context, request CreateRequest) (Application, error) {
	name, err := normalizeText(request.Name, MaxNameRunes, true)
	if err != nil {
		return Application{}, err
	}
	if name == "" {
		return Application{}, fmt.Errorf("%w: 应用名称不能为空", ErrInvalidRequest)
	}
	description, err := normalizeText(request.Description, MaxDescriptionRunes, false)
	if err != nil {
		return Application{}, err
	}
	iconRef, err := normalizeIconRef(request.IconRef)
	if err != nil {
		return Application{}, err
	}
	homepage, err := normalizeHomepage(request.Homepage)
	if err != nil {
		return Application{}, err
	}
	contactInfo, err := normalizeContactInfo(request.ContactInfo)
	if err != nil {
		return Application{}, err
	}
	ownerUserID, err := validateOwnerUserID(request.OwnerUserID)
	if err != nil {
		return Application{}, err
	}
	if ownerUserID != "" {
		eligible, err := s.store.UserEligibleAsOwner(ctx, ownerUserID)
		if err != nil {
			return Application{}, err
		}
		if !eligible {
			return Application{}, fmt.Errorf("%w: 负责人必须是可用账户", ErrInvalidRequest)
		}
	}
	if !request.ClientType.Valid() {
		return Application{}, fmt.Errorf("%w: 客户端类型必须是 public 或 confidential", ErrInvalidRequest)
	}
	return Application{
		Name:        name,
		Description: description,
		IconRef:     iconRef,
		Homepage:    homepage,
		OwnerUserID: ownerUserID,
		ContactInfo: contactInfo,
		ClientType:  request.ClientType,
	}, nil
}

// GetApplication 按应用 ID 查询，并写审计读取事件；审计失败时拒绝返回数据。
func (s *Service) GetApplication(ctx context.Context, caller Caller, id string) (Application, error) {
	if err := s.authorize(ctx, caller, ActionGetApplication, id); err != nil {
		return Application{}, err
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return Application{}, err
	}
	if !ValidApplicationID(id) {
		return Application{}, fmt.Errorf("%w: 应用 ID 格式无效", ErrInvalidRequest)
	}
	application, err := s.store.GetApplication(ctx, id)
	if err != nil {
		return Application{}, err
	}
	if err := s.recordRead(ctx, caller, ActionGetApplication, id); err != nil {
		return Application{}, err
	}
	return application, nil
}

// ListApplications 按有限分页与白名单排序检索应用。全部应用权限可列出全部；
// 应用管理员只能列出被分配的应用，不会因为请求参数而扩大范围。
func (s *Service) ListApplications(ctx context.Context, caller Caller, request ListRequest) (ListResult, error) {
	if err := s.authorize(ctx, caller, ActionListApplications, ""); err != nil {
		return ListResult{}, err
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return ListResult{}, err
	}
	all, applicationIDs, err := s.authorizer.ApplicationScope(ctx, caller)
	if err != nil {
		return ListResult{}, ErrAccessDenied
	}
	query, err := normalizeListRequest(request)
	if err != nil {
		return ListResult{}, err
	}
	query.AllApplications = all
	query.ApplicationIDs = applicationIDs
	query.IncludeDeleted = request.IncludeDeleted
	if !all && len(applicationIDs) == 0 {
		// 应用管理员没有任何分配时不查询数据库，也不泄露其他应用存在性。
		if err := s.recordRead(ctx, caller, ActionListApplications, ""); err != nil {
			return ListResult{}, err
		}
		return ListResult{Applications: []Application{}}, nil
	}
	applications, hasMore, err := s.store.ListApplications(ctx, query)
	if err != nil {
		return ListResult{}, err
	}
	if err := s.recordRead(ctx, caller, ActionListApplications, ""); err != nil {
		return ListResult{}, err
	}
	return ListResult{Applications: applications, HasMore: hasMore}, nil
}

// UpdateApplication 修改应用展示资料。允许修改名称/描述/图标引用/主页/负责人/
// 联系方式，不允许修改 ID、客户端类型或状态；应用管理员不能变更负责人。负责人
// 变更只改 owner_user_id，不自动转移任何管理权限。
func (s *Service) UpdateApplication(ctx context.Context, caller Caller, id string, request UpdateRequest) (Application, error) {
	if err := s.authorize(ctx, caller, ActionUpdateApplication, id); err != nil {
		return Application{}, err
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return Application{}, err
	}
	if !ValidApplicationID(id) {
		return Application{}, fmt.Errorf("%w: 应用 ID 格式无效", ErrInvalidRequest)
	}
	if request.ExpectedRowVersion <= 0 {
		return Application{}, fmt.Errorf("%w: 期望行版本必须大于 0", ErrInvalidRequest)
	}
	current, err := s.store.GetApplication(ctx, id)
	if err != nil {
		return Application{}, err
	}
	if current.Deleted() {
		// 逻辑删除是终态：不允许再改资料/启用（防“复活已删除应用”）。
		return Application{}, fmt.Errorf("%w: 应用已逻辑删除", ErrInvalidTransition)
	}
	updated, changes, err := s.buildUpdatedApplication(ctx, caller, current, request)
	if err != nil {
		return Application{}, err
	}
	if request.ExpectedRowVersion != current.RowVersion {
		return Application{}, ErrStateConflict
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	updated.RowVersion = current.RowVersion + 1
	updated.UpdatedAt = now
	updated.ID = current.ID
	updated.ScopeID = current.ScopeID
	updated.Status = current.Status
	updated.ClientType = current.ClientType
	event := audit.Event{
		Actor:     caller.actor,
		Action:    string(ActionUpdateApplication),
		Target:    audit.Target{Type: "application", ID: id},
		RequestID: caller.requestID,
		Changes:   changes,
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: "application.update_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.store.UpdateApplication(txCtx, tx, UpdateRecord{
			ApplicationID:      id,
			ExpectedRowVersion: current.RowVersion,
			Name:               updated.Name,
			Description:        updated.Description,
			IconRef:            updated.IconRef,
			Homepage:           updated.Homepage,
			OwnerUserID:        updated.OwnerUserID,
			ContactInfo:        updated.ContactInfo,
			Now:                now,
		})
	})
	if err != nil {
		return Application{}, mapCriticalError(err)
	}
	s.logger.Info("应用资料已更新", "application_id", id)
	return updated, nil
}

// buildUpdatedApplication 校验更新白名单并生成审计差异；负责人变更对应用管理员
// 拒绝，联系方式差异以 [REDACTED] 记录，不把完整联系信息写入审计明细。
func (s *Service) buildUpdatedApplication(ctx context.Context, caller Caller, current Application, request UpdateRequest) (Application, []audit.FieldChange, error) {
	name, err := normalizeText(request.Name, MaxNameRunes, true)
	if err != nil {
		return Application{}, nil, err
	}
	if name == "" {
		return Application{}, nil, fmt.Errorf("%w: 应用名称不能为空", ErrInvalidRequest)
	}
	description, err := normalizeText(request.Description, MaxDescriptionRunes, false)
	if err != nil {
		return Application{}, nil, err
	}
	iconRef, err := normalizeIconRef(request.IconRef)
	if err != nil {
		return Application{}, nil, err
	}
	homepage, err := normalizeHomepage(request.Homepage)
	if err != nil {
		return Application{}, nil, err
	}
	contactInfo, err := normalizeContactInfo(request.ContactInfo)
	if err != nil {
		return Application{}, nil, err
	}
	ownerUserID, err := validateOwnerUserID(request.OwnerUserID)
	if err != nil {
		return Application{}, nil, err
	}
	ownerChanged := ownerUserID != current.OwnerUserID
	if ownerChanged && caller.actor.Type == audit.ActorUser {
		return Application{}, nil, fmt.Errorf("%w: 应用管理员不能变更负责人", ErrAccessDenied)
	}
	if ownerUserID != "" && ownerChanged {
		eligible, err := s.store.UserEligibleAsOwner(ctx, ownerUserID)
		if err != nil {
			return Application{}, nil, err
		}
		if !eligible {
			return Application{}, nil, fmt.Errorf("%w: 负责人必须是可用账户", ErrInvalidRequest)
		}
	}
	updated := current
	updated.Name = name
	updated.Description = description
	updated.IconRef = iconRef
	updated.Homepage = homepage
	updated.OwnerUserID = ownerUserID
	updated.ContactInfo = contactInfo
	changes := make([]audit.FieldChange, 0, 6)
	appendChange := func(field, before, after string) {
		if before == after {
			return
		}
		changes = append(changes, audit.FieldChange{Field: field, Before: before, After: after})
	}
	appendChange("name", current.Name, updated.Name)
	appendChange("description", current.Description, updated.Description)
	appendChange("icon_ref", current.IconRef, updated.IconRef)
	appendChange("homepage", current.Homepage, updated.Homepage)
	appendChange("owner_user_id", current.OwnerUserID, updated.OwnerUserID)
	if current.ContactInfo != updated.ContactInfo {
		// 联系方式属于敏感联系信息：只记录字段被修改，不记录完整新旧值。
		changes = append(changes, audit.FieldChange{Field: "contact_info", Before: "[REDACTED]", After: "[REDACTED]"})
	}
	return updated, changes, nil
}

// EnableApplication 启用应用。重复启用幂等成功；停用后的依赖方必须重新检查状态。
// 启用会恢复该范围内被整体拒绝的有效权限，因此非受信操作者必须通过与赋权相同的
// 委派检查（权限集合 + 持有目标），无法安全校验时拒绝（仅受信通道可启用）。
func (s *Service) EnableApplication(ctx context.Context, caller Caller, request StatusRequest) (StatusResult, error) {
	return s.applyStatus(ctx, caller, request, StatusActive, ActionEnableApplication)
}

// DisableApplication 停用应用。它不删除应用或作用范围；依赖方必须检查应用状态，
// 未来令牌/会话模块消费该状态与可靠审计事件。重复停用幂等成功。
func (s *Service) DisableApplication(ctx context.Context, caller Caller, request StatusRequest) (StatusResult, error) {
	return s.applyStatus(ctx, caller, request, StatusDisabled, ActionDisableApplication)
}

// applyStatus 执行启停公共流程：授权、读取、幂等、乐观并发与审计一致提交。
func (s *Service) applyStatus(ctx context.Context, caller Caller, request StatusRequest, target Status, action Action) (StatusResult, error) {
	if err := s.authorize(ctx, caller, action, request.ApplicationID); err != nil {
		return StatusResult{}, err
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return StatusResult{}, err
	}
	if !ValidApplicationID(request.ApplicationID) {
		return StatusResult{}, fmt.Errorf("%w: 应用 ID 格式无效", ErrInvalidRequest)
	}
	if request.ExpectedRowVersion <= 0 {
		return StatusResult{}, fmt.Errorf("%w: 期望行版本必须大于 0", ErrInvalidRequest)
	}
	current, err := s.store.GetApplication(ctx, request.ApplicationID)
	if err != nil {
		return StatusResult{}, err
	}
	if current.Deleted() {
		// 已逻辑删除的应用不能再启用/停用：它只会被物理清理，不能被“复活”。
		return StatusResult{}, fmt.Errorf("%w: 应用已逻辑删除，不能再启停", ErrInvalidTransition)
	}
	if current.Status == target {
		event := audit.Event{
			Actor:     caller.actor,
			Action:    string(action),
			Target:    audit.Target{Type: "application", ID: current.ID},
			Outcome:   audit.OutcomeSuccess,
			RequestID: caller.requestID,
			Changes:   []audit.FieldChange{{Field: "result", After: "unchanged"}},
		}
		if err := s.audit.Record(ctx, event); err != nil {
			return StatusResult{}, fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
		}
		return StatusResult{Application: current, Changed: false}, nil
	}
	if request.ExpectedRowVersion != current.RowVersion {
		return StatusResult{}, ErrStateConflict
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	updated := current
	updated.Status = target
	updated.RowVersion = current.RowVersion + 1
	updated.UpdatedAt = now
	event := audit.Event{
		Actor:     caller.actor,
		Action:    string(action),
		Target:    audit.Target{Type: "application", ID: current.ID},
		RequestID: caller.requestID,
		Changes: []audit.FieldChange{
			{Field: "status", Before: string(current.Status), After: string(target)},
			{Field: "row_version", Before: formatInt64(current.RowVersion), After: formatInt64(updated.RowVersion)},
		},
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: "application.status_change_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		if target == StatusActive {
			// 停用应用会让其范围内全部权限整体拒绝；启用等于恢复这些权限，与直接
			// 赋权等价。与写入同一事务内按“将被恢复的权限集合 + 持有目标”复核
			// 委派资格；无资格的应用管理员不能通过重新启用应用恢复全应用权限，
			// 读取或校验失败一律 fail-closed（只有受信通道可无条件启用）。
			if guardErr := s.transfers.CheckScopeRestoration(txCtx, tx, caller.actor, current.ID); guardErr != nil {
				return guardErr
			}
		}
		return s.store.ApplyStatus(txCtx, tx, StatusChange{
			ApplicationID:      current.ID,
			ExpectedRowVersion: current.RowVersion,
			ExpectedStatus:     current.Status,
			NewStatus:          target,
			Now:                now,
		})
	})
	if err != nil {
		return StatusResult{}, mapCriticalError(err)
	}
	s.logger.Info("应用状态已变更", "application_id", current.ID, "status", string(target))
	return StatusResult{Application: updated, Changed: true}, nil
}

// PreviewDeletion 返回逻辑删除前影响预览：真实统计将要失效/保留的数据范围，并给出
// 是否可删除与阻塞原因。预览只读，不改变任何状态；删除的最终判定在
// DeleteApplication 中按当前状态重新执行。
func (s *Service) PreviewDeletion(ctx context.Context, caller Caller,
	applicationID string) (DeletionImpact, error) {
	if err := s.authorize(ctx, caller, ActionPreviewApplicationDeletion, applicationID); err != nil {
		return DeletionImpact{}, err
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return DeletionImpact{}, err
	}
	if !ValidApplicationID(applicationID) {
		return DeletionImpact{}, fmt.Errorf("%w: 应用 ID 格式无效", ErrInvalidRequest)
	}
	current, err := s.store.GetApplication(ctx, applicationID)
	if err != nil {
		return DeletionImpact{}, err
	}
	impact, err := s.store.DeletionImpact(ctx, applicationID)
	if err != nil {
		return DeletionImpact{}, err
	}
	impact.Application = current
	switch {
	case current.Deleted():
		impact.CanDelete = false
		impact.BlockReason = "应用已处于逻辑删除状态；后续只允许受控本地/系统通道在保留期后物理清理"
	case current.Status != StatusDisabled:
		impact.CanDelete = false
		impact.BlockReason = "必须先停用应用才能逻辑删除（停用可恢复，删除是终态）"
	default:
		impact.CanDelete = true
	}
	if err := s.recordRead(ctx, caller, ActionPreviewApplicationDeletion, applicationID); err != nil {
		return DeletionImpact{}, err
	}
	return impact, nil
}

// DeleteApplication 对已停用的应用执行逻辑删除（deleted_at_ms 非空）。
//
// 语义：立即让该应用的全部客户端凭证/旧令牌/会话/权限判定按不可用拒绝，但保留成员/
// 角色/权限/客户端/授权记录与审计供追溯；它不是停用（停用仍可恢复），也不是物理
// 清理（后者只允许受控本地/系统通道在保留期后执行）。重复删除按幂等成功返回。
func (s *Service) DeleteApplication(ctx context.Context, caller Caller,
	request DeletionRequest) (DeletionResult, error) {
	if err := s.authorize(ctx, caller, ActionDeleteApplication, request.ApplicationID); err != nil {
		return DeletionResult{}, err
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return DeletionResult{}, err
	}
	if !ValidApplicationID(request.ApplicationID) {
		return DeletionResult{}, fmt.Errorf("%w: 应用 ID 格式无效", ErrInvalidRequest)
	}
	if request.ExpectedRowVersion <= 0 {
		return DeletionResult{}, fmt.Errorf("%w: 期望行版本必须大于 0", ErrInvalidRequest)
	}
	current, err := s.store.GetApplication(ctx, request.ApplicationID)
	if err != nil {
		return DeletionResult{}, err
	}
	if current.Deleted() {
		// 幂等成功：不重复写状态变更，只记录一次“已删除”结果审计。
		event := audit.Event{
			Actor:     caller.actor,
			AppID:     current.ID,
			Action:    string(ActionDeleteApplication),
			Target:    audit.Target{Type: "application", ID: current.ID},
			Outcome:   audit.OutcomeSuccess,
			RequestID: caller.requestID,
			Changes:   []audit.FieldChange{{Field: "result", After: "already_deleted"}},
		}
		if err := s.audit.Record(ctx, event); err != nil {
			return DeletionResult{}, fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
		}
		return DeletionResult{Application: current, Changed: false}, nil
	}
	if current.Status != StatusDisabled {
		return DeletionResult{}, fmt.Errorf("%w: 只有已停用的应用可以逻辑删除", ErrInvalidTransition)
	}
	if request.ExpectedRowVersion != current.RowVersion {
		return DeletionResult{}, ErrStateConflict
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	updated := current
	updated.DeletedAt = now
	updated.RowVersion = current.RowVersion + 1
	updated.UpdatedAt = now
	event := audit.Event{
		Actor:     caller.actor,
		AppID:     current.ID,
		Action:    string(ActionDeleteApplication),
		Target:    audit.Target{Type: "application", ID: current.ID},
		RequestID: caller.requestID,
		Changes: []audit.FieldChange{
			{Field: "lifecycle", Before: string(current.Status), After: "deleted"},
			{Field: "deleted_at", After: now.Format(time.RFC3339Nano)},
			{Field: "row_version", Before: formatInt64(current.RowVersion),
				After: formatInt64(updated.RowVersion)},
			{Field: "retention", After: "保留审计与关联数据，物理清理需受控通道与保留期"},
		},
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: "application.delete_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.store.MarkApplicationDeleted(txCtx, tx, DeletionChange{
			ApplicationID:      current.ID,
			ExpectedRowVersion: current.RowVersion,
			Now:                now,
		})
	})
	if err != nil {
		return DeletionResult{}, mapCriticalError(err)
	}
	s.logger.Info("应用已逻辑删除", "application_id", current.ID)
	return DeletionResult{Application: updated, Changed: true}, nil
}

// PurgeApplication 物理清理已逻辑删除且超过保留期的应用。
//
// 只允许受控本地/系统操作者（页面/普通用户/应用管理员一律拒绝）；清理在审计事务中
// 完成：外键级联删除作用范围/成员/角色/权限/组/会话/客户端/授权/凭证/邀请/Webhook
// 配置/托管策略并显式清理刷新令牌族，但共享账户与安全审计记录（app_id_snapshot 无
// 外键）保留。目标已不存在时按幂等成功返回；失败整体回滚。
func (s *Service) PurgeApplication(ctx context.Context, caller Caller,
	request PurgeRequest) (PurgeResult, error) {
	if caller.actor.Type != audit.ActorLocalAdmin && caller.actor.Type != audit.ActorSystem {
		return PurgeResult{}, fmt.Errorf("%w: 只有受控本地/系统通道可以物理清理应用", ErrAccessDenied)
	}
	if err := s.authorize(ctx, caller, ActionPurgeApplication, request.ApplicationID); err != nil {
		return PurgeResult{}, err
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return PurgeResult{}, err
	}
	if !ValidApplicationID(request.ApplicationID) {
		return PurgeResult{}, fmt.Errorf("%w: 应用 ID 格式无效", ErrInvalidRequest)
	}
	current, err := s.store.GetApplication(ctx, request.ApplicationID)
	if err != nil {
		if errors.Is(err, ErrApplicationNotFound) {
			event := audit.Event{
				Actor:     caller.actor,
				Action:    string(ActionPurgeApplication),
				Target:    audit.Target{Type: "application", ID: request.ApplicationID},
				Outcome:   audit.OutcomeSuccess,
				RequestID: caller.requestID,
				Changes:   []audit.FieldChange{{Field: "result", After: "not_found"}},
			}
			if recordErr := s.audit.Record(ctx, event); recordErr != nil {
				return PurgeResult{}, fmt.Errorf("%w: %w", ErrAuditUnavailable, recordErr)
			}
			return PurgeResult{ApplicationID: request.ApplicationID, Changed: false}, nil
		}
		return PurgeResult{}, err
	}
	if !current.Deleted() {
		return PurgeResult{}, fmt.Errorf("%w: 只有逻辑删除后的应用可以物理清理", ErrInvalidTransition)
	}
	now := s.now().UTC()
	retention := s.purgeRetention
	if retention > 0 {
		age := now.Sub(current.DeletedAt)
		if age < retention {
			return PurgeResult{}, fmt.Errorf("%w: 逻辑删除后需满 %s 保留期才能物理清理",
				ErrInvalidTransition, retention)
		}
	}
	impact, err := s.store.DeletionImpact(ctx, current.ID)
	if err != nil {
		return PurgeResult{}, err
	}
	impact.Application = current
	event := audit.Event{
		Actor:     caller.actor,
		AppID:     current.ID,
		Action:    string(ActionPurgeApplication),
		Target:    audit.Target{Type: "application", ID: current.ID},
		RequestID: caller.requestID,
		Changes: []audit.FieldChange{
			{Field: "lifecycle", Before: "deleted", After: "purged"},
			{Field: "members", Before: formatInt64(int64(impact.MemberCount))},
			{Field: "roles", Before: formatInt64(int64(impact.RoleCount))},
			{Field: "permissions", Before: formatInt64(int64(impact.PermissionCount))},
			{Field: "sessions", Before: formatInt64(int64(impact.ActiveSessionCount))},
			{Field: "oauth_clients", Before: formatInt64(int64(impact.OAuthClientCount))},
			{Field: "refresh_token_families", Before: formatInt64(int64(impact.RefreshTokenFamilyCount))},
			{Field: "retained", After: "accounts + audit_events + history snapshots"},
		},
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: "application.purge_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.store.PurgeApplication(txCtx, tx, current.ID)
	})
	if err != nil {
		return PurgeResult{}, mapCriticalError(err)
	}
	s.logger.Info("应用已物理清理", "application_id", current.ID)
	return PurgeResult{ApplicationID: current.ID, Changed: true, Counts: impact}, nil
}

// authorize 校验可信调用者与授权器结果；缺失身份一律 ErrAccessDenied。
func (s *Service) authorize(ctx context.Context, caller Caller, action Action, applicationID string) error {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	if !action.Valid() {
		return ErrAccessDenied
	}
	if err := caller.actor.Validate(); err != nil {
		return ErrAccessDenied
	}
	if err := s.authorizer.Authorize(ctx, caller, action, applicationID); err != nil {
		return fmt.Errorf("%w: %w", ErrAccessDenied, err)
	}
	return nil
}

// recordRead 写成功读取审计；失败时拒绝返回数据（fail-closed）。
func (s *Service) recordRead(ctx context.Context, caller Caller, action Action, targetID string) error {
	event := audit.Event{
		Actor:     caller.actor,
		Action:    string(action),
		Target:    audit.Target{Type: "application", ID: targetID},
		Outcome:   audit.OutcomeSuccess,
		RequestID: caller.requestID,
	}
	if err := s.audit.Record(ctx, event); err != nil {
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	}
	return nil
}

// normalizeListRequest 校验并填充分页/排序参数。
func normalizeListRequest(request ListRequest) (ListQuery, error) {
	limit := request.Limit
	if limit == 0 {
		limit = DefaultListLimit
	}
	if limit < 0 || limit > MaxListLimit {
		return ListQuery{}, fmt.Errorf("%w: 每页数量必须在 1～%d 之间", ErrInvalidRequest, MaxListLimit)
	}
	if request.Offset < 0 || request.Offset > MaxListOffset {
		return ListQuery{}, fmt.Errorf("%w: 分页偏移必须在 0～%d 之间", ErrInvalidRequest, MaxListOffset)
	}
	sortField := request.Sort
	if sortField == "" {
		sortField = SortCreatedAt
	}
	if !sortField.Valid() {
		return ListQuery{}, fmt.Errorf("%w: 排序字段不在允许列表内", ErrInvalidRequest)
	}
	if request.Status != "" && !request.Status.Valid() {
		return ListQuery{}, fmt.Errorf("%w: 状态过滤值无效", ErrInvalidRequest)
	}
	return ListQuery{Limit: limit, Offset: request.Offset, Status: request.Status,
		Sort: sortField, Descending: request.Descending}, nil
}

// mapCriticalError 把事务错误映射为应用领域错误；审计失败优先判定。
func mapCriticalError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, audit.ErrAuditUnavailable):
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	case errors.Is(err, ErrInvalidRequest):
		return err
	case errors.Is(err, ErrAccessDenied), errors.Is(err, ErrStateConflict),
		errors.Is(err, ErrInvalidTransition), errors.Is(err, ErrMemberExists),
		errors.Is(err, ErrMemberNotFound), errors.Is(err, ErrTargetUserNotFound),
		errors.Is(err, ErrApplicationInactive), errors.Is(err, ErrUserNotEligible):
		return err
	case delegation.CodeOf(err) != "":
		// 委派检查拒绝：保留委派领域错误，由 CodeOf 映射为可诊断错误码。
		return err
	case errors.Is(err, ErrApplicationNotFound), errors.Is(err, ErrStoreUnavailable):
		return err
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, audit.ErrInvalidEvent):
		return fmt.Errorf("%w: 审计事件无效", ErrOptionsInvalid)
	default:
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
}

// formatInt64 把版本号转换为审计差异值文本。
func formatInt64(value int64) string {
	return strconv.FormatInt(value, 10)
}

// normalizeContext 把 nil ctx 当成 Background。
func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// isNil 检测 nil 接口与 typed nil 指针。
func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
