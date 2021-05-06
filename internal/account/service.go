package account

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// AuditRecorder 是账户服务依赖的安全审计写入契约；生产实现为 *audit.Recorder。
// 使用接口便于测试注入故障，但任何实现都必须提供 fail-closed 语义：返回错误时
// 调用方拒绝操作，不能静默丢弃审计。
type AuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
	ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error
}

// Store 是账户持久化契约，由 internal/account/sqlite 提供生产实现。
//
// CreateUser 必须使用调用方给出的 audit.Tx 执行插入，以便与成功审计在同一事务
// 提交；唯一用户名冲突返回 ErrUsernameTaken，其他存储失败返回 ErrStoreUnavailable
// 或可被 errors.Is 识别的安全错误（不得返回原始驱动错误文本）。
type Store interface {
	CreateUser(ctx context.Context, tx audit.Tx, user User) error
	GetUser(ctx context.Context, id string) (User, error)
	ListUsers(ctx context.Context, query ListQuery) ([]User, bool, error)
	// GetUserState 返回账户快照与受保护标记（is_root）。该标记不放进 User，
	// 避免普通查询接口顺带暴露系统管理资格。
	GetUserState(ctx context.Context, id string) (StateSnapshot, error)
	// PreviewDeletion 返回完成删除的影响范围快照。
	PreviewDeletion(ctx context.Context, id string) (DeletionPreview, error)
	// ApplyStateChange 在审计事务中执行条件 UPDATE；行版本/状态已被并发修改时
	// 必须返回 ErrStateConflict，且不得留下部分更新。
	ApplyStateChange(ctx context.Context, tx audit.Tx, change StateChange) error
	// CompleteDeletion 在审计事务中清理关联个人数据并删除 users 行；任一步失败
	// 整体回滚。
	CompleteDeletion(ctx context.Context, tx audit.Tx, request CompleteDeletionRequest) error
}

// StateSnapshot 是账户状态操作需要的内部快照；IsRoot 不通过公开 User 暴露。
type StateSnapshot struct {
	User   User
	IsRoot bool
}

// StateChange 是一次已通过状态机校验的条件状态更新。
type StateChange struct {
	UserID              string
	ExpectedRowVersion  int64
	ExpectedStatus      Status
	NewStatus           Status
	Now                 time.Time
	BumpSecurityVersion bool
}

// CompleteDeletionRequest 是完成删除的事务内请求。
type CompleteDeletionRequest struct {
	UserID             string
	ExpectedRowVersion int64
	Now                time.Time
}

// ListQuery 是已通过白名单校验的分页查询参数；仓储负责把 SortField 映射为固定
// SQL 列并加 id 作为稳定次序键。
type ListQuery struct {
	Limit      int
	Offset     int
	Status     Status
	Sort       SortField
	Descending bool
}

// Options 是构造账户服务的显式依赖。
type Options struct {
	// Store 是账户持久化；必填。
	Store Store
	// Audit 是安全审计写入器；必填。创建用户要求审计与业务一致提交。
	Audit AuditRecorder
	// Authorizer 判定可信调用者权限；必填，没有默认放行实现。
	Authorizer Authorizer
	// Now 是可注入时钟；nil 使用 time.Now。用户时间统一 UTC 毫秒。
	Now func() time.Time
	// Random 是安全随机源；nil 使用 crypto/rand.Reader。用于生成用户 ID。
	Random io.Reader
	// Logger 是运行日志器；nil 使用丢弃输出。日志不记录用户名/资料正文。
	Logger *slog.Logger
}

// Service 是账户领域服务。构造后不可变，可被多个 goroutine 并发使用；它不启动
// 后台协程、不提供 HTTP 端点，也不缓存用户数据。
type Service struct {
	store      Store
	audit      AuditRecorder
	authorizer Authorizer
	now        func() time.Time
	random     io.Reader
	logger     *slog.Logger
}

// New 校验依赖并构造账户服务。缺少 Store/Audit/Authorizer 时返回
// ErrOptionsInvalid，不会创建替代实现或默认放行权限。
func New(options Options) (*Service, error) {
	if isNilInterface(options.Store) {
		return nil, fmt.Errorf("%w: 账户存储为空", ErrOptionsInvalid)
	}
	if isNilInterface(options.Audit) {
		return nil, fmt.Errorf("%w: 安全审计写入器为空", ErrOptionsInvalid)
	}
	if isNilInterface(options.Authorizer) {
		return nil, fmt.Errorf("%w: 授权器为空", ErrOptionsInvalid)
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	random := options.Random
	if random == nil {
		random = rand.Reader
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
	}
	return &Service{
		store:      options.Store,
		audit:      options.Audit,
		authorizer: options.Authorizer,
		now:        now,
		random:     random,
		logger:     logger,
	}, nil
}

// CreateUser 创建普通用户。它完成用户名/资料校验、生成不可变 ID、在审计事务中
// 插入用户并写成功审计；用户名规范化值唯一冲突返回 ErrUsernameTaken。
//
// 创建状态固定为 active（本地初始化创建不经过自助注册/审核流程），is_root 与
// security_version 使用数据库默认值，调用方无法通过请求字段设置。
func (s *Service) CreateUser(ctx context.Context, caller Caller, request CreateRequest) (User, error) {
	if err := s.authorize(ctx, caller, ActionCreateUser); err != nil {
		return User{}, err
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return User{}, err
	}
	username, usernameNormalized, err := NormalizeUsername(request.Username)
	if err != nil {
		return User{}, err
	}
	nickname, err := normalizeNickname(request.Nickname)
	if err != nil {
		return User{}, err
	}
	biography, err := normalizeBiography(request.Biography)
	if err != nil {
		return User{}, err
	}
	language, err := normalizeLanguage(request.Language)
	if err != nil {
		return User{}, err
	}
	timezone, err := normalizeTimezone(request.Timezone)
	if err != nil {
		return User{}, err
	}
	if err := ValidateRequestID(caller.requestID); err != nil {
		return User{}, err
	}
	id, err := NewUserID(s.random)
	if err != nil {
		return User{}, fmt.Errorf("%w: %v", ErrStoreUnavailable, err)
	}
	currentTime := s.now().UTC().Truncate(time.Millisecond)
	user := User{
		ID:                 id,
		Username:           username,
		UsernameNormalized: usernameNormalized,
		Nickname:           nickname,
		Biography:          biography,
		Language:           language,
		Timezone:           timezone,
		Status:             StatusActive,
		RowVersion:         1,
		SecurityVersion:    1,
		CreatedAt:          currentTime,
		UpdatedAt:          currentTime,
	}
	event := audit.Event{
		Actor:     caller.actor,
		Action:    string(ActionCreateUser),
		Target:    audit.Target{Type: "user", ID: user.ID},
		RequestID: caller.requestID,
		Changes: []audit.FieldChange{
			{Field: "username", After: user.Username},
			{Field: "status", After: string(user.Status)},
		},
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: "user.create_failed",
		// 失败审计的错误码必须反映真实失败类别：用户名冲突 CONFLICT、存储
		// DB_UNAVAILABLE、审计 AUDIT_WRITE_FAILED、内部 INTERNAL_ERROR 等。
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.store.CreateUser(txCtx, tx, user)
	})
	if err != nil {
		return User{}, mapCriticalError(err)
	}
	// 日志不记录用户名、昵称或简介正文，只记录稳定 ID 与结果。
	s.logger.Info("账户已创建", "user_id", user.ID, "status", string(user.Status))
	return user, nil
}

// GetUser 按稳定用户 ID 查询账户快照，并写审计读取事件；审计失败时拒绝返回
// 数据（fail-closed）。用户不存在返回 ErrUserNotFound。
func (s *Service) GetUser(ctx context.Context, caller Caller, id string) (User, error) {
	if err := s.authorize(ctx, caller, ActionGetUser); err != nil {
		return User{}, err
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return User{}, err
	}
	if !ValidUserID(id) {
		return User{}, fmt.Errorf("%w: 用户 ID 格式无效", ErrInvalidRequest)
	}
	user, err := s.store.GetUser(ctx, id)
	if err != nil {
		return User{}, err
	}
	if err := s.recordRead(ctx, caller, ActionGetUser, id); err != nil {
		return User{}, err
	}
	return user, nil
}

// ListUsers 按有限分页与白名单排序检索用户，并写审计读取事件；审计失败时拒绝
// 返回数据。请求的 Limit/Offset/Status/Sort 超出允许范围返回 ErrInvalidRequest。
func (s *Service) ListUsers(ctx context.Context, caller Caller, request ListRequest) (ListResult, error) {
	if err := s.authorize(ctx, caller, ActionListUsers); err != nil {
		return ListResult{}, err
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return ListResult{}, err
	}
	query, err := normalizeListRequest(request)
	if err != nil {
		return ListResult{}, err
	}
	users, hasMore, err := s.store.ListUsers(ctx, query)
	if err != nil {
		return ListResult{}, err
	}
	if err := s.recordRead(ctx, caller, ActionListUsers, ""); err != nil {
		return ListResult{}, err
	}
	return ListResult{Users: users, HasMore: hasMore}, nil
}

// DisableUser 全局禁用账户：status -> disabled，row_version 与 security_version
// 各递增 1。已禁用时幂等成功；待删除账户返回 CONFLICT；root 返回 ACCESS_DENIED。
func (s *Service) DisableUser(ctx context.Context, caller Caller, request StateCommandRequest) (StateChangeResult, error) {
	return s.applyStateCommand(ctx, caller, request, CommandDisable)
}

// EnableUser 启用已禁用账户：status -> active，row_version 递增 1。
// security_version 不递减：重新启用不会恢复旧会话或旧令牌，未来会话层仍须按
// 安全版本拒绝旧凭证；已启用时幂等成功；其余状态返回 CONFLICT。
func (s *Service) EnableUser(ctx context.Context, caller Caller, request StateCommandRequest) (StateChangeResult, error) {
	return s.applyStateCommand(ctx, caller, request, CommandEnable)
}

// RequestDeletion 将账户标记为待删除：status -> pending_delete，row_version 与
// security_version 各递增 1，并写可靠审计事件作为会话失效依据。该阶段保留资料
// 与应用数据；完成删除由 CompleteDeletion 执行。重复请求幂等成功。
func (s *Service) RequestDeletion(ctx context.Context, caller Caller, request StateCommandRequest) (StateChangeResult, error) {
	return s.applyStateCommand(ctx, caller, request, CommandRequestDeletion)
}

// PreviewDeletion 返回完成删除会影响的应用成员关系、角色、用户组关系、一次性
// 凭证与名下应用数量，供不可逆删除前确认。它是只读快照，不执行删除。
func (s *Service) PreviewDeletion(ctx context.Context, caller Caller, id string) (DeletionPreview, error) {
	if err := s.authorize(ctx, caller, ActionPreviewDeletion); err != nil {
		return DeletionPreview{}, err
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return DeletionPreview{}, err
	}
	if !ValidUserID(id) {
		return DeletionPreview{}, fmt.Errorf("%w: 用户 ID 格式无效", ErrInvalidRequest)
	}
	preview, err := s.store.PreviewDeletion(ctx, id)
	if err != nil {
		return DeletionPreview{}, err
	}
	event := audit.Event{
		Actor:     caller.actor,
		Action:    string(ActionPreviewDeletion),
		Target:    audit.Target{Type: "user", ID: id},
		Outcome:   audit.OutcomeSuccess,
		RequestID: caller.requestID,
	}
	if err := s.audit.Record(ctx, event); err != nil {
		return DeletionPreview{}, fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	}
	return preview, nil
}

// CompleteDeletion 完成“待删除 -> 完成删除”生命周期：在审计事务中清理一次性
// 凭证、应用成员关系、角色与用户组关系，并删除 users 行；应用记录保留（owner
// 置空），安全审计历史保留脱敏快照。只有 pending_delete 状态可完成删除，root
// 永远拒绝；重复完成因用户已不存在而返回 ErrUserNotFound。
func (s *Service) CompleteDeletion(ctx context.Context, caller Caller, request StateCommandRequest) (DeletionResult, error) {
	if err := s.authorize(ctx, caller, ActionCompleteDeletion); err != nil {
		return DeletionResult{}, err
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return DeletionResult{}, err
	}
	if err := validateStateCommandRequest(request); err != nil {
		return DeletionResult{}, err
	}
	snapshot, err := s.store.GetUserState(ctx, request.UserID)
	if err != nil {
		return DeletionResult{}, err
	}
	if snapshot.IsRoot {
		return DeletionResult{}, ErrProtectedUser
	}
	if snapshot.User.Status != StatusPendingDelete {
		return DeletionResult{}, fmt.Errorf("%w: 只有待删除账户可以完成删除", ErrInvalidTransition)
	}
	if request.ExpectedRowVersion != snapshot.User.RowVersion {
		return DeletionResult{}, ErrStateConflict
	}
	preview, err := s.store.PreviewDeletion(ctx, request.UserID)
	if err != nil {
		return DeletionResult{}, err
	}
	if preview.IsRoot {
		return DeletionResult{}, ErrProtectedUser
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	event := audit.Event{
		Actor:     caller.actor,
		Action:    string(ActionCompleteDeletion),
		Target:    audit.Target{Type: "user", ID: request.UserID},
		RequestID: caller.requestID,
		Changes:   deletionChanges(preview),
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: "user.delete.complete_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.store.CompleteDeletion(txCtx, tx, CompleteDeletionRequest{
			UserID:             request.UserID,
			ExpectedRowVersion: request.ExpectedRowVersion,
			Now:                now,
		})
	})
	if err != nil {
		return DeletionResult{}, mapCriticalError(err)
	}
	s.logger.Info("账户已完成删除", "user_id", request.UserID)
	return DeletionResult{Preview: preview, DeletedAt: now}, nil
}

// applyStateCommand 执行 disable/enable/request_deletion 的公共流程：授权、读取
// 快照、状态机校验、幂等处理、乐观并发与审计一致提交。
func (s *Service) applyStateCommand(ctx context.Context, caller Caller, request StateCommandRequest, command UserCommand) (StateChangeResult, error) {
	if err := s.authorize(ctx, caller, command.action()); err != nil {
		return StateChangeResult{}, err
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return StateChangeResult{}, err
	}
	if err := validateStateCommandRequest(request); err != nil {
		return StateChangeResult{}, err
	}
	snapshot, err := s.store.GetUserState(ctx, request.UserID)
	if err != nil {
		return StateChangeResult{}, err
	}
	if snapshot.IsRoot {
		return StateChangeResult{}, ErrProtectedUser
	}
	nextStatus, changed, err := transitionStatus(snapshot.User.Status, command)
	if err != nil {
		return StateChangeResult{}, err
	}
	if !changed {
		// 幂等成功：状态已是目标值，不改版本；仍写成功审计以便追查重复请求。
		event := audit.Event{
			Actor:     caller.actor,
			Action:    string(command.action()),
			Target:    audit.Target{Type: "user", ID: request.UserID},
			Outcome:   audit.OutcomeSuccess,
			RequestID: caller.requestID,
			Changes: []audit.FieldChange{
				{Field: "result", After: "unchanged"},
			},
		}
		if err := s.audit.Record(ctx, event); err != nil {
			return StateChangeResult{}, fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
		}
		return StateChangeResult{User: snapshot.User, PreviousStatus: snapshot.User.Status, Changed: false}, nil
	}
	if request.ExpectedRowVersion != snapshot.User.RowVersion {
		return StateChangeResult{}, ErrStateConflict
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	updated := snapshot.User
	updated.Status = nextStatus
	updated.RowVersion = snapshot.User.RowVersion + 1
	updated.UpdatedAt = now
	securityVersion := snapshot.User.SecurityVersion
	if command.bumpsSecurityVersion() {
		securityVersion++
	}
	updated.SecurityVersion = securityVersion
	event := audit.Event{
		Actor:     caller.actor,
		Action:    string(command.action()),
		Target:    audit.Target{Type: "user", ID: request.UserID},
		RequestID: caller.requestID,
		Changes: []audit.FieldChange{
			{Field: "status", Before: string(snapshot.User.Status), After: string(nextStatus)},
			{Field: "row_version", Before: formatInt64(snapshot.User.RowVersion), After: formatInt64(updated.RowVersion)},
			{Field: "security_version", Before: formatInt64(snapshot.User.SecurityVersion), After: formatInt64(securityVersion)},
		},
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: "user.state_change_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.store.ApplyStateChange(txCtx, tx, StateChange{
			UserID:              request.UserID,
			ExpectedRowVersion:  snapshot.User.RowVersion,
			ExpectedStatus:      snapshot.User.Status,
			NewStatus:           nextStatus,
			Now:                 now,
			BumpSecurityVersion: command.bumpsSecurityVersion(),
		})
	})
	if err != nil {
		return StateChangeResult{}, mapCriticalError(err)
	}
	s.logger.Info("账户状态已变更", "user_id", request.UserID, "status", string(nextStatus))
	return StateChangeResult{User: updated, PreviousStatus: snapshot.User.Status, Changed: true}, nil
}

// validateStateCommandRequest 校验状态命令的 ID 与乐观并发版本。
func validateStateCommandRequest(request StateCommandRequest) error {
	if !ValidUserID(request.UserID) {
		return fmt.Errorf("%w: 用户 ID 格式无效", ErrInvalidRequest)
	}
	if request.ExpectedRowVersion <= 0 {
		return fmt.Errorf("%w: 期望行版本必须大于 0", ErrInvalidRequest)
	}
	return nil
}

// deletionChanges 把删除影响快照转换为审计差异字段（只记录计数，不记录个人资料）。
func deletionChanges(preview DeletionPreview) []audit.FieldChange {
	return []audit.FieldChange{
		{Field: "status", Before: string(preview.Status), After: "deleted"},
		{Field: "app_memberships", After: formatInt64(int64(preview.AppMemberships))},
		{Field: "user_roles", After: formatInt64(int64(preview.UserRoles))},
		{Field: "group_memberships", After: formatInt64(int64(preview.GroupMemberships))},
		{Field: "one_time_credentials", After: formatInt64(int64(preview.OneTimeCredentials))},
		{Field: "owned_applications", After: formatInt64(int64(preview.OwnedApplications))},
	}
}

// formatInt64 把计数/版本转换为审计差异值文本。
func formatInt64(value int64) string {
	return strconv.FormatInt(value, 10)
}

// authorize 校验可信调用身份与授权结果。任何缺失或未获准的身份一律
// ErrAccessDenied；不读取请求参数中的自称身份。
func (s *Service) authorize(ctx context.Context, caller Caller, action Action) error {
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
	if err := s.authorizer.Authorize(ctx, caller, action); err != nil {
		return fmt.Errorf("%w: %w", ErrAccessDenied, err)
	}
	return nil
}

// recordRead 记录成功读取审计；审计失败返回 ErrAuditUnavailable，调用方不再
// 返回用户数据。事件不包含被查询用户的资料正文。
func (s *Service) recordRead(ctx context.Context, caller Caller, action Action, targetID string) error {
	event := audit.Event{
		Actor:     caller.actor,
		Action:    string(action),
		Target:    audit.Target{Type: "user", ID: targetID},
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
	return ListQuery{
		Limit:      limit,
		Offset:     request.Offset,
		Status:     request.Status,
		Sort:       sortField,
		Descending: request.Descending,
	}, nil
}

// mapCreateError 把创建事务错误映射为账户领域错误。审计失败优先判定（即使
// 业务失败也要求失败审计可写），避免把审计故障伪装成用户冲突。
func mapCriticalError(err error) error {
	switch {
	case err == nil:
		return nil
	// 审计失败优先：即使业务同时失败，也不能把“失败证据未能可靠保存”伪装成
	// 普通业务冲突。
	case errors.Is(err, audit.ErrAuditUnavailable):
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	case errors.Is(err, ErrUsernameTaken):
		return ErrUsernameTaken
	case errors.Is(err, ErrProtectedUser), errors.Is(err, ErrInvalidTransition),
		errors.Is(err, ErrStateConflict):
		return err
	case errors.Is(err, ErrInvalidRequest):
		return err
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, audit.ErrInvalidEvent):
		return fmt.Errorf("%w: 审计事件无效", ErrOptionsInvalid)
	case errors.Is(err, ErrStoreUnavailable):
		return err
	default:
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
}

// normalizeContext 把 nil ctx 当成 Background 处理，避免调用方漏传导致 panic。
func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
