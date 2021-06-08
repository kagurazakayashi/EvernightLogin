package group

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
)

// ScopeInfo 是组作用范围数据库快照。
type ScopeInfo struct {
	ScopeID           string
	Kind              ScopeKind
	ApplicationID     string
	ApplicationActive bool
}

// GroupScope 是已解析的组作用范围，供仓储执行成员资格 SQL。
type GroupScope struct {
	ScopeID       string
	Kind          ScopeKind
	ApplicationID string
}

// ListQuery 是已校验的组列表查询。
type ListQuery struct {
	Limit       int
	Offset      int
	AllScopes   bool
	ScopeIDs    []string
	ScopeFilter string
}

// Store 是用户组持久化契约，由 internal/group/sqlite 提供生产实现。
type Store interface {
	GetScope(ctx context.Context, scopeID string) (ScopeInfo, error)
	CreateGroup(ctx context.Context, tx audit.Tx, group Group) error
	GetGroup(ctx context.Context, id string) (Group, error)
	// GetGroupScope 只读取组的作用范围，供先鉴权后读取完整记录使用。
	GetGroupScope(ctx context.Context, id string) (string, error)
	ListGroups(ctx context.Context, query ListQuery) ([]Group, bool, error)
	UpdateGroup(ctx context.Context, tx audit.Tx, id, name, description string, now time.Time) error
	DeleteGroup(ctx context.Context, tx audit.Tx, id string) error
	ListMembers(ctx context.Context, groupID string, limit, offset int) ([]Member, bool, error)
	ExistingMembers(ctx context.Context, groupID string, userIDs []string) ([]string, error)
	ValidateMembers(ctx context.Context, scope GroupScope, userIDs []string) (ineligible []string, err error)
	AddMembers(ctx context.Context, tx audit.Tx, groupID string, scope GroupScope, userIDs []string, now time.Time) (added int, err error)
	RemoveMembers(ctx context.Context, tx audit.Tx, groupID string, userIDs []string) (removed int, skipped int, err error)
	// ListGroupRoleEffectivePermissionIDs 在调用方事务内读取用户组通过角色当前
	// 会生效的权限 ID（角色/权限启用且非 root_only），供加成员前的委派检查。
	ListGroupRoleEffectivePermissionIDs(ctx context.Context, tx audit.Tx, groupID string) ([]string, error)
}

// AuditRecorder 是用户组服务依赖的安全审计契约。
type AuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
	RecordFailure(ctx context.Context, event audit.Event) error
	ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error
}

// Options 是用户组服务依赖。
type Options struct {
	Store      Store
	Audit      AuditRecorder
	Authorizer Authorizer
	Transfers  delegation.Guard
	// Sensitive 是敏感操作收敛入口（步骤 39）。默认 nil 时敏感成员变更直接拒绝
	// （fail-closed）；只有显式 AllowLegacyWithoutSensitive（仅供旧装配/测试过渡）
	// 才回退到既有 Authorizer/委派 Guard 保守校验。
	Sensitive SensitiveRunner
	// AllowLegacyWithoutSensitive 显式允许未接线敏感策略时沿用旧保守校验。
	// 默认 false；生产装配应注入 Sensitive。
	AllowLegacyWithoutSensitive bool
	Now                         func() time.Time
	Random                      io.Reader
	Logger                      *slog.Logger
}

// Service 是用户组领域服务；构造后不可变，可并发使用。
type Service struct {
	store       Store
	audit       AuditRecorder
	authorizer  Authorizer
	transfers   delegation.Guard
	sensitive   SensitiveRunner
	allowLegacy bool
	now         func() time.Time
	random      io.Reader
	logger      *slog.Logger
}

// New 校验依赖并构造服务。
func New(options Options) (*Service, error) {
	if isNil(options.Store) {
		return nil, fmt.Errorf("%w: 用户组存储为空", ErrOptionsInvalid)
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
	random := options.Random
	if random == nil {
		random = rand.Reader
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
	}
	return &Service{store: options.Store, audit: options.Audit, authorizer: options.Authorizer,
		transfers: options.Transfers, sensitive: options.Sensitive,
		allowLegacy: options.AllowLegacyWithoutSensitive,
		now:         now, random: random, logger: logger}, nil
}

// CreateGroup 在系统或应用范围创建用户组。应用范围要求应用存在且启用；组机器键
// 在同一范围唯一，显示名称可后续修改，scope/group_key 创建后不可变。
func (s *Service) CreateGroup(ctx context.Context, caller Caller, request CreateRequest) (Group, error) {
	if err := s.authorize(ctx, caller, ActionCreateGroup, request.ScopeID); err != nil {
		return Group{}, err
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return Group{}, err
	}
	kind, applicationID, err := ParseScope(request.ScopeID)
	if err != nil {
		return Group{}, err
	}
	scope, err := s.store.GetScope(ctx, strings.TrimSpace(request.ScopeID))
	if err != nil {
		return Group{}, err
	}
	if kind != scope.Kind || applicationID != scope.ApplicationID {
		return Group{}, ErrScopeInvalid
	}
	if kind == ScopeKindApplication && !scope.ApplicationActive {
		return Group{}, fmt.Errorf("%w: 应用当前不可创建用户组", ErrApplicationInactive)
	}
	groupKey, err := ValidateGroupKey(request.GroupKey)
	if err != nil {
		return Group{}, err
	}
	name, err := ValidateGroupName(request.Name)
	if err != nil {
		return Group{}, err
	}
	description, err := ValidateGroupDescription(request.Description)
	if err != nil {
		return Group{}, err
	}
	id, err := NewGroupID(s.random)
	if err != nil {
		return Group{}, fmt.Errorf("%w: %v", ErrStoreUnavailable, err)
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	group := Group{
		ID: id, ScopeID: scope.ScopeID, ScopeKind: kind, ApplicationID: applicationID,
		GroupKey: groupKey, Name: name, Description: description, CreatedAt: now, UpdatedAt: now,
	}
	event := audit.Event{
		Actor:     caller.actor,
		AppID:     applicationID,
		Action:    string(ActionCreateGroup),
		Target:    audit.Target{Type: "group", ID: group.ID},
		RequestID: caller.requestID,
		Changes: []audit.FieldChange{
			{Field: "scope_id", After: group.ScopeID},
			{Field: "group_key", After: group.GroupKey},
			{Field: "name", After: group.Name},
		},
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: "group.create_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.store.CreateGroup(txCtx, tx, group)
	})
	if err != nil {
		return Group{}, mapCriticalError(err)
	}
	s.logger.Info("用户组已创建", "group_id", group.ID, "scope_id", group.ScopeID)
	return group, nil
}

// GetGroup 按稳定 ID 读取用户组，并写审计读取事件。
func (s *Service) GetGroup(ctx context.Context, caller Caller, id string) (Group, error) {
	if !ValidGroupID(id) {
		return Group{}, fmt.Errorf("%w: 用户组 ID 格式无效", ErrInvalidRequest)
	}
	group, err := s.getAuthorizedGroup(ctx, caller, ActionGetGroup, id)
	if err != nil {
		return Group{}, err
	}
	if err := s.recordRead(ctx, caller, ActionGetGroup, group); err != nil {
		return Group{}, err
	}
	return group, nil
}

// ListGroups 在可管理范围内分页查询用户组；应用管理员只看到可管理应用组，
// ScopeID 过滤不能扩大范围。
func (s *Service) ListGroups(ctx context.Context, caller Caller, request ListRequest) (ListResult, error) {
	// 列表动作不按单一 scope 授权：空 ScopeID 是合法默认用法，可见范围完全由
	// ManageableScopes 决定，避免空 scope 被 ParseScope 提前拒绝。
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return ListResult{}, err
	}
	if err := caller.actor.Validate(); err != nil {
		return ListResult{}, ErrAccessDenied
	}
	all, scopes, err := s.authorizer.ManageableScopes(ctx, caller)
	if err != nil {
		return ListResult{}, ErrAccessDenied
	}
	limit := request.Limit
	if limit == 0 {
		limit = DefaultMemberListLimit
	}
	if limit < 0 || limit > MaxMemberListLimit {
		return ListResult{}, fmt.Errorf("%w: 每页数量必须在 1～%d 之间", ErrInvalidRequest, MaxMemberListLimit)
	}
	if request.Offset < 0 || request.Offset > MaxMemberOffset {
		return ListResult{}, fmt.Errorf("%w: 分页偏移无效", ErrInvalidRequest)
	}
	query := ListQuery{Limit: limit, Offset: request.Offset, AllScopes: all}
	filter := strings.TrimSpace(request.ScopeID)
	if filter != "" {
		if _, _, err := ParseScope(filter); err != nil {
			return ListResult{}, err
		}
		if !all {
			found := false
			for _, scopeID := range scopes {
				if scopeID == filter {
					found = true
					break
				}
			}
			if !found {
				return ListResult{}, ErrAccessDenied
			}
		}
		query.ScopeFilter = filter
	}
	if !all {
		if len(scopes) == 0 {
			if err := s.recordListRead(ctx, caller); err != nil {
				return ListResult{}, err
			}
			return ListResult{Groups: []Group{}}, nil
		}
		query.ScopeIDs = scopes
	}
	groups, hasMore, err := s.store.ListGroups(ctx, query)
	if err != nil {
		return ListResult{}, err
	}
	if err := s.recordListRead(ctx, caller); err != nil {
		return ListResult{}, err
	}
	return ListResult{Groups: groups, HasMore: hasMore}, nil
}

// UpdateGroup 修改组显示资料。只允许名称与说明；scope/group_key 不在请求中因此
// 不可能被转移。并发更新采用最后写入语义（表中无 row_version），审计记录前后值。
func (s *Service) UpdateGroup(ctx context.Context, caller Caller, id string, request UpdateRequest) (Group, error) {
	if !ValidGroupID(id) {
		return Group{}, fmt.Errorf("%w: 用户组 ID 格式无效", ErrInvalidRequest)
	}
	current, err := s.getAuthorizedGroup(ctx, caller, ActionUpdateGroup, id)
	if err != nil {
		return Group{}, err
	}
	name, err := ValidateGroupName(request.Name)
	if err != nil {
		return Group{}, err
	}
	description, err := ValidateGroupDescription(request.Description)
	if err != nil {
		return Group{}, err
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	updated := current
	updated.Name = name
	updated.Description = description
	updated.UpdatedAt = now
	changes := make([]audit.FieldChange, 0, 2)
	if current.Name != name {
		changes = append(changes, audit.FieldChange{Field: "name", Before: current.Name, After: name})
	}
	if current.Description != description {
		changes = append(changes, audit.FieldChange{Field: "description", Before: current.Description, After: description})
	}
	event := audit.Event{
		Actor:     caller.actor,
		AppID:     current.ApplicationID,
		Action:    string(ActionUpdateGroup),
		Target:    audit.Target{Type: "group", ID: id},
		RequestID: caller.requestID,
		Changes:   changes,
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: "group.update_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.store.UpdateGroup(txCtx, tx, id, name, description, now)
	})
	if err != nil {
		return Group{}, mapCriticalError(err)
	}
	return updated, nil
}

// DeleteGroup 删除用户组：组成员关系与（未来的）组角色关联随外键级联删除，
// 用户账户与安全审计历史保留。重复删除返回 ErrGroupNotFound。
func (s *Service) DeleteGroup(ctx context.Context, caller Caller, id string) error {
	if !ValidGroupID(id) {
		return fmt.Errorf("%w: 用户组 ID 格式无效", ErrInvalidRequest)
	}
	group, err := s.getAuthorizedGroup(ctx, caller, ActionDeleteGroup, id)
	if err != nil {
		return err
	}
	event := audit.Event{
		Actor:     caller.actor,
		AppID:     group.ApplicationID,
		Action:    string(ActionDeleteGroup),
		Target:    audit.Target{Type: "group", ID: id},
		RequestID: caller.requestID,
		Changes: []audit.FieldChange{
			{Field: "scope_id", Before: group.ScopeID},
			{Field: "group_key", Before: group.GroupKey},
			{Field: "name", Before: group.Name},
			{Field: "status", After: "deleted"},
		},
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: "group.delete_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.store.DeleteGroup(txCtx, tx, id)
	})
	if err != nil {
		return mapCriticalError(err)
	}
	s.logger.Info("用户组已删除", "group_id", id)
	return nil
}

// AddMembers 原子批量加入组成员。最多 MaxBatchMembers 人；全部成员必须满足范围
// 资格（系统组：全局 active；应用组：全局 active 且应用成员 active，应用启用），
// 任一失败整体回滚。请求前已存在的成员计入 Skipped，幂等成功。
func (s *Service) AddMembers(ctx context.Context, caller Caller, request MemberBatchRequest) (MemberBatchResult, error) {
	groupRecord, scope, err := s.prepareMemberMutation(ctx, caller, request.GroupID, ActionAddMembers)
	if err != nil {
		return MemberBatchResult{}, err
	}
	userIDs, err := normalizeMemberIDs(request.UserIDs)
	if err != nil {
		return MemberBatchResult{}, err
	}
	if scope.Kind == ScopeKindApplication && !scope.ApplicationActive {
		return MemberBatchResult{}, fmt.Errorf("%w: 应用当前不可加入组成员", ErrApplicationInactive)
	}
	groupScope := GroupScope{ScopeID: scope.ScopeID, Kind: scope.Kind, ApplicationID: scope.ApplicationID}
	ineligible, err := s.store.ValidateMembers(ctx, groupScope, userIDs)
	if err != nil {
		return MemberBatchResult{}, err
	}
	if len(ineligible) > 0 {
		// 成员资格不合格包含 root 账户（root 永不满足普通成员资格）。这是普通
		// 管理路径拒绝，必须留失败审计，避免反复尝试把 root 拉进已配角色的组
		// 却完全无痕；错误码与拒绝行为保持既有 ErrMemberNotEligible/USER_DISABLED。
		return MemberBatchResult{}, s.recordMemberRejection(ctx, caller, groupRecord, ActionAddMembers,
			CodeUserDisabled, "member_not_eligible",
			fmt.Errorf("%w: 存在 %d 名不合格成员", ErrMemberNotEligible, len(ineligible)))
	}
	existing, err := s.store.ExistingMembers(ctx, groupRecord.ID, userIDs)
	if err != nil {
		return MemberBatchResult{}, err
	}
	existingSet := make(map[string]struct{}, len(existing))
	for _, userID := range existing {
		existingSet[userID] = struct{}{}
	}
	toAdd := make([]string, 0, len(userIDs))
	for _, userID := range userIDs {
		if _, exists := existingSet[userID]; exists {
			continue
		}
		toAdd = append(toAdd, userID)
	}
	skipped := len(userIDs) - len(toAdd)
	if len(toAdd) == 0 {
		if err := s.recordMemberAttempt(ctx, caller, groupRecord, ActionAddMembers, userIDs, "added", 0, skipped); err != nil {
			return MemberBatchResult{}, err
		}
		return MemberBatchResult{Skipped: skipped}, nil
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	event := audit.Event{
		Actor:     caller.actor,
		AppID:     groupRecord.ApplicationID,
		Action:    string(ActionAddMembers),
		Target:    audit.Target{Type: "group", ID: groupRecord.ID},
		RequestID: caller.requestID,
		Changes:   memberBatchChanges(toAdd, "added", len(toAdd), skipped),
	}
	membersDigest, digestErr := memberSetDigest(toAdd)
	if digestErr != nil {
		return MemberBatchResult{}, digestErr
	}
	sensitiveResult, guardErr := s.authorizeSensitive(ctx, caller, "group.member.change",
		"group", groupRecord.ID, map[string]string{"direction": "add", "members": membersDigest})
	if guardErr != nil {
		return MemberBatchResult{}, guardErr
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: "group.member.add_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		// 与写入同一事务：组可能已配置角色，“先给组配角色、再把人拉进组”是
		// 间接提权路径，必须逐个目标检查操作者能否转授这些权限。
		refs, refErr := s.groupTransferRefs(txCtx, tx, groupRecord.ID)
		if refErr != nil {
			return refErr
		}
		if len(refs) > 0 {
			for _, userID := range toAdd {
				if guardErr := s.transfers.CheckAssignment(txCtx, tx, caller.actor, scope.ScopeID, refs,
					delegation.Target{Kind: delegation.TargetUser, ID: userID}); guardErr != nil {
					return guardErr
				}
			}
		}
		_, addErr := s.store.AddMembers(txCtx, tx, groupRecord.ID, groupScope, toAdd, now)
		return addErr
	})
	if err != nil {
		return MemberBatchResult{}, mapCriticalError(err)
	}
	s.logger.Info("组成员已加入", "group_id", groupRecord.ID, "added", len(toAdd), "skipped", skipped)
	s.notifySensitive(ctx, sensitiveResult)
	return MemberBatchResult{Added: len(toAdd), Skipped: skipped}, nil
}

// RemoveMembers 原子批量移除组成员。不要求应用仍启用（停用后仍可清理）；不存在
// 的成员计入 Skipped，幂等成功。移除不删除全局账户。
func (s *Service) RemoveMembers(ctx context.Context, caller Caller, request MemberBatchRequest) (MemberBatchResult, error) {
	groupRecord, _, err := s.prepareMemberMutation(ctx, caller, request.GroupID, ActionRemoveMembers)
	if err != nil {
		return MemberBatchResult{}, err
	}
	userIDs, err := normalizeMemberIDs(request.UserIDs)
	if err != nil {
		return MemberBatchResult{}, err
	}
	existing, err := s.store.ExistingMembers(ctx, groupRecord.ID, userIDs)
	if err != nil {
		return MemberBatchResult{}, err
	}
	existingSet := make(map[string]struct{}, len(existing))
	for _, userID := range existing {
		existingSet[userID] = struct{}{}
	}
	toRemove := make([]string, 0, len(existing))
	for _, userID := range userIDs {
		if _, exists := existingSet[userID]; exists {
			toRemove = append(toRemove, userID)
		}
	}
	skipped := len(userIDs) - len(toRemove)
	if len(toRemove) == 0 {
		// 全部成员本就不在组内：幂等成功，不制造虚假删除记录。
		if err := s.recordMemberAttempt(ctx, caller, groupRecord, ActionRemoveMembers, userIDs, "removed", 0, skipped); err != nil {
			return MemberBatchResult{}, err
		}
		return MemberBatchResult{Skipped: skipped}, nil
	}
	membersDigest, digestErr := memberSetDigest(toRemove)
	if digestErr != nil {
		return MemberBatchResult{}, digestErr
	}
	sensitiveRemove, guardErr := s.authorizeSensitive(ctx, caller, "group.member.change",
		"group", groupRecord.ID, map[string]string{"direction": "remove", "members": membersDigest})
	if guardErr != nil {
		return MemberBatchResult{}, guardErr
	}
	event := audit.Event{
		Actor:     caller.actor,
		AppID:     groupRecord.ApplicationID,
		Action:    string(ActionRemoveMembers),
		Target:    audit.Target{Type: "group", ID: groupRecord.ID},
		RequestID: caller.requestID,
		Changes:   memberBatchChanges(toRemove, "removed", len(toRemove), skipped),
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: "group.member.remove_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	var removed, raceSkipped int
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		var removeErr error
		removed, raceSkipped, removeErr = s.store.RemoveMembers(txCtx, tx, groupRecord.ID, toRemove)
		return removeErr
	})
	if err != nil {
		return MemberBatchResult{}, mapCriticalError(err)
	}
	s.logger.Info("组成员已移除", "group_id", groupRecord.ID, "removed", removed, "skipped", skipped+raceSkipped)
	s.notifySensitive(ctx, sensitiveRemove)
	return MemberBatchResult{Removed: removed, Skipped: skipped + raceSkipped}, nil
}

// ListMembers 分页读取组成员（包含稳定用户 ID 与加入时间）。
func (s *Service) ListMembers(ctx context.Context, caller Caller, request MemberListRequest) (MemberListResult, error) {
	if !ValidGroupID(request.GroupID) {
		return MemberListResult{}, fmt.Errorf("%w: 用户组 ID 格式无效", ErrInvalidRequest)
	}
	groupRecord, err := s.getAuthorizedGroup(ctx, caller, ActionListMembers, request.GroupID)
	if err != nil {
		return MemberListResult{}, err
	}
	limit := request.Limit
	if limit == 0 {
		limit = DefaultMemberListLimit
	}
	if limit < 0 || limit > MaxMemberListLimit {
		return MemberListResult{}, fmt.Errorf("%w: 每页数量必须在 1～%d 之间", ErrInvalidRequest, MaxMemberListLimit)
	}
	if request.Offset < 0 || request.Offset > MaxMemberOffset {
		return MemberListResult{}, fmt.Errorf("%w: 分页偏移无效", ErrInvalidRequest)
	}
	members, hasMore, err := s.store.ListMembers(ctx, groupRecord.ID, limit, request.Offset)
	if err != nil {
		return MemberListResult{}, err
	}
	if err := s.recordRead(ctx, caller, ActionListMembers, groupRecord); err != nil {
		return MemberListResult{}, err
	}
	return MemberListResult{Members: members, HasMore: hasMore}, nil
}

// prepareMemberMutation 读取组与范围并判权，返回仓储需要的范围信息。
func (s *Service) prepareMemberMutation(ctx context.Context, caller Caller, groupID string, action Action) (Group, ScopeInfo, error) {
	if !ValidGroupID(groupID) {
		return Group{}, ScopeInfo{}, fmt.Errorf("%w: 用户组 ID 格式无效", ErrInvalidRequest)
	}
	groupRecord, err := s.getAuthorizedGroup(ctx, caller, action, groupID)
	if err != nil {
		return Group{}, ScopeInfo{}, err
	}
	scope, err := s.store.GetScope(ctx, groupRecord.ScopeID)
	if err != nil {
		return Group{}, ScopeInfo{}, err
	}
	return groupRecord, scope, nil
}

// getAuthorizedGroup 先按可管理范围预鉴权，再读取组；对无任何管理范围的调用者
// 不查询数据库，对范围外组不读取完整记录（只读 scope 后拒绝），避免先读后鉴权
// 造成“存在/无权”差异扩大。组 ID 为随机值，但该顺序仍作为默认安全基线。
func (s *Service) getAuthorizedGroup(ctx context.Context, caller Caller, action Action, id string) (Group, error) {
	if !ValidGroupID(id) {
		return Group{}, fmt.Errorf("%w: 用户组 ID 格式无效", ErrInvalidRequest)
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return Group{}, err
	}
	if err := caller.actor.Validate(); err != nil {
		return Group{}, ErrAccessDenied
	}
	all, scopes, err := s.authorizer.ManageableScopes(ctx, caller)
	if err != nil {
		return Group{}, ErrAccessDenied
	}
	if all {
		groupRecord, err := s.store.GetGroup(ctx, id)
		if err != nil {
			return Group{}, err
		}
		if err := s.authorize(ctx, caller, action, groupRecord.ScopeID); err != nil {
			return Group{}, err
		}
		return groupRecord, nil
	}
	if len(scopes) == 0 {
		return Group{}, ErrAccessDenied
	}
	scopeID, err := s.store.GetGroupScope(ctx, id)
	if err != nil {
		return Group{}, err
	}
	allowed := false
	for _, candidate := range scopes {
		if candidate == scopeID {
			allowed = true
			break
		}
	}
	if !allowed {
		return Group{}, ErrAccessDenied
	}
	groupRecord, err := s.store.GetGroup(ctx, id)
	if err != nil {
		return Group{}, err
	}
	if err := s.authorize(ctx, caller, action, groupRecord.ScopeID); err != nil {
		return Group{}, err
	}
	return groupRecord, nil
}

// authorize 校验可信调用者与授权器结果。
func (s *Service) authorize(ctx context.Context, caller Caller, action Action, scopeID string) error {
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
	if err := s.authorizer.Authorize(ctx, caller, action, scopeID); err != nil {
		return fmt.Errorf("%w: %w", ErrAccessDenied, err)
	}
	return nil
}

// recordRead 写成功读取审计；失败时拒绝返回数据。
func (s *Service) recordRead(ctx context.Context, caller Caller, action Action, groupRecord Group) error {
	event := audit.Event{
		Actor:     caller.actor,
		AppID:     groupRecord.ApplicationID,
		Action:    string(action),
		Target:    audit.Target{Type: "group", ID: groupRecord.ID},
		Outcome:   audit.OutcomeSuccess,
		RequestID: caller.requestID,
	}
	if err := s.audit.Record(ctx, event); err != nil {
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	}
	return nil
}

// recordMemberAttempt 为幂等（无实际变化）的成员请求写成功审计。
func (s *Service) recordMemberAttempt(ctx context.Context, caller Caller, groupRecord Group, action Action, userIDs []string, label string, changed, skipped int) error {
	event := audit.Event{
		Actor:     caller.actor,
		AppID:     groupRecord.ApplicationID,
		Action:    string(action),
		Target:    audit.Target{Type: "group", ID: groupRecord.ID},
		Outcome:   audit.OutcomeSuccess,
		RequestID: caller.requestID,
		Changes:   memberBatchChanges(userIDs, label, changed, skipped),
	}
	if err := s.audit.Record(ctx, event); err != nil {
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	}
	return nil
}

// recordMemberRejection 为成员批量变更被拒绝写一条失败审计（不伪造成功审计），
// 并返回既有拒绝错误。审计使用独立事务，不受请求取消影响；审计失败时把
// ErrAuditUnavailable 一并加入错误链，拒绝仍生效。
func (s *Service) recordMemberRejection(ctx context.Context, caller Caller, groupRecord Group,
	action Action, code ErrorCode, reason string, cause error) error {
	event := audit.Event{
		Actor:      caller.actor,
		AppID:      groupRecord.ApplicationID,
		Action:     string(action),
		Target:     audit.Target{Type: "group", ID: groupRecord.ID},
		Outcome:    audit.OutcomeFailure,
		ErrorCode:  string(code),
		ReasonCode: reason,
		RequestID:  caller.requestID,
	}
	if err := s.audit.RecordFailure(ctx, event); err != nil {
		return errors.Join(cause, fmt.Errorf("%w: %w", ErrAuditUnavailable, err))
	}
	return cause
}

// recordListRead 为组列表写成功读取审计（无单一目标组）。
func (s *Service) recordListRead(ctx context.Context, caller Caller) error {
	event := audit.Event{
		Actor:     caller.actor,
		Action:    string(ActionListGroups),
		Target:    audit.Target{Type: "group"},
		Outcome:   audit.OutcomeSuccess,
		RequestID: caller.requestID,
	}
	if err := s.audit.Record(ctx, event); err != nil {
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	}
	return nil
}

// memberBatchChanges 把成员列表与统计转换为审计差异；成员逐个以 member_1.. 记录，
// 便于追查实际目标。字段总数不超过审计上限（≤12 成员 + 统计字段）。
func memberBatchChanges(userIDs []string, label string, changed, skipped int) []audit.FieldChange {
	changes := make([]audit.FieldChange, 0, len(userIDs)+2)
	for index, userID := range userIDs {
		changes = append(changes, audit.FieldChange{
			Field: "member_" + strconv.Itoa(index+1),
			After: userID,
		})
	}
	changes = append(changes,
		audit.FieldChange{Field: label, After: strconv.Itoa(changed)},
		audit.FieldChange{Field: "skipped", After: strconv.Itoa(skipped)},
	)
	return changes
}

// normalizeMemberIDs 校验批量用户 ID：数量 1～MaxBatchMembers、格式有效、去重；
// 空列表或超限返回 ErrInvalidRequest。
func normalizeMemberIDs(userIDs []string) ([]string, error) {
	if len(userIDs) == 0 {
		return nil, fmt.Errorf("%w: 成员列表不能为空", ErrInvalidRequest)
	}
	if len(userIDs) > MaxBatchMembers {
		return nil, fmt.Errorf("%w: 单次成员操作不能超过 %d 人", ErrInvalidRequest, MaxBatchMembers)
	}
	seen := make(map[string]struct{}, len(userIDs))
	result := make([]string, 0, len(userIDs))
	for _, raw := range userIDs {
		value := strings.TrimSpace(raw)
		if !account.ValidUserID(value) {
			return nil, fmt.Errorf("%w: 用户 ID 格式无效", ErrInvalidRequest)
		}
		if _, duplicated := seen[value]; duplicated {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("%w: 成员列表不能为空", ErrInvalidRequest)
	}
	return result, nil
}

// mapCriticalError 把事务错误映射为领域错误；审计失败优先。
func mapCriticalError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, audit.ErrAuditUnavailable):
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrGroupNotFound),
		errors.Is(err, ErrScopeInvalid), errors.Is(err, ErrMemberNotEligible),
		errors.Is(err, ErrApplicationInactive):
		return err
	case errors.Is(err, ErrGroupKeyTaken), errors.Is(err, ErrStateConflict),
		errors.Is(err, ErrAccessDenied):
		return err
	case delegation.CodeOf(err) != "":
		// 委派检查拒绝：保留委派领域错误，由 CodeOf 映射为可诊断错误码。
		return err
	case errors.Is(err, ErrStoreUnavailable):
		return err
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, audit.ErrInvalidEvent):
		return fmt.Errorf("%w: 审计事件无效", ErrOptionsInvalid)
	default:
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
}

// groupTransferRefs 在调用方事务内把用户组通过角色生效的权限转换为委派检查引用。
func (s *Service) groupTransferRefs(ctx context.Context, tx audit.Tx, groupID string) ([]delegation.PermissionRef, error) {
	ids, err := s.store.ListGroupRoleEffectivePermissionIDs(ctx, tx, groupID)
	if err != nil {
		return nil, err
	}
	refs := make([]delegation.PermissionRef, 0, len(ids))
	for _, id := range ids {
		refs = append(refs, delegation.PermissionRef{PermissionID: id})
	}
	return refs, nil
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
