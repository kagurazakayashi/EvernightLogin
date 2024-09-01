package app

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
	"github.com/kagurazakayashi/EvernightLogin/internal/search"
	"github.com/kagurazakayashi/EvernightLogin/internal/securityevent"
)

// memberTransferRefs 在调用方事务内把该用户在本应用范围内当前会生效的权限转换
// 为委派检查引用。
func (s *Service) memberTransferRefs(ctx context.Context, tx audit.Tx, applicationID, userID string) ([]delegation.PermissionRef, error) {
	ids, err := s.store.ListMemberEffectivePermissionIDs(ctx, tx, applicationID, userID)
	if err != nil {
		return nil, err
	}
	refs := make([]delegation.PermissionRef, 0, len(ids))
	for _, id := range ids {
		refs = append(refs, delegation.PermissionRef{PermissionID: id})
	}
	return refs, nil
}

// 应用成员服务方法。
//
// 安全不变量：
//   - 每个成员操作都先经过 Authorizer 按 ApplicationID 判权；调用者只能操作其
//     获准应用，不能通过请求参数扩大范围。
//   - 加入既有账户只接受稳定用户 ID，且必须是 active 账户；服务不提供用户名/
//     邮箱查找或自助加入入口，知道用户名/邮箱不能认领账户。
//   - 应用内禁用/移除只修改 app_memberships 中该应用的行，不修改 users 表，也不
//     影响同一用户在其他应用的成员关系。
//   - 应用专属资料只写 profile_json（app_memberships 行），不写全局资料。
//   - 加入、资料更新、启停与移除使用审计事务；成功审计写入失败时整体回滚。
//     移除/停用/应用停用产生可靠审计事件，未来令牌/会话模块必须消费这些事件并
//     在每次授权时读取当前成员状态；本包不提供会话/令牌撤销 API。

// AddApplicationMember 受控地把既有全局账户加入指定应用，初始状态为 active。
// 应用必须启用、目标账户必须存在且 active；重复加入返回 ErrMemberExists。
func (s *Service) AddApplicationMember(ctx context.Context, caller Caller, request AddMemberRequest) (Membership, error) {
	if err := s.authorize(ctx, caller, ActionAddApplicationMember, request.ApplicationID); err != nil {
		return Membership{}, err
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return Membership{}, err
	}
	if err := validateMembershipIDs(request.ApplicationID, request.UserID); err != nil {
		return Membership{}, err
	}
	application, err := s.loadMemberApplication(ctx, request.ApplicationID)
	if err != nil {
		return Membership{}, err
	}
	if application.Status != StatusActive {
		return Membership{}, fmt.Errorf("%w: 应用 %s 当前不可加入", ErrApplicationInactive, application.ID)
	}
	if err := s.requireActiveUser(ctx, caller, ActionAddApplicationMember, application.ID, request.UserID); err != nil {
		return Membership{}, err
	}
	profile, err := normalizeMemberProfile(request.Profile)
	if err != nil {
		return Membership{}, err
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	membership := Membership{
		ApplicationID: application.ID,
		UserID:        request.UserID,
		Status:        MembershipActive,
		Profile:       profile,
		RowVersion:    1,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	changes := memberProfileChanges(MemberProfile{}, profile)
	changes = append(changes,
		audit.FieldChange{Field: "status", After: string(MembershipActive)},
		audit.FieldChange{Field: "row_version", After: "1"},
	)
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:     caller.actor,
			AppID:     application.ID,
			Action:    string(ActionAddApplicationMember),
			Target:    membershipTarget(request.UserID),
			RequestID: caller.requestID,
			Changes:   changes,
		},
		FailureReasonCode: "application.member.add_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		// 与写入同一事务：该用户可能已有本应用角色分配（角色分配在成员移除后
		// 保留），重新加入成员会让这些权限恢复生效，必须检查可转授范围。
		refs, refErr := s.memberTransferRefs(txCtx, tx, application.ID, request.UserID)
		if refErr != nil {
			return refErr
		}
		if guardErr := s.transfers.CheckAssignment(txCtx, tx, caller.actor, application.ID, refs,
			delegation.Target{Kind: delegation.TargetUser, ID: request.UserID}); guardErr != nil {
			return guardErr
		}
		return s.store.CreateMembership(txCtx, tx, membership)
	})
	if err != nil {
		return Membership{}, mapCriticalError(err)
	}
	s.logger.Info("应用成员已加入",
		"application_id", membership.ApplicationID, "user_id", membership.UserID,
		"status", string(membership.Status))
	s.emitMembershipEvent(ctx, membership.ApplicationID, request.UserID, "active", caller.requestID)
	return membership, nil
}

// GetApplicationMember 读取指定应用中的成员关系与应用专属资料；读取写成功审计，
// 审计不可用时拒绝返回数据。
func (s *Service) GetApplicationMember(ctx context.Context, caller Caller, applicationID, userID string) (Membership, error) {
	if err := s.authorize(ctx, caller, ActionGetApplicationMember, applicationID); err != nil {
		return Membership{}, err
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return Membership{}, err
	}
	if err := validateMembershipIDs(applicationID, userID); err != nil {
		return Membership{}, err
	}
	if _, err := s.loadMemberApplication(ctx, applicationID); err != nil {
		return Membership{}, err
	}
	membership, err := s.store.GetMembership(ctx, applicationID, userID)
	if err != nil {
		return Membership{}, err
	}
	if err := s.recordMemberRead(ctx, caller, ActionGetApplicationMember, applicationID, userID); err != nil {
		return Membership{}, err
	}
	return membership, nil
}

// ListApplicationMembers 按应用隔离列出成员，支持有限分页、状态过滤与白名单排序。
// 查询始终带 ApplicationID，无法跨应用读取；读取失败或读审计失败时不返回数据。
func (s *Service) ListApplicationMembers(ctx context.Context, caller Caller, request MemberListRequest) (MemberListResult, error) {
	if err := s.authorize(ctx, caller, ActionListApplicationMembers, request.ApplicationID); err != nil {
		return MemberListResult{}, err
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return MemberListResult{}, err
	}
	if !ValidApplicationID(request.ApplicationID) {
		return MemberListResult{}, fmt.Errorf("%w: 应用 ID 格式无效", ErrInvalidRequest)
	}
	if _, err := s.loadMemberApplication(ctx, request.ApplicationID); err != nil {
		return MemberListResult{}, err
	}
	query, err := normalizeMemberListRequest(request)
	if err != nil {
		return MemberListResult{}, err
	}
	members, hasMore, err := s.store.ListMemberships(ctx, query)
	if err != nil {
		return MemberListResult{}, err
	}
	if err := s.recordMemberRead(ctx, caller, ActionListApplicationMembers, request.ApplicationID, ""); err != nil {
		return MemberListResult{}, err
	}
	return MemberListResult{Members: members, HasMore: hasMore}, nil
}

// UpdateApplicationMemberProfile 只更新指定应用内的成员资料与 row_version；应用
// 必须启用、目标账户必须 active。它不写全局资料，也不影响其他应用。
func (s *Service) UpdateApplicationMemberProfile(ctx context.Context, caller Caller, request MemberProfileRequest) (Membership, error) {
	if err := s.authorize(ctx, caller, ActionUpdateApplicationMemberProfile, request.ApplicationID); err != nil {
		return Membership{}, err
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return Membership{}, err
	}
	if err := validateMembershipIDs(request.ApplicationID, request.UserID); err != nil {
		return Membership{}, err
	}
	if request.ExpectedRowVersion <= 0 {
		return Membership{}, fmt.Errorf("%w: 期望行版本必须大于 0", ErrInvalidRequest)
	}
	application, err := s.loadMemberApplication(ctx, request.ApplicationID)
	if err != nil {
		return Membership{}, err
	}
	if application.Status != StatusActive {
		return Membership{}, ErrApplicationInactive
	}
	current, err := s.store.GetMembership(ctx, application.ID, request.UserID)
	if err != nil {
		return Membership{}, err
	}
	if request.ExpectedRowVersion != current.RowVersion {
		return Membership{}, ErrStateConflict
	}
	if err := s.requireActiveUser(ctx, caller, ActionUpdateApplicationMemberProfile, application.ID, request.UserID); err != nil {
		return Membership{}, err
	}
	profile, err := normalizeMemberProfile(request.Profile)
	if err != nil {
		return Membership{}, err
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	updated := current
	updated.Profile = profile
	updated.RowVersion = current.RowVersion + 1
	updated.UpdatedAt = now
	changes := memberProfileChanges(current.Profile, profile)
	changes = append(changes, audit.FieldChange{
		Field:  "row_version",
		Before: formatInt64(current.RowVersion),
		After:  formatInt64(updated.RowVersion),
	})
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:     caller.actor,
			AppID:     application.ID,
			Action:    string(ActionUpdateApplicationMemberProfile),
			Target:    membershipTarget(request.UserID),
			RequestID: caller.requestID,
			Changes:   changes,
		},
		FailureReasonCode: "application.member.profile_update_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.store.UpdateMembershipProfile(txCtx, tx, MemberProfileUpdate{
			ApplicationID:      application.ID,
			UserID:             request.UserID,
			ExpectedRowVersion: current.RowVersion,
			Profile:            profile,
			Now:                now,
		})
	})
	if err != nil {
		return Membership{}, mapCriticalError(err)
	}
	s.logger.Info("应用成员资料已更新",
		"application_id", updated.ApplicationID, "user_id", updated.UserID)
	return updated, nil
}

// EnableApplicationMember 把应用内成员状态设为 active。应用与全局账户都必须
// active；重复启用幂等成功（Changed=false）。
func (s *Service) EnableApplicationMember(ctx context.Context, caller Caller, request MemberStatusRequest) (MemberStatusResult, error) {
	return s.applyMemberStatus(ctx, caller, request, MembershipActive, ActionEnableApplicationMember)
}

// DisableApplicationMember 把应用内成员状态设为 disabled。它只影响该应用，不修改
// 全局账户或其他应用成员关系；应用停用后仍允许执行该安全操作。
func (s *Service) DisableApplicationMember(ctx context.Context, caller Caller, request MemberStatusRequest) (MemberStatusResult, error) {
	return s.applyMemberStatus(ctx, caller, request, MembershipDisabled, ActionDisableApplicationMember)
}

// applyMemberStatus 执行应用内成员启停公共流程。
func (s *Service) applyMemberStatus(ctx context.Context, caller Caller, request MemberStatusRequest, target MembershipStatus, action Action) (MemberStatusResult, error) {
	if err := s.authorize(ctx, caller, action, request.ApplicationID); err != nil {
		return MemberStatusResult{}, err
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return MemberStatusResult{}, err
	}
	if err := validateMembershipIDs(request.ApplicationID, request.UserID); err != nil {
		return MemberStatusResult{}, err
	}
	if request.ExpectedRowVersion <= 0 {
		return MemberStatusResult{}, fmt.Errorf("%w: 期望行版本必须大于 0", ErrInvalidRequest)
	}
	application, err := s.loadMemberApplication(ctx, request.ApplicationID)
	if err != nil {
		return MemberStatusResult{}, err
	}
	if target == MembershipActive {
		// 启用成员会恢复应用访问资格：应用必须处于 active；全局账户状态在真正
		// 发生状态转换前检查（已是目标状态的幂等请求不改任何状态）。
		if application.Status != StatusActive {
			return MemberStatusResult{}, ErrApplicationInactive
		}
	}
	current, err := s.store.GetMembership(ctx, application.ID, request.UserID)
	if err != nil {
		return MemberStatusResult{}, err
	}
	if current.Status == target {
		event := audit.Event{
			Actor:     caller.actor,
			AppID:     application.ID,
			Action:    string(action),
			Target:    membershipTarget(request.UserID),
			Outcome:   audit.OutcomeSuccess,
			RequestID: caller.requestID,
			Changes:   []audit.FieldChange{{Field: "result", After: "unchanged"}},
		}
		if err := s.audit.Record(ctx, event); err != nil {
			return MemberStatusResult{}, fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
		}
		return MemberStatusResult{Membership: current, Changed: false}, nil
	}
	if request.ExpectedRowVersion != current.RowVersion {
		return MemberStatusResult{}, ErrStateConflict
	}
	if target == MembershipActive {
		if err := s.requireActiveUser(ctx, caller, action, application.ID, request.UserID); err != nil {
			return MemberStatusResult{}, err
		}
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	updated := current
	updated.Status = target
	updated.RowVersion = current.RowVersion + 1
	updated.UpdatedAt = now
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:     caller.actor,
			AppID:     application.ID,
			Action:    string(action),
			Target:    membershipTarget(request.UserID),
			RequestID: caller.requestID,
			Changes: []audit.FieldChange{
				{Field: "status", Before: string(current.Status), After: string(target)},
				{Field: "row_version", Before: formatInt64(current.RowVersion), After: formatInt64(updated.RowVersion)},
			},
		},
		FailureReasonCode: "application.member.status_change_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		if target == MembershipActive {
			// 重新启用成员会恢复既有角色分配的有效权限：同一事务内检查可转授范围。
			refs, refErr := s.memberTransferRefs(txCtx, tx, application.ID, request.UserID)
			if refErr != nil {
				return refErr
			}
			if guardErr := s.transfers.CheckAssignment(txCtx, tx, caller.actor, application.ID, refs,
				delegation.Target{Kind: delegation.TargetUser, ID: request.UserID}); guardErr != nil {
				return guardErr
			}
		}
		return s.store.ApplyMembershipStatus(txCtx, tx, MemberStatusChange{
			ApplicationID:      application.ID,
			UserID:             request.UserID,
			ExpectedRowVersion: current.RowVersion,
			ExpectedStatus:     current.Status,
			NewStatus:          target,
			Now:                now,
		})
	})
	if err != nil {
		return MemberStatusResult{}, mapCriticalError(err)
	}
	s.logger.Info("应用成员状态已变更",
		"application_id", updated.ApplicationID, "user_id", updated.UserID,
		"status", string(target))
	s.emitMembershipEvent(ctx, updated.ApplicationID, updated.UserID, string(target),
		caller.requestID)
	return MemberStatusResult{Membership: updated, Changed: true}, nil
}

// RemoveApplicationMember 移除指定应用中的成员关系，并写可靠审计事件。它不删除
// 全局账户、不修改其他应用成员关系；应用停用后仍允许执行该安全操作。未来令牌/
// 会话模块必须消费 application.member.remove 事件并在授权时检查当前成员状态。
func (s *Service) RemoveApplicationMember(ctx context.Context, caller Caller, request RemoveMemberRequest) error {
	if err := s.authorize(ctx, caller, ActionRemoveApplicationMember, request.ApplicationID); err != nil {
		return err
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateMembershipIDs(request.ApplicationID, request.UserID); err != nil {
		return err
	}
	if request.ExpectedRowVersion <= 0 {
		return fmt.Errorf("%w: 期望行版本必须大于 0", ErrInvalidRequest)
	}
	application, err := s.loadMemberApplication(ctx, request.ApplicationID)
	if err != nil {
		return err
	}
	current, err := s.store.GetMembership(ctx, application.ID, request.UserID)
	if err != nil {
		return err
	}
	if request.ExpectedRowVersion != current.RowVersion {
		return ErrStateConflict
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:     caller.actor,
			AppID:     application.ID,
			Action:    string(ActionRemoveApplicationMember),
			Target:    membershipTarget(request.UserID),
			RequestID: caller.requestID,
			Changes: []audit.FieldChange{
				{Field: "status", Before: string(current.Status), After: "removed"},
				{Field: "row_version", Before: formatInt64(current.RowVersion), After: "removed"},
			},
		},
		FailureReasonCode: "application.member.remove_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.store.RemoveMembership(txCtx, tx, MemberRemove{
			ApplicationID:      application.ID,
			UserID:             request.UserID,
			ExpectedRowVersion: current.RowVersion,
		})
	})
	if err != nil {
		return mapCriticalError(err)
	}
	s.logger.Info("应用成员已移除",
		"application_id", application.ID, "user_id", request.UserID)
	s.emitMembershipEvent(ctx, application.ID, request.UserID, "removed", caller.requestID)
	return nil
}

// emitMembershipEvent 在成员关系审计事务提交后通知可选 Webhook；失败只记运行日志，
// 不回滚已完成的成员变更（通知不是权限正确性的前置条件）。
func (s *Service) emitMembershipEvent(ctx context.Context, applicationID, userID, status,
	requestID string) {
	if s.events == nil {
		return
	}
	key := "app.membership.changed:" + applicationID + ":" + userID + ":" + requestID
	if requestID == "" {
		key = "app.membership.changed:" + applicationID + ":" + userID + ":" + status + ":" +
			strconv.FormatInt(s.now().UTC().UnixNano(), 10)
	}
	event := securityevent.Event{
		Type: securityevent.TypeAppMembershipChanged, ApplicationID: applicationID,
		UserID: userID, IdempotencyKey: key, OccurredAt: s.now(),
		RequestID: requestID, Data: map[string]string{"status": status},
	}
	if err := s.events.Emit(context.WithoutCancel(ctx), event); err != nil {
		s.logger.Warn("应用成员安全事件通知失败", "error_category", "webhook_emit_failed")
	}
}

// loadMemberApplication 读取应用记录并保持领域错误语义；应用不存在返回
// ErrApplicationNotFound（映射 REQ_INVALID）。
func (s *Service) loadMemberApplication(ctx context.Context, applicationID string) (Application, error) {
	application, err := s.store.GetApplication(ctx, applicationID)
	if err != nil {
		return Application{}, err
	}
	return application, nil
}

// requireActiveUser 要求目标全局账户存在、为 active 且不是 root；只在加入/启用/
// 资料更新等恢复或维持应用访问资格的操作前调用。停用/移除用于清理，不要求账户
// active。
//
// root 只能通过受保护的本地通道管理，不能成为任何应用成员（与 internal/group
// 的 root 组成员排除规则一致）：root 目标返回既有 USER_DISABLED 语义并写一条
// 失败审计，避免普通应用管理员反复尝试给 root 建立成员/业务资格却无痕。
func (s *Service) requireActiveUser(ctx context.Context, caller Caller, action Action, applicationID, userID string) error {
	status, isRoot, found, err := s.store.LookupUserState(ctx, userID)
	if err != nil {
		return err
	}
	if !found {
		return ErrTargetUserNotFound
	}
	if isRoot {
		return s.recordRootMemberRejection(ctx, caller, action, applicationID, userID)
	}
	if status != account.StatusActive {
		return fmt.Errorf("%w: 当前状态为 %s", ErrUserNotEligible, status)
	}
	return nil
}

// recordRootMemberRejection 为“root 不能成为应用成员/业务成员资格”的普通管理
// 拒绝写失败审计，返回既有 USER_DISABLED 语义（不新增错误码）。审计使用独立
// 事务，不受请求取消影响；审计失败时把 ErrAuditUnavailable 一并加入错误链。
func (s *Service) recordRootMemberRejection(ctx context.Context, caller Caller, action Action, applicationID, userID string) error {
	cause := fmt.Errorf("%w: root 账户不能成为应用成员", ErrUserNotEligible)
	event := audit.Event{
		Actor:      caller.actor,
		AppID:      applicationID,
		Action:     string(action),
		Target:     membershipTarget(userID),
		Outcome:    audit.OutcomeFailure,
		ErrorCode:  string(CodeUserDisabled),
		ReasonCode: "root_protected",
		RequestID:  caller.requestID,
	}
	if err := s.audit.RecordFailure(ctx, event); err != nil {
		return errors.Join(cause, fmt.Errorf("%w: %w", ErrAuditUnavailable, err))
	}
	return cause
}

// recordMemberRead 写成员读取成功审计；失败时拒绝返回数据（fail-closed）。
func (s *Service) recordMemberRead(ctx context.Context, caller Caller, action Action, applicationID, userID string) error {
	event := audit.Event{
		Actor:     caller.actor,
		AppID:     applicationID,
		Action:    string(action),
		Target:    membershipTarget(userID),
		Outcome:   audit.OutcomeSuccess,
		RequestID: caller.requestID,
	}
	if err := s.audit.Record(ctx, event); err != nil {
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	}
	return nil
}

// validateMembershipIDs 校验应用 ID 与目标用户 ID 的固定格式；在授权之后调用，
// 未授权调用者不会先得到 ID 是否存在/格式的额外信息。
func validateMembershipIDs(applicationID, userID string) error {
	if !ValidApplicationID(applicationID) {
		return fmt.Errorf("%w: 应用 ID 格式无效", ErrInvalidRequest)
	}
	if !account.ValidUserID(userID) {
		return fmt.Errorf("%w: 用户 ID 格式无效", ErrInvalidRequest)
	}
	return nil
}

// membershipTarget 返回成员审计目标：应用范围在 Event.AppID，目标稳定 ID 为用户 ID。
func membershipTarget(userID string) audit.Target {
	return audit.Target{Type: "application_member", ID: userID}
}

// memberProfileChanges 生成应用专属资料的脱敏差异：只记录发生变化的字段名，前后
// 值都记为 [REDACTED]，避免把应用内资料正文写入审计明细。
func memberProfileChanges(before, after MemberProfile) []audit.FieldChange {
	changes := make([]audit.FieldChange, 0, 3)
	appendChange := func(field, beforeValue, afterValue string) {
		if beforeValue == afterValue {
			return
		}
		changes = append(changes, audit.FieldChange{
			Field:  field,
			Before: "[REDACTED]",
			After:  "[REDACTED]",
		})
	}
	appendChange("profile.display_name", before.DisplayName, after.DisplayName)
	appendChange("profile.title", before.Title, after.Title)
	appendChange("profile.note", before.Note, after.Note)
	return changes
}

// normalizeMemberListRequest 校验并填充应用成员列表分页/过滤参数。
func normalizeMemberListRequest(request MemberListRequest) (MemberListQuery, error) {
	if !ValidApplicationID(request.ApplicationID) {
		return MemberListQuery{}, fmt.Errorf("%w: 应用 ID 格式无效", ErrInvalidRequest)
	}
	limit := request.Limit
	if limit == 0 {
		limit = DefaultListLimit
	}
	if limit < 0 || limit > MaxListLimit {
		return MemberListQuery{}, fmt.Errorf("%w: 每页数量必须在 1～%d 之间", ErrInvalidRequest, MaxListLimit)
	}
	if request.Offset < 0 || request.Offset > MaxListOffset {
		return MemberListQuery{}, fmt.Errorf("%w: 分页偏移必须在 0～%d 之间", ErrInvalidRequest, MaxListOffset)
	}
	sortField := request.Sort
	if sortField == "" {
		sortField = MemberSortCreatedAt
	}
	if !sortField.Valid() {
		return MemberListQuery{}, fmt.Errorf("%w: 排序字段不在允许列表内", ErrInvalidRequest)
	}
	if request.Status != "" && !request.Status.Valid() {
		return MemberListQuery{}, fmt.Errorf("%w: 成员状态过滤值无效", ErrInvalidRequest)
	}
	searchText, err := search.NormalizeQuery(request.Search)
	if err != nil {
		return MemberListQuery{}, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	searchFields, err := account.NormalizeUserSearchFields(request.SearchFields)
	if err != nil {
		// 复用账户白名单的错误语义（未知字段/邮箱电话），并保持本领域错误包装，
		// 调用方用 errors.Is(app.ErrInvalidRequest) 判断仍然成立。
		return MemberListQuery{}, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	return MemberListQuery{
		ApplicationID: request.ApplicationID,
		Limit:         limit,
		Offset:        request.Offset,
		Status:        request.Status,
		Sort:          sortField,
		Descending:    request.Descending,
		Search:        searchText,
		SearchFields:  searchFields,
	}, nil
}
