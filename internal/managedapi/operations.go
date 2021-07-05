package managedapi

import (
	"context"
	"fmt"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/group"
	"github.com/kagurazakayashi/EvernightLogin/internal/permission"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
)

// ListMeta 是分页查询公共参数。
type ListMeta struct {
	Meta
	Limit  int
	Offset int
}

// GetApplicationRequest 读取本应用资料。
type GetApplicationRequest struct{ Meta }

// ListMembersRequest 分页查询本应用成员。
type ListMembersRequest struct {
	ListMeta
	Status     string
	Sort       string
	Descending bool
}

// GetMemberRequest 读取单个成员。
type GetMemberRequest struct {
	Meta
	UserID string
}

// UpdateMemberProfileRequest 更新应用内成员资料（只写应用内 profile 字段）。
type UpdateMemberProfileRequest struct {
	Meta
	UserID             string
	ExpectedRowVersion int64
	DisplayName        *string
	Title              *string
	Note               *string
}

// MemberActionRequest 成员启用/禁用/移除。
type MemberActionRequest struct {
	Meta
	UserID             string
	ExpectedRowVersion int64
}

// CreateUserRequest 创建全新账户并建立本应用成员关系。
type CreateUserRequest struct {
	Meta
	Username  string
	Nickname  *string
	Biography *string
}

// ListGroupsRequest 分页列出本应用用户组。
type ListGroupsRequest struct{ ListMeta }

// GetGroupRequest 读取用户组。
type GetGroupRequest struct {
	Meta
	GroupID string
}

// ListGroupMembersRequest 分页列出组成员。
type ListGroupMembersRequest struct {
	ListMeta
	GroupID string
}

// GroupMembersRequest 批量增删组成员（原子，受 max_batch 限制）。
type GroupMembersRequest struct {
	Meta
	GroupID string
	UserIDs []string
}

// ListRolesRequest 分页列出本应用角色。
type ListRolesRequest struct{ ListMeta }

// GetRoleRequest 读取角色。
type GetRoleRequest struct {
	Meta
	RoleID string
}

// RoleTargetRequest 角色分配给用户/从用户撤回。
type RoleTargetRequest struct {
	Meta
	RoleID string
	UserID string
}

// RoleGroupTargetRequest 角色分配给用户组/从组撤回。
type RoleGroupTargetRequest struct {
	Meta
	RoleID  string
	GroupID string
}

// ListRoleSubresourceRequest 角色权限组合/分配列表。
type ListRoleSubresourceRequest struct {
	Meta
	RoleID string
}

// ListPermissionsRequest 分页列出本应用自定义权限。
type ListPermissionsRequest struct{ ListMeta }

// GetPermissionRequest 读取权限。
type GetPermissionRequest struct {
	Meta
	PermissionID string
}

// execute 完成统一准备、审计与错误映射。body 只会在授权通过后执行。
func (s *Service) execute(ctx context.Context, principal Principal, meta Meta, opID,
	targetType, targetID string,
	body func(grantCtx context.Context, state resolved) (any, error)) (any, error) {
	state, grantCtx, err := s.prepare(ctx, principal, meta, opID)
	if err != nil {
		// 优先使用 prepare 已解析出的真实操作者（主体解析成功后失败）；只有主体
		// 本身无法确认时才记录匿名失败，避免丢失"审计真实操作者"。
		actor := audit.Actor{Type: audit.ActorAnonymous}
		if state.actor.Type != "" {
			actor = state.actor
		}
		event := audit.Event{
			Actor: actor, AppID: state.appID, Action: "managed_api." + opID,
			Target:  audit.Target{Type: targetType, ID: targetID},
			Outcome: audit.OutcomeFailure, ErrorCode: string(errorCodeOf(err)),
			ReasonCode: reasonOf(err), RequestID: meta.RequestID,
		}
		if auditErr := s.opts.Audit.RecordFailure(ctx, event); auditErr != nil {
			s.logger.Warn("托管管理 API 拒绝审计写入失败", "operation", opID,
				"error_category", "audit_unavailable")
		}
		return nil, err
	}
	value, bodyErr := body(grantCtx, state)
	if bodyErr != nil {
		return nil, s.fail(ctx, state, meta, opID, targetType, targetID, bodyErr)
	}
	s.success(ctx, state, meta, opID, targetType, targetID)
	return value, nil
}

// checkWriteFields 校验写入字段白名单。
func checkWriteFields(state resolved, objectType string, actual map[string]bool) error {
	return CheckWriteFields(state.policy, objectType, actual)
}

// GetApplication 读取本应用资料（字段按策略投影）。
func (s *Service) GetApplication(ctx context.Context, principal Principal,
	request GetApplicationRequest) (View, error) {
	ctx = normalizeContext(ctx)
	value, err := s.execute(ctx, principal, request.Meta, OpApplicationGet,
		ObjectApplication, principal.appID, func(grantCtx context.Context, state resolved) (any, error) {
			if objectErr := s.requireObject(state, ObjectApplication, state.appID); objectErr != nil {
				return nil, objectErr
			}
			caller, callerErr := s.appCaller(state)
			if callerErr != nil {
				return nil, callerErr
			}
			// 应用资料不是公开信息：代表用户必须是目标应用的有效成员；服务身份是
			// 应用自身，无需成员关系。成员校验使用既有应用服务（读审计保留）。
			if state.kind == PrincipalUser {
				if _, memberErr := s.opts.App.GetApplicationMember(grantCtx, caller,
					state.appID, state.userID); memberErr != nil {
					// 非成员不区分"不存在/已停用"，统一按成员关系缺失拒绝。
					return nil, &ServiceError{Code: CodeAppMembershipRequired,
						Reason: "membership_required", Cause: memberErr}
				}
			}
			record, getErr := s.opts.App.GetApplication(grantCtx, caller, state.appID)
			if getErr != nil {
				return nil, getErr
			}
			return ProjectApplication(state.policy, record), nil
		})
	if err != nil {
		return View{}, err
	}
	return value.(View), nil
}

// ListMembers 分页查询本应用成员；状态/排序/分页受策略与全局上限约束，结果按
// 策略对象范围与数据范围过滤。全局显示字段仅在策略允许可读时按成员逐条读取。
func (s *Service) ListMembers(ctx context.Context, principal Principal,
	request ListMembersRequest) (MemberListResult, error) {
	ctx = normalizeContext(ctx)
	value, err := s.execute(ctx, principal, request.Meta, OpMembersList, ObjectMember, "",
		func(grantCtx context.Context, state resolved) (any, error) {
			limit, offset, pageErr := clampLimitOffset(state.policy, request.Limit, request.Offset)
			if pageErr != nil {
				return nil, pageErr
			}
			status := app.MembershipStatus(strings.TrimSpace(request.Status))
			if status != "" && !status.Valid() {
				return nil, fmt.Errorf("%w: 成员状态筛选无效", ErrInvalidRequest)
			}
			sortField := app.MemberSortField(strings.TrimSpace(request.Sort))
			if sortField != "" {
				if !sortField.Valid() {
					return nil, fmt.Errorf("%w: 排序字段不在白名单", ErrInvalidRequest)
				}
				if !state.policy.ReadAllowed(ObjectMember, string(sortField)) && string(sortField) != "user_id" {
					return nil, fmt.Errorf("%w: 按不可读字段排序被拒绝", ErrInvalidRequest)
				}
			}
			caller, callerErr := s.appCaller(state)
			if callerErr != nil {
				return nil, callerErr
			}
			result, listErr := s.opts.App.ListApplicationMembers(grantCtx, caller,
				app.MemberListRequest{ApplicationID: state.appID, Limit: limit, Offset: offset,
					Status: status, Sort: sortField, Descending: request.Descending})
			if listErr != nil {
				return nil, listErr
			}
			filter, filterErr := s.objectFilter(state, ObjectMember)
			if filterErr != nil {
				return nil, filterErr
			}
			views := make([]MemberView, 0, len(result.Members))
			for _, membership := range result.Members {
				if !filter(membership.UserID) {
					continue
				}
				views = append(views, s.memberView(grantCtx, state, membership))
			}
			return MemberListResult{Members: views, HasMore: result.HasMore}, nil
		})
	if err != nil {
		return MemberListResult{}, err
	}
	return value.(MemberListResult), nil
}

// memberView 构造成员投影；仅在策略允许全局显示字段时读取账户服务（读审计由
// 账户服务记录），否则不读取任何全局账户资料。
func (s *Service) memberView(ctx context.Context, state resolved, membership app.Membership) MemberView {
	needUser := state.policy.ReadAllowed(ObjectMember, "username") ||
		state.policy.ReadAllowed(ObjectMember, "nickname") ||
		state.policy.ReadAllowed(ObjectMember, "user_status")
	if !needUser {
		return ProjectMember(state.policy, membership, nil)
	}
	caller, err := s.accountCaller(state)
	if err != nil {
		return ProjectMember(state.policy, membership, nil)
	}
	record, err := s.opts.Account.GetUser(ctx, caller, membership.UserID)
	if err != nil {
		return ProjectMember(state.policy, membership, nil)
	}
	return ProjectMember(state.policy, membership, &record)
}

// GetMember 读取单个成员。
func (s *Service) GetMember(ctx context.Context, principal Principal,
	request GetMemberRequest) (MemberView, error) {
	ctx = normalizeContext(ctx)
	value, err := s.execute(ctx, principal, request.Meta, OpMembersGet, ObjectMember, request.UserID,
		func(grantCtx context.Context, state resolved) (any, error) {
			if objectErr := s.requireObject(state, ObjectMember, request.UserID); objectErr != nil {
				return nil, objectErr
			}
			caller, callerErr := s.appCaller(state)
			if callerErr != nil {
				return nil, callerErr
			}
			membership, getErr := s.opts.App.GetApplicationMember(grantCtx, caller,
				state.appID, request.UserID)
			if getErr != nil {
				return nil, getErr
			}
			return s.memberView(grantCtx, state, membership), nil
		})
	if err != nil {
		return MemberView{}, err
	}
	return value.(MemberView), nil
}

// UpdateMemberProfile 更新应用内成员资料；只允许策略可写字段，不影响全局资料。
func (s *Service) UpdateMemberProfile(ctx context.Context, principal Principal,
	request UpdateMemberProfileRequest) (MemberView, error) {
	ctx = normalizeContext(ctx)
	value, err := s.execute(ctx, principal, request.Meta, OpMembersUpdateProfile,
		ObjectMember, request.UserID,
		func(grantCtx context.Context, state resolved) (any, error) {
			if objectErr := s.requireObject(state, ObjectMember, request.UserID); objectErr != nil {
				return nil, objectErr
			}
			if err := checkWriteFields(state, ObjectMember, map[string]bool{
				"display_name": request.DisplayName != nil,
				"title":        request.Title != nil,
				"note":         request.Note != nil,
			}); err != nil {
				return nil, err
			}
			profile := app.MemberProfile{}
			if request.DisplayName != nil {
				profile.DisplayName = *request.DisplayName
			}
			if request.Title != nil {
				profile.Title = *request.Title
			}
			if request.Note != nil {
				profile.Note = *request.Note
			}
			caller, callerErr := s.appCaller(state)
			if callerErr != nil {
				return nil, callerErr
			}
			membership, updateErr := s.opts.App.UpdateApplicationMemberProfile(grantCtx, caller,
				app.MemberProfileRequest{ApplicationID: state.appID, UserID: request.UserID,
					Profile: profile, ExpectedRowVersion: request.ExpectedRowVersion})
			if updateErr != nil {
				return nil, updateErr
			}
			return s.memberView(grantCtx, state, membership), nil
		})
	if err != nil {
		return MemberView{}, err
	}
	return value.(MemberView), nil
}

// UpdateMemberStatus 启用/禁用本应用成员。
func (s *Service) UpdateMemberStatus(ctx context.Context, principal Principal,
	request MemberActionRequest, enable bool) (MemberView, error) {
	ctx = normalizeContext(ctx)
	opID := OpMembersDisable
	if enable {
		opID = OpMembersEnable
	}
	value, err := s.execute(ctx, principal, request.Meta, opID, ObjectMember, request.UserID,
		func(grantCtx context.Context, state resolved) (any, error) {
			if objectErr := s.requireObject(state, ObjectMember, request.UserID); objectErr != nil {
				return nil, objectErr
			}
			caller, callerErr := s.appCaller(state)
			if callerErr != nil {
				return nil, callerErr
			}
			memberRequest := app.MemberStatusRequest{ApplicationID: state.appID,
				UserID: request.UserID, ExpectedRowVersion: request.ExpectedRowVersion}
			var (
				membership app.Membership
				opErr      error
			)
			if enable {
				var result app.MemberStatusResult
				result, opErr = s.opts.App.EnableApplicationMember(grantCtx, caller, memberRequest)
				membership = result.Membership
			} else {
				var result app.MemberStatusResult
				result, opErr = s.opts.App.DisableApplicationMember(grantCtx, caller, memberRequest)
				membership = result.Membership
			}
			if opErr != nil {
				return nil, opErr
			}
			return s.memberView(grantCtx, state, membership), nil
		})
	if err != nil {
		return MemberView{}, err
	}
	return value.(MemberView), nil
}

// RemoveMember 移除本应用成员关系（不删除全局账户）。
func (s *Service) RemoveMember(ctx context.Context, principal Principal,
	request MemberActionRequest) error {
	ctx = normalizeContext(ctx)
	_, err := s.execute(ctx, principal, request.Meta, OpMembersRemove, ObjectMember, request.UserID,
		func(grantCtx context.Context, state resolved) (any, error) {
			if objectErr := s.requireObject(state, ObjectMember, request.UserID); objectErr != nil {
				return nil, objectErr
			}
			caller, callerErr := s.appCaller(state)
			if callerErr != nil {
				return nil, callerErr
			}
			return nil, s.opts.App.RemoveApplicationMember(grantCtx, caller,
				app.RemoveMemberRequest{ApplicationID: state.appID, UserID: request.UserID,
					ExpectedRowVersion: request.ExpectedRowVersion})
		})
	return err
}

// CreateUserWithMembership 创建全新账户并建立本应用成员关系。已存在用户名不会
// 被认领（拒绝按用户名关联已有账户）；失败时返回明确错误，不宣称成功。
func (s *Service) CreateUserWithMembership(ctx context.Context, principal Principal,
	request CreateUserRequest) (MemberView, error) {
	ctx = normalizeContext(ctx)
	value, err := s.execute(ctx, principal, request.Meta, OpUsersCreate, ObjectUser, "",
		func(grantCtx context.Context, state resolved) (any, error) {
			if err := checkWriteFields(state, ObjectUser, map[string]bool{
				"username": request.Username != "", "nickname": request.Nickname != nil,
				"biography": request.Biography != nil,
			}); err != nil {
				return nil, err
			}
			accountCaller, callerErr := s.accountCaller(state)
			if callerErr != nil {
				return nil, callerErr
			}
			create := account.CreateRequest{Username: request.Username}
			if request.Nickname != nil {
				create.Nickname = *request.Nickname
			}
			if request.Biography != nil {
				create.Biography = *request.Biography
			}
			created, createErr := s.opts.Account.CreateUser(grantCtx, accountCaller, create)
			if createErr != nil {
				return nil, createErr
			}
			appCaller, callerErr := s.appCaller(state)
			if callerErr != nil {
				return nil, callerErr
			}
			membership, memberErr := s.opts.App.AddApplicationMember(grantCtx, appCaller,
				app.AddMemberRequest{ApplicationID: state.appID, UserID: created.ID})
			if memberErr != nil {
				// 账户已创建但成员关系失败：不回滚全局账户（删除账户是更高风险操作），
				// 返回失败并写托管失败审计；调用方需人工核对。
				s.logger.Warn("托管创建账户后建立成员关系失败",
					"application_id", state.appID, "error_category", "membership_failed")
				return nil, memberErr
			}
			view := ProjectMember(state.policy, membership, &created)
			if denyErr := s.opts.Audit.Record(grantCtx, audit.Event{
				Actor: state.actor, AppID: state.appID, Action: "managed_api.users.create_with_membership.created",
				Target:    audit.Target{Type: ObjectUser, ID: created.ID},
				RequestID: request.RequestID, Outcome: audit.OutcomeSuccess,
			}); denyErr != nil {
				s.logger.Warn("托管创建账户审计写入失败", "error_category", "audit_unavailable")
			}
			return view, nil
		})
	if err != nil {
		return MemberView{}, err
	}
	return value.(MemberView), nil
}

// ListGroups 分页列出本应用用户组。
func (s *Service) ListGroups(ctx context.Context, principal Principal,
	request ListGroupsRequest) (ListResult, error) {
	ctx = normalizeContext(ctx)
	value, err := s.execute(ctx, principal, request.Meta, OpGroupsList, ObjectGroup, "",
		func(grantCtx context.Context, state resolved) (any, error) {
			limit, offset, pageErr := clampLimitOffset(state.policy, request.Limit, request.Offset)
			if pageErr != nil {
				return nil, pageErr
			}
			caller, callerErr := s.groupCaller(state)
			if callerErr != nil {
				return nil, callerErr
			}
			result, listErr := s.opts.Group.ListGroups(grantCtx, caller,
				group.ListRequest{ScopeID: state.appID, Limit: limit, Offset: offset})
			if listErr != nil {
				return nil, listErr
			}
			filter, filterErr := s.objectFilter(state, ObjectGroup)
			if filterErr != nil {
				return nil, filterErr
			}
			views := make([]View, 0, len(result.Groups))
			for _, record := range result.Groups {
				if !filter(record.ID) {
					continue
				}
				views = append(views, ProjectGroup(state.policy, record))
			}
			return ListResult{Items: views, HasMore: result.HasMore}, nil
		})
	if err != nil {
		return ListResult{}, err
	}
	return value.(ListResult), nil
}

// GetGroup 读取用户组。
func (s *Service) GetGroup(ctx context.Context, principal Principal,
	request GetGroupRequest) (View, error) {
	ctx = normalizeContext(ctx)
	value, err := s.execute(ctx, principal, request.Meta, OpGroupsGet, ObjectGroup, request.GroupID,
		func(grantCtx context.Context, state resolved) (any, error) {
			if objectErr := s.requireObject(state, ObjectGroup, request.GroupID); objectErr != nil {
				return nil, objectErr
			}
			caller, callerErr := s.groupCaller(state)
			if callerErr != nil {
				return nil, callerErr
			}
			record, getErr := s.opts.Group.GetGroup(grantCtx, caller, request.GroupID)
			if getErr != nil {
				return nil, getErr
			}
			return ProjectGroup(state.policy, record), nil
		})
	if err != nil {
		return View{}, err
	}
	return value.(View), nil
}

// ListGroupMembers 分页列出组成员。
func (s *Service) ListGroupMembers(ctx context.Context, principal Principal,
	request ListGroupMembersRequest) (ListResult, error) {
	ctx = normalizeContext(ctx)
	value, err := s.execute(ctx, principal, request.Meta, OpGroupMembersList, ObjectGroup,
		request.GroupID, func(grantCtx context.Context, state resolved) (any, error) {
			if objectErr := s.requireObject(state, ObjectGroup, request.GroupID); objectErr != nil {
				return nil, objectErr
			}
			limit, offset, pageErr := clampLimitOffset(state.policy, request.Limit, request.Offset)
			if pageErr != nil {
				return nil, pageErr
			}
			caller, callerErr := s.groupCaller(state)
			if callerErr != nil {
				return nil, callerErr
			}
			result, listErr := s.opts.Group.ListMembers(grantCtx, caller,
				group.MemberListRequest{GroupID: request.GroupID, Limit: limit, Offset: offset})
			if listErr != nil {
				return nil, listErr
			}
			filter, filterErr := s.objectFilter(state, ObjectUser)
			if filterErr != nil {
				return nil, filterErr
			}
			views := make([]View, 0, len(result.Members))
			for _, member := range result.Members {
				if !filter(member.UserID) {
					continue
				}
				views = append(views, View{ID: member.UserID, Fields: map[string]any{
					"user_id": member.UserID, "created_at": member.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00")}})
			}
			return ListResult{Items: views, HasMore: result.HasMore}, nil
		})
	if err != nil {
		return ListResult{}, err
	}
	return value.(ListResult), nil
}

// UpdateGroupMembers 批量加入/移除组成员（原子，受 max_batch 限制）。
func (s *Service) UpdateGroupMembers(ctx context.Context, principal Principal,
	request GroupMembersRequest, add bool) error {
	ctx = normalizeContext(ctx)
	opID := OpGroupMembersRemove
	if add {
		opID = OpGroupMembersAdd
	}
	_, err := s.execute(ctx, principal, request.Meta, opID, ObjectGroup, request.GroupID,
		func(grantCtx context.Context, state resolved) (any, error) {
			if objectErr := s.requireObject(state, ObjectGroup, request.GroupID); objectErr != nil {
				return nil, objectErr
			}
			if len(request.UserIDs) == 0 || len(request.UserIDs) > state.policy.Limits.MaxBatch {
				return nil, fmt.Errorf("%w: 批量成员数量超过上限", ErrInvalidRequest)
			}
			for _, userID := range request.UserIDs {
				if !account.ValidUserID(userID) {
					return nil, fmt.Errorf("%w: 用户 ID 格式无效", ErrInvalidRequest)
				}
				if objectErr := s.requireObject(state, ObjectUser, userID); objectErr != nil {
					return nil, objectErr
				}
			}
			caller, callerErr := s.groupCaller(state)
			if callerErr != nil {
				return nil, callerErr
			}
			batch := group.MemberBatchRequest{GroupID: request.GroupID, UserIDs: request.UserIDs}
			if add {
				_, batchErr := s.opts.Group.AddMembers(grantCtx, caller, batch)
				return nil, batchErr
			}
			_, batchErr := s.opts.Group.RemoveMembers(grantCtx, caller, batch)
			return nil, batchErr
		})
	return err
}

// ListRoles 分页列出本应用角色。
func (s *Service) ListRoles(ctx context.Context, principal Principal,
	request ListRolesRequest) (ListResult, error) {
	ctx = normalizeContext(ctx)
	value, err := s.execute(ctx, principal, request.Meta, OpRolesList, ObjectRole, "",
		func(grantCtx context.Context, state resolved) (any, error) {
			limit, offset, pageErr := clampLimitOffset(state.policy, request.Limit, request.Offset)
			if pageErr != nil {
				return nil, pageErr
			}
			caller, callerErr := s.roleCaller(state)
			if callerErr != nil {
				return nil, callerErr
			}
			result, listErr := s.opts.Role.ListRoles(grantCtx, caller,
				role.ListRequest{ScopeID: state.appID, Limit: limit, Offset: offset})
			if listErr != nil {
				return nil, listErr
			}
			filter, filterErr := s.objectFilter(state, ObjectRole)
			if filterErr != nil {
				return nil, filterErr
			}
			views := make([]View, 0, len(result.Roles))
			for _, record := range result.Roles {
				if !filter(record.ID) {
					continue
				}
				views = append(views, ProjectRole(state.policy, record))
			}
			return ListResult{Items: views, HasMore: result.HasMore}, nil
		})
	if err != nil {
		return ListResult{}, err
	}
	return value.(ListResult), nil
}

// GetRole 读取角色。
func (s *Service) GetRole(ctx context.Context, principal Principal,
	request GetRoleRequest) (View, error) {
	ctx = normalizeContext(ctx)
	value, err := s.execute(ctx, principal, request.Meta, OpRolesGet, ObjectRole, request.RoleID,
		func(grantCtx context.Context, state resolved) (any, error) {
			if objectErr := s.requireObject(state, ObjectRole, request.RoleID); objectErr != nil {
				return nil, objectErr
			}
			caller, callerErr := s.roleCaller(state)
			if callerErr != nil {
				return nil, callerErr
			}
			record, getErr := s.opts.Role.GetRole(grantCtx, caller, request.RoleID)
			if getErr != nil {
				return nil, getErr
			}
			return ProjectRole(state.policy, record), nil
		})
	if err != nil {
		return View{}, err
	}
	return value.(View), nil
}

// ListRolePermissions 列出角色权限组合。
func (s *Service) ListRolePermissions(ctx context.Context, principal Principal,
	request ListRoleSubresourceRequest) ([]View, error) {
	ctx = normalizeContext(ctx)
	value, err := s.execute(ctx, principal, request.Meta, OpRolePermissionsList, ObjectRole,
		request.RoleID, func(grantCtx context.Context, state resolved) (any, error) {
			if objectErr := s.requireObject(state, ObjectRole, request.RoleID); objectErr != nil {
				return nil, objectErr
			}
			caller, callerErr := s.roleCaller(state)
			if callerErr != nil {
				return nil, callerErr
			}
			items, listErr := s.opts.Role.ListRolePermissions(grantCtx, caller, request.RoleID)
			if listErr != nil {
				return nil, listErr
			}
			filter, filterErr := s.objectFilter(state, ObjectPermission)
			if filterErr != nil {
				return nil, filterErr
			}
			views := make([]View, 0, len(items))
			for _, item := range items {
				if !filter(item.PermissionID) {
					continue
				}
				views = append(views, View{ID: item.PermissionID, Fields: map[string]any{
					"permission_id": item.PermissionID, "key": item.Key, "enabled": item.Enabled}})
			}
			return views, nil
		})
	if err != nil {
		return nil, err
	}
	return value.([]View), nil
}

// ListRoleAssignments 列出角色分配。
func (s *Service) ListRoleAssignments(ctx context.Context, principal Principal,
	request ListRoleSubresourceRequest) (map[string]any, error) {
	ctx = normalizeContext(ctx)
	value, err := s.execute(ctx, principal, request.Meta, OpRoleAssignmentsList, ObjectRole,
		request.RoleID, func(grantCtx context.Context, state resolved) (any, error) {
			if objectErr := s.requireObject(state, ObjectRole, request.RoleID); objectErr != nil {
				return nil, objectErr
			}
			caller, callerErr := s.roleCaller(state)
			if callerErr != nil {
				return nil, callerErr
			}
			assignments, listErr := s.opts.Role.ListRoleAssignments(grantCtx, caller, request.RoleID)
			if listErr != nil {
				return nil, listErr
			}
			userFilter, filterErr := s.objectFilter(state, ObjectUser)
			if filterErr != nil {
				return nil, filterErr
			}
			groupFilter, filterErr := s.objectFilter(state, ObjectGroup)
			if filterErr != nil {
				return nil, filterErr
			}
			users := make([]string, 0, len(assignments.Users))
			for _, assignment := range assignments.Users {
				if userFilter(assignment.UserID) {
					users = append(users, assignment.UserID)
				}
			}
			groups := make([]string, 0, len(assignments.Groups))
			for _, assignment := range assignments.Groups {
				if groupFilter(assignment.GroupID) {
					groups = append(groups, assignment.GroupID)
				}
			}
			return map[string]any{"users": users, "groups": groups}, nil
		})
	if err != nil {
		return nil, err
	}
	return value.(map[string]any), nil
}

// AssignUserRole/RevokeUserRole：经既有角色服务（真实用户 Caller 保留 delegation
// Guard）；服务身份在目录中被禁止。
func (s *Service) AssignUserRole(ctx context.Context, principal Principal,
	request RoleTargetRequest, assign bool) error {
	ctx = normalizeContext(ctx)
	opID := OpRoleRevokeUser
	if assign {
		opID = OpRoleAssignUser
	}
	_, err := s.execute(ctx, principal, request.Meta, opID, ObjectRole, request.RoleID,
		func(grantCtx context.Context, state resolved) (any, error) {
			if objectErr := s.requireObject(state, ObjectRole, request.RoleID); objectErr != nil {
				return nil, objectErr
			}
			if objectErr := s.requireObject(state, ObjectUser, request.UserID); objectErr != nil {
				return nil, objectErr
			}
			caller, callerErr := s.roleCaller(state)
			if callerErr != nil {
				return nil, callerErr
			}
			if assign {
				if _, assignErr := s.opts.Role.AssignUserRole(grantCtx, caller, request.RoleID, request.UserID); assignErr != nil {
					return nil, assignErr
				}
				return nil, nil
			}
			if _, revokeErr := s.opts.Role.RevokeUserRole(grantCtx, caller, request.RoleID, request.UserID); revokeErr != nil {
				return nil, revokeErr
			}
			return nil, nil
		})
	return err
}

// AssignGroupRole/RevokeGroupRole。
func (s *Service) AssignGroupRole(ctx context.Context, principal Principal,
	request RoleGroupTargetRequest, assign bool) error {
	ctx = normalizeContext(ctx)
	opID := OpRoleRevokeGroup
	if assign {
		opID = OpRoleAssignGroup
	}
	_, err := s.execute(ctx, principal, request.Meta, opID, ObjectRole, request.RoleID,
		func(grantCtx context.Context, state resolved) (any, error) {
			if objectErr := s.requireObject(state, ObjectRole, request.RoleID); objectErr != nil {
				return nil, objectErr
			}
			if objectErr := s.requireObject(state, ObjectGroup, request.GroupID); objectErr != nil {
				return nil, objectErr
			}
			caller, callerErr := s.roleCaller(state)
			if callerErr != nil {
				return nil, callerErr
			}
			if assign {
				if _, assignErr := s.opts.Role.AssignGroupRole(grantCtx, caller, request.RoleID, request.GroupID); assignErr != nil {
					return nil, assignErr
				}
				return nil, nil
			}
			if _, revokeErr := s.opts.Role.RevokeGroupRole(grantCtx, caller, request.RoleID, request.GroupID); revokeErr != nil {
				return nil, revokeErr
			}
			return nil, nil
		})
	return err
}

// ListPermissions 分页列出本应用自定义权限。
func (s *Service) ListPermissions(ctx context.Context, principal Principal,
	request ListPermissionsRequest) (ListResult, error) {
	ctx = normalizeContext(ctx)
	value, err := s.execute(ctx, principal, request.Meta, OpPermissionsList, ObjectPermission, "",
		func(grantCtx context.Context, state resolved) (any, error) {
			limit, offset, pageErr := clampLimitOffset(state.policy, request.Limit, request.Offset)
			if pageErr != nil {
				return nil, pageErr
			}
			caller, callerErr := s.permissionCaller(state)
			if callerErr != nil {
				return nil, callerErr
			}
			result, listErr := s.opts.Permission.ListPermissions(grantCtx, caller,
				permission.ListRequest{ScopeID: state.appID, Limit: limit, Offset: offset})
			if listErr != nil {
				return nil, listErr
			}
			filter, filterErr := s.objectFilter(state, ObjectPermission)
			if filterErr != nil {
				return nil, filterErr
			}
			views := make([]View, 0, len(result.Permissions))
			for _, record := range result.Permissions {
				if !filter(record.ID) {
					continue
				}
				views = append(views, ProjectPermission(state.policy, record))
			}
			return ListResult{Items: views, HasMore: result.HasMore}, nil
		})
	if err != nil {
		return ListResult{}, err
	}
	return value.(ListResult), nil
}

// GetPermission 读取本应用自定义权限。
func (s *Service) GetPermission(ctx context.Context, principal Principal,
	request GetPermissionRequest) (View, error) {
	ctx = normalizeContext(ctx)
	value, err := s.execute(ctx, principal, request.Meta, OpPermissionsGet,
		ObjectPermission, request.PermissionID,
		func(grantCtx context.Context, state resolved) (any, error) {
			if objectErr := s.requireObject(state, ObjectPermission, request.PermissionID); objectErr != nil {
				return nil, objectErr
			}
			caller, callerErr := s.permissionCaller(state)
			if callerErr != nil {
				return nil, callerErr
			}
			record, getErr := s.opts.Permission.GetPermission(grantCtx, caller, request.PermissionID)
			if getErr != nil {
				return nil, getErr
			}
			return ProjectPermission(state.policy, record), nil
		})
	if err != nil {
		return View{}, err
	}
	return View(value.(View)), nil
}
