package managedapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	"github.com/kagurazakayashi/EvernightLogin/internal/group"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
	"github.com/kagurazakayashi/EvernightLogin/internal/permission"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// AuditRecorder 是安全审计写入契约；生产实现为 *internal/audit.Recorder。
type AuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
	RecordFailure(ctx context.Context, event audit.Event) error
	ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error
}

// PolicyAuthorizer 判定操作者能否读取/修改托管管理 API 委托策略（受信配置通道）。
type PolicyAuthorizer interface {
	AuthorizePolicy(ctx context.Context, actor audit.Actor, requestID string) error
}

// TrustedPolicyAuthorizer 是显式白名单策略配置授权器：只允许列出的本地管理员与
// 系统组件；普通用户/应用身份一律拒绝。它是受信配置通道，不是业务授权模型。
type TrustedPolicyAuthorizer struct {
	localAdmins map[string]struct{}
	systems     map[string]struct{}
}

// NewTrustedPolicyAuthorizer 构造受信策略授权器；列表不能同时为空。
func NewTrustedPolicyAuthorizer(localAdminIDs, systemIDs []string) (*TrustedPolicyAuthorizer, error) {
	if len(localAdminIDs) == 0 && len(systemIDs) == 0 {
		return nil, fmt.Errorf("%w: 至少需要一个本地管理员或系统组件", ErrOptionsInvalid)
	}
	authorizer := &TrustedPolicyAuthorizer{
		localAdmins: make(map[string]struct{}, len(localAdminIDs)),
		systems:     make(map[string]struct{}, len(systemIDs)),
	}
	for _, id := range localAdminIDs {
		if err := (audit.Actor{Type: audit.ActorLocalAdmin, ID: id}).Validate(); err != nil {
			return nil, fmt.Errorf("%w: 本地管理员标识无效", ErrOptionsInvalid)
		}
		authorizer.localAdmins[id] = struct{}{}
	}
	for _, id := range systemIDs {
		if err := (audit.Actor{Type: audit.ActorSystem, ID: id}).Validate(); err != nil {
			return nil, fmt.Errorf("%w: 系统组件标识无效", ErrOptionsInvalid)
		}
		authorizer.systems[id] = struct{}{}
	}
	return authorizer, nil
}

// AuthorizePolicy 实现 PolicyAuthorizer。
func (a *TrustedPolicyAuthorizer) AuthorizePolicy(_ context.Context, actor audit.Actor,
	_ string) error {
	if a == nil {
		return ErrAccessDenied
	}
	switch actor.Type {
	case audit.ActorLocalAdmin:
		if _, ok := a.localAdmins[actor.ID]; ok {
			return nil
		}
	case audit.ActorSystem:
		if _, ok := a.systems[actor.ID]; ok {
			return nil
		}
	}
	return ErrAccessDenied
}

// Options 是托管管理 API 的显式依赖；任一必需依赖缺失（含 typed-nil）拒绝构造。
type Options struct {
	Store      Store
	Audit      AuditRecorder
	Authz      *authz.Service
	Sessions   *session.Service
	Clients    *oauthclient.Service
	Account    *account.Service
	App        *app.Service
	Role       *role.Service
	Group      *group.Service
	Permission *permission.Service
	// PolicyAuthorizer 是策略配置/读取的受信通道授权器；必填。
	PolicyAuthorizer PolicyAuthorizer
	// Reauth 是步骤 39 敏感操作收敛入口；策略变更必须通过（未接线拒绝变更）。
	Reauth reauth.OperationRunner
	Now    func() time.Time
	Random io.Reader
	Logger *slog.Logger
}

// Service 是托管管理 API；构造后不可变、可并发使用，不启动协程、不注册 HTTP。
type Service struct {
	opts   Options
	now    func() time.Time
	logger *slog.Logger
}

// New 校验依赖并构造服务。
func New(options Options) (*Service, error) {
	for name, dependency := range map[string]any{
		"存储": options.Store, "审计": options.Audit, "权限引擎": options.Authz,
		"会话服务": options.Sessions, "客户端认证": options.Clients,
		"账户服务": options.Account, "应用服务": options.App, "角色服务": options.Role,
		"用户组服务": options.Group, "权限服务": options.Permission,
		"策略配置授权器":   options.PolicyAuthorizer,
		"策略再次认证执行器": options.Reauth,
	} {
		if isNilInterface(dependency) {
			return nil, fmt.Errorf("%w: %s为空", ErrOptionsInvalid, name)
		}
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
	}
	return &Service{opts: options, now: now, logger: logger}, nil
}

// Meta 请求元数据（已在校验时使用）在 managedapi.go 定义。

// PolicyView 是策略查询结果。
type PolicyView struct {
	ApplicationID string `json:"application_id"`
	Policy        Policy `json:"policy"`
	RowVersion    int64  `json:"row_version"`
	UpdatedBy     string `json:"updated_by"`
}

// SetPolicyRequest 是受信通道写入策略的请求。
type SetPolicyRequest struct {
	ApplicationID      string
	Policy             Policy
	ExpectedRowVersion int64
	RequestID          string
	// ReauthBinding 是可选的页面一次性批准摘要（应用/行版本/规范化策略摘要）。
	// 非空时随再次认证参数传入，宿主可用它拒绝“确认后替换策略”的重放。
	ReauthBinding string
}

// GetPolicy 读取应用策略（受信配置通道）。
func (s *Service) GetPolicy(ctx context.Context, actor audit.Actor, applicationID, requestID string) (PolicyView, error) {
	ctx = normalizeContext(ctx)
	if err := actor.Validate(); err != nil {
		return PolicyView{}, fmt.Errorf("%w: 操作者标识无效", ErrInvalidRequest)
	}
	if err := s.opts.PolicyAuthorizer.AuthorizePolicy(ctx, actor, requestID); err != nil {
		return PolicyView{}, fmt.Errorf("%w: %w", ErrAccessDenied, err)
	}
	if !app.ValidApplicationID(applicationID) {
		return PolicyView{}, fmt.Errorf("%w: 应用 ID 格式无效", ErrInvalidRequest)
	}
	record, found, err := s.opts.Store.GetPolicy(ctx, applicationID)
	if err != nil {
		return PolicyView{}, err
	}
	if !found {
		return PolicyView{}, fmt.Errorf("%w: 策略不存在", ErrPolicyDisabled)
	}
	return PolicyView{ApplicationID: record.ApplicationID, Policy: record.Policy,
		RowVersion: record.RowVersion, UpdatedBy: record.UpdatedBy}, nil
}

// ListPolicies 分页列出策略（受信配置通道）。
func (s *Service) ListPolicies(ctx context.Context, actor audit.Actor, requestID string,
	limit, offset int) ([]PolicyView, bool, error) {
	ctx = normalizeContext(ctx)
	if err := actor.Validate(); err != nil {
		return nil, false, fmt.Errorf("%w: 操作者标识无效", ErrInvalidRequest)
	}
	if err := s.opts.PolicyAuthorizer.AuthorizePolicy(ctx, actor, requestID); err != nil {
		return nil, false, fmt.Errorf("%w: %w", ErrAccessDenied, err)
	}
	if limit <= 0 || limit > MaxPolicyLimit {
		limit = DefaultPolicyLimit
	}
	if offset < 0 || offset > MaxPolicyOffset {
		return nil, false, fmt.Errorf("%w: 分页偏移无效", ErrInvalidRequest)
	}
	records, hasMore, err := s.opts.Store.ListPolicies(ctx, limit, offset)
	if err != nil {
		return nil, false, err
	}
	views := make([]PolicyView, 0, len(records))
	for _, record := range records {
		views = append(views, PolicyView{ApplicationID: record.ApplicationID,
			Policy: record.Policy, RowVersion: record.RowVersion, UpdatedBy: record.UpdatedBy})
	}
	return views, hasMore, nil
}

// SetPolicy 写入应用委托策略：受信通道 + 敏感操作近期认证 + 行版本条件更新 +
// 同事务审计；策略结构与字段/上限由 Validate 严格校验。
func (s *Service) SetPolicy(ctx context.Context, actor audit.Actor,
	request SetPolicyRequest) (PolicyView, error) {
	ctx = normalizeContext(ctx)
	if err := actor.Validate(); err != nil {
		return PolicyView{}, fmt.Errorf("%w: 操作者标识无效", ErrInvalidRequest)
	}
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		return PolicyView{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if err := s.opts.PolicyAuthorizer.AuthorizePolicy(ctx, actor, request.RequestID); err != nil {
		return PolicyView{}, fmt.Errorf("%w: %w", ErrAccessDenied, err)
	}
	if !app.ValidApplicationID(request.ApplicationID) {
		return PolicyView{}, fmt.Errorf("%w: 应用 ID 格式无效", ErrInvalidRequest)
	}
	if request.ExpectedRowVersion < 0 {
		return PolicyView{}, fmt.Errorf("%w: 行版本无效", ErrInvalidRequest)
	}
	if err := request.Policy.Validate(); err != nil {
		return PolicyView{}, err
	}
	status, found, err := s.opts.Store.ApplicationStatus(ctx, request.ApplicationID)
	if err != nil {
		return PolicyView{}, err
	}
	if !found {
		return PolicyView{}, fmt.Errorf("%w: 应用不存在", ErrInvalidRequest)
	}
	if status != "active" {
		return PolicyView{}, fmt.Errorf("%w: 应用已停用", ErrPolicyDisabled)
	}
	if isNilInterface(s.opts.Reauth) {
		return PolicyView{}, fmt.Errorf("%w: 策略变更需要再次验证（未接线）", ErrAccessDenied)
	}
	caller, err := reauthUserCaller(actor)
	if err != nil {
		return PolicyView{}, ErrAccessDenied
	}
	params := map[string]string{
		"application_id":       request.ApplicationID,
		"expected_row_version": fmt.Sprint(request.ExpectedRowVersion),
	}
	if request.ReauthBinding != "" {
		params["reauth_binding"] = request.ReauthBinding
	}
	if _, err := s.opts.Reauth.Authorize(ctx, caller, reauth.Request{
		ScopeID: "system", OperationID: "managed_api.policy.manage",
		TargetType: "application", TargetID: request.ApplicationID,
		Params:      params,
		Description: "修改应用托管管理 API 委托策略", RequestID: request.RequestID,
	}); err != nil {
		return PolicyView{}, fmt.Errorf("%w: %w", ErrAccessDenied, err)
	}
	now := s.now()
	record := PolicyRecord{ApplicationID: request.ApplicationID, Policy: request.Policy,
		UpdatedBy: actor.ID, CreatedAt: now, UpdatedAt: now}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: actor, Action: "managed_api.policy.updated",
			AppID:     request.ApplicationID,
			Target:    audit.Target{Type: "app_managed_api_policy", ID: request.ApplicationID},
			RequestID: request.RequestID,
			Changes: []audit.FieldChange{
				{Field: "row_version", Before: fmt.Sprint(request.ExpectedRowVersion)},
				{Field: "operations", After: fmt.Sprint(len(request.Policy.Operations.Allowed))},
			},
		},
		FailureReasonCode:   "managed_api.policy_update_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(err)) },
	}
	written := false
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		ok, writeErr := s.opts.Store.SetPolicyTx(txCtx, tx, record, request.ExpectedRowVersion)
		if writeErr != nil {
			return writeErr
		}
		if !ok {
			return ErrVersionConflict
		}
		written = ok
		return nil
	}); err != nil {
		if errors.Is(err, ErrVersionConflict) {
			return PolicyView{}, ErrVersionConflict
		}
		if errors.Is(err, ErrAuditUnavailable) || errors.Is(err, audit.ErrAuditUnavailable) {
			return PolicyView{}, ErrAuditUnavailable
		}
		return PolicyView{}, ErrStoreUnavailable
	}
	if !written {
		return PolicyView{}, ErrVersionConflict
	}
	rowVersion := request.ExpectedRowVersion + 1
	if request.ExpectedRowVersion == 0 {
		rowVersion = 1
	}
	return PolicyView{ApplicationID: request.ApplicationID, Policy: request.Policy,
		RowVersion: rowVersion, UpdatedBy: actor.ID}, nil
}

// resolved 是一次托管请求已解析的主体、策略与授权范围。
type resolved struct {
	actor    audit.Actor
	kind     PrincipalKind
	appID    string
	userID   string
	clientID string
	policy   Policy
	// scopeAll 表示数据范围不受显式 resources 限制；scopeResources 是交集白名单。
	scopeAll       bool
	scopeResources map[string]struct{}
}

// dataScope 表示代表用户的有效数据范围交集（undefined/none 已被拒绝，不会出现）。
type dataScope struct {
	all       bool
	resources map[string]struct{}
}

// prepare 完成元数据/主体/策略/操作/权限校验，返回携带 grant 的上下文。
func (s *Service) prepare(ctx context.Context, principal Principal, meta Meta,
	opID string) (resolved, context.Context, error) {
	ctx = normalizeContext(ctx)
	if err := validateMeta(meta); err != nil {
		return resolved{}, nil, err
	}
	operation, ok := LookupOperation(opID)
	if !ok {
		return resolved{}, nil, fmt.Errorf("%w: 未知操作", ErrInvalidRequest)
	}
	state, err := s.resolvePrincipal(ctx, principal)
	if err != nil {
		return resolved{}, nil, err
	}
	record, found, err := s.opts.Store.GetPolicy(ctx, state.appID)
	if err != nil {
		return state, nil, err
	}
	if !found {
		return state, nil, ErrPolicyDisabled
	}
	if !record.Policy.OperationAllowed(opID) {
		return state, nil, fmt.Errorf("%w: 操作未在委托策略中允许", ErrAccessDenied)
	}
	state.policy = record.Policy
	if state.kind == PrincipalService {
		if !operation.ServiceAllowed || !record.Policy.ServiceOperationAllowed(opID) {
			return state, nil, fmt.Errorf("%w: 服务身份不允许该操作", ErrAccessDenied)
		}
		scope, scopeErr := operationScope(record.Policy, operation.ObjectType)
		if scopeErr != nil {
			return state, nil, scopeErr
		}
		state.scopeAll = scope.all
		state.scopeResources = scope.resources
	} else {
		scope, scopeErr := s.effectiveDataScope(ctx, state.userID, state.appID, operation)
		if scopeErr != nil {
			return state, nil, scopeErr
		}
		state.scopeAll = scope.all
		state.scopeResources = scope.resources
	}
	grantCtx := WithGrant(ctx, Grant{Actor: state.actor, AppID: state.appID,
		OperationID: opID, Policy: state.policy, RequestID: meta.RequestID,
		Service: state.kind == PrincipalService})
	return state, grantCtx, nil
}

// resolvePrincipal 解析可信主体（会话/客户端认证）并确定目标应用。
func (s *Service) resolvePrincipal(ctx context.Context, principal Principal) (resolved, error) {
	switch principal.kind {
	case PrincipalUser:
		userSession, err := s.opts.Sessions.Validate(ctx, principal.sessionSecret)
		if err != nil || !userSession.IsNormal() || userSession.UserID == "" {
			return resolved{}, fmt.Errorf("%w: 用户会话无效", ErrAccessDenied)
		}
		appID := principal.appID
		if appID == "" {
			appID = userSession.AppID
		}
		if appID == "" || !app.ValidApplicationID(appID) {
			return resolved{}, fmt.Errorf("%w: 缺少可信目标应用", ErrInvalidRequest)
		}
		if userSession.AppID != "" && userSession.AppID != appID {
			return resolved{}, fmt.Errorf("%w: 会话应用与目标应用不一致", ErrObjectForbidden)
		}
		return resolved{actor: audit.Actor{Type: audit.ActorUser, ID: userSession.UserID},
			kind: PrincipalUser, appID: appID, userID: userSession.UserID}, nil
	case PrincipalService:
		if !app.ValidApplicationID(principal.clientID) {
			return resolved{}, fmt.Errorf("%w: 客户端标识无效", ErrInvalidRequest)
		}
		var identity oauthclient.ClientIdentity
		var authErr error
		if principal.clientSecret != "" {
			identity, authErr = s.opts.Clients.VerifyClientSecret(ctx, principal.clientID,
				principal.clientSecret)
		} else if principal.certificate != "" {
			identity, authErr = s.opts.Clients.VerifyClientCertificate(ctx, principal.clientID,
				principal.certificate)
		} else {
			return resolved{}, fmt.Errorf("%w: 缺少服务身份凭证", ErrAccessDenied)
		}
		if authErr != nil || identity.ClientID != principal.clientID {
			return resolved{}, fmt.Errorf("%w: 服务身份认证失败", ErrAccessDenied)
		}
		actorID := "managed-service:" + principal.clientID
		if err := (audit.Actor{Type: audit.ActorSystem, ID: actorID}).Validate(); err != nil {
			return resolved{}, fmt.Errorf("%w: 服务审计标识无效", ErrOptionsInvalid)
		}
		return resolved{actor: audit.Actor{Type: audit.ActorSystem, ID: actorID},
			kind: PrincipalService, appID: principal.clientID,
			clientID: principal.clientID}, nil
	default:
		return resolved{}, fmt.Errorf("%w: 调用主体类别未知", ErrAccessDenied)
	}
}

// effectiveDataScope 用 internal/authz 计算代表用户的当前权限与数据范围交集；
// undefined/none 一律 fail-closed（与 authz/delegation 语义一致）。
func (s *Service) effectiveDataScope(ctx context.Context, userID, appID string,
	operation Operation) (dataScope, error) {
	if len(operation.Permissions) == 0 {
		// 无需业务权限的操作（应用自述信息）的数据范围不受权限限制；但调用方必须
		// 是目标应用的成员——该成员校验在具体操作（GetApplication）中通过既有应用
		// 服务显式完成，不能仅凭宿主提供的应用 ID 读取。
		return dataScope{all: true}, nil
	}
	caller, err := authz.UserCaller(userID)
	if err != nil {
		return dataScope{}, ErrAccessDenied
	}
	result, err := s.opts.Authz.Check(ctx, caller, authz.CheckRequest{
		SubjectUserID: userID, ScopeID: appID,
		Permissions: operation.Permissions, Mode: authz.ModeAll,
	})
	if err != nil {
		return dataScope{}, fmt.Errorf("%w: 权限判定不可用", ErrStoreUnavailable)
	}
	if !result.Allowed {
		return dataScope{}, mapAuthzDenial(result)
	}
	scope := dataScope{all: true}
	for _, decision := range result.Permissions {
		if !decision.Allowed {
			return dataScope{}, fmt.Errorf("%w: 权限未满足", ErrAccessDenied)
		}
		switch decision.DataScope.Mode {
		case authz.DataScopeAll:
			continue
		case authz.DataScopeResources:
			scope = intersectResourceScope(scope, decision.DataScope.Resources)
		default:
			// undefined/none：不声明数据范围视为不可判定 → fail-closed。
			return dataScope{}, fmt.Errorf("%w: 数据范围未声明或为空", ErrObjectForbidden)
		}
	}
	return scope, nil
}

// intersectResourceScope 与新的 resources 白名单取交集。
func intersectResourceScope(current dataScope, resources []string) dataScope {
	next := make(map[string]struct{}, len(resources))
	for _, resource := range resources {
		next[resource] = struct{}{}
	}
	if current.all {
		return dataScope{resources: next}
	}
	intersection := make(map[string]struct{}, len(current.resources))
	for resource := range current.resources {
		if _, ok := next[resource]; ok {
			intersection[resource] = struct{}{}
		}
	}
	return dataScope{resources: intersection}
}

// operationScope 把策略对象范围转为服务身份的数据范围。
func operationScope(policy Policy, objectType string) (dataScope, error) {
	scope, ok := policy.ObjectScopeOf(objectType)
	if !ok {
		return dataScope{}, fmt.Errorf("%w: 对象类型未在委托策略中声明", ErrObjectForbidden)
	}
	switch scope.Mode {
	case ScopeModeAll:
		return dataScope{all: true}, nil
	case ScopeModeResources:
		resources := make(map[string]struct{}, len(scope.Resources))
		for _, resource := range scope.Resources {
			resources[resource] = struct{}{}
		}
		return dataScope{resources: resources}, nil
	default:
		return dataScope{}, fmt.Errorf("%w: 对象范围模式非法", ErrObjectForbidden)
	}
}

// mapAuthzDenial 把 authz 拒绝结果映射为托管错误。
func mapAuthzDenial(result authz.CheckResult) error {
	switch result.Code {
	case authz.CodeUserDisabled:
		return &ServiceError{Code: CodeUserDisabled, Reason: "user_disabled"}
	case authz.CodeAppMembershipRequired:
		return &ServiceError{Code: CodeAppMembershipRequired, Reason: "membership_required"}
	case authz.CodeClientDisabled:
		return &ServiceError{Code: CodeClientDisabled, Reason: "client_disabled"}
	case authz.CodePermissionRequired:
		return &ServiceError{Code: CodePermissionRequired, Reason: "permission_required"}
	case authz.CodePermissionDisabled:
		return &ServiceError{Code: CodePermissionRequired, Reason: "permission_disabled"}
	case authz.CodePermissionUnknown:
		return &ServiceError{Code: CodeReqInvalid, Reason: "permission_unknown"}
	case authz.CodeAppScopeMismatch:
		return &ServiceError{Code: CodeAppScopeMismatch, Reason: "app_scope_mismatch"}
	case authz.CodeResourceForbidden:
		return &ServiceError{Code: CodeResourceForbidden, Reason: "resource_forbidden"}
	case authz.CodeAuthzUnavailable, authz.CodeDBUnavailable:
		return fmt.Errorf("%w: 权限服务不可用", ErrStoreUnavailable)
	default:
		return &ServiceError{Code: CodeAccessDenied, Reason: "access_denied"}
	}
}

// requireObject 校验对象 ID 在策略对象范围与代表用户数据范围内（调服务前）。
func (s *Service) requireObject(state resolved, objectType, objectID string) error {
	if objectID == "" {
		return fmt.Errorf("%w: 目标对象为空", ErrInvalidRequest)
	}
	if !state.policy.ResourceAllowed(objectType, objectID) {
		return fmt.Errorf("%w: 目标对象不在应用委托范围", ErrObjectForbidden)
	}
	if !state.scopeAll {
		if _, ok := state.scopeResources[objectID]; !ok {
			return fmt.Errorf("%w: 目标对象不在数据范围", ErrObjectForbidden)
		}
	}
	return nil
}

// objectFilter 返回列表/子资源读取的对象过滤器：策略对象范围（未声明或未命中
// 一律排除/拒绝）与代表用户数据范围的交集。对象范围未声明时 fail-closed 拒绝，
// 避免"未配置即全部可见"。
func (s *Service) objectFilter(state resolved, objectType string) (func(string) bool, error) {
	scope, ok := state.policy.ObjectScopeOf(objectType)
	if !ok {
		return nil, fmt.Errorf("%w: 对象类型 %q 未在委托策略中声明范围", ErrObjectForbidden, objectType)
	}
	var policyResources map[string]struct{}
	switch scope.Mode {
	case ScopeModeAll:
	case ScopeModeResources:
		policyResources = make(map[string]struct{}, len(scope.Resources))
		for _, resource := range scope.Resources {
			policyResources[resource] = struct{}{}
		}
	default:
		return nil, fmt.Errorf("%w: 对象范围模式非法", ErrObjectForbidden)
	}
	dataResources := state.scopeResources
	return func(id string) bool {
		if policyResources != nil {
			if _, ok := policyResources[id]; !ok {
				return false
			}
		}
		if !state.scopeAll {
			if _, ok := dataResources[id]; !ok {
				return false
			}
		}
		return true
	}, nil
}

// serviceCaller 构造代表用户或服务身份的服务 Caller 所需审计身份。
func (s *Service) actorOf(state resolved) audit.Actor { return state.actor }

// accountCaller 返回账户服务的可信 Caller。
func (s *Service) accountCaller(state resolved) (account.Caller, error) {
	if state.kind == PrincipalService {
		return account.SystemCaller(state.actor.ID)
	}
	return account.UserCaller(state.userID)
}

// appCaller 返回应用服务的可信 Caller。
func (s *Service) appCaller(state resolved) (app.Caller, error) {
	if state.kind == PrincipalService {
		return app.SystemCaller(state.actor.ID)
	}
	return app.UserCaller(state.userID)
}

// roleCaller 返回角色服务的可信 Caller。
func (s *Service) roleCaller(state resolved) (role.Caller, error) {
	if state.kind == PrincipalService {
		return role.SystemCaller(state.actor.ID)
	}
	return role.UserCaller(state.userID)
}

// groupCaller 返回用户组服务的可信 Caller。
func (s *Service) groupCaller(state resolved) (group.Caller, error) {
	if state.kind == PrincipalService {
		return group.SystemCaller(state.actor.ID)
	}
	return group.UserCaller(state.userID)
}

// permissionCaller 返回权限服务的可信 Caller。
func (s *Service) permissionCaller(state resolved) (permission.Caller, error) {
	if state.kind == PrincipalService {
		return permission.SystemCaller(state.actor.ID)
	}
	return permission.UserCaller(state.userID)
}

// recordManagedAudit 写托管调用审计（成功或失败）；失败只记运行日志（业务写入
// 以既有服务审计为准），拒绝路径不影响拒绝结论。
func (s *Service) recordManagedAudit(ctx context.Context, state resolved, meta Meta,
	opID, objectType, objectID, outcome, errorCode, reason string) {
	event := audit.Event{
		Actor: state.actor, AppID: state.appID, Action: "managed_api." + opID,
		Target:    audit.Target{Type: objectType, ID: objectID},
		RequestID: meta.RequestID, Outcome: audit.Outcome(outcome),
		ErrorCode: errorCode, ReasonCode: reason,
	}
	var err error
	if outcome == string(audit.OutcomeFailure) {
		err = s.opts.Audit.RecordFailure(ctx, event)
	} else {
		err = s.opts.Audit.Record(ctx, event)
	}
	if err != nil {
		s.logger.Warn("托管管理 API 审计写入失败", "operation", opID,
			"error_category", "audit_unavailable")
	}
}

// errorCodeOf 计算稳定错误码：优先沿用底层服务映射出的 ServiceError.Code，再按
// 本包哨兵/既有 CodeOf，最后用既有服务的 CodeOf 映射（不再把业务拒绝退化为
// INTERNAL_ERROR）。
func errorCodeOf(err error) ErrorCode {
	var serviceErr *ServiceError
	if errors.As(err, &serviceErr) && serviceErr.Code != "" {
		return serviceErr.Code
	}
	if code := CodeOf(err); code != "" && code != CodeInternalError {
		return code
	}
	if code := serviceErrorCode(err); code != "" && code != CodeInternalError {
		return code
	}
	return CodeInternalError
}

// fail 记录失败审计并返回稳定映射后的错误。
func (s *Service) fail(ctx context.Context, state resolved, meta Meta, opID, objectType,
	objectID string, err error) error {
	code := errorCodeOf(err)
	reason := reasonOf(err)
	s.recordManagedAudit(ctx, state, meta, opID, objectType, objectID,
		string(audit.OutcomeFailure), string(code), reason)
	var serviceErr *ServiceError
	if errors.As(err, &serviceErr) {
		return serviceErr
	}
	return &ServiceError{Code: code, Reason: reason, Cause: err}
}

// success 记录成功审计。
func (s *Service) success(ctx context.Context, state resolved, meta Meta, opID,
	objectType, objectID string) {
	s.recordManagedAudit(ctx, state, meta, opID, objectType, objectID,
		string(audit.OutcomeSuccess), "", "")
}

// reasonOf 返回稳定内部原因码（不含用户输入）。
func reasonOf(err error) string {
	var serviceErr *ServiceError
	if errors.As(err, &serviceErr) && serviceErr.Reason != "" {
		return serviceErr.Reason
	}
	switch {
	case errors.Is(err, ErrObjectForbidden), errors.Is(err, ErrAccessDenied),
		errors.Is(err, ErrPolicyDisabled):
		return "access_denied"
	case errors.Is(err, ErrInvalidRequest):
		return "invalid_request"
	case errors.Is(err, ErrVersionConflict):
		return "version_conflict"
	case errors.Is(err, ErrStoreUnavailable):
		return "store_unavailable"
	case errors.Is(err, ErrAuditUnavailable):
		return "audit_unavailable"
	default:
		return "operation_failed"
	}
}

// isManagedSentinel 报告错误是否为本包哨兵（用于错误映射边界）。
func isManagedSentinel(err error) bool {
	for _, sentinel := range []error{ErrOptionsInvalid, ErrInvalidRequest, ErrAccessDenied,
		ErrPolicyDisabled, ErrObjectForbidden, ErrVersionConflict, ErrStoreUnavailable,
		ErrAuditUnavailable} {
		if errors.Is(err, sentinel) {
			return true
		}
	}
	return false
}

// serviceErrorCode 把底层既有服务错误映射为根包已登记错误码（只复用既有码）。
func serviceErrorCode(err error) ErrorCode {
	if err == nil {
		return ""
	}
	codes := []string{
		string(account.CodeOf(err)), string(app.CodeOf(err)), string(role.CodeOf(err)),
		string(group.CodeOf(err)), string(permission.CodeOf(err)), string(authz.CodeOf(err)),
		string(session.CodeOf(err)),
	}
	for _, code := range codes {
		switch ErrorCode(code) {
		case CodeReqInvalid, CodeAccessDenied, CodePermissionRequired,
			CodeAppMembershipRequired, CodeAppScopeMismatch, CodeUserDisabled,
			CodeClientDisabled, CodeResourceForbidden, CodeConflict, CodeRateLimited,
			CodeDBUnavailable, CodeAuditWriteFailed:
			return ErrorCode(code)
		}
	}
	return CodeInternalError
}

// reauthUserCaller 把受信审计身份转换成再次认证调用者。
func reauthUserCaller(actor audit.Actor) (reauth.Caller, error) {
	switch actor.Type {
	case audit.ActorUser:
		return reauth.UserCaller(actor.ID)
	case audit.ActorSystem:
		return reauth.SystemCaller(actor.ID)
	case audit.ActorLocalAdmin:
		return reauth.LocalAdminCaller(actor.ID)
	default:
		return reauth.Caller{}, ErrAccessDenied
	}
}

// clampLimitOffset 按策略与全局上限校验分页参数。
func clampLimitOffset(policy Policy, limit, offset int) (int, int, error) {
	if limit == 0 {
		limit = DefaultPolicyLimit
		if limit > policy.Limits.MaxLimit {
			limit = policy.Limits.MaxLimit
		}
	}
	if offset == 0 {
		offset = 0
	}
	if limit < 0 || limit > policy.Limits.MaxLimit || limit > MaxPolicyLimit {
		return 0, 0, fmt.Errorf("%w: 分页数量超过上限", ErrInvalidRequest)
	}
	if offset < 0 || offset > policy.Limits.MaxOffset || offset > MaxPolicyOffset {
		return 0, 0, fmt.Errorf("%w: 分页偏移超过上限", ErrInvalidRequest)
	}
	return limit, offset, nil
}

// 编译期断言：DelegatedAuthorizer 实现既有服务的 Authorizer 接口。
var (
	_ account.Authorizer    = (*AccountAuthorizer)(nil)
	_ app.Authorizer        = (*AppAuthorizer)(nil)
	_ role.Authorizer       = (*RoleAuthorizer)(nil)
	_ group.Authorizer      = (*GroupAuthorizer)(nil)
	_ permission.Authorizer = (*PermissionAuthorizer)(nil)
)

// unused import guards（strings/session 在错误映射与 caller 中使用）。
var _ = strings.TrimSpace
