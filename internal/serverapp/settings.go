// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package serverapp

// 步骤 232：管理 HTTP 配置设置路由。复用 adminapi 的会话/CSRF/envelope 与
// internal/settings 的同一核心；每请求重新判定真实 settings.manage，root-only 字段
// 以真实 root/LocalAdmin 判定；敏感策略默认值恢复只接受真实 root 用户并再次认证。
// 未提供 ConfigPath（内联配置）时不注册写/读路由（fail-closed，404）。

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/kagurazakayashi/EvernightLogin/config"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/adminapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/settings"
	"github.com/kagurazakayashi/EvernightLogin/internal/transport"
	"net/http"
	"strings"
	"time"
)

// buildAdminSettingsRoutes 构造设置领域路由；核心服务构造失败或没有可写配置路径时
// 返回 nil，管理 API 不注册这些路径（404）。
func buildAdminSettingsRoutes(deps Deps, managed *ManagedServices,
	gate *SecurityGate) []adminapi.DomainRoute {
	if strings.TrimSpace(deps.ConfigPath) == "" || managed == nil || gate == nil {
		return nil
	}
	service, err := settings.New(settings.Options{
		ConfigPath: deps.ConfigPath,
		Effective:  func() config.Config { return deps.Config },
		Audit:      deps.Audit,
		Now:        deps.Now,
	})
	if err != nil {
		return nil
	}
	handler := &settingsHTTP{service: service, managed: managed, gate: gate}
	return []adminapi.DomainRoute{
		{Method: http.MethodGet, Pattern: "settings", Handler: handler.fields},
		{Method: http.MethodGet, Pattern: "settings/status", Handler: handler.status},
		{Method: http.MethodPost, Pattern: "settings/validate", Handler: handler.validate},
		{Method: http.MethodPut, Pattern: "settings", Handler: handler.update},
		{Method: http.MethodPost, Pattern: "settings/sensitive-policy/restore",
			Handler: handler.restoreSensitive},
	}
}

type settingsHTTP struct {
	service *settings.Service
	managed *ManagedServices
	gate    *SecurityGate
}

// authorizeManage 每请求真实判定 settings.manage；失败统一 ACCESS_DENIED，不泄露
// 现有配置值。
func (h *settingsHTTP) authorizeManage(ctx context.Context, caller account.Caller) error {
	actor := caller.Actor()
	if actor.Type == audit.ActorSystem || actor.Type == audit.ActorLocalAdmin {
		return nil
	}
	if !account.ValidUserID(actor.ID) {
		return settingsDomainError(&settings.Error{Code: settings.CodeAccessDenied,
			Message: "缺少修改常规设置的权限"})
	}
	if err := h.managed.Checker.check(ctx, actor.ID, "settings.manage", "system"); err != nil {
		return settingsDomainError(&settings.Error{Code: settings.CodeAccessDenied,
			Message: "缺少修改常规设置的权限"})
	}
	return nil
}

// allowRoot 判定调用者是否为 root/受信主体（决定 root-only 字段可写性）。
//
// root-only 敏感设置字段是 AGENTS 第 7 节规定的 root 专属身份能力，不能由普通
// settings.manage 获得，因此这里保留 root 身份判定；常规设置写入仍先经权限内核的
// settings.manage 检查（停用/未实现对 root 同样拒绝）。
func (h *settingsHTTP) allowRoot(ctx context.Context, caller account.Caller) bool {
	if h.managed.Roots == nil {
		return false
	}
	allowed, err := h.managed.Roots.trustedActor(ctx, caller.Actor())
	return err == nil && allowed
}

func decodeSettingsJSON(request *http.Request, target any) error {
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return settingsDomainError(&settings.Error{Code: settings.CodeReqInvalid,
			Message: "请求体格式无效"})
	}
	if decoder.More() {
		return settingsDomainError(&settings.Error{Code: settings.CodeReqInvalid,
			Message: "请求体包含多余内容"})
	}
	return nil
}

type settingsChangesInput struct {
	Changes map[string]string `json:"changes"`
}

type settingsUpdateInput struct {
	ExpectedVersion string            `json:"expected_version"`
	Changes         map[string]string `json:"changes"`
	Reason          string            `json:"reason"`
}

type settingsRestoreInput struct {
	ScopeID         string `json:"scope_id"`
	OperationID     string `json:"operation_id"`
	All             bool   `json:"all"`
	ExpectedVersion int64  `json:"expected_version"`
	Password        string `json:"password"`
	TOTPCode        string `json:"totp_code"`
	Reason          string `json:"reason"`
}

func (h *settingsHTTP) fields(ctx context.Context, caller account.Caller,
	_ *http.Request) (any, error) {
	if err := h.authorizeManage(ctx, caller); err != nil {
		return nil, err
	}
	view, err := h.service.Fields(ctx, h.allowRoot(ctx, caller))
	if err != nil {
		return nil, settingsDomainError(err)
	}
	fields := make([]map[string]any, 0, len(view.Fields))
	for _, field := range view.Fields {
		fields = append(fields, map[string]any{
			"field": field.Field, "value": field.Value, "disk_value": field.DiskValue,
			"class": field.Class, "secret": field.Secret, "root_only": field.RootOnly,
			"writable": field.Writable, "pending_restart": field.PendingRestart})
	}
	return map[string]any{"configured": view.Configured, "version": view.Version,
		"effective_version": view.EffectiveVersion, "fields": fields,
		"hot_reloadable": view.HotReloadable, "restart_required": view.RestartRequired,
		"note": view.Note}, nil
}

func (h *settingsHTTP) status(ctx context.Context, caller account.Caller,
	_ *http.Request) (any, error) {
	if err := h.authorizeManage(ctx, caller); err != nil {
		return nil, err
	}
	status, err := h.service.Status(ctx)
	if err != nil {
		return nil, settingsDomainError(err)
	}
	return map[string]any{"configured": status.Configured, "version": status.Version,
		"effective_version": status.EffectiveVersion, "writable": status.Writable,
		"pending_hot": status.PendingHot, "pending_restart": status.PendingRestart,
		"host_reload_needed": status.HostReloadNeeded,
		"last_error_code":    status.LastErrorCode,
		"last_write_version": status.LastWriteVersion}, nil
}

func (h *settingsHTTP) validate(ctx context.Context, caller account.Caller,
	request *http.Request) (any, error) {
	if err := h.authorizeManage(ctx, caller); err != nil {
		return nil, err
	}
	var input settingsChangesInput
	if err := decodeSettingsJSON(request, &input); err != nil {
		return nil, err
	}
	result, err := h.service.Validate(ctx, input.Changes, h.allowRoot(ctx, caller))
	if err != nil {
		return nil, settingsDomainError(err)
	}
	items := make([]map[string]any, 0, len(result.Errors))
	for _, item := range result.Errors {
		items = append(items, map[string]any{"field": item.Field,
			"code": item.Code, "detail": item.Detail})
	}
	return map[string]any{"valid": result.Valid, "errors": items,
		"changed_fields": result.ChangedFields, "writable": result.Writable,
		"restart_required": result.RestartRequired}, nil
}

func (h *settingsHTTP) update(ctx context.Context, caller account.Caller,
	request *http.Request) (any, error) {
	if err := h.authorizeManage(ctx, caller); err != nil {
		return nil, err
	}
	var input settingsUpdateInput
	if err := decodeSettingsJSON(request, &input); err != nil {
		return nil, err
	}
	result, err := h.service.Update(ctx, settings.UpdateInput{
		ExpectedVersion: input.ExpectedVersion, Changes: input.Changes,
		Reason: strings.TrimSpace(input.Reason), Actor: caller.Actor(),
		RequestID: requestIDFromContext(ctx), AllowRoot: h.allowRoot(ctx, caller)})
	if err != nil {
		return nil, settingsDomainError(err)
	}
	return map[string]any{"version": result.Version,
		"previous_version": result.PreviousVersion, "changed_fields": result.ChangedFields,
		"hot_fields": result.HotFields, "restart_fields": result.RestartFields,
		"applied_now": result.AppliedNow, "host_reload_needed": result.HostReloadNeeded,
		"note": result.Note}, nil
}

// restoreSensitive 恢复敏感操作策略默认值：真实 root 用户 + 再次认证 + 关键审计；
// 普通 settings.manage、LocalAdmin、未完成强认证均拒绝。
func (h *settingsHTTP) restoreSensitive(ctx context.Context, caller account.Caller,
	request *http.Request) (any, error) {
	actor := caller.Actor()
	if actor.Type != audit.ActorUser || h.managed.Roots == nil {
		return nil, settingsDomainError(&settings.Error{Code: settings.CodeAccessDenied,
			Message: "敏感操作策略默认值只能由真实 root 用户恢复"})
	}
	isRoot, err := h.managed.Roots.isRoot(ctx, actor.ID)
	if err != nil || !isRoot {
		return nil, settingsDomainError(&settings.Error{Code: settings.CodeAccessDenied,
			Message: "敏感操作策略默认值只能由真实 root 用户恢复"})
	}
	var input settingsRestoreInput
	if err := decodeSettingsJSON(request, &input); err != nil {
		return nil, err
	}
	if h.gate == nil || h.gate.Policy == nil || h.gate.Reauth == nil {
		return nil, settingsDomainError(&settings.Error{Code: settings.CodeConfigInvalid,
			Message: "敏感策略服务未装配"})
	}
	approved, err := h.authorizePolicyRestore(ctx, caller, input)
	if err != nil {
		return nil, err
	}
	policyCaller, err := policy.UserCaller(actor.ID)
	if err != nil {
		return nil, settingsDomainError(&settings.Error{Code: settings.CodeAccessDenied,
			Message: "策略调用者无效"})
	}
	before, err := h.gate.Policy.Effective(approved, policyCaller, input.ScopeID)
	if err != nil {
		return nil, settingsPolicyError(err)
	}
	after, err := h.gate.Policy.Restore(approved, policyCaller, policy.RestoreRequest{
		ScopeID: input.ScopeID, OperationID: input.OperationID, All: input.All,
		ExpectedVersion: input.ExpectedVersion, RequestID: requestIDFromContext(ctx)})
	if err != nil {
		return nil, settingsPolicyError(err)
	}
	removed := 0
	for _, operation := range before.Operations {
		if operation.Source == policy.SourceOverride {
			removed++
		}
	}
	for _, operation := range after.Operations {
		if operation.Source == policy.SourceOverride {
			removed--
		}
	}
	if removed < 0 {
		removed = 0
	}
	return map[string]any{"scope_id": input.ScopeID, "restored": true,
		"removed_overrides": removed, "version": after.Version}, nil
}

// authorizePolicyRestore 执行真实再次认证并返回带信号的上下文。
func (h *settingsHTTP) authorizePolicyRestore(ctx context.Context, caller account.Caller,
	input settingsRestoreInput) (context.Context, error) {
	reauthCaller, err := reauth.CallerFromActor(caller.Actor())
	if err != nil {
		return ctx, settingsDomainError(&settings.Error{Code: settings.CodeAccessDenied,
			Message: "敏感操作再次认证未通过"})
	}
	challenge, err := h.gate.Reauth.BeginChallenge(ctx, reauthCaller,
		reauth.ChallengeRequest{ScopeID: input.ScopeID,
			OperationID: policy.OperationPolicyChange, TargetType: "policy",
			TargetID:    input.ScopeID,
			Params:      map[string]string{"action": "restore_defaults"},
			Description: "恢复敏感操作策略默认值", RequestID: requestIDFromContext(ctx),
			MinimumStrength: policy.StrengthStrong})
	if err != nil {
		return ctx, settingsReauthError(err)
	}
	if !challenge.Required {
		return ctx, nil
	}
	if strings.TrimSpace(input.Password) == "" {
		return ctx, settingsDomainError(&settings.Error{Code: settings.CodeAccessDenied,
			Message: "敏感操作需要近期密码验证"})
	}
	grant, err := h.gate.Reauth.VerifyChallenge(ctx, reauthCaller,
		reauth.VerifyChallengeRequest{ChallengeID: challenge.ID,
			Password: input.Password, TOTPCode: input.TOTPCode,
			RequestID: requestIDFromContext(ctx)})
	if err != nil {
		return ctx, settingsReauthError(err)
	}
	return reauth.WithSignals(ctx, reauth.Signals{VerifiedAt: time.Now().UTC(),
		Strength: grant.GrantedStrength, Complete: true, Confirmed: true,
		ApprovalToken: grant.Token}), nil
}

// requestIDFromContext 读取 adminapi 写入的请求编号（用于关联审计）。
func requestIDFromContext(ctx context.Context) string {
	return transportRequestID(ctx)
}

// transportRequestID 由 transport 包的上下文读取函数转发；单独包装便于测试替换。
func transportRequestID(ctx context.Context) string {
	return transport.RequestIDFromContext(ctx)
}

// settingsDomainError 把核心错误投影为 adminapi 领域错误。
func settingsDomainError(err error) error {
	if err == nil {
		return nil
	}
	var coreErr *settings.Error
	if !errors.As(err, &coreErr) {
		return &adminapi.DomainError{Code: settings.CodeInternalError,
			Message: "配置操作失败"}
	}
	return &adminapi.DomainError{Code: coreErr.Code, Message: coreErr.Message}
}

// settingsPolicyError 把 policy 错误映射为管理 API 稳定错误。
func settingsPolicyError(err error) error {
	switch {
	case errors.Is(err, policy.ErrRootRequired), errors.Is(err, policy.ErrAccessDenied):
		return &adminapi.DomainError{Code: settings.CodeAccessDenied,
			Message: "敏感操作策略默认值只能由真实 root 用户恢复"}
	case errors.Is(err, policy.ErrVersionConflict):
		return &adminapi.DomainError{Code: settings.CodeConflict,
			Message: "敏感策略已被其他操作修改"}
	case errors.Is(err, policy.ErrReauthRequired), errors.Is(err, policy.ErrConfirmationRequired):
		return &adminapi.DomainError{Code: "REAUTH_REQUIRED", Message: "敏感操作需要再次认证"}
	case errors.Is(err, policy.ErrVerificationUnavailable):
		return &adminapi.DomainError{Code: "MFA_REQUIRED", Message: "敏感操作需要更强认证"}
	case errors.Is(err, policy.ErrAuditUnavailable):
		return &adminapi.DomainError{Code: settings.CodeAuditWriteFailed, Message: "关键审计不可用"}
	default:
		return &adminapi.DomainError{Code: settings.CodeInternalError, Message: "敏感策略操作失败"}
	}
}

// settingsReauthError 把 reauth 错误投影为 REAUTH_REQUIRED/MFA_REQUIRED。
func settingsReauthError(err error) error {
	switch reauth.CodeOf(err) {
	case reauth.CodeMFARequired:
		return &adminapi.DomainError{Code: "MFA_REQUIRED", Message: "敏感操作需要更强认证"}
	case reauth.CodeAccessDenied, reauth.CodeAuthFailed:
		return &adminapi.DomainError{Code: settings.CodeAccessDenied,
			Message: "敏感操作再次认证未通过"}
	default:
		return &adminapi.DomainError{Code: "REAUTH_REQUIRED",
			Message: "敏感操作需要再次认证"}
	}
}
