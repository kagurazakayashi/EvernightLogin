// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package app

// 受控配置管理公开门面（步骤 232）：身份/权限/错误码映射与 policy 恢复入口；
// 字段白名单、秘密遮盖、版本冲突、原子写、审计回滚、待重启语义由
// internal/settings 统一实现，Go/HTTP/CLI 共用。

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/settings"
)

var settingsFacadeRegistry sync.Map

// SettingsService 是受认证、按字段白名单的配置查询/校验/变更/状态服务。
type SettingsService interface {
	Fields(ctx context.Context, req SettingsFieldsRequest) (SettingsView, error)
	Validate(ctx context.Context, req SettingsValidateRequest) (SettingsValidation, error)
	Update(ctx context.Context, req SettingsUpdateRequest) (SettingsUpdateResult, error)
	Status(ctx context.Context, req SettingsStatusRequest) (SettingsStatus, error)
	RestoreSensitiveDefaults(ctx context.Context,
		req SettingsRestoreSensitiveRequest) (SettingsRestoreSensitiveResult, error)
}

// SettingsFieldsRequest 是配置字段查询请求。
type SettingsFieldsRequest struct {
	Caller    AdminCaller
	RequestID string
}

// SettingsValidateRequest 是配置变更校验请求；Changes 为字段路径→字符串值。
type SettingsValidateRequest struct {
	Caller    AdminCaller
	Changes   map[string]string
	RequestID string
}

// SettingsUpdateRequest 是配置写入请求；ExpectedVersion 必须是最近读取的磁盘
// SHA-256 版本，用于并发修改冲突检查。
type SettingsUpdateRequest struct {
	Caller          AdminCaller
	ExpectedVersion string
	Changes         map[string]string
	Reason          string
	RequestID       string
}

// SettingsStatusRequest 是配置状态查询请求。
type SettingsStatusRequest struct {
	Caller    AdminCaller
	RequestID string
}

// SettingsRestoreSensitiveRequest 是敏感操作策略默认值恢复请求（仅真实 root）。
type SettingsRestoreSensitiveRequest struct {
	Caller          AdminCaller
	ScopeID         string
	OperationID     string
	All             bool
	ExpectedVersion int64
	Password        string
	TOTPCode        string
	Reason          string
	RequestID       string
}

// SettingField 是单个配置字段的公开视图。
type SettingField struct {
	Field          string
	Value          string
	DiskValue      string
	Class          string
	Secret         bool
	RootOnly       bool
	Writable       bool
	PendingRestart bool
}

// SettingsView 是配置字段整体视图。
type SettingsView struct {
	Configured       bool
	Version          string
	EffectiveVersion string
	Fields           []SettingField
	HotReloadable    []string
	RestartRequired  []string
	Note             string
}

// SettingsValidation 是校验结果；合法为 true 时 Changes 可用于 Update。
type SettingsValidation struct {
	Valid           bool
	Errors          []SettingValidationError
	ChangedFields   []string
	RootOnlyFields  []string
	Writable        bool
	RestartRequired []string
}

// SettingValidationError 是单字段校验错误（不含秘密值）。
type SettingValidationError struct {
	Field  string
	Code   string
	Detail string
}

// SettingsUpdateResult 是配置写入结果。
type SettingsUpdateResult struct {
	Version          string
	PreviousVersion  string
	ChangedFields    []string
	HotFields        []string
	RestartFields    []string
	AppliedNow       bool
	HostReloadNeeded bool
	Note             string
}

// SettingsStatus 是配置状态与失败保留语义视图。
type SettingsStatus struct {
	Configured       bool
	Version          string
	EffectiveVersion string
	Writable         bool
	PendingHot       []string
	PendingRestart   []string
	HostReloadNeeded bool
	LastErrorCode    string
	LastErrorAt      time.Time
	LastWriteVersion string
}

// SettingsRestoreSensitiveResult 是敏感策略恢复结果。
type SettingsRestoreSensitiveResult struct {
	ScopeID          string
	Restored         bool
	RemovedOverrides int
	Version          int64
	RequestID        string
}

// Settings 返回受控配置管理服务。
func (r *Runtime) Settings() SettingsService {
	if r == nil {
		return &settingsFacade{}
	}
	value, _ := settingsFacadeRegistry.LoadOrStore(r, &settingsFacade{
		r: r, admin: &adminFacade{r: r}})
	facade, ok := value.(*settingsFacade)
	if !ok {
		return &settingsFacade{r: r, admin: &adminFacade{r: r}}
	}
	return facade
}

type settingsFacade struct {
	r     *Runtime
	admin *adminFacade

	coreOnce sync.Once
	core     *settings.Service
	coreErr  error
}

// service 延迟构造共享核心；构造不打开文件、不启动协程。
func (s *settingsFacade) service() (*settings.Service, error) {
	if s.r == nil {
		return nil, settingsError(settings.CodeConfigInvalid, "运行时未初始化")
	}
	s.coreOnce.Do(func() {
		s.core, s.coreErr = settings.New(settings.Options{
			ConfigPath: s.r.opts.ConfigPath,
			Effective:  func() configValue { return s.r.config },
			Audit:      runtimeAuditRecorder(s.r),
			Now:        s.r.runtimeNow,
		})
	})
	return s.core, s.coreErr
}

// configValue 是 settings.Options.Effective 的返回类型别名辅助；直接使用公开
// config.Config，避免在门面里复制配置结构。
type configValue = login.Config

// runtimeAuditRecorder 返回真实审计写入器；nil 时核心会在写操作 fail-closed。
func runtimeAuditRecorder(r *Runtime) settings.AuditRecorder {
	if r.base == nil || r.base.Audit == nil {
		return nil
	}
	return r.base.Audit
}

// settingsRequireManage 校验调用者：LocalAdmin 为受信宿主；管理会话必须持有系统
// settings.manage（先于任何配置读取/写入，未授权不泄露现有值）。
func (s *settingsFacade) settingsRequireManage(ctx context.Context, caller AdminCaller,
	requestID string) (adminRequest, error) {
	call, err := s.begin(ctx, caller, requestID)
	if err != nil {
		return adminRequest{}, err
	}
	if call.identity.local {
		return call, nil
	}
	managed := s.r.managedServices()
	if managed == nil || managed.Authz == nil {
		return adminRequest{}, call.configError("授权服务未装配")
	}
	authzCaller, err := s.admin.authzCaller(call.identity)
	if err != nil {
		return adminRequest{}, call.configError("授权调用者无效")
	}
	result, err := managed.Authz.Check(ctx, authzCaller, authz.CheckRequest{
		SubjectUserID: call.identity.userID, ScopeID: "system",
		Permissions: []string{"settings.manage"}, Mode: authz.ModeAll})
	if err != nil {
		return adminRequest{}, call.domainError("设置权限校验失败", string(authz.CodeOf(err)))
	}
	if !result.Allowed {
		return adminRequest{}, call.domainError("缺少修改常规设置的权限", "ACCESS_DENIED")
	}
	return call, nil
}

func (s *settingsFacade) begin(ctx context.Context, caller AdminCaller,
	requestID string) (adminRequest, error) {
	return s.admin.begin(ctx, caller, requestID)
}

func (s *settingsFacade) Fields(ctx context.Context,
	req SettingsFieldsRequest) (SettingsView, error) {
	call, err := s.settingsRequireManage(ctx, req.Caller, req.RequestID)
	if err != nil {
		return SettingsView{}, err
	}
	service, err := s.service()
	if err != nil {
		return SettingsView{}, mapSettingsError(call, err)
	}
	view, err := service.Fields(ctx, call.identity.local)
	if err != nil {
		return SettingsView{}, mapSettingsError(call, err)
	}
	result := SettingsView{Configured: view.Configured, Version: view.Version,
		EffectiveVersion: view.EffectiveVersion, HotReloadable: view.HotReloadable,
		RestartRequired: view.RestartRequired, Note: view.Note}
	result.Fields = make([]SettingField, 0, len(view.Fields))
	for _, field := range view.Fields {
		result.Fields = append(result.Fields, SettingField{Field: field.Field,
			Value: field.Value, DiskValue: field.DiskValue, Class: field.Class,
			Secret: field.Secret, RootOnly: field.RootOnly, Writable: field.Writable,
			PendingRestart: field.PendingRestart})
	}
	return result, nil
}

func (s *settingsFacade) Validate(ctx context.Context,
	req SettingsValidateRequest) (SettingsValidation, error) {
	call, err := s.settingsRequireManage(ctx, req.Caller, req.RequestID)
	if err != nil {
		return SettingsValidation{}, err
	}
	service, err := s.service()
	if err != nil {
		return SettingsValidation{}, mapSettingsError(call, err)
	}
	result, err := service.Validate(ctx, req.Changes, call.identity.local)
	if err != nil {
		return SettingsValidation{}, mapSettingsError(call, err)
	}
	validation := SettingsValidation{Valid: result.Valid, ChangedFields: result.ChangedFields,
		RootOnlyFields: result.RootOnlyFields, Writable: result.Writable,
		RestartRequired: result.RestartRequired}
	for _, item := range result.Errors {
		validation.Errors = append(validation.Errors, SettingValidationError{
			Field: item.Field, Code: item.Code, Detail: item.Detail})
	}
	return validation, nil
}

func (s *settingsFacade) Update(ctx context.Context,
	req SettingsUpdateRequest) (SettingsUpdateResult, error) {
	call, err := s.settingsRequireManage(ctx, req.Caller, req.RequestID)
	if err != nil {
		return SettingsUpdateResult{}, err
	}
	service, err := s.service()
	if err != nil {
		return SettingsUpdateResult{}, mapSettingsError(call, err)
	}
	result, err := service.Update(ctx, settings.UpdateInput{
		ExpectedVersion: req.ExpectedVersion, Changes: req.Changes,
		Reason: strings.TrimSpace(req.Reason), Actor: call.identity.actor,
		RequestID: call.requestID, AllowRoot: call.identity.local})
	if err != nil {
		return SettingsUpdateResult{}, mapSettingsError(call, err)
	}
	return SettingsUpdateResult{Version: result.Version,
		PreviousVersion: result.PreviousVersion, ChangedFields: result.ChangedFields,
		HotFields: result.HotFields, RestartFields: result.RestartFields,
		AppliedNow: result.AppliedNow, HostReloadNeeded: result.HostReloadNeeded,
		Note: result.Note}, nil
}

func (s *settingsFacade) Status(ctx context.Context,
	req SettingsStatusRequest) (SettingsStatus, error) {
	call, err := s.settingsRequireManage(ctx, req.Caller, req.RequestID)
	if err != nil {
		return SettingsStatus{}, err
	}
	service, err := s.service()
	if err != nil {
		return SettingsStatus{}, mapSettingsError(call, err)
	}
	status, err := service.Status(ctx)
	if err != nil {
		return SettingsStatus{}, mapSettingsError(call, err)
	}
	return SettingsStatus{Configured: status.Configured, Version: status.Version,
		EffectiveVersion: status.EffectiveVersion, Writable: status.Writable,
		PendingHot: status.PendingHot, PendingRestart: status.PendingRestart,
		HostReloadNeeded: status.HostReloadNeeded, LastErrorCode: status.LastErrorCode,
		LastErrorAt: status.LastErrorAt, LastWriteVersion: status.LastWriteVersion}, nil
}

// RestoreSensitiveDefaults 恢复敏感操作策略默认值：只接受真实 root 用户会话，
// 走真实 policy.Restore（再次认证+关键审计+版本冲突）；LocalAdmin/普通 settings.manage
// 均不可获得。
func (s *settingsFacade) RestoreSensitiveDefaults(ctx context.Context,
	req SettingsRestoreSensitiveRequest) (SettingsRestoreSensitiveResult, error) {
	call, err := s.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return SettingsRestoreSensitiveResult{}, err
	}
	if call.identity.local || call.identity.userID == "" {
		return SettingsRestoreSensitiveResult{}, call.domainError(
			"敏感操作策略默认值只能由真实 root 用户恢复", "ACCESS_DENIED")
	}
	gate := s.r.securityGate()
	if gate == nil || gate.Policy == nil {
		return SettingsRestoreSensitiveResult{}, call.configError("敏感策略服务未装配")
	}
	policyCaller, err := policy.UserCaller(call.identity.userID)
	if err != nil {
		return SettingsRestoreSensitiveResult{}, call.configError("策略调用者无效")
	}
	policyCaller, err = bindCaller(policyCaller, call.requestID)
	if err != nil {
		return SettingsRestoreSensitiveResult{}, err
	}
	approved, err := s.admin.sensitiveContext(ctx, call.identity,
		policy.OperationPolicyChange, "policy", strings.TrimSpace(req.ScopeID),
		map[string]string{"action": "restore_defaults"},
		req.Password, req.TOTPCode, call.requestID)
	if err != nil {
		return SettingsRestoreSensitiveResult{}, err
	}
	before, err := gate.Policy.Effective(approved, policyCaller, req.ScopeID)
	if err != nil {
		return SettingsRestoreSensitiveResult{}, mapPolicyError(call, "读取敏感策略失败", err)
	}
	after, err := gate.Policy.Restore(approved, policyCaller, policy.RestoreRequest{
		ScopeID: req.ScopeID, OperationID: req.OperationID, All: req.All,
		ExpectedVersion: req.ExpectedVersion, RequestID: call.requestID})
	if err != nil {
		return SettingsRestoreSensitiveResult{}, mapPolicyError(call, "恢复敏感策略默认值失败", err)
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
	return SettingsRestoreSensitiveResult{ScopeID: req.ScopeID, Restored: true,
		RemovedOverrides: removed, Version: after.Version, RequestID: call.requestID}, nil
}

// mapSettingsError 把核心错误映射为公开稳定错误码。
func mapSettingsError(call adminRequest, err error) error {
	if err == nil {
		return nil
	}
	var coreErr *settings.Error
	if !errors.As(err, &coreErr) {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return call.domainError("配置请求已取消或超时", "INTERNAL_ERROR")
		}
		return call.domainError("配置操作失败", "INTERNAL_ERROR")
	}
	switch coreErr.Code {
	case settings.CodeReqInvalid:
		return call.domainError(coreErr.Message, "REQ_INVALID")
	case settings.CodeAccessDenied:
		return call.domainError(coreErr.Message, "ACCESS_DENIED")
	case settings.CodeConfigInvalid:
		return call.domainError(coreErr.Message, "CONFIG_INVALID")
	case settings.CodeConflict:
		return call.domainError(coreErr.Message, "CONFLICT")
	case settings.CodeAuditWriteFailed:
		return call.domainError(coreErr.Message, "AUDIT_WRITE_FAILED")
	default:
		return call.domainError(coreErr.Message, "INTERNAL_ERROR")
	}
}

// mapPolicyError 把 policy 领域错误映射为稳定公开错误。
func mapPolicyError(call adminRequest, message string, err error) error {
	switch {
	case errors.Is(err, policy.ErrRootRequired), errors.Is(err, policy.ErrAccessDenied):
		return call.domainError(message, "ACCESS_DENIED")
	case errors.Is(err, policy.ErrVersionConflict):
		return call.domainError(message, "CONFLICT")
	case errors.Is(err, policy.ErrReauthRequired), errors.Is(err, policy.ErrConfirmationRequired):
		return call.domainError(message, "REAUTH_REQUIRED")
	case errors.Is(err, policy.ErrVerificationUnavailable):
		return call.domainError(message, "MFA_REQUIRED")
	case errors.Is(err, policy.ErrInvalidRequest), errors.Is(err, policy.ErrInvalidChange),
		errors.Is(err, policy.ErrOperationUnknown), errors.Is(err, policy.ErrScopeUnknown),
		errors.Is(err, policy.ErrDefaultUnavailable):
		return call.domainError(message, "REQ_INVALID")
	case errors.Is(err, policy.ErrAuditUnavailable):
		return call.domainError(message, "AUDIT_WRITE_FAILED")
	case errors.Is(err, policy.ErrStoreUnavailable):
		return call.domainError(message, "DB_UNAVAILABLE")
	default:
		return call.domainError(message, "INTERNAL_ERROR")
	}
}

// settingsError 是构造核心错误的最小辅助（仅测试/构造期使用）。
func settingsError(code, message string) error {
	return &settings.Error{Code: code, Message: message}
}
