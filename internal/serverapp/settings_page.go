// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package serverapp

// 步骤 232：管理页配置设置后端适配器。页面契约来自根包，真实授权/审计/原子写
// 复用 internal/settings 与生产 permissionChecker/root 识别器；每次调用重新判定，
// 不缓存权限。未配置可写 YAML 时返回 nil（页面不注册，404）。

import (
	"context"
	"errors"
	"github.com/kagurazakayashi/EvernightLogin/config"
	"github.com/kagurazakayashi/EvernightLogin/errs"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/settings"
	"github.com/kagurazakayashi/EvernightLogin/internal/transport"
	ui "github.com/kagurazakayashi/EvernightLogin/ui"
	"strings"
)

type settingsPageBackend struct {
	service *settings.Service
	managed *ManagedServices
}

// newSettingsSettingsPageBackend 构造管理页配置设置后端；没有可写配置文件时返回 nil。
func newSettingsSettingsPageBackend(deps Deps,
	managed *ManagedServices) (ui.UIAdminSettingsBackend, error) {
	if strings.TrimSpace(deps.ConfigPath) == "" || managed == nil ||
		managed.Checker == nil || managed.Roots == nil {
		return nil, nil
	}
	service, err := settings.New(settings.Options{ConfigPath: deps.ConfigPath,
		Effective: func() config.Config { return deps.Config }, Audit: deps.Audit,
		Now: deps.Now})
	if err != nil {
		return nil, err
	}
	return &settingsPageBackend{service: service, managed: managed}, nil
}

func (b *settingsPageBackend) authorize(ctx context.Context, adminID string) (bool, error) {
	if err := b.managed.Checker.check(ctx, adminID, "settings.manage", "system"); err != nil {
		return false, pageSettingsError(&settings.Error{Code: settings.CodeAccessDenied,
			Message: "缺少修改常规设置的权限"})
	}
	allowRoot, err := b.managed.Roots.isRoot(ctx, adminID)
	if err != nil {
		return false, pageSettingsError(&settings.Error{Code: settings.CodeAccessDenied,
			Message: "无法判定受信设置权限"})
	}
	return allowRoot, nil
}

func (b *settingsPageBackend) GetSettings(ctx context.Context,
	adminID string) (ui.UIAdminSettingsView, error) {
	allowRoot, err := b.authorize(ctx, adminID)
	if err != nil {
		return ui.UIAdminSettingsView{}, err
	}
	view, err := b.service.Fields(ctx, allowRoot)
	if err != nil {
		return ui.UIAdminSettingsView{}, pageSettingsError(err)
	}
	return settingsPageView(view), nil
}

func (b *settingsPageBackend) UpdateSettings(ctx context.Context, adminID string,
	change ui.UIAdminSettingsChange) (ui.UIAdminSettingsView, error) {
	allowRoot, err := b.authorize(ctx, adminID)
	if err != nil {
		return ui.UIAdminSettingsView{}, err
	}
	requestID := strings.TrimSpace(change.RequestID)
	if requestID == "" {
		requestID = transport.RequestIDFromContext(ctx)
	}
	if _, err := b.service.Update(ctx, settings.UpdateInput{
		ExpectedVersion: change.ExpectedVersion, Changes: change.Changes,
		Reason: change.Reason, Actor: audit.Actor{Type: audit.ActorUser, ID: adminID},
		RequestID: requestID, AllowRoot: allowRoot}); err != nil {
		return ui.UIAdminSettingsView{}, pageSettingsError(err)
	}
	view, err := b.service.Fields(ctx, allowRoot)
	if err != nil {
		return ui.UIAdminSettingsView{}, pageSettingsError(err)
	}
	return settingsPageView(view), nil
}

func settingsPageView(view settings.View) ui.UIAdminSettingsView {
	result := ui.UIAdminSettingsView{Configured: view.Configured,
		Version: view.Version, EffectiveVersion: view.EffectiveVersion,
		PendingHot: view.HotReloadable, PendingRestart: view.RestartRequired,
		HostReloadNeeded: len(view.HotReloadable) > 0 || len(view.RestartRequired) > 0,
		Note:             view.Note}
	result.Fields = make([]ui.UIAdminSettingsField, 0, len(view.Fields))
	for _, field := range view.Fields {
		result.Fields = append(result.Fields, ui.UIAdminSettingsField{
			Field: field.Field, Value: field.Value, DiskValue: field.DiskValue,
			Class: field.Class, Secret: field.Secret, RootOnly: field.RootOnly,
			Writable: field.Writable, PendingRestart: field.PendingRestart})
	}
	return result
}

func pageSettingsError(err error) error {
	if err == nil {
		return nil
	}
	var coreErr *settings.Error
	if !errors.As(err, &coreErr) {
		return errs.NewAppError(errs.CodeInternalError, "配置操作失败")
	}
	code := errs.CodeInternalError
	switch coreErr.Code {
	case settings.CodeReqInvalid:
		code = errs.CodeReqInvalid
	case settings.CodeAccessDenied:
		code = errs.CodeAccessDenied
	case settings.CodeConfigInvalid:
		code = errs.CodeConfigInvalid
	case settings.CodeConflict:
		code = errs.CodeConflict
	case settings.CodeAuditWriteFailed:
		code = errs.CodeAuditWriteFailed
	}
	return errs.NewAppError(code, coreErr.Message)
}
