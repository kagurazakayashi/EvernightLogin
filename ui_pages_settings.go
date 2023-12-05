package login

// 步骤 232：管理页“配置设置”入口（可选装配）。
// 页面只做展示与表单提交；后端适配器负责每请求重新判定真实 settings.manage 与
// root-only 字段，秘密字段只显示脱敏标记且不可提交。未提供后端时不注册路由（404）。

import (
	"context"
	"net/http"
	"strings"
)

// UIPageAdminSettingsOptions 是管理页配置设置入口配置。
type UIPageAdminSettingsOptions struct {
	// Backend 是配置设置页面后端；nil 时不注册设置页面。
	Backend UIAdminSettingsBackend
}

// UIAdminSettingsBackend 是管理页配置设置的最小契约；实现必须每请求重新判定
// settings.manage，并按真实 root/受信身份决定 root-only 字段的可见写权限。
type UIAdminSettingsBackend interface {
	GetSettings(ctx context.Context, adminID string) (UIAdminSettingsView, error)
	UpdateSettings(ctx context.Context, adminID string,
		change UIAdminSettingsChange) (UIAdminSettingsView, error)
}

// UIAdminSettingsField 是页面字段视图；秘密值只允许脱敏标记。
type UIAdminSettingsField struct {
	Field          string
	Value          string
	DiskValue      string
	Class          string
	Secret         bool
	RootOnly       bool
	Writable       bool
	PendingRestart bool
}

// UIAdminSettingsView 是配置设置页面视图。
type UIAdminSettingsView struct {
	Configured       bool
	Version          string
	EffectiveVersion string
	Fields           []UIAdminSettingsField
	PendingHot       []string
	PendingRestart   []string
	HostReloadNeeded bool
	Note             string
}

// UIAdminSettingsChange 是页面提交的字段变更。
type UIAdminSettingsChange struct {
	ExpectedVersion string
	Changes         map[string]string
	Reason          string
	RequestID       string
}

// settings 渲染配置设置页面并处理表单提交。
func (h *adminPageHandlers) settings(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	options := h.pages.options.Settings
	if options == nil || isNilUIValue(options.Backend) {
		return UIPageOutcome{StatusCode: http.StatusNotFound,
			ErrorSummary: text("page.admin.settings.unavailable")}, nil
	}
	requestID := request.FormValue("request_id")
	view, err := options.Backend.GetSettings(ctx, page.Session.UserID)
	if err != nil {
		return adminErrorOutcome(err, nil, "page.admin.settings.load_failed"), nil
	}
	data := map[string]any{"settings": view, "requestID": requestID}
	outcome := UIPageOutcome{Data: data}
	if request.Method != http.MethodPost {
		return outcome, nil
	}
	changes := make(map[string]string)
	for _, field := range view.Fields {
		if !field.Writable || field.Secret || strings.HasPrefix(field.Field, "secrets.") {
			continue
		}
		name := "field." + field.Field
		if !request.Form.Has(name) {
			continue
		}
		value := request.FormValue(name)
		if value != field.Value {
			changes[field.Field] = value
		}
	}
	if len(changes) == 0 {
		data["status"] = "unchanged"
		return outcome, nil
	}
	updated, updateErr := options.Backend.UpdateSettings(ctx, page.Session.UserID,
		UIAdminSettingsChange{ExpectedVersion: view.Version, Changes: changes,
			Reason: request.FormValue("reason"), RequestID: requestID})
	if updateErr != nil {
		return adminErrorOutcome(updateErr, nil, "page.admin.settings.update_failed"), nil
	}
	data["settings"] = updated
	data["status"] = "saved"
	return outcome, nil
}
