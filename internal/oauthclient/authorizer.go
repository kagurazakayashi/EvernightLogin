package oauthclient

import (
	"context"
	"fmt"
	"reflect"

	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// AppAuthorizer 用既有 internal/app 的应用管理授权语义实现 Authorizer：
//   - 读取安全设置映射为应用读取权限（application.get）；
//   - 登记/修改安全设置与轮换/撤销凭证映射为应用更新权限（application.update），
//     因为客户端安全设置属于应用的可信配置，应用管理员只应管理自己获准的应用，
//     系统/本地操作者按 app.Authorizer 的既有规则判定。
//
// 细粒度权限键（applications.update / applications.credentials.manage）的 authz
// 数据范围接线属于后续令牌/管理接口步骤；本适配器不缓存结果、不做默认放行，
// app.Authorizer 拒绝或故障时一律 ACCESS_DENIED（fail-closed）。
type AppAuthorizer struct {
	authorizer app.Authorizer
}

// NewAppAuthorizer 构造基于 app.Authorizer 的客户端管理授权器；nil（含 typed-nil）
// 返回错误，不创建默认放行实现。
func NewAppAuthorizer(authorizer app.Authorizer) (*AppAuthorizer, error) {
	if isNilDependency(authorizer) {
		return nil, fmt.Errorf("%w: 应用授权器为空", ErrOptionsInvalid)
	}
	return &AppAuthorizer{authorizer: authorizer}, nil
}

// AuthorizeClient 实现 Authorizer。
func (a *AppAuthorizer) AuthorizeClient(ctx context.Context, caller Caller, applicationID string, action Action) error {
	ctx = normalizeContext(ctx)
	if err := caller.actor.Validate(); err != nil || !app.ValidApplicationID(applicationID) {
		return ErrAccessDenied
	}
	appCaller, err := appCallerFromActor(caller.actor)
	if err != nil {
		return ErrAccessDenied
	}
	var appAction app.Action
	switch action {
	case ActionRead:
		appAction = app.ActionGetApplication
	case ActionUpdateSettings, ActionManageCredentials:
		appAction = app.ActionUpdateApplication
	default:
		return ErrAccessDenied
	}
	if err := a.authorizer.Authorize(ctx, appCaller, appAction, applicationID); err != nil {
		return ErrAccessDenied
	}
	return nil
}

// appCallerFromActor 把可信审计身份转换为 app.Caller；匿名身份拒绝。
func appCallerFromActor(actor audit.Actor) (app.Caller, error) {
	switch actor.Type {
	case audit.ActorUser:
		return app.UserCaller(actor.ID)
	case audit.ActorSystem:
		return app.SystemCaller(actor.ID)
	case audit.ActorLocalAdmin:
		return app.LocalBootstrapCaller(actor.ID)
	default:
		return app.Caller{}, ErrAccessDenied
	}
}

// isNilDependency 识别 typed-nil 依赖（接口内保存 nil 指针仍按缺失处理）。
func isNilDependency(value any) bool {
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

var _ Authorizer = (*AppAuthorizer)(nil)
