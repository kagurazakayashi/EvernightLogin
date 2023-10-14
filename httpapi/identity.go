package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/kagurazakayashi/EvernightLogin/correlation"
)

// ErrIdentityInvalid 表示宿主提供的可信身份结构无效。它不是认证失败本身，而是
// 宿主身份建立契约被违反；HTTP 处理会把它映射为 AUTH_FAILED 并拒绝。
var ErrIdentityInvalid = errors.New("身份结构无效")

// IdentityKind 是可信身份的类型。身份只能由已经验证的会话、令牌或宿主可信
// 上下文建立，不能由请求参数或客户端自填字段声明。
type IdentityKind string

const (
	// IdentityKindUser 表示已认证用户。
	IdentityKindUser IdentityKind = "user"
	// IdentityKindApplication 表示应用服务身份（如 Client Credentials）；必须
	// 带 AppID，且不冒充某个用户。
	IdentityKindApplication IdentityKind = "application"
	// IdentityKindSystem 表示宿主系统组件身份；不得由普通 HTTP 客户端建立。
	IdentityKindSystem IdentityKind = "system"
)

// Valid 报告身份类型是否已定义。
func (k IdentityKind) Valid() bool {
	switch k {
	case IdentityKindUser, IdentityKindApplication, IdentityKindSystem:
		return true
	default:
		return false
	}
}

// Identity 是 HTTP 层建立并传递给服务层的可信身份。SubjectID 是稳定不透明 ID；
// AppID 是可选应用范围（应用身份必填）。显示名、邮箱等资料不放在这里。
type Identity struct {
	Kind      IdentityKind
	SubjectID string
	AppID     string
}

// Validate 校验身份结构：类型已定义、SubjectID 非空且是受限 ID 字符集、应用
// 身份必须带 AppID。它只做结构校验；权限判断必须由服务层完成。
func (i Identity) Validate() error {
	if !i.Kind.Valid() {
		return fmt.Errorf("%w: 身份类型未定义", ErrIdentityInvalid)
	}
	if i.SubjectID == "" {
		return fmt.Errorf("%w: 身份主体 ID 不能为空", ErrIdentityInvalid)
	}
	if err := correlation.Validate("身份主体 ID", i.SubjectID); err != nil {
		return fmt.Errorf("%w: %v", ErrIdentityInvalid, err)
	}
	if i.Kind == IdentityKindApplication && i.AppID == "" {
		return fmt.Errorf("%w: 应用身份必须带应用范围", ErrIdentityInvalid)
	}
	if i.AppID != "" {
		if err := correlation.Validate("应用范围 ID", i.AppID); err != nil {
			return fmt.Errorf("%w: %v", ErrIdentityInvalid, err)
		}
	}
	return nil
}

// IdentityResolver 从请求建立可信身份。实现必须基于已验证会话、OAuth 令牌或
// 宿主可信上下文；不得读取客户端自填的 user_id、actor_id、is_root 等字段。
//
// 返回错误表示身份建立失败；如果返回根包/errs 的 *AppError 则保留其错误码与
// HTTP 状态，其他错误统一映射为 AUTH_FAILED（401）且不向调用者暴露细节。
type IdentityResolver interface {
	ResolveIdentity(ctx context.Context, request *http.Request) (Identity, error)
}

// IdentityResolverFunc 是 IdentityResolver 的函数适配器。
type IdentityResolverFunc func(ctx context.Context, request *http.Request) (Identity, error)

// ResolveIdentity 实现 IdentityResolver。
func (f IdentityResolverFunc) ResolveIdentity(ctx context.Context, request *http.Request) (Identity, error) {
	if f == nil {
		return Identity{}, fmt.Errorf("%w: 身份解析函数为空", ErrIdentityInvalid)
	}
	return f(ctx, request)
}
