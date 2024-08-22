// 本文件定义宿主可注入的公开授权契约与公开权限类型（步骤 88）。
//
// 设计边界：
//   - Permission 是稳定机器标识，不是展示文案；作用范围（system / application）
//     分开声明，跨作用范围不互相代替。
//   - AccessRequest 只携带可信边界建立的身份与待判定的资源标识，不接受请求参数
//     自称 root、角色或权限。身份本身不授予任何权限，判定必须由宿主注入的真实
//     授权扩展完成。
//   - 未注入授权扩展、扩展报错或返回异常时一律拒绝（fail-closed），不会因为
//     缺少依赖而放行；本包不提供「允许全部」「跳过鉴权」或「伪造 root」的公开
//     入口。system 身份也只是主体类型，不会自动获得任何权限。
//   - 真实授权判定来源（内部 authz 引擎）尚未包装成公开类型；宿主当前需在模块内
//     装配真实授权器后通过 AccessController 注入，或用宿主自己的策略服务实现。
//     该契约不能当作「已接入生产鉴权」的证明。
package access

import (
	"context"
	"fmt"

	"github.com/kagurazakayashi/EvernightLogin/correlation"
	"github.com/kagurazakayashi/EvernightLogin/httpapi"
)

// Identity 与 IdentityKind 复用 HTTP 公共身份契约，避免第二套身份类型。
type Identity = httpapi.Identity
type IdentityKind = httpapi.IdentityKind

const (
	IdentityKindApplication = httpapi.IdentityKindApplication
)

// MaxPermissionLength 是权限机器标识的最大长度。
const MaxPermissionLength = 128

// MaxResourceIDLength 是资源标识的最大长度。资源标识由具体业务定义，本包只做
// 长度与控制字符边界检查，不推断资源归属。
const MaxResourceIDLength = 256

// Permission 是权限的稳定机器标识（例如 "users.read"），在声明的作用范围内唯一。
// 权限标识只用于判定请求，不包含展示文案，也不能由客户端输入直接构造为已获授权。
type Permission string

// Validate 校验权限标识：非空、长度受限、只允许 ASCII 字母/数字与 . _ - : /。
func (p Permission) Validate() error {
	value := string(p)
	if value == "" {
		return fmt.Errorf("权限标识不能为空")
	}
	if len(value) > MaxPermissionLength {
		return fmt.Errorf("权限标识长度不能超过 %d 个字符", MaxPermissionLength)
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		allowed := (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '.' || character == '_' || character == '-' ||
			character == ':' || character == '/'
		if !allowed {
			return fmt.Errorf("权限标识只能包含 ASCII 字母、数字与 . _ - : /")
		}
	}
	return nil
}

// String 返回权限的稳定字符串。
func (p Permission) String() string { return string(p) }

// PermissionScope 是权限判定的作用范围。系统权限与应用权限分开判定，应用权限
// 必须带应用范围，不能用一个作用范围的权限代替另一个。
type PermissionScope string

const (
	// PermissionScopeSystem 表示系统作用范围（全局账户、系统角色等）。
	PermissionScopeSystem PermissionScope = "system"
	// PermissionScopeApplication 表示应用作用范围（应用成员、应用角色等）。
	PermissionScopeApplication PermissionScope = "application"
)

// Valid 报告作用范围是否已定义。
func (s PermissionScope) Valid() bool {
	return s == PermissionScopeSystem || s == PermissionScopeApplication
}

// AccessRequest 是一次授权判定请求。Identity 必须来自可信边界（会话、令牌或
// 宿主可信上下文）；ResourceID 为空表示只判定功能权限，具体资源归属仍由业务侧
// 校验。
type AccessRequest struct {
	// Identity 是可信主体身份；AccessRequest.Validate 会重新校验其结构。
	Identity Identity
	// Permission 是待判定的权限机器标识。
	Permission Permission
	// Scope 是权限作用范围；应用范围必须提供 AppID。
	Scope PermissionScope
	// AppID 是应用作用范围；应用身份必须与 Identity.AppID 一致。
	AppID string
	// ResourceID 是可选业务资源标识；为空时只判定功能权限。
	ResourceID string
}

// Validate 校验访问请求结构：身份合法、权限标识合法、作用范围已定义、应用范围
// 带 AppID 且与可信身份的应用范围一致、资源标识长度与控制字符合法。它只做结构
// 校验，不做授权判定。
func (r AccessRequest) Validate() error {
	if err := r.Identity.Validate(); err != nil {
		return err
	}
	if err := r.Permission.Validate(); err != nil {
		return err
	}
	if !r.Scope.Valid() {
		return fmt.Errorf("权限作用范围未定义: %q", string(r.Scope))
	}
	if r.Scope == PermissionScopeApplication && r.AppID == "" {
		return fmt.Errorf("应用作用范围必须提供应用 ID")
	}
	if r.AppID != "" {
		if err := correlation.Validate("访问请求应用 ID", r.AppID); err != nil {
			return err
		}
	}
	if r.AppID != "" && r.Identity.AppID != "" && r.AppID != r.Identity.AppID {
		return fmt.Errorf("访问请求的应用范围与可信身份应用范围不一致")
	}
	if r.Identity.Kind == IdentityKindApplication && r.AppID == "" {
		return fmt.Errorf("应用身份必须带应用范围")
	}
	if r.ResourceID != "" {
		if len(r.ResourceID) > MaxResourceIDLength {
			return fmt.Errorf("资源标识长度不能超过 %d 个字符", MaxResourceIDLength)
		}
		for index := 0; index < len(r.ResourceID); index++ {
			character := r.ResourceID[index]
			if character < 0x20 || character == 0x7f {
				return fmt.Errorf("资源标识不能包含控制字符")
			}
		}
	}
	return nil
}

// AccessDecision 是授权判定的结果。Allowed 为 true 才表示获准；Reason 与
// DataScope 是给有权调用者的稳定说明，不能包含秘密或内部实现细节。
type AccessDecision struct {
	// Allowed 表示是否获准；零值为拒绝。
	Allowed bool
	// Reason 是稳定的判定原因标识（例如 "permission_granted"）。
	Reason string
	// DataScope 是可选的受控数据范围说明；为空表示未声明，调用方应按拒绝
	// 或最小范围处理，不得假设为全部数据。
	DataScope string
}

// AccessController 是宿主注入的真实授权判定扩展。
//
// 实现要求：
//   - 必须基于真实会话/令牌/权限数据判定，不能把请求参数当作已获授权；
//   - 返回错误表示判定无法完成，调用方（Instance.CheckAccess）会按 fail-closed
//     拒绝，不会因为错误而放行；
//   - 不得修改请求、不得因为缺少依赖而返回 Allowed=true；
//   - 不得提供伪造 root 或关闭鉴权的旁路。
type AccessController interface {
	// CheckAccess 判定一个访问请求；返回 error 表示判定失败。
	CheckAccess(ctx context.Context, request AccessRequest) (AccessDecision, error)
}

// AccessControllerFunc 是 AccessController 的函数适配器。
type AccessControllerFunc func(ctx context.Context, request AccessRequest) (AccessDecision, error)

// CheckAccess 实现 AccessController。
func (f AccessControllerFunc) CheckAccess(ctx context.Context, request AccessRequest) (AccessDecision, error) {
	if f == nil {
		return AccessDecision{}, fmt.Errorf("授权判定函数为空")
	}
	return f(ctx, request)
}

// CheckAccess 通过宿主注入的 AccessController 做一次授权判定。
//
// 失败策略（fail-closed）：
//   - 请求结构非法 → REQ_INVALID，不调用扩展；
//   - 未注入 AccessController → 拒绝并返回 AUTHZ_UNAVAILABLE；
//   - 扩展返回错误、或返回 error 同时声称 Allowed=true → 拒绝并返回
//     AUTHZ_UNAVAILABLE，错误只保留为原因链，不改变为放行；
//   - 扩展正常返回 → 原样返回其判定（Allowed=false 也是正常拒绝）。
//
// system 身份不会自动获准；本方法没有「跳过判定」参数。可靠判定需要宿主装配
// 真实授权扩展，未装配时的拒绝是预期行为而不是故障。
//
// 与生命周期解耦：CheckAccess 不要求实例已启动，Start 之前或 Close 之后调用都
// 按同一规则委托给注入的 AccessController（未注入仍然拒绝），不会因为实例已关闭
// 而放行，也不依赖实例运行状态；宿主应自行保证只在服务可用期处理业务请求，就绪
// 判断请使用 Ready。
