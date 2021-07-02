// Package securityevent 定义认证域安全事件的最小共享模型，供产生方（账户禁用、
// 会话退出、授权撤回、退出应用、应用成员变更）与通知实现（签名 Webhook）解耦。
//
// 设计边界：
//   - 本包是叶子包，不导入项目内部业务包，避免产生方与通知实现之间的循环依赖。
//   - Event 只承载稳定标识与严格白名单字段：不含密码、令牌、会话秘密、验证码、
//     签名密钥或自由文本；通知实现必须再次校验类型与数据白名单。
//   - Emitter 是可选依赖：未注入表示宿主未启用安全事件通知，产生方不得因此失败或
//     改变业务结果（撤销/禁用正确性不依赖通知）。
package securityevent

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Type 是安全事件类型（稳定字符串，写入 Webhook 事件体，不可随意改变含义）。
type Type string

const (
	// TypeUserDisabled 表示账户被禁用（用户级，通知用户仍为 active 成员的应用）。
	TypeUserDisabled Type = "user.disabled"
	// TypeUserEnabled 表示账户被重新启用。
	TypeUserEnabled Type = "user.enabled"
	// TypeSessionLoggedOut 表示单个会话被用户退出或管理员强制下线。
	TypeSessionLoggedOut Type = "session.logged_out"
	// TypeSessionAllRevoked 表示账户全部活动会话被批量撤销。
	TypeSessionAllRevoked Type = "session.all_revoked"
	// TypeAuthorizationRevoked 表示用户撤回某次应用授权。
	TypeAuthorizationRevoked Type = "oauth.authorization.revoked"
	// TypeAppLogout 表示用户退出某应用（撤销该应用下授权与在线标记）。
	TypeAppLogout Type = "app.logout"
	// TypeAppMembershipChanged 表示应用成员关系新增/启用/停用/移除。
	TypeAppMembershipChanged Type = "app.membership.changed"
)

// valid 报告事件类型是否已定义。
func (t Type) Valid() bool {
	switch t {
	case TypeUserDisabled, TypeUserEnabled, TypeSessionLoggedOut, TypeSessionAllRevoked,
		TypeAuthorizationRevoked, TypeAppLogout, TypeAppMembershipChanged:
		return true
	}
	return false
}

// Event 是一次待通知的安全事件。字段由产生方在业务操作成功后填充：
//   - ApplicationID 为空表示用户级事件，由通知实现按“该用户仍为 active 成员的应用”
//     扇出；非空表示只通知该应用的 Webhook 端点。
//   - IdempotencyKey 由产生方按逻辑事件稳定生成（8～128 字节），同一事件重复 Emit
//     返回既有记录，不重复投递。
//   - Data 是严格白名单的少量补充字段（状态/计数等），不含秘密与自由文本。
type Event struct {
	Type           Type
	ApplicationID  string
	UserID         string
	IdempotencyKey string
	OccurredAt     time.Time
	RequestID      string
	Data           map[string]string
}

// Emitter 是安全事件通知契约；生产实现为 internal/webhook.Service，nil 表示未启用。
// Emit 必须幂等（同一 IdempotencyKey 不重复创建投递），并在事件已可靠落库后返回。
// 端点/投递失败不得回滚或改变产生方已完成的业务操作。
type Emitter interface {
	Emit(ctx context.Context, event Event) error
}

// MaxIdempotencyKeyBytes 是幂等键长度上限（与 webhook 表约束一致）。
const MaxIdempotencyKeyBytes = 128

// Validate 校验事件的最小安全边界：类型已定义、主体标识有界、幂等键可用、数据
// 键值有界且不含控制字符/换行（防止把自由文本注入通知体）。
func (e Event) Validate() error {
	if !e.Type.Valid() {
		return fmt.Errorf("安全事件类型未定义")
	}
	if len(e.UserID) > 64 {
		return fmt.Errorf("安全事件用户标识过长")
	}
	if len(e.ApplicationID) > 128 {
		return fmt.Errorf("安全事件应用标识过长")
	}
	if len(e.RequestID) > 128 {
		return fmt.Errorf("安全事件请求编号过长")
	}
	if len(e.IdempotencyKey) < 8 || len(e.IdempotencyKey) > MaxIdempotencyKeyBytes {
		return fmt.Errorf("安全事件幂等键长度无效")
	}
	if e.OccurredAt.IsZero() {
		return fmt.Errorf("安全事件缺少发生时间")
	}
	if len(e.Data) > 8 {
		return fmt.Errorf("安全事件数据字段过多")
	}
	for key, value := range e.Data {
		if key == "" || len(key) > 32 || len(value) > 128 {
			return fmt.Errorf("安全事件数据字段长度无效")
		}
		if strings.ContainsFunc(key, func(r rune) bool { return r < 0x20 || r == 0x7f }) ||
			strings.ContainsFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return fmt.Errorf("安全事件数据字段包含控制字符")
		}
	}
	return nil
}
