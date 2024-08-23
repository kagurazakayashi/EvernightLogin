package app

import (
	"context"
	"time"
)

// VerifiedSession 是第二步通过后签发的完整会话；秘密只返回一次。
type VerifiedSession struct {
	UserID        string
	SessionID     string
	SessionSecret []byte
	CSRFSecret    []byte
	ExpiresAt     time.Time
	// Method/Strength 是本次第二步因素与达到的认证强度（"totp"/"passkey"/"email"）。
	Method   string
	Strength string
}

// SessionDeviceRequest 是本人设备列表请求；SessionSecret 必须是仍有效且可访问普通
// 业务的会话秘密。
type SessionDeviceRequest struct {
	SessionSecret []byte
	Page          AdminPage
}

// SessionDevice 是设备列表的一条脱敏会话摘要（不含秘密/CSRF/验证摘要）。
type SessionDevice struct {
	ID                string
	AppID             string
	Kind              string
	Reason            string
	CreatedAt         time.Time
	LastSeenAt        time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	RememberMe        bool
	Current           bool
	ClientUserAgent   string
	ClientAddress     string
}

// SessionDeviceList 是本人设备列表结果。
type SessionDeviceList struct {
	Devices []SessionDevice
	Total   int64
	HasMore bool
	Page    AdminPageInfo
}

// SessionDeviceRevokeRequest 是本人退出指定设备的请求；身份只来自会话秘密。
type SessionDeviceRevokeRequest struct {
	SessionSecret   []byte
	TargetSessionID string
	RequestID       string
}

// SessionDeviceRevokeResult 是本人退出指定设备的结果；Revoked=false 表示目标
// 不属于本人、不存在或已失效（幂等，不泄露他人会话）。
type SessionDeviceRevokeResult struct {
	TargetSessionID string
	Revoked         bool
}

// SessionRevokeOthersRequest 是本人退出其他会话的请求；KeepCurrent=true 保留当前
// 会话，false 退出全部本人会话。
type SessionRevokeOthersRequest struct {
	SessionSecret []byte
	KeepCurrent   bool
	RequestID     string
}

// SessionRevokeOthersResult 是退出其他/全部会话的结果。
type SessionRevokeOthersResult struct {
	Revoked     int64
	KeptCurrent bool
}

// SessionService 会话语义：校验当前会话、应用+权限联合检查、撤销当前会话。
//
// 安全边界（步骤 208）：
//   - Validate 只证明“会话此刻有效且是完整会话”，不证明会话属于当前业务应用，
//     也不证明用户具备当前操作需要的权限；业务/管理操作禁止只靠 Validate 放行。
//     需要应用绑定与权限联合判断时使用 Authorize（复用既有授权内核）。
//   - ValidateCSRF 只校验与会话绑定的 CSRF 令牌；CSRF 通过不会提升受限会话权限，
//     也不代替 Application/权限判断。来源（Origin/Referer）仍由宿主 HTTP 防护层
//     负责，不能只靠 CSRF 令牌。
//   - 三个方法都不会延长会话。
type SessionService interface {
	Validate(ctx context.Context, sessionSecret []byte) (SessionInfo, error)
	ValidateCSRF(ctx context.Context, sessionSecret []byte, token string) error
	// Authorize 对一个完整（非受限）会话执行“应用绑定 + 所需权限”联合检查，复用
	// 既有授权内核（令牌/当前权限/应用状态/成员状态/数据范围交集语义由权限引擎
	// 保证）。CSRFToken 非空时先校验 CSRF，但 CSRF 通过不会提高授权结果；受限会话
	// 一律拒绝。授权拒绝以决策返回（Allowed=false + 稳定 Code/Reason，error 为 nil），
	// 只有会话无效、输入非法或内部故障才返回 error。
	Authorize(ctx context.Context, req SessionAccessRequest) (SessionAccessDecision, error)
	Revoke(ctx context.Context, sessionSecret []byte) error
	// ListDevices 分页列出当前会话所属用户的本人活动会话（设备列表）；不包含会话
	// 秘密/CSRF/验证摘要，offset 在并发登录/退出下不保证快照一致。
	ListDevices(ctx context.Context, req SessionDeviceRequest) (SessionDeviceList, error)
	// RevokeDevice 让当前会话本人退出指定的其他设备。目标不属于本人/不存在/已失效
	// 按幂等成功返回 Revoked=false，不泄露他人会话存在性；受限会话拒绝。
	RevokeDevice(ctx context.Context, req SessionDeviceRevokeRequest) (SessionDeviceRevokeResult, error)
	// RevokeOtherDevices 退出本人其他全部会话；KeepCurrent=true 时保留当前会话
	// （“退出其他设备”），false 时退出全部（含当前）。返回实际撤销数量。
	RevokeOtherDevices(ctx context.Context, req SessionRevokeOthersRequest) (SessionRevokeOthersResult, error)
}

// SessionAccessRequest 是“会话 + 应用绑定 + 所需权限”的联合检查请求。
//
// 安全语义：
//   - SessionSecret 必须来自可信边界（Cookie/Authorization 或宿主自己的安全存储），
//     不能来自 URL、查询参数或客户端自填字段；
//   - AppID 必填：会话没有当前应用边界时不能做业务授权判断；
//   - Permissions 必须是业务服务端确定的权限键，不能由客户端任意指定后当成“已授权”；
//     Mode 为空按 all 处理；
//   - CSRFToken 可选：适合写操作在同一个入口里同时校验 CSRF；它只参与校验，不会
//     提升会话或权限。
type SessionAccessRequest struct {
	SessionSecret []byte
	// AppID 是当前业务请求所属应用（"app_..." 稳定 ID）；必填。
	AppID string
	// Permissions 是当前操作需要的权限键（例如 "app.invoice.approve"）。
	Permissions []string
	// Mode 是 "all"（默认）或 "any"。
	Mode string
	// CSRFToken 是可选的会话绑定 CSRF 令牌；非空时先校验。
	CSRFToken string
	// RequestID 用于关联调用、领域审计与返回错误；空编号统一生成，非法编号拒绝。
	RequestID string
}

// SessionAccessDecision 是联合检查结果：Allowed=true 表示会话有效、属于当前应用
// 且具备所需权限；Allowed=false 时 Code/Reason 是稳定公开拒绝码与原因。
type SessionAccessDecision struct {
	UserID    string
	SessionID string
	AppID     string
	Allowed   bool
	Code      string
	Reason    string
	// RequestID 是与调用/审计/错误一致的请求编号。
	RequestID string
}

// SessionInfo 是校验通过后的会话快照；不含会话秘密和 CSRF 令牌。
type SessionInfo struct {
	UserID               string
	SessionID            string
	AppID                string
	ExpiresAt            time.Time
	IdleExpiresAt        time.Time
	CreatedAt            time.Time
	SecurityVersion      int64
	AuthMethods          []string
	StrongAuthVerifiedAt time.Time
}
