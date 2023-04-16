package app

import (
	"context"
	"net"
	"time"
)

// RootRequest 是首次 root 初始化请求。Password 只用于本次受限初始化，不保存、
// 不返回、不记录；调用方应尽快清空自己的副本。
type RootRequest struct {
	Username    string
	DisplayName string
	Password    string
	RequestID   string
}

// RootResult 是首次初始化结果（不含密码、密钥或会话）。
type RootResult struct {
	UserID             string
	State              string
	StrongAuthRequired bool
	SecurityVersion    int64
}

// CreateUserRequest 是宿主受信创建用户请求。
type CreateUserRequest struct {
	Username  string
	Password  string
	Email     string
	Nickname  string
	Language  string
	Timezone  string
	RequestID string
}

// User 是脱敏用户视图。
type User struct {
	ID        string
	Username  string
	Nickname  string
	Email     string
	Status    string
	CreatedAt time.Time
}

// LoginRequest 是一次密码登录请求（口令只用于本次验证）。
type LoginRequest struct {
	Username  string
	Password  string
	AppID     string
	ClientIP  string
	RequestID string
}

// LoginResult 是登录结果；SessionSecret 只在本结果出现一次。
type LoginResult struct {
	UserID        string
	SessionID     string
	SessionSecret []byte
	CSRFSecret    []byte
	ExpiresAt     time.Time
	Restricted    bool
	RequiredSteps []string
}

// AccessRequest 是联合权限检查请求（权限由业务服务端确定）。
type AccessRequest struct {
	UserID     string
	AppID      string
	Permission string
	Mode       string
	ResourceID string
	RequestID  string
}

// AccessDecision 是权限检查结果；Reason/Code 为稳定公开值。
type AccessDecision struct {
	Allowed     bool
	Code        string
	Reason      string
	RequestID   string
	Application string
}

// GrantRoleRequest 是宿主受信角色分配请求（Phase A 暂未开放，返回明确错误）。
type GrantRoleRequest struct {
	UserID string
	AppID  string
	RoleID string
}

// BootstrapService 是首次初始化门面。
type BootstrapService interface {
	EnsureRoot(ctx context.Context, req RootRequest) (RootResult, error)
}

// UserService 是宿主受信用户门面。
type UserService interface {
	Create(ctx context.Context, req CreateUserRequest) (User, error)
}

// AuthService 是密码登录门面。
type AuthService interface {
	Login(ctx context.Context, req LoginRequest) (LoginResult, error)
}

// AccessService 是联合权限检查门面。
type AccessService interface {
	Check(ctx context.Context, req AccessRequest) (AccessDecision, error)
}

// SessionService 会话语义有限：撤销当前会话。
type SessionService interface {
	Revoke(ctx context.Context, sessionSecret []byte) error
}

// AdminService 是受信管理门面；Phase A 不提供角色分配（留 146-149）。
type AdminService interface {
	GrantApplicationRole(ctx context.Context, req GrantRoleRequest) error
}

var _ = net.IP{}
