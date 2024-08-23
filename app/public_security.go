package app

import (
	"context"
	"time"
)

// TOTPBindingBeginRequest 开始绑定 TOTP（敏感操作 mfa.add，需要近期密码验证）。
type TOTPBindingBeginRequest struct {
	SessionSecret []byte
	// Password 是本次敏感操作再次认证的密码；服务端不会保存它。
	Password  string
	RequestID string
}

// TOTPBindingStart 是 TOTP 绑定开始结果；Secret/OTPAuthURL 只返回一次。
type TOTPBindingStart struct {
	BindingID     string
	Secret        string
	OTPAuthURL    string
	ExpiresAt     time.Time
	PeriodSeconds int
	Digits        int
}

// TOTPBindingConfirmRequest 用一次性验证码确认 TOTP 绑定。
type TOTPBindingConfirmRequest struct {
	SessionSecret []byte
	BindingID     string
	Code          string
	RequestID     string
}

// TOTPBinding 是已激活 TOTP 绑定的脱敏元数据。
type TOTPBinding struct {
	BindingID   string
	Status      string
	CreatedAt   time.Time
	ActivatedAt time.Time
}

// SecurityStatusRequest 查询当前账户的认证/恢复能力概览。
type SecurityStatusRequest struct {
	SessionSecret []byte
	RequestID     string
}

// SecurityStatus 是认证/恢复能力概览（不含秘密或代码）。
type SecurityStatus struct {
	TOTPActive             bool
	EmailFactorActive      bool
	PasskeyEnabled         bool
	PasskeyCount           int
	RecoveryCodesRemaining int
	StrongFactorBound      bool
}

// SecurityService 是认证/安全设置门面：敏感操作经真实再次认证后执行。
type SecurityService interface {
	// Status 返回当前账户的认证/恢复能力概览。
	Status(ctx context.Context, req SecurityStatusRequest) (SecurityStatus, error)
	// BeginTOTPBinding 开始绑定 TOTP（敏感操作 mfa.add，需要近期密码验证）。
	BeginTOTPBinding(ctx context.Context, req TOTPBindingBeginRequest) (TOTPBindingStart, error)
	// ConfirmTOTPBinding 用一次性验证码确认 TOTP 绑定。
	ConfirmTOTPBinding(ctx context.Context, req TOTPBindingConfirmRequest) (TOTPBinding, error)
	// GenerateRecoveryCodes 生成新一组恢复代码（敏感操作，需要近期认证）。
	GenerateRecoveryCodes(ctx context.Context, req RecoveryCodesRequest) (RecoveryCodes, error)
}
