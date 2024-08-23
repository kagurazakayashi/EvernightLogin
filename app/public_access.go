package app

import (
	"context"
)

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

// AccessService 是联合权限检查门面。
type AccessService interface {
	Check(ctx context.Context, req AccessRequest) (AccessDecision, error)
}
