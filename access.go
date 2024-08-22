package login

// 公开授权契约位于 access/，本文件只保留 Instance.CheckAccess 的根实现与
// 既有错误映射；类型别名见 alias_contracts.go。

import (
	"context"
	"strings"
)

// CheckAccess 通过宿主注入的 AccessController 做一次授权判定。
//
// 失败策略（fail-closed）：
//   - 请求结构非法 → REQ_INVALID，不调用扩展；
//   - 未注入 AccessController → 拒绝并返回 AUTHZ_UNAVAILABLE；
//   - 扩展返回错误、或返回 error 同时声称 Allowed=true → 拒绝并返回
//     AUTHZ_UNAVAILABLE，错误只保留为原因链，不改变为放行；
//   - 扩展正常返回 → 原样返回其判定（Allowed=false 也是正常拒绝）。
//
// system 身份不会自动获准；本方法没有「跳过判定」参数。
func (i *Instance) CheckAccess(ctx context.Context, request AccessRequest) (AccessDecision, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return AccessDecision{}, NewAppError(CodeAuthzUnavailable, "授权判定已取消",
			WithCause(err), WithRequestID(NewRequestID()))
	}
	if err := request.Validate(); err != nil {
		return AccessDecision{}, NewAppError(CodeReqInvalid, "访问请求无效",
			WithCause(err), WithRequestID(NewRequestID()))
	}

	i.mu.Lock()
	controller := i.embedded.accessControl
	i.mu.Unlock()
	if controller == nil {
		return AccessDecision{}, NewAppError(CodeAuthzUnavailable,
			"未配置授权扩展，访问被拒绝", WithRequestID(NewRequestID()))
	}

	decision, err := controller.CheckAccess(ctx, request)
	if err != nil {
		return AccessDecision{}, NewAppError(CodeAuthzUnavailable,
			"授权判定失败，访问被拒绝", WithCause(err), WithRequestID(NewRequestID()))
	}
	if decision.Allowed && strings.TrimSpace(decision.Reason) == "" {
		// 允许判定必须带稳定原因，避免出现无法解释的放行。
		return AccessDecision{}, NewAppError(CodeAuthzUnavailable,
			"授权扩展返回了无原因的放行结果，访问被拒绝", WithRequestID(NewRequestID()))
	}
	return decision, nil
}
