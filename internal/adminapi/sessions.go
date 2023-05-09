package adminapi

import (
	"fmt"

	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// sessionAdminRevokeInput 是 POST /sessions/revoke 的请求体。
//
// 目标用户与目标会话必须且只能给出一个；scope_app_id 为空表示系统范围，非空
// 表示仅撤销绑定该应用范围的会话（应用范围管理员不得跨应用）。confirm 只是
// 明确后果的交互要求，不是授权；权限、强认证、root 保护与审计由会话服务重新判定。
type sessionAdminRevokeInput struct {
	Confirm         bool   `json:"confirm"`
	ScopeAppID      string `json:"scope_app_id"`
	TargetUserID    string `json:"target_user_id"`
	TargetSessionID string `json:"target_session_id"`
	RequestID       string `json:"request_id"`
	Reason          string `json:"reason"`
}

// handleSessionAdminRevoke 处理 POST /sessions/revoke（步骤 151）。
func (s *Server) handleSessionAdminRevoke(c *callContext) error {
	var input sessionAdminRevokeInput
	if err := c.decodeJSON(&input); err != nil {
		return err
	}
	if err := requireConfirm(input.Confirm); err != nil {
		return err
	}
	if input.Reason == "" || len([]rune(input.Reason)) > MaxReasonBytes {
		return fmt.Errorf("%w: 必须提供不超过 %d 字符的理由", ErrInvalidRequest, MaxReasonBytes)
	}
	secret, ok := s.session.SessionSecretFromRequest(c.request)
	if !ok || secret == "" {
		return s.codeProblem(string(codeAccessDenied), nil)
	}
	result, err := s.sessionRevoker.AdminRevoke(c.request.Context(), secret,
		session.AdminRevokeRequest{
			ScopeAppID:      input.ScopeAppID,
			TargetUserID:    input.TargetUserID,
			TargetSessionID: input.TargetSessionID,
			RequestID:       firstNonEmpty(input.RequestID, c.requestID),
			Reason:          input.Reason,
		})
	if err != nil {
		return s.sessionProblem(err)
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{
		"revoked":      result.Revoked,
		"scope_app_id": input.ScopeAppID,
		"request_id":   c.requestID,
	})
	return nil
}
