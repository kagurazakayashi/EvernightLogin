package adminapi

import (
	"fmt"
	"time"

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
	result, err := s.sessionRevoker.AdminRevoke(withExplicitConfirm(c.request.Context()), secret,
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

// handleSessionAdminList 处理 GET /sessions（步骤 187）：按目标用户与作用范围查询
// 当前活动会话。强认证、sessions.revoke 范围授权、root/受保护目标拒绝与读取审计
// 全部由会话服务判定；本层只解析查询参数、转交与序列化，不含任何秘密。
func (s *Server) handleSessionAdminList(c *callContext) error {
	secret, ok := s.session.SessionSecretFromRequest(c.request)
	if !ok || secret == "" {
		return s.codeProblem(string(codeAccessDenied), nil)
	}
	page, err := queryInt(c.request, "page", 1, 1, 100000)
	if err != nil {
		return err
	}
	pageSize, err := queryInt(c.request, "page_size", 20, 1, 100)
	if err != nil {
		return err
	}
	requestID := firstNonEmpty(c.request.URL.Query().Get("request_id"), c.requestID)
	result, err := s.sessionLister.AdminListSessions(c.request.Context(), secret,
		session.AdminSessionListRequest{
			ScopeAppID:   c.request.URL.Query().Get("scope_app_id"),
			TargetUserID: c.request.URL.Query().Get("target_user_id"),
			Page:         page,
			PageSize:     pageSize,
			RequestID:    requestID,
		})
	if err != nil {
		return s.sessionProblem(err)
	}
	items := make([]map[string]any, 0, len(result.Sessions))
	for _, item := range result.Sessions {
		items = append(items, sessionSummaryJSON(item))
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{
		"target_user_id": result.TargetUserID,
		"scope_app_id":   result.ScopeAppID,
		"page":           result.Page,
		"page_size":      result.PageSize,
		"total":          result.Total,
		"has_more":       result.HasMore,
		"sessions":       items,
	})
	return nil
}

// sessionSummaryJSON 序列化管理员会话查询的公开摘要；绝不包含会话秘密、CSRF
// 令牌或验证摘要。Client 字段只是展示参考（UserAgent 自称、Address 无地理含义）。
func sessionSummaryJSON(item session.SessionSummary) map[string]any {
	return map[string]any{
		"id":                  item.ID,
		"app_id":              item.AppID,
		"kind":                string(item.Kind),
		"reason":              string(item.Reason),
		"created_at":          item.CreatedAt.UTC().Format(time.RFC3339),
		"last_seen_at":        item.LastSeenAt.UTC().Format(time.RFC3339),
		"idle_expires_at":     item.IdleExpiresAt.UTC().Format(time.RFC3339),
		"absolute_expires_at": item.AbsoluteExpiresAt.UTC().Format(time.RFC3339),
		"remember_me":         item.RememberMe,
		"current":             item.Current,
		"client": map[string]any{
			"user_agent": item.Client.UserAgent,
			"address":    item.Client.Address,
		},
	}
}
