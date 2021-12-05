package adminapi

import (
	"errors"
	"net/http"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
)

// 通知读取/测试端点的稳定能力码。它们与 cmd/loginctl 的既有诊断码同名同义
// （管理 API 传输层能力码），不属于根包 HTTP 业务错误码注册表，因此不加入
// emittedErrorCodes；响应仍是统一错误 envelope，带 request_id 与稳定 code。
const (
	// codeNotificationTestDisabled 表示宿主未注入本地捕获 notifier，通知测试被禁用。
	codeNotificationTestDisabled = "NOTIFICATION_TEST_DISABLED"
	// codeMailDiagnosticsUnavailable 表示通知配置/投递通道未装配，无法读取或测试。
	codeMailDiagnosticsUnavailable = "MAIL_DIAGNOSTICS_UNAVAILABLE"
)

// DeliveryModeLocalCapture 是唯一允许执行通知测试的投递模式；任何其他值
// （smtp/webhook/空）都按真实投递处理并拒绝。
const DeliveryModeLocalCapture = "local_capture"

// capabilityProblem 构造“能力未装配”的稳定错误响应：固定 503，不读取根包
// 注册表投影（这两个码是管理 API/CLI 的诊断能力码），但保持统一 envelope 与
// request_id，消息直白说明原因。
func (s *Server) capabilityProblem(code, message string, cause error) *problem {
	return &problem{status: http.StatusServiceUnavailable, code: code,
		message: message, cause: cause}
}

// handleNotificationStatus 处理 GET /notifications：返回脱敏的通知配置/启用状态。
// 仅返回是否存在可用投递通道、是否本地捕获与渠道键；不返回 SMTP/密钥/收件地址。
func (s *Server) handleNotificationStatus(c *callContext) error {
	if s.notifications == nil {
		return s.capabilityProblem(codeMailDiagnosticsUnavailable,
			"通知配置与投递通道尚未装配", nil)
	}
	status, err := s.notifications.NotificationStatus(c.request.Context(), c.caller)
	if err != nil {
		if errors.Is(err, reauth.ErrReauthRequired) {
			return s.codeProblem(string(codeReauthRequired), err)
		}
		return s.capabilityProblem(codeMailDiagnosticsUnavailable,
			"通知配置暂时不可读取", err)
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{"notifications": status})
	return nil
}

// notificationTestInput 是通知测试请求体；必须显式确认。
type notificationTestInput struct {
	Confirm bool `json:"confirm"`
}

// handleNotificationTest 处理 POST /notifications/test。
//
// 安全约束：禁止真实外发。只在宿主注入本地捕获 notifier、且敏感策略与真实审计
// 均可用时执行；任一缺失 fail-closed：
//   - 未注入 notifier → 503 NOTIFICATION_TEST_DISABLED；
//   - 未装配敏感策略（reauth）→ 403 REAUTH_REQUIRED；
//   - 审计不可用 → 503 MAIL_DIAGNOSTICS_UNAVAILABLE；
//   - 未确认 → 400 REQ_INVALID。
//
// 测试结果只返回捕获摘要（捕获编号、渠道键、脱敏接收者、时间），不含正文/秘密。
func (s *Server) handleNotificationTest(c *callContext) error {
	var input notificationTestInput
	if err := c.decodeJSON(&input); err != nil {
		return err
	}
	if err := requireConfirm(input.Confirm); err != nil {
		return err
	}
	if s.notifications == nil {
		return s.capabilityProblem(codeNotificationTestDisabled,
			"本地捕获通知器未装配，通知测试已禁用（不会真实外发）", nil)
	}
	// 执行前核验投递模式：只有宿主明确声明“本地捕获/不真实投递”才允许测试。
	// 不能仅凭注入接口就假设安全——若宿主误注入真实投递实现，必须 fail-closed，
	// 否则可能真实外发且响应 real_delivery=false 失真。
	status, statusErr := s.notifications.NotificationStatus(c.request.Context(), c.caller)
	if statusErr != nil {
		s.recordNotificationRejection(c, "notification_status_unavailable", statusErr)
		return s.capabilityProblem(codeNotificationTestDisabled,
			"无法确认通知投递模式，通知测试已拒绝", statusErr)
	}
	if !status.LocalCapture || status.DeliveryMode != DeliveryModeLocalCapture {
		s.recordNotificationRejection(c, "notification_real_delivery_refused", nil)
		return s.capabilityProblem(codeNotificationTestDisabled,
			"当前通知实现不是本地捕获模式，禁止执行通知测试（不会真实外发）", nil)
	}
	// 敏感策略（strong reauth）必填：未装配时拒绝，不静默降级。
	if problem := s.authorizeSensitive(c.request.Context(), c.caller,
		OperationNotificationTest, "system", "notification", "", c.requestID,
		map[string]string{"mode": "local_capture"}); problem != nil {
		return problem
	}
	// 关键操作要求真实审计可用；审计不可用时拒绝测试，不留下虚假成功。
	if s.auditRecorder == nil {
		return s.capabilityProblem(codeMailDiagnosticsUnavailable,
			"安全审计不可用，通知测试被拒绝", nil)
	}
	result, err := s.notifications.TestNotification(c.request.Context(),
		c.caller, c.requestID)
	event := audit.Event{
		Actor:     c.caller.Actor(),
		Action:    "notifications.test",
		Target:    audit.Target{Type: "notification", ID: firstNonEmpty(result.Channel, "local_capture")},
		RequestID: c.requestID,
	}
	if err != nil {
		event.Outcome = audit.OutcomeFailure
		event.ErrorCode = string(codeMailFailed)
		event.ReasonCode = "notification_test_failed"
		if recordErr := s.auditRecorder.RecordFailure(c.request.Context(), event); recordErr != nil {
			return s.codeProblem(string(codeAuditWriteFailed), recordErr)
		}
		if errors.Is(err, reauth.ErrReauthRequired) {
			return s.codeProblem(string(codeReauthRequired), err)
		}
		return s.codeProblem(string(codeMailFailed), err)
	}
	event.Outcome = audit.OutcomeSuccess
	if err := s.auditRecorder.Record(c.request.Context(), event); err != nil {
		return s.codeProblem(string(codeAuditWriteFailed), err)
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{"capture": result,
		"delivery": DeliveryModeLocalCapture, "real_delivery": false})
	return nil
}

// recordNotificationRejection 尽力写入拒绝审计；审计不可用时不改变拒绝结论。
func (s *Server) recordNotificationRejection(c *callContext, reasonCode string, cause error) {
	if s.auditRecorder == nil {
		return
	}
	event := audit.Event{
		Actor: c.caller.Actor(), Action: "notifications.test",
		Target:    audit.Target{Type: "notification", ID: "local_capture"},
		Outcome:   audit.OutcomeFailure,
		ErrorCode: string(codeAccessDenied), ReasonCode: reasonCode,
		RequestID: c.requestID,
	}
	if recordErr := s.auditRecorder.RecordFailure(c.request.Context(), event); recordErr != nil {
		s.logger.Warn("通知测试拒绝审计写入失败", "request_id", c.requestID,
			"error_category", "audit_unavailable")
	}
	_ = cause
}
