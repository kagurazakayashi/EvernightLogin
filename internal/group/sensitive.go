package group

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
)

// SensitiveRunner 是敏感操作收敛入口（生产实现 *reauth.Service）。nil 时保持既有
// Authorizer/委派 Guard 保守校验；接线后组成员变更作为额外前置必须通过策略。
type SensitiveRunner = reauth.OperationRunner

// authorizeSensitive 执行敏感策略前置判定；失败一律 fail-closed 为 ACCESS_DENIED，
// 不替代也不绕过既有委派 Guard 的事务内检查。
func (s *Service) authorizeSensitive(ctx context.Context, caller Caller, operationID, targetType,
	targetID string, params map[string]string) (reauth.Result, error) {
	if s.sensitive == nil {
		if s.allowLegacy {
			// 显式过渡开关：沿用既有 Authorizer/委派 Guard 保守校验。
			return reauth.Result{}, nil
		}
		// 未装配敏感策略时默认拒绝敏感操作，不静默跳过步骤 38 策略。
		return reauth.Result{}, ErrAccessDenied
	}
	guardCaller, err := reauth.CallerFromActor(caller.actor)
	if err != nil {
		return reauth.Result{}, ErrAccessDenied
	}
	result, err := s.sensitive.Authorize(ctx, guardCaller, reauth.Request{
		ScopeID: "system", OperationID: operationID, TargetType: targetType, TargetID: targetID,
		Params: params, Description: "用户组成员变更", RequestID: caller.requestID,
	})
	if err != nil {
		return reauth.Result{}, fmt.Errorf("%w: %w", ErrAccessDenied, err)
	}
	return result, nil
}

// notifySensitive 发送成功告知；失败不回滚已完成变更。
func (s *Service) notifySensitive(ctx context.Context, result reauth.Result) {
	if s.sensitive == nil || result.OperationID == "" {
		return
	}
	if err := s.sensitive.NotifyOutcome(ctx, result, reauth.OutcomeSuccess); err != nil {
		s.logger.Warn("组成员变更安全告知未完成", "error", err)
	}
}

// memberSetDigest 对规范化后的成员 ID 集合计算稳定摘要（排序去重后连结再 SHA-256）。
// 批准必须绑定完整集合，避免“批准加 1 人、实际加 N 人或换人”。
func memberSetDigest(userIDs []string) (string, error) {
	if len(userIDs) == 0 {
		return "", nil
	}
	normalized := make([]string, 0, len(userIDs))
	seen := make(map[string]struct{}, len(userIDs))
	for _, userID := range userIDs {
		value := strings.TrimSpace(userID)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	sort.Strings(normalized)
	sum := sha256.Sum256([]byte(strings.Join(normalized, "\x00")))
	return hex.EncodeToString(sum[:]), nil
}
