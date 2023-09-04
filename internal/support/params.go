package support

// 步骤 188：客服敏感操作参数摘要的唯一构造器（service 与 CLI 的 186 证明共用）。

// ParamsCaseCreate 返回登记求助单的 Sensitive 参数（与 service.CreateCase 一致）。
func ParamsCaseCreate(targetUserID, reason, requestID string) map[string]string {
	return map[string]string{
		"target_user_id": targetUserID,
		"reason_sha256":  reasonDigest(reason),
		"request_id":     requestID,
	}
}

// ParamsCaseReassign 返回变更求助单指派的 Sensitive 参数。
func ParamsCaseReassign(caseID, targetUserID, newAssigneeUserID, requestID string) map[string]string {
	return map[string]string{
		"case_id":              caseID,
		"target_user_id":       targetUserID,
		"new_assignee_user_id": newAssigneeUserID,
		"request_id":           requestID,
	}
}

// ParamsCaseTransition 返回变更求助单状态的 Sensitive 参数。
func ParamsCaseTransition(caseID, targetUserID, toStatus, requestID string) map[string]string {
	return map[string]string{
		"case_id":        caseID,
		"target_user_id": targetUserID,
		"to_status":      toStatus,
		"request_id":     requestID,
	}
}

// ParamsResetSend 返回向目标原验证邮箱发送找回入口的 Sensitive 参数。
func ParamsResetSend(caseID, targetUserID, requestID string) map[string]string {
	return map[string]string{
		"case_id":        caseID,
		"target_user_id": targetUserID,
		"request_id":     requestID,
	}
}
