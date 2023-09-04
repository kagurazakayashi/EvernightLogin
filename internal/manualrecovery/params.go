package manualrecovery

// 步骤 188：把敏感操作参数摘要的构造收敛为唯一实现，供领域服务与 CLI 的 186 证明
// 绑定共用，避免 CLI 复制摘要算法导致 begin --params 与领域 Authorize 不一致。

// ParamsRequest 返回发起人工恢复申请的 Sensitive 参数（与 service.Create 一致）。
func ParamsRequest(targetUserID string, operation OperationType, basis VerificationBasis,
	reference, evidenceSummary, delivery, supportCaseID string) map[string]string {
	return map[string]string{
		"target_user_id":         targetUserID,
		"operation_type":         string(operation),
		"verification_basis":     string(basis),
		"verification_reference": reference,
		"evidence_digest":        digestHex(digestString(evidenceSummary))[:16],
		"delivery_channel":       delivery,
		"support_case_id":        supportCaseID,
	}
}

// ParamsApprove 返回独立审批/拒绝的 Sensitive 参数。
func ParamsApprove(record RequestRecord, decision string) map[string]string {
	params := map[string]string{
		"request_id":     record.ID,
		"target_user_id": record.TargetUserID,
		"operation_type": string(record.Operation),
	}
	if decision == "reject" {
		params["decision"] = "reject"
		return params
	}
	params["content_digest"] = digestHex(record.ContentDigest)
	return params
}

// ParamsExecute 返回执行人工恢复的 Sensitive 参数。
func ParamsExecute(record RequestRecord, approval ApprovalRecord) map[string]string {
	return map[string]string{
		"request_id":     record.ID,
		"approval_id":    approval.ID,
		"target_user_id": record.TargetUserID,
		"operation_type": string(record.Operation),
		"content_digest": digestHex(record.ContentDigest),
	}
}

// ParamsApproveRaw 供 CLI 从只读详情投影构造审批/拒绝的 Sensitive 参数（与
// ParamsApprove 同一键集合），避免 CLI 自行猜测摘要/字段。
func ParamsApproveRaw(requestID, targetUserID, operation, contentDigestHex, decision string) map[string]string {
	params := map[string]string{
		"request_id": requestID, "target_user_id": targetUserID, "operation_type": operation,
	}
	if decision == "reject" {
		params["decision"] = "reject"
		return params
	}
	params["content_digest"] = contentDigestHex
	return params
}

// ParamsExecuteRaw 供 CLI 从只读详情投影构造执行的 Sensitive 参数。
func ParamsExecuteRaw(requestID, approvalID, targetUserID, operation, contentDigestHex string) map[string]string {
	return map[string]string{
		"request_id": requestID, "approval_id": approvalID, "target_user_id": targetUserID,
		"operation_type": operation, "content_digest": contentDigestHex,
	}
}
