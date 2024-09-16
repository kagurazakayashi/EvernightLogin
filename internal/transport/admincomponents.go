package transport

import (
	"fmt"
	"strings"
)

// 本文件定义管理 API OpenAPI 文档中的 schema 组件：统一信封、错误对象、各域公开
// DTO 与列表/流式响应。DTO 字段名取自 internal/adminapi 与 internal/serverapp 的
// 真实 JSON 投影（json tag/响应 map key），类型按公开语义标注为 string/integer/
// boolean/object/array；时间字段使用 date-time。嵌套大对象（诊断报告、快照）标记为
// 通用对象并在 description 说明字段以领域公开视图为准，不伪造不存在的字段名。

// adminSchemaType 把简写类型转换为 OpenAPI schema。
func adminSchemaType(fieldType string) map[string]any {
	switch fieldType {
	case "date-time":
		return map[string]any{"type": "string", "format": "date-time"}
	case "array<object>":
		return map[string]any{"type": "array", "items": map[string]any{"type": "object"}}
	case "array<string>":
		return map[string]any{"type": "array", "items": map[string]any{"type": "string"}}
	case "object":
		return map[string]any{"type": "object"}
	default:
		return map[string]any{"type": fieldType}
	}
}

// adminObject 构造带字段说明的对象 schema。
func adminObject(description string, fields map[string]string) map[string]any {
	properties := make(map[string]any, len(fields))
	for name, fieldType := range fields {
		properties[name] = adminSchemaType(fieldType)
	}
	return map[string]any{
		"type":        "object",
		"description": description,
		"properties":  properties,
	}
}

// adminGenericObject 构造字段以领域公开视图为准的通用对象 schema。
func adminGenericObject(description string) map[string]any {
	return map[string]any{
		"type":                 "object",
		"description":          description + "（字段名与层级以领域公开视图为准；本 schema 不伪造未确认字段）",
		"additionalProperties": true,
	}
}

// adminListSchema 构造分页列表 data schema：<key> 数组 + has_more/limit/offset + 额外键。
func adminListSchema(key, itemComponent, description string, extraKeys []string) (map[string]any, error) {
	if _, ok := AdminComponentSchemas()[itemComponent]; !ok {
		return nil, fmt.Errorf("列表项组件 %q 未登记", itemComponent)
	}
	properties := map[string]any{
		key:        map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/" + itemComponent}},
		"has_more": map[string]any{"type": "boolean", "description": "是否还有更多数据（按同一条件继续分页）。"},
		"limit":    map[string]any{"type": "integer", "description": "本次生效的每页条数。"},
		"offset":   map[string]any{"type": "integer", "description": "本次生效的偏移。"},
	}
	for _, extra := range extraKeys {
		switch extra {
		case "next_offset":
			properties["next_offset"] = map[string]any{"type": "integer",
				"description": "下一页 offset（游标/偏移组合时使用）；缺失表示无下一页。"}
		case "next_cursor":
			properties["next_cursor"] = map[string]any{"type": "string",
				"description": "稳定游标：下一页请求带 cursor；与 offset 互斥。"}
		case "order":
			properties["order"] = map[string]any{"type": "string", "description": "本次生效的稳定排序。"}
		case "scope":
			properties["scope"] = map[string]any{"type": "object", "description": "本次生效的数据范围（scope_id/scope_kind）。"}
		case "retention":
			properties["retention"] = map[string]any{"$ref": "#/components/schemas/AdminRetention"}
		case "scope_trimmed":
			properties["scope_trimmed"] = map[string]any{"type": "boolean",
				"description": "结果是否因调用者数据范围被裁剪（不表示跨范围数据被返回）。"}
		default:
			return nil, fmt.Errorf("列表额外键 %q 未登记", extra)
		}
	}
	return map[string]any{
		"type":        "object",
		"description": description,
		"properties":  properties,
		"required":    []string{key, "has_more", "limit", "offset"},
	}, nil
}

// AdminComponentSchemas 返回管理 API 的 schema 组件（名称 → OpenAPI schema）。
// 生成器与测试共用同一份定义，避免手写第二套字段。
func AdminComponentSchemas() map[string]any {
	return map[string]any{
		"AdminSuccessEnvelope": adminObject("管理 API 成功信封。", map[string]string{
			"ok": "boolean", "request_id": "string", "data": "object",
		}),
		"AdminErrorEnvelope": adminObject("管理 API 失败信封；错误码来自根包 errs 注册表。", map[string]string{
			"ok": "boolean", "code": "string", "message": "string", "request_id": "string",
		}),
		"AdminAuditActor": adminObject("审计事件操作者公开投影。", map[string]string{
			"type": "string", "id": "string",
		}),
		"AdminAuditTarget": adminObject("审计事件目标公开投影。", map[string]string{
			"type": "string", "id": "string",
		}),
		"AdminAuditChange": adminObject("已脱敏字段变更。", map[string]string{
			"field": "string", "before": "string", "after": "string",
		}),
		"AdminAuditEvent": adminObject("审计事件公开视图（不含秘密与原始日志）。", map[string]string{
			"id": "string", "occurred_at": "date-time", "actor": "object", "app_id": "string",
			"action": "string", "target": "object", "outcome": "string", "error_code": "string",
			"reason_code": "string", "request_id": "string", "task_id": "string",
			"changes": "array<object>",
		}),
		"AdminScope": adminObject("数据范围公开投影。", map[string]string{
			"id": "string", "kind": "string",
		}),
		"AdminRetention": adminObject("审计保留策略公开视图。", map[string]string{
			"days": "integer", "configured": "boolean", "version": "integer",
			"cutoff": "date-time", "updated_at": "date-time",
		}),
		"AdminTaskSummary": adminObject("后台任务公开摘要（不含任务载荷）。", map[string]string{
			"id": "string", "kind": "string", "state": "string", "executor_id": "string",
			"attempt": "integer", "max_attempts": "integer", "error_code": "string",
			"failure_reason": "string", "request_id": "string", "created_at": "date-time",
			"started_at": "date-time", "finished_at": "date-time",
		}),
		"AdminExport": adminObject("审计导出任务公开视图；异步任务“已提交/已接受取消”不等于完成/已取消。", map[string]string{
			"id": "string", "scope_id": "string", "scope_kind": "string", "format": "string",
			"state": "string", "requested_by": "object", "max_rows": "integer",
			"row_count": "integer", "truncated": "boolean", "task_id": "string",
			"file_available": "boolean", "file_expires_at": "date-time", "error_code": "string",
			"failure_reason": "string", "request_id": "string", "executor_id": "string",
			"created_at": "date-time", "started_at": "date-time", "finished_at": "date-time",
			"task": "object",
		}),
		"AdminPurgeRun": adminObject("审计清理运行公开视图；计数是真实扫描/清理结果。", map[string]string{
			"id": "string", "kind": "string", "scope_id": "string", "scope_kind": "string",
			"state": "string", "task_id": "string", "requested_by": "object", "cutoff": "date-time",
			"batch_size": "integer", "max_records": "integer", "scanned": "integer",
			"cleaned": "integer", "skipped": "integer", "failed": "integer", "batches": "integer",
			"limit_reached": "boolean", "error_code": "string", "failure_reason": "string",
			"request_id": "string", "executor_id": "string", "created_at": "date-time",
			"started_at": "date-time", "finished_at": "date-time", "task": "object",
		}),
		"AdminPurgePreview": adminObject("审计清理预演（只读，不删除数据）。", map[string]string{
			"scope_id": "string", "scope_kind": "string", "cutoff": "date-time",
			"batch_size": "integer", "max_records": "integer", "estimated_count": "integer",
			"at_least": "boolean", "retention": "object", "within_retention": "boolean",
			"maintenance_protected": "boolean", "artifacts_included": "boolean",
			"digest": "string", "generated_at": "date-time",
		}),
		"AdminCancelResult": adminObject("取消受理结果：accepted 只表示“已受理取消”，终态以任务/状态查询为准。", map[string]string{
			"state": "string", "accepted": "boolean", "already_requested": "boolean",
		}),
		"AdminReportHistoryItem": adminObject("报告历史列表项（按调用者数据范围裁剪）。", map[string]string{
			"id": "string", "plan_id": "string", "name": "string", "owner": "string",
			"scope_id": "string", "scope_kind": "string", "app_id": "string", "template": "string",
			"state": "string", "formats": "array<string>", "detail_rows": "integer",
			"artifacts": "array<object>", "task_id": "string", "executor_id": "string",
			"error_code": "string", "failure_reason": "string", "request_id": "string",
			"created_at": "date-time", "started_at": "date-time", "finished_at": "date-time",
			"expires_at": "date-time", "cleanup_state": "string",
		}),
		"AdminReportView": adminObject("报告详情公开视图。", map[string]string{
			"id": "string", "scope_id": "string", "scope_kind": "string", "state": "string",
			"formats": "array<string>", "requested_by": "object", "created_at": "date-time",
			"started_at": "date-time", "finished_at": "date-time", "generated_at": "date-time",
			"schema_version": "string", "template_version": "string", "overall_status": "string",
			"notes": "string", "artifacts": "array<object>", "artifact_expires_at": "date-time",
			"task_id": "string", "executor_id": "string", "error_code": "string",
			"failure_reason": "string", "request_id": "string", "retry_of": "string",
		}),
		"AdminReportSnapshot": adminGenericObject("报告快照（按报告模板/结构生成的只读数据；字段以领域快照定义为准）"),
		"AdminReportTicket": adminObject("一次性报告下载票据：token 只返回一次，绑定报告/格式/调用者，过期或重复兑换被拒绝。", map[string]string{
			"token": "string", "report_id": "string", "format": "string",
		}),
		"AdminReportCleanupPreview": adminObject("报告清理预演（只读）。", map[string]string{
			"policy": "object", "targets": "array<object>", "target_count": "integer",
			"total_bytes": "integer", "scopes": "array<object>", "oldest_expires_at": "date-time",
			"newest_expires_at": "date-time", "previewed_at": "date-time", "note": "string",
		}),
		"AdminReportCleanupResult": adminObject("报告清理真实结果。", map[string]string{
			"operator": "string", "started_at": "date-time", "finished_at": "date-time",
			"requested_count": "integer", "cleaned_count": "integer", "failed_count": "integer",
			"deleted_files": "integer", "freed_bytes": "integer", "skipped_count": "integer",
			"failures": "array<object>", "policy": "object", "raw_audit_note": "string",
		}),
		"AdminReportPlan": adminObject("报告生成计划公开视图。", map[string]string{
			"id": "string", "schedule_id": "string", "version": "integer", "name": "string",
			"enabled": "boolean", "permission_state": "string", "permission_reason": "string",
			"schedule_type": "string", "expression": "string", "time_zone": "string",
			"period_description": "string", "scope_id": "string", "scope_kind": "string",
			"window_days": "integer", "formats": "array<string>", "detail_rows": "integer",
			"max_catch_up": "integer", "timeout_seconds": "integer", "max_attempts": "integer",
			"owner": "string", "execution_actor": "string", "next_run": "date-time",
			"next_run_unknown": "boolean", "next_run_reason": "string",
			"created_at": "date-time", "updated_at": "date-time",
		}),
		"AdminPlanDeletePreview": adminObject("报告计划删除预演（含不可逆说明）。", map[string]string{
			"plan_id": "string", "name": "string", "scope_id": "string", "enabled": "boolean",
			"next_run": "date-time", "next_run_unknown": "boolean", "missed_policy": "string",
			"active_tasks_note": "string", "history_note": "string", "raw_audit_note": "string",
			"irreversible": "boolean", "permission_state": "string", "permission_reason": "string",
			"created_at": "date-time", "previewed_at": "date-time",
		}),
		"AdminBackupArtifact": adminObject("备份产物公开视图；file_exists/downloadable 反映真实可用性，不暴露宿主路径。", map[string]string{
			"backup_id": "string", "job_id": "string", "schedule_id": "string", "origin": "string",
			"size_bytes": "integer", "file_sha256": "string", "manifest_sha256": "string",
			"format_version": "string", "schema_version": "string", "content_database": "boolean",
			"content_attach": "boolean", "content_config": "boolean", "entry_count": "integer",
			"hostname": "string", "app_version": "string", "verification": "string",
			"verified_at": "date-time", "retention_version": "integer", "cleanup": "boolean",
			"cleaned_at": "date-time", "created_at": "date-time", "published_at": "date-time",
			"file_exists": "boolean", "is_last_usable": "boolean", "protection_reason": "string",
			"downloadable": "boolean",
		}),
		"AdminBackupJob": adminObject("备份任务公开视图；state/stage 是真实进展，进度不表示成功。", map[string]string{
			"id": "string", "kind": "string", "origin": "string", "schedule_id": "string",
			"state": "string", "stage_code": "string", "stage_description": "string",
			"progress_done": "integer", "progress_total": "integer", "progress_unit": "string",
			"attempt": "integer", "max_attempts": "integer", "initiator": "string",
			"error_code": "string", "failure_reason": "string", "request_id": "string",
			"backup_id": "string", "notification_state": "string", "notification_code": "string",
			"result_summary": "string", "created_at": "date-time", "started_at": "date-time",
			"finished_at": "date-time", "updated_at": "date-time",
		}),
		"AdminBackupSchedule": adminObject("备份计划公开视图（含下次运行与权限状态）。", map[string]string{
			"id": "string", "name": "string", "enabled": "boolean", "schedule_type": "string",
			"expression": "string", "time_zone": "string", "period_description": "string",
			"missed_policy": "string", "max_catch_up": "integer", "timeout_seconds": "integer",
			"max_attempts": "integer", "owner": "string", "execution_actor": "string",
			"scope_id": "string", "next_run": "date-time", "next_run_unknown": "boolean",
			"retention_version": "integer", "notify_failures": "boolean",
			"notify_success": "boolean", "last_scheduled_at": "date-time",
			"created_at": "date-time", "updated_at": "date-time", "permission_state": "string",
		}),
		"AdminBackupCapabilities": adminObject("当前部署的备份能力与下载票据有效期（秒）。", map[string]string{
			"read": "boolean", "create": "boolean", "cancel": "boolean", "download": "boolean",
			"retention": "boolean", "cleanup": "boolean", "download_ttl_seconds": "integer",
		}),
		"AdminBackupCreateResult": adminObject("备份/清理任务受理结果；existing=true 表示命中去重（未重复创建）。", map[string]string{
			"job_id": "string", "existing": "boolean", "state": "string",
		}),
		"AdminBackupCancelResult": adminObject("备份任务取消受理结果；accepted 不等于已取消。", map[string]string{
			"job_id": "string", "accepted": "boolean", "already_requested": "boolean",
			"state": "string", "note": "string",
		}),
		"AdminBackupTicket": adminObject("一次性备份下载票据：token 只返回一次，短期有效，兑换时再次授权并检查产物状态。", map[string]string{
			"backup_id": "string", "token": "string", "expires_at": "date-time",
		}),
		"AdminBackupRetention": adminObject("备份保留策略公开视图。", map[string]string{
			"policy": "object", "is_default": "boolean", "last_cleanup": "object",
		}),
		"AdminBackupCleanupPreview": adminObject("备份清理预演（只读；protected 表示受保留策略保护）。", map[string]string{
			"policy": "object", "targets": "array<object>", "protected": "array<object>",
			"total_retained": "integer", "total_bytes": "integer", "target_bytes": "integer",
			"previewed_at": "date-time", "note": "string",
		}),
		"AdminTaskAttempt": adminObject("任务尝试历史项。", map[string]string{
			"attempt": "integer", "started_at": "date-time", "finished_at": "date-time",
			"outcome": "string", "error_code": "string",
		}),
		"AdminTaskDetail": adminObject("任务详情（显式剔除任务载荷与秘密）。", map[string]string{
			"id": "string", "kind": "string", "state": "string", "initiator": "string",
			"executor_id": "string", "canceller": "string", "cancellation_reason": "string",
			"attempt": "integer", "max_attempts": "integer", "permission_required": "string",
			"timeout_seconds": "integer", "error_code": "string", "failure_reason": "string",
			"request_id": "string", "created_at": "date-time", "updated_at": "date-time",
			"started_at": "date-time", "cancel_requested_at": "date-time",
			"finished_at": "date-time", "next_attempt_at": "date-time", "deadline": "date-time",
			"attempts": "array<object>",
		}),
		"AdminTaskList": adminObject("任务列表项公开摘要。", map[string]string{
			"id": "string", "kind": "string", "state": "string", "initiator": "string",
			"executor_id": "string", "attempt": "integer", "max_attempts": "integer",
			"error_code": "string", "failure_reason": "string", "request_id": "string",
			"created_at": "date-time", "started_at": "date-time", "finished_at": "date-time",
		}),
		"AdminErrorCode": adminObject("错误码注册表条目（HTTP 状态与默认消息同源）。", map[string]string{
			"code": "string", "message": "string", "http_status": "integer",
		}),
		"AdminMeta": adminObject("管理 API 元信息（版本/直连路径/认证要求/服务与限制快照）。", map[string]string{
			"api_version": "string", "base_path": "string", "authentication": "object",
			"services": "object", "limits": "object",
		}),
		"AdminNotificationStatus": adminGenericObject("安全通知/邮件投递配置的脱敏状态（不包含 SMTP 密码等秘密）"),
		"AdminSecurityNotification": adminObject("安全告知分页记录（脱敏白名单：不含正文、验证码、链接；读取权限由 Reader 重新判定）。", map[string]string{
			"id": "string", "user_id": "string", "operation_id": "string",
			"target_type": "string", "target_id": "string", "outcome": "string",
			"state": "string", "error_code": "string", "reason_code": "string",
			"recipient_masked": "string", "delivery_id": "string",
			"delivery_state": "string", "delivery_error_code": "string",
			"created_at": "date-time",
		}),
		"AdminMailDelivery": adminObject("邮件投递记录分页项（脱敏白名单：不含加密载荷、完整收件人或磁盘路径）。", map[string]string{
			"delivery_id": "string", "kind": "string", "state": "string",
			"recipient_masked": "string", "owner_type": "string", "owner_id": "string",
			"attempts": "integer", "max_attempts": "integer", "last_error_code": "string",
			"request_id": "string", "created_at": "date-time", "updated_at": "date-time",
		}),
		"AdminNotificationTest": adminObject("本地捕获测试结果；real_delivery=false 表示绝不真实外发，捕获不等于通道可达。", map[string]string{
			"capture": "object", "delivery": "string", "real_delivery": "boolean",
		}),
		"AdminSupportCase": adminObject("客服求助单公开视图（目标邮箱/用户名按脱敏展示）。", map[string]string{
			"id": "string", "target_user_id": "string", "target_masked_username": "string",
			"target_masked_email": "string", "reason": "string", "status": "string",
			"assignee_user_id": "string", "created_by_user_id": "string",
			"created_at": "date-time", "updated_at": "date-time", "row_version": "integer",
		}),
		"AdminRecoveryRequest": adminObject("人工恢复申请公开视图（批准人/内容摘要与一致性；不含令牌、验证码或用户新秘密）。", map[string]string{
			"id": "string", "target_user_id": "string", "initiator_user_id": "string",
			"operation": "string", "status": "string", "delivery": "string", "reason": "string",
			"created_at": "date-time", "expires_at": "date-time", "approval": "object",
			"has_approval": "boolean", "approval_id": "string", "content_digest": "string",
			"content_consistent": "boolean", "failure_reason": "string",
		}),
		"AdminSupportListResult": adminObject("客服列表结果（items + has_more/next_offset，按数据范围裁剪）。", map[string]string{
			"items": "array<object>", "has_more": "boolean", "next_offset": "integer",
		}),
		"AdminSupportSimpleResult": adminObject("客服写操作的脱敏结果（按操作不同包含 id/status/sent 等字段）。", map[string]string{
			"id": "string", "status": "string", "sent": "boolean", "manual_review": "string",
			"rejected": "boolean", "cancelled": "boolean", "assignee_user_id": "string",
			"sessions_revoked": "integer", "factors_reset": "integer", "error_code": "string",
		}),
		"AdminDiagnosticsReport": adminGenericObject("脱敏运行诊断快照（只读；不含秘密/个人资料/内部连接细节）"),
		"AdminDiagnosticsErrors": adminGenericObject("按 request_id 关联的有界错误列表（只读脱敏）"),
		"AdminDiagnosticsExport": adminGenericObject("有界脱敏诊断导出（exported_at/report 及可选 errors）"),
		"AdminSettingsFields": adminObject("配置字段脱敏视图（秘密字段已遮盖；含磁盘/有效值/待重启标记）。", map[string]string{
			"configured": "boolean", "version": "string", "effective_version": "string",
			"fields": "array<object>", "hot_reloadable": "array<string>",
			"restart_required": "array<string>", "note": "string",
		}),
		"AdminSettingsStatus": adminObject("配置状态（磁盘/有效版本、待重载、最近错误码）。", map[string]string{
			"configured": "boolean", "version": "string", "effective_version": "string",
			"writable": "boolean", "pending_hot": "array<string>",
			"pending_restart": "array<string>", "host_reload_needed": "boolean",
			"last_error_code": "string", "last_write_version": "string",
		}),
		"AdminSettingsValidate": adminGenericObject("配置校验结果（不落盘）"),
		"AdminSettingsUpdate":   adminGenericObject("配置更新结果（原子写入 + 版本冲突检查）"),
		"AdminSettingsRestore":  adminGenericObject("敏感策略恢复结果（仅真实 root + 再次认证 + 版本冲突）"),
		"AdminDownloadStream": map[string]any{
			"type": "string", "format": "binary",
			"description": "受控文件流式字节。不暴露宿主路径；下载票据一次性、短期有效，兑换时再次授权并重新检查产物状态。",
		},
		"AdminDeletedArtifact": adminObject("删除结果。", map[string]string{
			"deleted": "boolean", "plan_id": "string", "schedule_id": "string",
		}),
		// ===== 步骤 269：用户/角色/组/权限/应用/会话（管理组）=====
		"AdminUserSummary": adminObject("用户列表/创建结果公开摘要（不含密码、邮箱等秘密）。", map[string]string{
			"id": "string", "username": "string", "nickname": "string", "status": "string",
			"row_version": "integer", "security_version": "integer",
			"created_at": "date-time", "updated_at": "date-time",
		}),
		"AdminUserDetail": adminObject("用户详情公开视图（不含密码/邮箱等秘密）。", map[string]string{
			"id": "string", "username": "string", "nickname": "string", "biography": "string",
			"language": "string", "timezone": "string", "status": "string",
			"row_version": "integer", "security_version": "integer",
			"created_at": "date-time", "updated_at": "date-time",
		}),
		"AdminUserValidity": adminObject("账户有效期公开视图（UTC；valid_from/valid_until 可为 null 表示不限制该端）。", map[string]string{
			"user_id": "string", "status": "string", "is_root": "boolean",
			"valid_from": "date-time", "valid_until": "date-time",
			"row_version": "integer", "available": "boolean", "reason": "string",
			"checked_at": "date-time",
		}),
		"AdminUserDeletionPreview": adminObject("删除用户影响预览（计数为真实关联数量，预览不是删除授权）。", map[string]string{
			"user_id": "string", "username": "string", "is_root": "boolean",
			"app_memberships": "integer", "user_roles": "integer",
			"group_memberships": "integer", "one_time_credentials": "integer",
			"owned_applications": "integer", "row_version": "integer",
		}),
		"AdminRoleSummary": adminObject("角色列表/创建结果公开摘要。", map[string]string{
			"id": "string", "scope_id": "string", "key": "string", "name": "string",
			"description": "string", "is_builtin": "boolean", "enabled": "boolean",
			"created_at": "date-time", "updated_at": "date-time",
		}),
		"AdminRoleDetail": adminObject("角色详情（limits 为使用边界说明）。", map[string]string{
			"id": "string", "scope_id": "string", "key": "string", "name": "string",
			"description": "string", "limits": "string", "is_builtin": "boolean",
			"enabled": "boolean", "created_at": "date-time", "updated_at": "date-time",
		}),
		"AdminRoleAssignmentUser": adminObject("角色分配给用户的条目（数据范围为稳定 ID/时间，不含跨域资料）。", map[string]string{
			"user_id": "string", "scope_id": "string", "data_scope": "object",
			"assigned_by": "string", "assigned_at": "date-time",
		}),
		"AdminRoleAssignmentGroup": adminObject("角色分配给用户组的条目。", map[string]string{
			"group_id": "string", "scope_id": "string", "data_scope": "object",
			"assigned_at": "date-time",
		}),
		"AdminGroupSummary": adminObject("用户组列表/创建结果公开摘要。", map[string]string{
			"id": "string", "scope_id": "string", "group_key": "string", "name": "string",
			"description": "string", "created_at": "date-time", "updated_at": "date-time",
		}),
		"AdminGroupMember": adminObject("用户组成员条目（只返回稳定 ID 与加入时间）。", map[string]string{
			"group_id": "string", "user_id": "string", "joined_at": "date-time",
		}),
		"AdminPermissionSummary": adminObject("权限定义公开摘要。", map[string]string{
			"id": "string", "key": "string", "name": "string", "scope_id": "string",
			"enabled": "boolean", "root_only": "boolean",
		}),
		"AdminApplicationSummary": adminObject("应用列表公开摘要。", map[string]string{
			"id": "string", "name": "string", "description": "string", "owner_user_id": "string",
			"status": "string", "client_type": "string", "scope_id": "string",
			"row_version": "integer", "created_at": "date-time", "updated_at": "date-time",
		}),
		"AdminApplicationDetail": adminObject("应用详情公开视图（不含客户端秘密）。", map[string]string{
			"id": "string", "name": "string", "description": "string", "homepage": "string",
			"owner_user_id": "string", "status": "string", "client_type": "string",
			"scope_id": "string", "row_version": "integer",
			"created_at": "date-time", "updated_at": "date-time",
		}),
		"AdminAppMember": adminObject("应用成员条目（应用内资料；不含全局秘密）。", map[string]string{
			"user_id": "string", "status": "string", "row_version": "integer",
			"created_at": "date-time", "updated_at": "date-time",
		}),
		"AdminAppManagedPolicy": adminObject("应用托管 API 委托策略公开视图（allowed/service_allowed 为操作 ID 列表，limits 为分页/批量上限）。", map[string]string{
			"state": "string", "application_id": "string", "row_version": "integer",
			"can_write": "boolean", "allowed": "array<string>",
			"service_allowed": "array<string>", "limits": "object",
		}),
		"AdminAppOAuthResult": adminObject("OAuth 客户端登记/更新结果：client_id 可公开；秘密只在登记时返回一次且不进入日志/审计。", map[string]string{
			"client_id": "string", "has_secret": "boolean",
		}),
		"AdminAppSecret": adminObject("应用客户端秘密轮换结果：secret 只在本次响应出现一次（shown_once=true），之后不可再读。", map[string]string{
			"secret_id": "string", "secret": "string", "shown_once": "boolean",
		}),
		"AdminAppCertificate": adminObject("应用证书登记结果（指纹公开，私钥永不返回）。", map[string]string{
			"id": "string", "fingerprint": "string",
		}),
		"AdminSessionSummary": adminObject("管理员会话查询摘要（不含会话秘密、CSRF 令牌或验证摘要；client 仅为展示参考）。", map[string]string{
			"id": "string", "app_id": "string", "kind": "string", "reason": "string",
			"created_at": "date-time", "last_seen_at": "date-time",
			"idle_expires_at": "date-time", "absolute_expires_at": "date-time",
			"remember_me": "boolean", "current": "boolean", "client": "object",
		}),
		"AdminSessionRevokeResult": adminObject("强制下线结果（revoked=实际撤销数量；确认不是授权，权限/强认证/root 保护由会话服务判定）。", map[string]string{
			"revoked": "integer", "scope_app_id": "string", "request_id": "string",
		}),
	}
}

// AdminSuccessDataSchema 把契约的 Success 声明解析为 OpenAPI schema。
//
// Success 取值：
//   - 组件名（如 AdminExport）：data 即该组件；
//   - "list:<key>:<itemComponent>"：分页列表，ExtraKeys 为额外键标记；
//   - "download"：流式二进制；
//   - "object"：对象，ExtraKeys 用 "name:type" 或 "name:ref:Component" 精确声明
//     顶层键（不留空泛 object）；ExtraKeys 为空时退化为通用对象。
func AdminSuccessDataSchema(success string, extraKeys []string) (map[string]any, error) {
	switch {
	case success == "":
		return nil, fmt.Errorf("缺少成功响应声明")
	case success == "object":
		if len(extraKeys) == 0 {
			return adminGenericObject("成功响应 data（操作特定字段见说明）"), nil
		}
		properties := make(map[string]any, len(extraKeys))
		for _, entry := range extraKeys {
			name, schema, err := adminObjectKeySchema(entry)
			if err != nil {
				return nil, err
			}
			properties[name] = schema
		}
		return map[string]any{
			"type":       "object",
			"properties": properties,
		}, nil
	case success == "download":
		return map[string]any{"$ref": "#/components/schemas/AdminDownloadStream"}, nil
	case strings.HasPrefix(success, "list:"):
		parts := strings.Split(strings.TrimPrefix(success, "list:"), ":")
		if len(parts) != 2 {
			return nil, fmt.Errorf("列表成功声明 %q 格式应为 list:<key>:<itemComponent>", success)
		}
		return adminListSchema(parts[0], parts[1], "分页列表结果；授权与数据范围先于分页/计数。", extraKeys)
	case strings.HasPrefix(success, "page:"):
		// 管理列表统一页结构：items 数组 + has_more/limit/offset/next_offset/sort/desc。
		parts := strings.Split(strings.TrimPrefix(success, "page:"), ":")
		if len(parts) != 2 {
			return nil, fmt.Errorf("页列表成功声明 %q 格式应为 page:<key>:<itemComponent>", success)
		}
		key, component := parts[0], parts[1]
		if _, ok := AdminComponentSchemas()[component]; !ok {
			return nil, fmt.Errorf("页列表项组件 %q 未登记", component)
		}
		return map[string]any{
			"type":        "object",
			"description": "管理列表页结果；授权与数据范围先于分页/计数。",
			"required":    []string{key, "has_more", "limit", "offset", "next_offset"},
			"properties": map[string]any{
				key: map[string]any{"type": "array", "items": map[string]any{
					"$ref": "#/components/schemas/" + component}},
				"has_more":    map[string]any{"type": "boolean", "description": "是否还有更多数据。"},
				"limit":       map[string]any{"type": "integer", "description": "本次生效的每页条数。"},
				"offset":      map[string]any{"type": "integer", "description": "本次生效的偏移。"},
				"next_offset": map[string]any{"type": "integer", "description": "下一页 offset。"},
				"sort":        map[string]any{"type": "string", "description": "本次生效的排序字段（空表示领域默认）。"},
				"desc":        map[string]any{"type": "boolean", "description": "是否降序。"},
			},
		}, nil
	default:
		if _, ok := AdminComponentSchemas()[success]; !ok {
			return nil, fmt.Errorf("成功响应组件 %q 未登记", success)
		}
		return map[string]any{"$ref": "#/components/schemas/" + success}, nil
	}
}

// adminObjectKeySchema 解析对象 data 的顶层键声明："name:type"、"name:ref:Component"
// 或 "name:refs:Component"（对象数组）。
func adminObjectKeySchema(entry string) (string, map[string]any, error) {
	parts := strings.Split(entry, ":")
	if len(parts) < 2 || strings.TrimSpace(parts[0]) == "" {
		return "", nil, fmt.Errorf("对象键声明 %q 格式应为 name:type / name:ref:Component / name:refs:Component", entry)
	}
	name := strings.TrimSpace(parts[0])
	if len(parts) == 3 && (parts[1] == "ref" || parts[1] == "refs") {
		component := strings.TrimSpace(parts[2])
		if _, ok := AdminComponentSchemas()[component]; !ok {
			return "", nil, fmt.Errorf("对象键 %s 引用的组件 %q 未登记", name, component)
		}
		ref := map[string]any{"$ref": "#/components/schemas/" + component}
		if parts[1] == "ref" {
			return name, ref, nil
		}
		return name, map[string]any{"type": "array", "items": ref}, nil
	}
	switch parts[1] {
	case "string", "integer", "boolean", "object", "array", "date-time", "array<object>", "array<string>":
		return name, adminSchemaType(parts[1]), nil
	default:
		return "", nil, fmt.Errorf("对象键 %s 的类型 %q 未登记", name, parts[1])
	}
}
