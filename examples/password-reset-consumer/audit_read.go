// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package main

// 只读审计诊断：外部回归程序需要区分“公开响应防枚举”与“管理/审计诊断可辨别”。
//
// 本文件用外部模块自己的 SQLite 依赖（modernc.org/sqlite）以只读模式打开测试临时
// 数据库，读取 password.reset_* 审计行；**不写入任何数据**，不修改认证状态，也不
// 冒充管理接口。生产管理入口仍是管理 API/CLI/页面，这里仅用于验收证据。

import (
	"database/sql"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

// auditEvidence 是一条只读审计诊断行（脱敏字段）。
type auditEvidence struct {
	Action     string `json:"action"`
	Outcome    string `json:"outcome"`
	ReasonCode string `json:"reason_code,omitempty"`
	ErrorCode  string `json:"error_code,omitempty"`
	TargetType string `json:"target_type,omitempty"`
	RequestID  string `json:"request_id,omitempty"`
}

// readAuditDiagnostics 以只读方式读取找回相关审计行（不含秘密/邮箱/目标原始值）。
func readAuditDiagnostics(dbPath string) ([]auditEvidence, error) {
	if strings.TrimSpace(dbPath) == "" {
		return nil, fmt.Errorf("审计诊断缺少数据库路径")
	}
	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("以只读方式打开测试数据库失败: %w", err)
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	rows, err := db.Query(`SELECT action,outcome,COALESCE(reason_code,''),COALESCE(error_code,''),
COALESCE(target_type,''),COALESCE(request_id,'') FROM audit_events WHERE action LIKE 'password.reset%'
ORDER BY occurred_at_ms ASC`)
	if err != nil {
		return nil, fmt.Errorf("读取找回审计行失败: %w", err)
	}
	defer func() { _ = rows.Close() }()
	evidence := make([]auditEvidence, 0, 16)
	for rows.Next() {
		var item auditEvidence
		if err := rows.Scan(&item.Action, &item.Outcome, &item.ReasonCode,
			&item.ErrorCode, &item.TargetType, &item.RequestID); err != nil {
			return nil, fmt.Errorf("扫描审计行失败: %w", err)
		}
		evidence = append(evidence, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("读取审计行失败: %w", err)
	}
	return evidence, nil
}

// auditHasRequestID 报告审计证据中是否存在指定请求编号的行（208 编号贯穿断言）。
func auditHasRequestID(evidence []auditEvidence, requestID string) bool {
	if requestID == "" {
		return false
	}
	for _, item := range evidence {
		if item.RequestID == requestID {
			return true
		}
	}
	return false
}

// auditHasReason 在审计证据中查找包含指定原因/错误码的行（诊断分离断言用）。
func auditHasReason(evidence []auditEvidence, fragments ...string) bool {
	for _, item := range evidence {
		text := strings.ToLower(item.ReasonCode + "|" + item.ErrorCode + "|" + item.Outcome)
		matched := true
		for _, fragment := range fragments {
			if !strings.Contains(text, strings.ToLower(fragment)) {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}
