package manualrecovery

import (
	"context"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// Store 是人工恢复持久化契约，由 internal/manualrecovery/sqlite 提供 SQLite 实现。
//
// 实现约束：
//   - 所有 *Tx 方法必须使用调用方给出的 audit.Tx，与成功审计在同一事务提交；
//     任何一步失败整体回滚。
//   - 状态迁移使用条件更新（匹配当前状态与行版本），并发审批/执行只有一方成功。
//   - 同一请求最多一个 active 批准（唯一索引）；同一批准最多一次执行（唯一索引）。
//   - 不保存证据明文、密码、MFA 秘密、恢复代码或凭证/token。
type Store interface {
	// InsertRequestTx 在审计事务内创建申请。
	InsertRequestTx(ctx context.Context, tx audit.Tx, record RequestRecord) error
	// GetRequest 按 ID 读取申请。
	GetRequest(ctx context.Context, requestID string) (RequestRecord, bool, error)
	// ListRequests 按状态（可选）与发起者（可选）列出申请，按创建时间倒序；
	// 返回 hasMore 表示还有更多行。只读，不改变状态；不用于授权决策。
	ListRequests(ctx context.Context, statuses []Status, initiatorUserID string,
		offset, limit int) ([]RequestRecord, bool, error)
	// TransitionRequestTx 条件迁移申请状态：必须匹配期望状态（多次并发迁移只有
	// 一方成功）；同时递增行版本并写入结局原因。更新后返回当前记录。
	TransitionRequestTx(ctx context.Context, tx audit.Tx, requestID string, from, to Status,
		closedReason string, now time.Time) (bool, error)
	// InsertApprovalTx 在审计事务内插入批准记录。
	InsertApprovalTx(ctx context.Context, tx audit.Tx, record ApprovalRecord) error
	// GetActiveApproval 返回请求当前 active 批准。
	GetActiveApproval(ctx context.Context, requestID string) (ApprovalRecord, bool, error)
	// GetLatestApproval 返回请求最近一次批准（含已消费/失效/过期历史），供页面展示
	// 真实批准时间窗口；没有批准时返回 false。只读，不改变任何状态。
	GetLatestApproval(ctx context.Context, requestID string) (ApprovalRecord, bool, error)
	// ApproverHistory 报告指定用户是否曾是该请求的审批人（含已消费/失效历史），
	// 供审批后仍可查看申请（历史参与人授权）。
	ApproverHistory(ctx context.Context, requestID, approverUserID string) (bool, error)
	// FinishApprovalTx 条件结束 active 批准（consumed/invalidated/expired）。
	FinishApprovalTx(ctx context.Context, tx audit.Tx, approvalID string, status ApprovalStatus,
		reason string, now time.Time) (bool, error)
	// ClaimExecutionTx 条件把请求 approved→executing 并创建 running 执行记录；返回
	// 是否赢得本次唯一执行权。
	ClaimExecutionTx(ctx context.Context, tx audit.Tx, record RequestRecord, execution ExecutionRecord,
		now time.Time) (bool, error)
	// GetExecution 按请求读取执行记录。
	GetExecution(ctx context.Context, requestID string) (ExecutionRecord, bool, error)
	// FinishExecutionTx 在审计事务内条件完成执行（running→终态）、请求终态与批准结束；
	// 任一条件不满足返回 false 并整体回滚。
	FinishExecutionTx(ctx context.Context, tx audit.Tx, requestID, executionID, approvalID string,
		executionStatus string, requestStatus Status, approvalStatus ApprovalStatus,
		outcome ExecutionOutcome, errorCode, notificationState string, now time.Time) (bool, error)
	// SetNotificationState 在独立事务中记录通知结果（通知失败不回滚已完成的恢复）。
	SetNotificationState(ctx context.Context, requestID, state string) error
}
