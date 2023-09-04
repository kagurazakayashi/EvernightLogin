package manualrecovery

// 步骤 188：独立审批人/执行人的待办列表与账号关系投影。
//
// 安全不变量：
//   - 列表只返回最小必要字段；目标标识经服务端脱敏，完整目标仅在参与者详情读取
//     （GetRequest/GetRequestForApproval/GetRequestForPage）通过后展示。
//   - 候选集来自真实存储（按状态与发起者过滤），逐条按当前 StaffAuthorizer 资格与
//     参与关系过滤；任何授权依赖错误按 fail-closed 跳过该条（不返回未判权项）。
//   - 只读，不改变申请/批准/执行状态；不写“参与人读取被拒”的误导审计。

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// ListMode 是列表模式。
type ListMode string

const (
	// ListModeInitiated 是我发起的申请。
	ListModeInitiated ListMode = "initiated"
	// ListModePendingApproval 是当前待我审批的申请（逐条复核审批资格）。
	ListModePendingApproval ListMode = "pending_approval"
	// ListModeExecutable 是等待期已过、当前待我执行的申请（逐条复核执行资格与三权分离）。
	ListModeExecutable ListMode = "executable"
	// ListModeHistory 是我参与的近期历史（发起者/审批人）。
	ListModeHistory ListMode = "history"
)

// ListRequest 是列表查询参数。
type ListRequest struct {
	Mode      ListMode
	Operation OperationType // 空表示两种操作类型
	Offset    int
	Limit     int
}

// ListItem 是列表最小必要字段（Q6 裁决）；不含秘密/完整目标标识。
type ListItem struct {
	RequestID     string
	SupportCaseID string
	Operation     OperationType
	Status        Status
	TargetMasked  string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	// MyRelation 是当前人与该申请的关系：initiator/approver/executor/
	// candidate_approver/candidate_executor。
	MyRelation string
}

// ListPage 是列表结果。
type ListPage struct {
	Items      []ListItem
	HasMore    bool
	NextOffset int
}

// ListForPage 返回当前工作人员的待办/历史列表；仅用于页面与 CLI 只读展示。
func (s *Service) ListForPage(ctx context.Context, caller Caller, request ListRequest) (ListPage, error) {
	ctx = normalizeContext(ctx)
	if err := s.requireEnabled(ctx, caller, "list"); err != nil {
		return ListPage{}, err
	}
	if !caller.IsUser() || s.opts.Staff == nil {
		return ListPage{}, ErrAccessDenied
	}
	limit := request.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	if request.Offset < 0 {
		return ListPage{}, fmt.Errorf("%w: 分页偏移无效", ErrInvalidRequest)
	}
	var statuses []Status
	var initiator string
	switch request.Mode {
	case ListModeInitiated, ListModeHistory:
		// 发起者自己的申请（history 只列当前参与过且非终态/近期的自己申请；
		// 审批人历史需要额外 join，本版先返回“我发起的”，页面能力提示如实）。
		initiator = caller.actor.ID
		statuses = nil
	case ListModePendingApproval:
		statuses = []Status{StatusPendingApproval}
	case ListModeExecutable:
		statuses = []Status{StatusApproved}
	default:
		return ListPage{}, fmt.Errorf("%w: 列表模式无效", ErrInvalidRequest)
	}
	records, hasMore, err := s.opts.Store.ListRequests(ctx, statuses, initiator,
		request.Offset, limit+1)
	if err != nil {
		return ListPage{}, ErrStoreUnavailable
	}
	items := make([]ListItem, 0, len(records))
	for _, record := range records {
		if len(items) >= limit {
			hasMore = true
			break
		}
		if request.Operation != "" && record.Operation != request.Operation {
			continue
		}
		relation, ok := s.listRelation(ctx, caller, record, request.Mode)
		if !ok {
			continue
		}
		items = append(items, ListItem{
			RequestID: record.ID, SupportCaseID: record.SupportCaseID,
			Operation: record.Operation, Status: record.Status,
			TargetMasked: maskUserID(record.TargetUserID),
			CreatedAt:    record.CreatedAt, ExpiresAt: record.ExpiresAt,
			MyRelation: relation,
		})
	}
	next := request.Offset + len(items)
	return ListPage{Items: items, HasMore: hasMore, NextOffset: next}, nil
}

// listRelation 判定当前人与申请的关系；不满足当前模式资格时返回 false（跳过）。
func (s *Service) listRelation(ctx context.Context, caller Caller, record RequestRecord,
	mode ListMode) (string, bool) {
	if caller.actor.ID == record.InitiatorUserID {
		if mode == ListModeInitiated || mode == ListModeHistory {
			return "initiator", true
		}
		return "", false
	}
	if caller.actor.ID == record.TargetUserID {
		return "", false
	}
	switch mode {
	case ListModePendingApproval:
		if record.Status != StatusPendingApproval {
			return "", false
		}
		if err := s.opts.Staff.AuthorizeApproval(ctx, caller.actor.ID, record.TargetUserID,
			scopeSystem, record.Operation); err != nil {
			return "", false
		}
		return "candidate_approver", true
	case ListModeExecutable:
		if record.Status != StatusApproved {
			return "", false
		}
		approval, found, err := s.opts.Store.GetActiveApproval(ctx, record.ID)
		if err != nil || !found {
			return "", false
		}
		if caller.actor.ID == approval.ApproverUserID {
			return "", false
		}
		if s.now().UTC().Before(approval.NotBefore) || !s.now().UTC().Before(approval.ExpiresAt) {
			return "", false
		}
		if err := s.opts.Staff.AuthorizeExecution(ctx, caller.actor.ID, record.TargetUserID,
			record.Operation); err != nil {
			return "", false
		}
		return "candidate_executor", true
	default:
		return "", false
	}
}

// maskUserID 返回服务端脱敏的用户标识（保留前缀与末 4 位；不输出完整 ID）。
func maskUserID(userID string) string {
	trimmed := strings.TrimSpace(userID)
	if len(trimmed) <= 8 {
		return "****"
	}
	prefixEnd := strings.IndexByte(trimmed, '_')
	if prefixEnd < 0 || prefixEnd > 4 {
		prefixEnd = 0
	}
	prefix := trimmed[:prefixEnd+1]
	if len(prefix) > 4 {
		prefix = prefix[:4]
	}
	return prefix + "****" + trimmed[len(trimmed)-4:]
}
