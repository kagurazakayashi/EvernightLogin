package app

// 公开管理列表的统一分页契约（步骤 216）。
//
// 目的：用户、用户组、角色、权限与关联列表在 Go 门面、管理 HTTP API、CLI 与页面
// 使用同一套默认值/最大值/非法输入语义与结果元数据，避免每个入口各写一份。
//
// 语义与边界：
//   - Limit=0 使用默认值 20；显式负值或超过 100 由 NormalizeAdminPage 拒绝
//     （REQ_INVALID），不静默放大或截断；
//   - Offset 必须在 0～1_000_000 之间（深分页上限，避免昂贵扫描）；
//   - HasMore 表示“按当前排序在 offset+本页条数之后仍有记录”，本门面不返回总条数，
//     避免对增长列表做无界 COUNT；
//   - NextOffset 只是下一页建议值；offset 分页在并发新增/删除/重排下**不保证快照
//     一致**（可能重复或跳过）。需要稳定导出的宿主应使用稳定游标或快照，而不是依赖
//     offset 翻页；
//   - 授权与可见字段过滤在各领域服务先于分页/计数执行，本类型不携带任何数据范围。

import (
	"github.com/kagurazakayashi/EvernightLogin"
)

const (
	// AdminDefaultPageLimit 是公开管理列表默认每页条数。
	AdminDefaultPageLimit = 20
	// AdminMaxPageLimit 是公开管理列表允许的最大每页条数。
	AdminMaxPageLimit = 100
	// AdminMaxPageOffset 是 offset 分页允许的最大偏移（深分页上限）。
	AdminMaxPageOffset = 1_000_000
)

// AdminPage 是公开管理列表的统一分页输入。
type AdminPage struct {
	Limit  int
	Offset int
}

// AdminPageInfo 是公开管理列表的统一分页结果元数据（不含总条数）。
type AdminPageInfo struct {
	// Limit/Offset 是本次实际生效的分页参数（默认值已解析）。
	Limit  int
	Offset int
	// Returned 是本页返回的条目数。
	Returned int
	// HasMore 表示当前排序下本页之后仍有记录。
	HasMore bool
	// NextOffset 是下一页建议 offset（= Offset+Returned）；HasMore=false 时可忽略。
	NextOffset int
}

// NormalizeAdminPage 规范化公开分页输入：零值使用默认每页条数；非法 Limit/Offset
// 返回稳定的 REQ_INVALID 公开错误（不静默截断，也不执行任何领域查询）。
func NormalizeAdminPage(page AdminPage) (AdminPage, error) {
	limit := page.Limit
	if limit == 0 {
		limit = AdminDefaultPageLimit
	}
	if limit < 0 || limit > AdminMaxPageLimit {
		return AdminPage{}, login.NewAppError(login.CodeReqInvalid,
			"每页数量必须在 1～100 之间（0 表示使用默认 20）")
	}
	if page.Offset < 0 || page.Offset > AdminMaxPageOffset {
		return AdminPage{}, login.NewAppError(login.CodeReqInvalid,
			"分页偏移必须在 0～1000000 之间")
	}
	return AdminPage{Limit: limit, Offset: page.Offset}, nil
}

// NewAdminPageInfo 构造分页结果元数据；returned 是本页实际返回条数。
func NewAdminPageInfo(page AdminPage, returned int, hasMore bool) AdminPageInfo {
	if returned < 0 {
		returned = 0
	}
	return AdminPageInfo{
		Limit: page.Limit, Offset: page.Offset, Returned: returned,
		HasMore: hasMore, NextOffset: page.Offset + returned,
	}
}
