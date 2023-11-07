package app

// 稳定游标列表的公开辅助（步骤 218）。216 的 AdminPage 是 offset 分页契约；
// 审计事件、报告历史、后台任务等会持续追加的大流水使用服务端不透明游标：
//   - 游标由服务端生成，绑定查询范围与筛选条件；客户端只原样回传；
//   - 非法/篡改/筛选不匹配由领域服务返回 REQ_INVALID，本文件只做长度与 limit 的
//     公开输入边界检查，不复制领域的摘要校验；
//   - 游标分页不提供总数，也不与 offset 混用。

import (
	"github.com/kagurazakayashi/EvernightLogin"
)

const (
	// AdminMaxCursorBytes 是调用方可回传游标的最大长度（防御性上限）。
	AdminMaxCursorBytes = 4096
)

// normalizeAdminCursorLimit 规范化游标列表的每页条数：0 使用默认 20，非法值返回
// REQ_INVALID；与 216 的 AdminPage Limit 语义一致。
func normalizeAdminCursorLimit(limit int) (int, error) {
	if limit == 0 {
		limit = AdminDefaultPageLimit
	}
	if limit < 0 || limit > AdminMaxPageLimit {
		return 0, login.NewAppError(login.CodeReqInvalid,
			"每页数量必须在 1～100 之间（0 表示使用默认 20）")
	}
	return limit, nil
}

// normalizeAdminCursor 校验调用方回传的游标长度；内容绑定由领域服务校验。
func normalizeAdminCursor(cursor string) (string, error) {
	if len(cursor) > AdminMaxCursorBytes {
		return "", login.NewAppError(login.CodeReqInvalid, "游标过长")
	}
	return cursor, nil
}

// normalizeAdminPage 规范化 offset 列表的分页输入（复用 216 契约）。
func normalizeAdminPage(page AdminPage) (AdminPage, error) {
	return NormalizeAdminPage(page)
}
