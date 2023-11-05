package app

// 公开有界分页遍历辅助（步骤 220）。
//
// 目的：宿主与 CLI 需要对 216/217 的公开列表（用户、用户组、角色/权限、应用/
// 成员、角色关联、会话/设备）做“按页处理”而不是手工拼 offset 循环。本文件提供
// 可选的流式迭代器，复用 app.AdminPage / app.AdminPageInfo 契约，不新增全量
// 端点，也不替代单页列表方法；小调用者继续直接使用各领域单页 API。
//
// 安全与边界：
//   - 迭代器不解释授权、应用范围或字段可见性；这些必须由调用方在 fetch 里调用
//     带可信 Caller / ScopeID 的领域列表方法完成。迭代器只负责遍历边界。
//   - 默认有界：MaxPages=0 使用 DefaultIterationMaxPages，MaxItems=0 使用
//     DefaultIterationMaxItems；调用方不能通过“不设上限”一次拉取全表。
//   - context 取消后立即停止且不再发起 fetch；fetch/visit 错误向上返回，不吞掉，
//     同时返回已处理的部分结果。
//   - offset 分页在并发新增/删除/重排下不保证快照一致（与 AdminPageInfo 契约
//     相同）；需要稳定导出的调用方应使用稳定游标或快照，而不是本迭代器。
//   - 防止重复/回退 offset 与“空页但 HasMore”造成的死循环；结果元数据与请求
//     不一致时按 ErrPageNotAdvancing 停止，不继续翻页。

import (
	"context"
	"errors"
	"fmt"

	"github.com/kagurazakayashi/EvernightLogin"
)

const (
	// DefaultIterationMaxPages 是未显式设置 MaxPages 时的默认最大页数。
	DefaultIterationMaxPages = 10
	// MaxIterationMaxPages 是调用方允许设置的最大页数上限。
	MaxIterationMaxPages = 1000
	// DefaultIterationMaxItems 是未显式设置 MaxItems 时的默认最大处理条目数。
	DefaultIterationMaxItems = 1000
	// MaxIterationMaxItems 是调用方允许设置的最大条目数上限。
	MaxIterationMaxItems = 100000
)

// 迭代停止原因（IterationResult.StopReason 的稳定取值）。
const (
	// IterationStopComplete 表示已到达列表末尾（HasMore=false）。
	IterationStopComplete = "complete"
	// IterationStopMaxPages 表示达到调用方/默认最大页数而提前停止。
	IterationStopMaxPages = "max_pages"
	// IterationStopMaxItems 表示达到调用方/默认最大条目数而提前停止（可能截断
	// 当前页的尾部条目）。
	IterationStopMaxItems = "max_items"
	// IterationStopContextCanceled 表示 context 被取消/超时后停止。
	IterationStopContextCanceled = "context_canceled"
	// IterationStopFetchError 表示某页读取失败后停止。
	IterationStopFetchError = "fetch_error"
	// IterationStopVisitError 表示访问回调返回错误后停止。
	IterationStopVisitError = "visit_error"
)

// ErrPageNotAdvancing 表示分页没有可靠前进：重复/回退 offset、空页却声明有更多、
// NextOffset 与返回条数不一致，或调用方 fetch 返回的分页元数据与请求不一致。
// 调用方应停止翻页并检查领域列表实现或并发变更，不能忽略后继续循环。
var ErrPageNotAdvancing = errors.New("分页未前进")

// IterationOptions 是有界遍历配置。
//
// Page 是起始页：Limit=0 使用 AdminDefaultPageLimit，Offset 通常为 0，也可从
// 中间页开始；非法 Limit/Offset 返回 REQ_INVALID。MaxPages/MaxItems 为 0 时使用
// 安全默认值；负值或超过上限返回 REQ_INVALID。两者同时生效，先达到者停止。
type IterationOptions struct {
	Page     AdminPage
	MaxPages int
	MaxItems int
}

// IterationResult 是一次遍历的结果与明确的部分语义。调用方通过 Complete 判断
// 是否到达列表末尾，通过 Stopped/StopReason 判断是否因上限或取消提前停止；
// 条目本身由 visit 流式处理，迭代器不保留全部条目。
type IterationResult struct {
	// Pages 是成功读取并处理（至少尝试 visit）的页数。
	Pages int
	// Items 是实际交给 visit 的条目数（截断时按实际交付计数）。
	Items int
	// LastPage 是最后成功读取页的分页元数据；未读取任何页时为零值。
	LastPage AdminPageInfo
	// Complete 表示已到达列表末尾（最后一页 HasMore=false）。
	Complete bool
	// Stopped 表示因上限、取消或错误提前停止；此时 Complete 通常为 false。
	Stopped bool
	// StopReason 是稳定停止原因（IterationStop* 常量之一）；Complete 时是
	// IterationStopComplete。
	StopReason string
}

// IterateAdminPages 按 AdminPage 契约有界遍历列表。
//
// fetch 负责调用具体领域列表方法并返回本页条目与分页元数据；visit 逐页消费
// 条目（流式，不整表驻留）。两者都不能为 nil。迭代器保证：
//   - 每页 fetch/visit 前检查 context；取消后不再调用 fetch；
//   - 默认最多 10 页/1000 项，可显式调小；超过上限返回部分结果与 nil 错误；
//   - 达到 MaxItems 时只把当前页允许的前缀交给 visit，并标记 max_items 停止；
//   - 分页未前进（重复/回退 offset、空页 HasMore、NextOffset 不一致）返回
//     ErrPageNotAdvancing，不无限循环；
//   - fetch/visit 错误原样包装返回，同时返回已处理的部分结果。
//
// 返回的 error 为 nil 表示遍历按计划完成或按上限停止；取消返回 ctx.Err()；
// 调用方应同时检查 IterationResult 的部分语义。
func IterateAdminPages[T any](ctx context.Context, options IterationOptions,
	fetch func(ctx context.Context, page AdminPage) (items []T, info AdminPageInfo, err error),
	visit func(ctx context.Context, info AdminPageInfo, items []T) error,
) (IterationResult, error) {
	if ctx == nil {
		return IterationResult{}, login.NewAppError(login.CodeReqInvalid, "缺少上下文")
	}
	if fetch == nil || visit == nil {
		return IterationResult{}, login.NewAppError(login.CodeReqInvalid,
			"分页遍历需要 fetch 与 visit 回调")
	}
	page, err := NormalizeAdminPage(options.Page)
	if err != nil {
		return IterationResult{}, err
	}
	maxPages := options.MaxPages
	if maxPages == 0 {
		maxPages = DefaultIterationMaxPages
	}
	if maxPages < 0 || maxPages > MaxIterationMaxPages {
		return IterationResult{}, login.NewAppError(login.CodeReqInvalid,
			fmt.Sprintf("最大页数必须在 1～%d 之间（0 表示默认 %d）",
				MaxIterationMaxPages, DefaultIterationMaxPages))
	}
	maxItems := options.MaxItems
	if maxItems == 0 {
		maxItems = DefaultIterationMaxItems
	}
	if maxItems < 0 || maxItems > MaxIterationMaxItems {
		return IterationResult{}, login.NewAppError(login.CodeReqInvalid,
			fmt.Sprintf("最大条目数必须在 1～%d 之间（0 表示默认 %d）",
				MaxIterationMaxItems, DefaultIterationMaxItems))
	}

	result := IterationResult{}
	seenOffsets := make(map[int]struct{}, maxPages)
	for {
		if ctxErr := ctx.Err(); ctxErr != nil {
			result.Stopped = true
			result.StopReason = IterationStopContextCanceled
			return result, ctxErr
		}
		if result.Pages >= maxPages {
			result.Stopped = true
			result.StopReason = IterationStopMaxPages
			return result, nil
		}
		if result.Items >= maxItems {
			result.Stopped = true
			result.StopReason = IterationStopMaxItems
			return result, nil
		}
		if _, duplicate := seenOffsets[page.Offset]; duplicate {
			return result, fmt.Errorf("%w: offset %d 重复出现", ErrPageNotAdvancing, page.Offset)
		}
		seenOffsets[page.Offset] = struct{}{}

		items, info, fetchErr := fetch(ctx, page)
		if fetchErr != nil {
			result.Stopped = true
			result.StopReason = IterationStopFetchError
			return result, fmt.Errorf("第 %d 页读取失败: %w", result.Pages+1, fetchErr)
		}
		if contractErr := checkPageContract(page, items, info); contractErr != nil {
			result.Stopped = true
			result.StopReason = IterationStopFetchError
			result.LastPage = info
			return result, contractErr
		}

		deliver := items
		truncated := false
		if remaining := maxItems - result.Items; len(deliver) > remaining {
			deliver = deliver[:remaining]
			truncated = true
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			result.Stopped = true
			result.StopReason = IterationStopContextCanceled
			return result, ctxErr
		}
		visitInfo := info
		if truncated {
			// 只交付前缀时，把元数据也调整为“本次实际交付”的口径，避免 visit
			// 误以为整页都已处理；同时保留仍有更多数据的语义。
			visitInfo.Returned = len(deliver)
			visitInfo.NextOffset = page.Offset + len(deliver)
			visitInfo.HasMore = true
		}
		if len(deliver) > 0 {
			if visitErr := visit(ctx, visitInfo, deliver); visitErr != nil {
				result.Stopped = true
				result.StopReason = IterationStopVisitError
				result.LastPage = visitInfo
				return result, fmt.Errorf("第 %d 页处理失败: %w", result.Pages+1, visitErr)
			}
		}
		result.Pages++
		result.Items += len(deliver)
		result.LastPage = visitInfo
		if truncated {
			result.Stopped = true
			result.StopReason = IterationStopMaxItems
			return result, nil
		}
		if !info.HasMore {
			result.Complete = true
			result.StopReason = IterationStopComplete
			return result, nil
		}
		page = AdminPage{Limit: info.Limit, Offset: info.NextOffset}
	}
}

// checkPageContract 校验 fetch 返回的分页元数据与请求/条目一致：请求回显一致、
// Returned 等于实际条目数、HasMore 时 NextOffset 必须严格前进且等于
// Offset+Returned；空页不允许声明 HasMore。任何不一致都返回 ErrPageNotAdvancing，
// 避免上游实现缺陷导致无限翻页。
func checkPageContract[T any](page AdminPage, items []T, info AdminPageInfo) error {
	if info.Limit != page.Limit || info.Offset != page.Offset {
		return fmt.Errorf("%w: 分页元数据与请求不一致（请求 limit=%d offset=%d，返回 limit=%d offset=%d）",
			ErrPageNotAdvancing, page.Limit, page.Offset, info.Limit, info.Offset)
	}
	if info.Returned != len(items) {
		return fmt.Errorf("%w: Returned=%d 与实际条目数 %d 不一致",
			ErrPageNotAdvancing, info.Returned, len(items))
	}
	expectedNext := page.Offset + info.Returned
	if info.NextOffset != expectedNext {
		return fmt.Errorf("%w: NextOffset=%d，期望 %d（offset+returned）",
			ErrPageNotAdvancing, info.NextOffset, expectedNext)
	}
	if info.HasMore {
		if info.Returned == 0 {
			return fmt.Errorf("%w: 空页声明 HasMore", ErrPageNotAdvancing)
		}
		if info.NextOffset <= page.Offset {
			return fmt.Errorf("%w: NextOffset=%d 未前进（offset=%d）",
				ErrPageNotAdvancing, info.NextOffset, page.Offset)
		}
	}
	return nil
}
