package managecli

// 步骤 220：CLI 有界列表遍历辅助。
//
// 列表命令默认保持单页 --limit/--offset 行为；显式 --all 时使用公开
// app.IterateAdminPages 有界遍历（默认最多 10 页/1000 项，可用 --max-pages/
// --max-items 调小或调大但不超过公开上限）。--all 与 --offset 互斥；--limit
// 在 --all 下作为每页大小。迭代只负责边界；授权/范围仍由各列表命令的领域服务
// 判定，不改变单页输出契约。

import (
	"context"
	"errors"
	"fmt"
	appapi "github.com/kagurazakayashi/EvernightLogin/app"
	"github.com/kagurazakayashi/EvernightLogin/errs"
	"strings"
)

// listIterationOptions 是 CLI 列表遍历参数。
type listIterationOptions struct {
	All      bool
	MaxPages int
	MaxItems int
}

// listIterationFlagDefs 返回各列表命令追加的遍历 flags。
func listIterationFlagDefs() []flagDef {
	return []flagDef{
		{name: "all", value: false},
		{name: "max-pages", value: true},
		{name: "max-items", value: true},
	}
}

// parseListIterationOptions 解析并校验遍历参数：
//   - --max-pages/--max-items 仅能与 --all 一起使用；
//   - 0 表示使用公开默认（10 页/1000 项），负数或超过公开上限拒绝；
//   - --all 与 --offset 互斥（--limit 可作每页大小）。
func parseListIterationOptions(values map[string]string) (listIterationOptions, error) {
	options := listIterationOptions{All: boolFlag(values, "all")}
	maxPages, err := parseIntFlag(values, "max-pages", 0)
	if err != nil {
		return listIterationOptions{}, err
	}
	if maxPages < 0 || maxPages > appapi.MaxIterationMaxPages {
		return listIterationOptions{}, fmt.Errorf("--max-pages 必须在 1～%d 之间（0 表示默认 %d）",
			appapi.MaxIterationMaxPages, appapi.DefaultIterationMaxPages)
	}
	maxItems, err := parseIntFlag(values, "max-items", 0)
	if err != nil {
		return listIterationOptions{}, err
	}
	if maxItems < 0 || maxItems > appapi.MaxIterationMaxItems {
		return listIterationOptions{}, fmt.Errorf("--max-items 必须在 1～%d 之间（0 表示默认 %d）",
			appapi.MaxIterationMaxItems, appapi.DefaultIterationMaxItems)
	}
	options.MaxPages = maxPages
	options.MaxItems = maxItems
	if !options.All {
		if maxPages != 0 || maxItems != 0 {
			return listIterationOptions{}, errors.New("--max-pages/--max-items 需要与 --all 一起使用")
		}
		return options, nil
	}
	if _, provided := values["offset"]; provided {
		return listIterationOptions{}, errors.New("--all 与 --offset 互斥；--all 从列表开头有界遍历")
	}
	if _, provided := values["max-pages"]; provided && maxPages == 0 {
		return listIterationOptions{}, errors.New("--max-pages 必须为正整数")
	}
	if _, provided := values["max-items"]; provided && maxItems == 0 {
		return listIterationOptions{}, errors.New("--max-items 必须为正整数")
	}
	return options, nil
}

// iterateCommandList 用公开有界迭代器收集列表条目。fetch 负责把公开 AdminPage
// 转为领域分页请求并返回本页条目 + 分页元数据；授权/范围检查仍由 fetch 内的领域
// 服务完成。不收集超过 MaxItems 的条目（迭代器保证）。
func iterateCommandList[T any](r *runner, options listIterationOptions, pageLimit int,
	fetch func(page appapi.AdminPage) ([]T, appapi.AdminPageInfo, error),
) ([]T, appapi.IterationResult, error) {
	items := make([]T, 0, 16)
	if pageLimit == 0 {
		pageLimit = appapi.AdminDefaultPageLimit
	}
	result, err := appapi.IterateAdminPages(r.ctx, appapi.IterationOptions{
		Page:     appapi.AdminPage{Limit: pageLimit},
		MaxPages: options.MaxPages,
		MaxItems: options.MaxItems,
	}, func(_ context.Context, page appapi.AdminPage) ([]T, appapi.AdminPageInfo, error) {
		return fetch(page)
	}, func(_ context.Context, _ appapi.AdminPageInfo, pageItems []T) error {
		items = append(items, pageItems...)
		return nil
	})
	return items, result, err
}

// listIterationFailure 把遍历错误映射为稳定 CLI 退出码：分页契约/参数错误按用法
// 错误（ExitUsage），领域错误保留领域稳定码与退出码映射。
func (r *runner) listIterationFailure(operation string, codeOf func(error) any, err error) int {
	if errors.Is(err, appapi.ErrPageNotAdvancing) ||
		errs.IsErrorCode(err, errs.CodeReqInvalid) {
		return r.usage("%s遍历失败：%v", operation, err)
	}
	return r.domainFailure(operation, codeOf(err), err)
}

// listIterationMetadata 生成 --all 时的公开遍历元数据；不包含任何行数据或秘密。
func listIterationMetadata(result appapi.IterationResult, pageLimit int) map[string]any {
	limit := result.LastPage.Limit
	if limit == 0 {
		limit = pageLimit
	}
	if limit == 0 {
		limit = appapi.AdminDefaultPageLimit
	}
	return map[string]any{
		"all":         true,
		"pages":       result.Pages,
		"items_total": result.Items,
		"complete":    result.Complete,
		"stopped":     result.Stopped,
		"stop_reason": result.StopReason,
		"limit":       limit,
		"offset":      0,
		"has_more":    !result.Complete,
	}
}

// listIterationFooter 在纯文本模式下提示达到遍历上限；完整结束时无额外输出。
func (r *runner) listIterationFooter(result appapi.IterationResult) {
	if result.Complete {
		return
	}
	reason := strings.TrimSpace(result.StopReason)
	if reason == "" {
		reason = "未完成"
	}
	fmt.Fprintf(r.stdout, "（达到遍历上限，已停止：%s；可用 --max-pages/--max-items 调整，或使用 --offset 手工翻页）\n", reason)
}
