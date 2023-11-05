package app

import (
	"context"
	"errors"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin"
)

// fakePageFetcher 按预置页返回条目；分页元数据严格按 AdminPageInfo 契约构造，
// 用于精确控制每页条数/offset/HasMore。
type fakePageFetcher struct {
	pages [][]int
	calls int
}

func (f *fakePageFetcher) fetch(_ context.Context, page AdminPage) ([]int, AdminPageInfo, error) {
	index := f.calls
	f.calls++
	if index >= len(f.pages) {
		return nil, AdminPageInfo{}, errors.New("fake fetch 超出预置页数")
	}
	items := f.pages[index]
	hasMore := index+1 < len(f.pages)
	return items, NewAdminPageInfo(page, len(items), hasMore), nil
}

// collect 返回访问到的页与条目。
type visitRecorder struct {
	pages [][]int
	infos []AdminPageInfo
}

func (v *visitRecorder) visit(_ context.Context, info AdminPageInfo, items []int) error {
	copied := append([]int(nil), items...)
	v.pages = append(v.pages, copied)
	v.infos = append(v.infos, info)
	return nil
}

// TestIterateAdminPagesSuccess 覆盖正常多页遍历与流式交付。
func TestIterateAdminPagesSuccess(t *testing.T) {
	fetcher := &fakePageFetcher{pages: [][]int{{1, 2}, {3, 4}, {5}}}
	recorder := &visitRecorder{}
	result, err := IterateAdminPages(context.Background(),
		IterationOptions{Page: AdminPage{Limit: 2}}, fetcher.fetch, recorder.visit)
	if err != nil {
		t.Fatalf("正常遍历返回错误: %v", err)
	}
	if result.Pages != 3 || result.Items != 5 || !result.Complete || result.Stopped ||
		result.StopReason != IterationStopComplete {
		t.Fatalf("结果异常: %+v", result)
	}
	if fetcher.calls != 3 || len(recorder.pages) != 3 {
		t.Fatalf("fetch/visit 次数 = %d/%d", fetcher.calls, len(recorder.pages))
	}
	if recorder.pages[2][0] != 5 || result.LastPage.HasMore {
		t.Fatalf("末页交付异常: %+v last=%+v", recorder.pages, result.LastPage)
	}
}

// TestIterateAdminPagesEmptyList 覆盖空列表（一页空结果即完成）。
func TestIterateAdminPagesEmptyList(t *testing.T) {
	fetcher := &fakePageFetcher{pages: [][]int{{}}}
	result, err := IterateAdminPages(context.Background(),
		IterationOptions{Page: AdminPage{Limit: 2}}, fetcher.fetch, (&visitRecorder{}).visit)
	if err != nil {
		t.Fatalf("空列表返回错误: %v", err)
	}
	if !result.Complete || result.Items != 0 || result.Pages != 1 {
		t.Fatalf("空列表结果异常: %+v", result)
	}
}

// TestIterateAdminPagesDefaultBounds 覆盖默认页数上限：不设置时不能一次拉全表。
func TestIterateAdminPagesDefaultBounds(t *testing.T) {
	pages := make([][]int, 15)
	for index := range pages {
		pages[index] = []int{index}
	}
	fetcher := &fakePageFetcher{pages: pages}
	result, err := IterateAdminPages(context.Background(),
		IterationOptions{Page: AdminPage{Limit: 1}}, fetcher.fetch, (&visitRecorder{}).visit)
	if err != nil {
		t.Fatalf("默认上限返回错误: %v", err)
	}
	if result.Pages != DefaultIterationMaxPages || result.Items != DefaultIterationMaxPages ||
		!result.Stopped || result.Complete || result.StopReason != IterationStopMaxPages {
		t.Fatalf("默认上限结果异常: %+v", result)
	}
	if fetcher.calls != DefaultIterationMaxPages {
		t.Fatalf("fetch 次数 = %d，期望 %d", fetcher.calls, DefaultIterationMaxPages)
	}
}

// TestIterateAdminPagesMaxPages 覆盖显式最大页数。
func TestIterateAdminPagesMaxPages(t *testing.T) {
	fetcher := &fakePageFetcher{pages: [][]int{{1}, {2}, {3}}}
	result, err := IterateAdminPages(context.Background(),
		IterationOptions{Page: AdminPage{Limit: 1}, MaxPages: 2},
		fetcher.fetch, (&visitRecorder{}).visit)
	if err != nil {
		t.Fatalf("最大页数返回错误: %v", err)
	}
	if result.Pages != 2 || result.Items != 2 || !result.Stopped ||
		result.Complete || result.StopReason != IterationStopMaxPages {
		t.Fatalf("最大页数结果异常: %+v", result)
	}
	if fetcher.calls != 2 {
		t.Fatalf("fetch 次数 = %d，期望 2", fetcher.calls)
	}
}

// TestIterateAdminPagesMaxItemsTruncation 覆盖最大条目数截断与部分语义。
func TestIterateAdminPagesMaxItemsTruncation(t *testing.T) {
	fetcher := &fakePageFetcher{pages: [][]int{{1, 2, 3}, {4, 5, 6}, {7}}}
	recorder := &visitRecorder{}
	result, err := IterateAdminPages(context.Background(),
		IterationOptions{Page: AdminPage{Limit: 3}, MaxItems: 5},
		fetcher.fetch, recorder.visit)
	if err != nil {
		t.Fatalf("最大条目数返回错误: %v", err)
	}
	if result.Pages != 2 || result.Items != 5 || !result.Stopped || result.Complete ||
		result.StopReason != IterationStopMaxItems {
		t.Fatalf("最大条目数结果异常: %+v", result)
	}
	if len(recorder.pages) != 2 || len(recorder.pages[0]) != 3 || len(recorder.pages[1]) != 2 {
		t.Fatalf("交付页异常: %+v", recorder.pages)
	}
	if recorder.infos[1].Returned != 2 || !recorder.infos[1].HasMore {
		t.Fatalf("截断页元数据异常: %+v", recorder.infos[1])
	}
}

// TestIterateAdminPagesMaxItemsExactEnd 覆盖“刚好达到条目上限且列表已结束”视为
// 完整完成，而不是截断停止。
func TestIterateAdminPagesMaxItemsExactEnd(t *testing.T) {
	fetcher := &fakePageFetcher{pages: [][]int{{1, 2}}}
	result, err := IterateAdminPages(context.Background(),
		IterationOptions{Page: AdminPage{Limit: 2}, MaxItems: 2},
		fetcher.fetch, (&visitRecorder{}).visit)
	if err != nil {
		t.Fatalf("返回错误: %v", err)
	}
	if !result.Complete || result.Stopped || result.StopReason != IterationStopComplete {
		t.Fatalf("刚好结束的语义异常: %+v", result)
	}
}

// TestIterateAdminPagesInvalidOptions 覆盖非法选项在触达领域前返回 REQ_INVALID。
func TestIterateAdminPagesInvalidOptions(t *testing.T) {
	validFetch := (&fakePageFetcher{pages: [][]int{{1}}}).fetch
	validVisit := (&visitRecorder{}).visit
	cases := []struct {
		name    string
		ctx     context.Context
		options IterationOptions
		fetch   func(context.Context, AdminPage) ([]int, AdminPageInfo, error)
		visit   func(context.Context, AdminPageInfo, []int) error
	}{
		{"nil context", nil, IterationOptions{}, validFetch, validVisit},
		{"nil fetch", context.Background(), IterationOptions{}, nil, validVisit},
		{"nil visit", context.Background(), IterationOptions{}, validFetch, nil},
		{"非法页大小", context.Background(),
			IterationOptions{Page: AdminPage{Limit: AdminMaxPageLimit + 1}}, validFetch, validVisit},
		{"非法 offset", context.Background(),
			IterationOptions{Page: AdminPage{Offset: -1}}, validFetch, validVisit},
		{"负数最大页数", context.Background(),
			IterationOptions{MaxPages: -1}, validFetch, validVisit},
		{"超限最大页数", context.Background(),
			IterationOptions{MaxPages: MaxIterationMaxPages + 1}, validFetch, validVisit},
		{"负数最大条目", context.Background(),
			IterationOptions{MaxItems: -1}, validFetch, validVisit},
		{"超限最大条目", context.Background(),
			IterationOptions{MaxItems: MaxIterationMaxItems + 1}, validFetch, validVisit},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := IterateAdminPages(test.ctx, test.options, test.fetch, test.visit)
			if !login.IsErrorCode(err, login.CodeReqInvalid) {
				t.Fatalf("期望 REQ_INVALID，实际 %v", err)
			}
		})
	}
}

// TestIterateAdminPagesPageContractViolations 覆盖分页元数据不一致/空页 HasMore/
// NextOffset 不匹配等死循环防护。
func TestIterateAdminPagesPageContractViolations(t *testing.T) {
	cases := []struct {
		name  string
		fetch func(context.Context, AdminPage) ([]int, AdminPageInfo, error)
	}{
		{"重复 offset", func(_ context.Context, _ AdminPage) ([]int, AdminPageInfo, error) {
			return []int{1}, AdminPageInfo{Limit: 1, Offset: 0, Returned: 1,
				HasMore: true, NextOffset: 1}, nil
		}},
		{"NextOffset 未前进", func(_ context.Context, page AdminPage) ([]int, AdminPageInfo, error) {
			return []int{1}, AdminPageInfo{Limit: page.Limit, Offset: page.Offset,
				Returned: 1, HasMore: true, NextOffset: page.Offset}, nil
		}},
		{"空页 HasMore", func(_ context.Context, page AdminPage) ([]int, AdminPageInfo, error) {
			return nil, AdminPageInfo{Limit: page.Limit, Offset: page.Offset,
				Returned: 0, HasMore: true, NextOffset: page.Offset}, nil
		}},
		{"Returned 不匹配", func(_ context.Context, page AdminPage) ([]int, AdminPageInfo, error) {
			return []int{1}, AdminPageInfo{Limit: page.Limit, Offset: page.Offset,
				Returned: 5, HasMore: true, NextOffset: page.Offset + 5}, nil
		}},
		{"请求回显不一致", func(_ context.Context, _ AdminPage) ([]int, AdminPageInfo, error) {
			return []int{1}, AdminPageInfo{Limit: 9, Offset: 7, Returned: 1,
				HasMore: true, NextOffset: 8}, nil
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			// 前两页按请求合法前进，第三页开始违反契约，确保前两页已正常处理。
			calls := 0
			fetch := func(ctx context.Context, page AdminPage) ([]int, AdminPageInfo, error) {
				calls++
				if calls <= 2 {
					return []int{calls}, NewAdminPageInfo(page, 1, true), nil
				}
				return test.fetch(ctx, page)
			}
			_, err := IterateAdminPages(context.Background(),
				IterationOptions{Page: AdminPage{Limit: 1}, MaxPages: 5},
				fetch, (&visitRecorder{}).visit)
			if !errors.Is(err, ErrPageNotAdvancing) {
				t.Fatalf("期望 ErrPageNotAdvancing，实际 %v", err)
			}
		})
	}
}

// TestIterateAdminPagesFetchAndVisitErrors 覆盖中途错误不吞、部分结果可读。
func TestIterateAdminPagesFetchAndVisitErrors(t *testing.T) {
	t.Run("fetch 错误", func(t *testing.T) {
		sentinel := errors.New("第 2 页存储故障")
		fetcher := &fakePageFetcher{pages: [][]int{{1, 2}, {3}}}
		calls := 0
		fetch := func(ctx context.Context, page AdminPage) ([]int, AdminPageInfo, error) {
			calls++
			if calls == 2 {
				return nil, AdminPageInfo{}, sentinel
			}
			return fetcher.fetch(ctx, page)
		}
		recorder := &visitRecorder{}
		result, err := IterateAdminPages(context.Background(),
			IterationOptions{Page: AdminPage{Limit: 2}}, fetch, recorder.visit)
		if !errors.Is(err, sentinel) {
			t.Fatalf("期望错误链包含 fetch 错误，实际 %v", err)
		}
		if result.Items != 2 || len(recorder.pages) != 1 || !result.Stopped ||
			result.StopReason != IterationStopFetchError {
			t.Fatalf("fetch 错误部分结果异常: %+v pages=%+v", result, recorder.pages)
		}
	})
	t.Run("visit 错误", func(t *testing.T) {
		sentinel := errors.New("处理中止")
		fetcher := &fakePageFetcher{pages: [][]int{{1, 2}, {3}}}
		visit := func(context.Context, AdminPageInfo, []int) error { return sentinel }
		result, err := IterateAdminPages(context.Background(),
			IterationOptions{Page: AdminPage{Limit: 2}}, fetcher.fetch, visit)
		if !errors.Is(err, sentinel) {
			t.Fatalf("期望错误链包含 visit 错误，实际 %v", err)
		}
		if fetcher.calls != 1 || !result.Stopped || result.StopReason != IterationStopVisitError {
			t.Fatalf("visit 错误结果异常: %+v calls=%d", result, fetcher.calls)
		}
	})
}

// TestIterateAdminPagesCancelStopsFetching 验证取消后不再发起下一页请求。
func TestIterateAdminPagesCancelStopsFetching(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fetcher := &fakePageFetcher{pages: [][]int{{1}, {2}, {3}}}
	visit := func(_ context.Context, _ AdminPageInfo, _ []int) error {
		cancel()
		return nil
	}
	result, err := IterateAdminPages(ctx,
		IterationOptions{Page: AdminPage{Limit: 1}}, fetcher.fetch, visit)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("期望 context.Canceled，实际 %v", err)
	}
	if result.StopReason != IterationStopContextCanceled || !result.Stopped || result.Complete {
		t.Fatalf("取消结果异常: %+v", result)
	}
	if fetcher.calls != 1 {
		t.Fatalf("取消后仍发起了 fetch：calls=%d", fetcher.calls)
	}
}

// TestIterateAdminPagesNormalizesPageLimit 验证 Page.Limit=0 使用公开默认值。
func TestIterateAdminPagesNormalizesPageLimit(t *testing.T) {
	fetcher := &fakePageFetcher{pages: [][]int{{1}}}
	var firstPage AdminPage
	fetch := func(ctx context.Context, page AdminPage) ([]int, AdminPageInfo, error) {
		firstPage = page
		return fetcher.fetch(ctx, page)
	}
	if _, err := IterateAdminPages(context.Background(), IterationOptions{},
		fetch, (&visitRecorder{}).visit); err != nil {
		t.Fatalf("返回错误: %v", err)
	}
	if firstPage.Limit != AdminDefaultPageLimit {
		t.Fatalf("首屏 Limit = %d，期望默认 %d", firstPage.Limit, AdminDefaultPageLimit)
	}
}
