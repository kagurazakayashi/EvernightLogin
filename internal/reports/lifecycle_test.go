package reports

// 本文件验证步骤 79 的生命周期安全路径（包内测试，使用明确标注的替身仓储）：
//   - 进程重启后历史回源并再次授权，撤销权限后旧报告 ID 不可读/不可下载；
//   - 短期下载令牌的一次性、到期、调用者绑定与失权拒绝；
//   - 报告文件清理预览/执行、真实失败不伪造成功、与原始审计删除隔离；
//   - 计划管理读模型同步、编辑行版本并发保护与对账重建。
//
// 真实 SQLite 仓储往返与调度 Tick 端到端测试在 internal/reports/sqlite 包中验证。

import (
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// fakeHistoryStore 是 reports.HistoryStore 的内存替身：验证服务层回源/授权/清理
// 语义。真实 SQLite 行为由 internal/reports/sqlite 的适配器测试覆盖。
type fakeHistoryStore struct {
	mu       sync.Mutex
	records  map[string]HistoryRecord
	order    []string
	writeErr error
	// failCleaned 指定报告在标记“已清理”时失败，用于验证失败不伪造成功。
	failCleaned map[string]error
}

// newFakeHistoryStore 构造空的历史替身。
func newFakeHistoryStore() *fakeHistoryStore {
	return &fakeHistoryStore{records: make(map[string]HistoryRecord),
		failCleaned: make(map[string]error)}
}

// RecordReportHistory 实现 HistoryRecorder。
func (f *fakeHistoryStore) RecordReportHistory(_ context.Context,
	record HistoryRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.writeErr != nil {
		return f.writeErr
	}
	if _, exists := f.records[record.ReportID]; !exists {
		f.order = append(f.order, record.ReportID)
	}
	f.records[record.ReportID] = record
	return nil
}

// accessAllows 判断替身范围是否覆盖记录。
func accessAllows(access AccessScope, scopeID string) bool {
	if access.AllData {
		return true
	}
	for _, id := range access.ResourceIDs {
		if id == scopeID {
			return true
		}
	}
	return false
}

// GetHistory 实现 HistoryReader。
func (f *fakeHistoryStore) GetHistory(_ context.Context, reportID string,
	access AccessScope) (HistoryRecord, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	record, found := f.records[reportID]
	if !found || !accessAllows(access, record.ScopeID) {
		return HistoryRecord{}, false, nil
	}
	return record, true, nil
}

// ListHistory 实现 HistoryReader。
func (f *fakeHistoryStore) ListHistory(_ context.Context,
	query HistoryQuery) (HistoryPage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	limit := clampHistoryLimit(query.Limit)
	records := make([]HistoryRecord, 0, len(f.order))
	for _, id := range f.order {
		record := f.records[id]
		if !accessAllows(query.Access, record.ScopeID) {
			continue
		}
		if query.PlanID != "" && record.PlanID != query.PlanID {
			continue
		}
		if query.State != "" && record.State != query.State {
			continue
		}
		if query.Owner != nil && record.Owner != *query.Owner {
			continue
		}
		if !query.BeforeCreatedAt.IsZero() {
			if record.CreatedAt.After(query.BeforeCreatedAt) {
				continue
			}
			if record.CreatedAt.Equal(query.BeforeCreatedAt) &&
				record.ReportID >= query.BeforeID {
				continue
			}
		}
		records = append(records, record)
	}
	sort.Slice(records, func(left, right int) bool {
		if !records[left].CreatedAt.Equal(records[right].CreatedAt) {
			return records[left].CreatedAt.After(records[right].CreatedAt)
		}
		return records[left].ReportID > records[right].ReportID
	})
	page := HistoryPage{Records: records}
	if len(records) > limit {
		page.Records = records[:limit]
		page.HasMore = true
	}
	return page, nil
}

// clampHistoryLimit 归一化替身分页大小。
func clampHistoryLimit(limit int) int {
	if limit <= 0 {
		return historyDefaultLimit
	}
	if limit > historyMaxLimit {
		return historyMaxLimit
	}
	return limit
}

// ListHistoryScopeIDs 实现 HistoryReader。
func (f *fakeHistoryStore) ListHistoryScopeIDs(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	seen := make(map[string]struct{}, 4)
	scopes := make([]string, 0, 4)
	for _, id := range f.order {
		scopeID := f.records[id].ScopeID
		if _, exists := seen[scopeID]; exists {
			continue
		}
		seen[scopeID] = struct{}{}
		scopes = append(scopes, scopeID)
	}
	sort.Strings(scopes)
	return scopes, nil
}

// cleanupCandidate 判断记录是否已到期且未清理。
func (f *fakeHistoryStore) candidate(record HistoryRecord, cutoff time.Time) bool {
	return !record.ExpiresAt.IsZero() && record.ExpiresAt.Before(cutoff) &&
		record.CleanupState != "cleaned"
}

// ListCleanupCandidateScopes 实现 HistoryReader。
func (f *fakeHistoryStore) ListCleanupCandidateScopes(
	_ context.Context, cutoff time.Time) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	seen := make(map[string]struct{}, 4)
	scopes := make([]string, 0, 4)
	for _, id := range f.order {
		record := f.records[id]
		if !f.candidate(record, cutoff) {
			continue
		}
		if _, exists := seen[record.ScopeID]; exists {
			continue
		}
		seen[record.ScopeID] = struct{}{}
		scopes = append(scopes, record.ScopeID)
	}
	sort.Strings(scopes)
	return scopes, nil
}

// ListCleanupCandidates 实现 HistoryReader。
func (f *fakeHistoryStore) ListCleanupCandidates(_ context.Context, access AccessScope,
	cutoff time.Time, limit int) ([]HistoryRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if limit <= 0 {
		limit = DefaultCleanupBatch
	}
	candidates := make([]HistoryRecord, 0, len(f.order))
	for _, id := range f.order {
		record := f.records[id]
		if !accessAllows(access, record.ScopeID) || !f.candidate(record, cutoff) {
			continue
		}
		candidates = append(candidates, record)
	}
	sort.Slice(candidates, func(left, right int) bool {
		if !candidates[left].ExpiresAt.Equal(candidates[right].ExpiresAt) {
			return candidates[left].ExpiresAt.Before(candidates[right].ExpiresAt)
		}
		return candidates[left].ReportID < candidates[right].ReportID
	})
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	return candidates, nil
}

// MarkHistoryCleanup 实现 HistoryReader：只允许 none→pending→cleaned 前进。
func (f *fakeHistoryStore) MarkHistoryCleanup(_ context.Context,
	reportID, cleanupState string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	record, found := f.records[reportID]
	if !found {
		return ErrConflict
	}
	if normalize, err := normalizeFakeCleanupState(cleanupState); err != nil {
		return err
	} else {
		cleanupState = normalize
	}
	if cleanupState == "cleaned" {
		if failErr := f.failCleaned[reportID]; failErr != nil {
			return failErr
		}
	}
	switch {
	case record.CleanupState == "cleaned":
		return ErrConflict
	case record.CleanupState == "pending" && cleanupState == "pending":
		return ErrConflict
	}
	record.CleanupState = cleanupState
	f.records[reportID] = record
	return nil
}

// normalizeFakeCleanupState 校验替身清理状态。
func normalizeFakeCleanupState(state string) (string, error) {
	switch state {
	case "none", "pending", "cleaned":
		return state, nil
	default:
		return "", ErrInvalidRequest
	}
}

// 编译期确认替身实现完整历史契约。
var _ HistoryStore = (*fakeHistoryStore)(nil)

// newLifecycleEnv 构造带可变假时钟与历史替身的报告环境。
func newLifecycleEnv(t *testing.T, now *time.Time) (*testEnv, *fakeHistoryStore) {
	t.Helper()
	env := newTestEnv(t)
	env.now = func() time.Time { return *now }
	history := newFakeHistoryStore()
	service, err := New(Options{Source: env.source, Authorizer: env.authorizer,
		Root: env.root, Sensitive: env.sensitive, Audit: env.recorder,
		Enqueuer: env.enqueuer, Canceller: env.canceller, Tasks: env.tasks,
		OutputDir: env.outputDir, MaxDetailRows: 50, Now: env.now,
		History: history})
	if err != nil {
		t.Fatalf("构造带历史替身的报告服务失败: %v", err)
	}
	env.service = service
	return env, history
}

// restartService 用同一输出目录与历史替身构造“新进程”服务。
func restartService(t *testing.T, env *testEnv, history HistoryStore) *Service {
	t.Helper()
	service, err := New(Options{Source: env.source, Authorizer: env.authorizer,
		Root: env.root, Sensitive: env.sensitive, Audit: env.recorder,
		Enqueuer: env.enqueuer, Canceller: env.canceller, Tasks: env.tasks,
		OutputDir: env.outputDir, MaxDetailRows: 50, Now: env.now,
		History: history})
	if err != nil {
		t.Fatalf("构造重启后的报告服务失败: %v", err)
	}
	return service
}

// TestHistoryFallbackReauthorizesAfterRestart 验证进程重启后历史回源、按当前权限
// 重新授权、数据范围收缩与旧 ID 失权拒绝。
func TestHistoryFallbackReauthorizesAfterRestart(t *testing.T) {
	now := baseTime
	env, history := newLifecycleEnv(t, &now)
	ctx := context.Background()
	env.grantAll(testUserID(1), ScopeSystem, stats.ScopeGrant{Allowed: true, AllData: true})
	reportID, generated := env.startAndGenerate(t, env.startRequest(t))
	if len(history.order) == 0 || generated.State != StateSucceeded {
		t.Fatalf("历史未写入或报告未成功: history=%d state=%s",
			len(history.order), generated.State)
	}
	restarted := restartService(t, env, history)
	caller := testCaller(t, 1)
	got, err := restarted.Get(ctx, caller, reportID)
	if err != nil || got.State != StateSucceeded || len(got.Artifacts) == 0 {
		t.Fatalf("重启后回源查询失败: state=%s artifacts=%d err=%v",
			got.State, len(got.Artifacts), err)
	}
	// 当前权限撤销后，旧报告 ID 不得再读取。
	env.authorizer.deny(PermissionRead, ScopeSystem)
	if _, err := restarted.Get(ctx, caller, reportID); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("撤销读取后回源错误 = %v，期望 ErrAccessDenied", err)
	}
	env.authorizer.allow(PermissionRead, ScopeSystem,
		stats.ScopeGrant{Allowed: true, AllData: true})
	// 撤销导出后不可下载，但查看元数据仍允许。
	env.authorizer.deny(PermissionExport, ScopeSystem)
	if _, err := restarted.OpenFile(ctx, caller, reportID, FormatHTML); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("撤销导出后下载错误 = %v，期望 ErrAccessDenied", err)
	}
	env.authorizer.allow(PermissionExport, ScopeSystem,
		stats.ScopeGrant{Allowed: true, AllData: true})
	file, err := restarted.OpenFile(ctx, caller, reportID, FormatHTML)
	if err != nil || file.Bytes == 0 {
		t.Fatalf("重启后下载失败: bytes=%d err=%v", file.Bytes, err)
	}
	if _, err := restarted.GetSnapshot(ctx, caller, reportID); err != nil {
		t.Fatalf("重启后快照回源失败: %v", err)
	}
	// 数据范围收缩：生成时是 AllData，当前只给空资源集合，必须拒绝回源。
	for _, permission := range []string{PermissionRead, PermissionExport} {
		env.authorizer.allow(permission, ScopeSystem,
			stats.ScopeGrant{Allowed: true, AllData: false})
	}
	if _, err := restarted.Get(ctx, caller, reportID); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("数据范围收缩后回源错误 = %v，期望 ErrAccessDenied", err)
	}
	env.authorizer.allow(PermissionRead, ScopeSystem,
		stats.ScopeGrant{Allowed: true, AllData: true})
	env.authorizer.allow(PermissionExport, ScopeSystem,
		stats.ScopeGrant{Allowed: true, AllData: true})
	// 列表：所有者可见；无关用户不可见；拥有管理权限的管理者可见。
	list, err := restarted.HistoryList(ctx, HistoryListRequest{Caller: caller})
	if err != nil || len(list.Records) != 1 {
		t.Fatalf("所有者历史列表 = %d, err=%v", len(list.Records), err)
	}
	other := testCaller(t, 9)
	if list, err := restarted.HistoryList(ctx,
		HistoryListRequest{Caller: other}); err != nil || len(list.Records) != 0 {
		t.Fatalf("无关用户历史列表 = %d, err=%v，期望 0", len(list.Records), err)
	}
	env.authorizer.allow(PermissionRead, ScopeSystem,
		stats.ScopeGrant{Allowed: true, AllData: true})
	env.authorizer.allow(PermissionScheduleManage, ScopeSystem,
		stats.ScopeGrant{Allowed: true, AllData: true})
	env.authorizer.allow(PermissionGenerate, ScopeSystem,
		stats.ScopeGrant{Allowed: true, AllData: true})
	env.authorizer.allow(PermissionExport, ScopeSystem,
		stats.ScopeGrant{Allowed: true, AllData: true})
	if list, err := restarted.HistoryList(ctx,
		HistoryListRequest{Caller: other}); err != nil || len(list.Records) != 1 {
		t.Fatalf("管理者历史列表 = %d, err=%v，期望 1", len(list.Records), err)
	}
	// 不存在的编号与越权编号都按“不存在/无权”处理。
	if _, err := restarted.Get(ctx, caller, "rpt_"+repeatHex('a', 32)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("不存在编号错误 = %v，期望 ErrNotFound", err)
	}
}

// repeatHex 生成指定长度的十六进制字符串（测试数据）。
func repeatHex(c byte, count int) string {
	buffer := make([]byte, count)
	for index := range buffer {
		buffer[index] = c
	}
	return string(buffer)
}

// TestDownloadTicketOneTimeExpiryAndBinding 验证短期下载令牌的绑定、一次性、到期、
// 失权与重启后回源可用。
func TestDownloadTicketOneTimeExpiryAndBinding(t *testing.T) {
	now := baseTime
	env, history := newLifecycleEnv(t, &now)
	ctx := context.Background()
	env.grantAll(testUserID(1), ScopeSystem, stats.ScopeGrant{Allowed: true, AllData: true})
	reportID, _ := env.startAndGenerate(t, env.startRequest(t))
	caller := testCaller(t, 1)
	ticket, err := env.service.IssueDownloadTicket(ctx, caller, reportID, FormatHTML)
	if err != nil {
		t.Fatalf("签发下载令牌失败: %v", err)
	}
	if len(ticket.Token) != 64 || ticket.ReportID != reportID ||
		ticket.Format != FormatHTML || !ticket.ExpiresAt.After(now) {
		t.Fatalf("令牌元数据不正确: %+v", ticket)
	}
	file, err := env.service.RedeemDownloadTicket(ctx, caller, ticket.Token)
	if err != nil || file.Bytes == 0 {
		t.Fatalf("兑换下载令牌失败: bytes=%d err=%v", file.Bytes, err)
	}
	// 一次性：同一令牌不能再次兑换。
	if _, err := env.service.RedeemDownloadTicket(ctx, caller,
		ticket.Token); !errors.Is(err, ErrTicketInvalid) {
		t.Fatalf("重复兑换错误 = %v，期望 ErrTicketInvalid", err)
	}
	// 调用者绑定：他人拿到令牌也不能兑换，且不消费原令牌。
	ticket, err = env.service.IssueDownloadTicket(ctx, caller, reportID, FormatHTML)
	if err != nil {
		t.Fatalf("再次签发令牌失败: %v", err)
	}
	if _, err := env.service.RedeemDownloadTicket(ctx, testCaller(t, 9),
		ticket.Token); !errors.Is(err, ErrTicketAccessDenied) {
		t.Fatalf("他人兑换错误 = %v，期望 ErrTicketAccessDenied", err)
	}
	if _, err := env.service.RedeemDownloadTicket(ctx, caller, ticket.Token); err != nil {
		t.Fatalf("令牌被他人尝试后失效: %v", err)
	}
	// 到期：超过最大有效期后不可兑换。
	ticket, err = env.service.IssueDownloadTicket(ctx, caller, reportID, FormatHTML)
	if err != nil {
		t.Fatalf("签发票据失败: %v", err)
	}
	now = now.Add(MaxDownloadTicketTTL + time.Minute)
	if _, err := env.service.RedeemDownloadTicket(ctx, caller,
		ticket.Token); !errors.Is(err, ErrTicketExpired) {
		t.Fatalf("过期令牌错误 = %v，期望 ErrTicketExpired", err)
	}
	// 失权后不可签发。
	env.authorizer.deny(PermissionExport, ScopeSystem)
	if _, err := env.service.IssueDownloadTicket(ctx, caller, reportID,
		FormatHTML); !errors.Is(err, ErrTicketNotAllowed) || !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("失权签发错误 = %v，期望 ErrTicketNotAllowed/ErrAccessDenied", err)
	}
	env.authorizer.allow(PermissionExport, ScopeSystem,
		stats.ScopeGrant{Allowed: true, AllData: true})
	// 重启后令牌仍可兑换（令牌在签发进程内存中，重启后重新签发即可）。
	restarted := restartService(t, env, history)
	restartedTicket, err := restarted.IssueDownloadTicket(ctx, caller, reportID, FormatJSON)
	if err != nil {
		t.Fatalf("重启后签发令牌失败: %v", err)
	}
	restartedFile, err := restarted.RedeemDownloadTicket(ctx, caller, restartedTicket.Token)
	if err != nil || restartedFile.Format != FormatJSON {
		t.Fatalf("重启后兑换令牌失败: %+v err=%v", restartedFile, err)
	}
	_ = restarted
	// 非法令牌格式。
	if _, err := env.service.RedeemDownloadTicket(ctx, caller, "not-a-token"); !errors.Is(err, ErrTicketInvalid) {
		t.Fatalf("非法令牌错误 = %v，期望 ErrTicketInvalid", err)
	}
}

// TestCleanupPreviewAndExecuteIsolation 验证报告文件清理的预览/执行/失败真实性与
// 原始审计隔离（只操作报告文件与历史清理状态）。
func TestCleanupPreviewAndExecuteIsolation(t *testing.T) {
	now := baseTime
	env, history := newLifecycleEnv(t, &now)
	ctx := context.Background()
	env.grantAll(testUserID(1), ScopeSystem, stats.ScopeGrant{Allowed: true, AllData: true})
	env.authorizer.allow(PermissionCleanup, ScopeSystem,
		stats.ScopeGrant{Allowed: true, AllData: true})
	caller := testCaller(t, 1)
	firstID, _ := env.startAndGenerate(t, env.startRequest(t))
	now = now.Add(time.Minute)
	secondID, _ := env.startAndGenerate(t, env.startRequest(t))
	if len(env.outputEntries(t)) != 6 {
		t.Fatalf("产物文件数 = %d，期望 6", len(env.outputEntries(t)))
	}
	// 未到期时不应有可清理目标。
	preview, err := env.service.CleanupPreview(ctx, caller)
	if err != nil {
		t.Fatalf("清理预览失败: %v", err)
	}
	if preview.TargetCount != 0 {
		t.Fatalf("未到期目标数 = %d，期望 0", preview.TargetCount)
	}
	// 到期 + 宽限期后，预览出现真实目标。
	now = baseTime.Add(DefaultArtifactTTL + DefaultCleanupGracePeriod + 2*time.Minute)
	preview, err = env.service.CleanupPreview(ctx, caller)
	if err != nil {
		t.Fatalf("到期后清理预览失败: %v", err)
	}
	if preview.TargetCount != 2 || preview.TotalBytes <= 0 ||
		len(preview.Scopes) != 1 || preview.Scopes[0] != ScopeSystem {
		t.Fatalf("清理预览 = %+v，期望 2 个目标", preview)
	}
	if preview.Policy.RawAuditNote == "" || preview.Policy.HistoryNote == "" {
		t.Fatal("清理预览缺少原始审计隔离说明")
	}
	result, err := env.service.CleanupExecute(ctx, CleanupExecuteRequest{Caller: caller,
		Reason: "按保留策略清理过期报告文件"})
	if err != nil {
		t.Fatalf("执行清理失败: %v", err)
	}
	if result.RequestedCount != 2 || result.CleanedCount != 2 ||
		result.FailedCount != 0 || result.DeletedFiles != 6 || result.FreedBytes <= 0 {
		t.Fatalf("清理结果不真实: %+v", result)
	}
	if entries := env.outputEntries(t); len(entries) != 0 {
		t.Fatalf("清理后仍有 %d 个产物文件", len(entries))
	}
	for _, reportID := range []string{firstID, secondID} {
		record, found, err := history.GetHistory(ctx, reportID, AccessScope{AllData: true})
		if err != nil || !found || record.CleanupState != "cleaned" {
			t.Fatalf("清理状态未推进: found=%v err=%v record=%+v", found, err, record)
		}
	}
	if !env.recorder.hasAction(ActionCleanupRequest) || !env.recorder.hasAction(ActionCleanupFinish) {
		t.Fatal("清理审计未记录意图与结果")
	}
	// 清理后不再可下载，元数据仍可查看（真实状态保留）。
	restarted := restartService(t, env, history)
	if _, err := restarted.OpenFile(ctx, caller, firstID, FormatHTML); !errors.Is(err, ErrConflict) {
		t.Fatalf("清理后下载错误 = %v，期望 ErrConflict", err)
	}
	if view, err := restarted.Get(ctx, caller, firstID); err != nil || view.State != StateSucceeded {
		t.Fatalf("清理后历史状态被篡改: state=%s err=%v", view.State, err)
	}
	// 无 reports.cleanup 权限时预览为空目标且不泄露内容。
	other := testCaller(t, 9)
	env.authorizer.allow(PermissionRead, ScopeSystem,
		stats.ScopeGrant{Allowed: true, AllData: true})
	otherPreview, err := env.service.CleanupPreview(ctx, other)
	if err != nil {
		t.Fatalf("无清理权限预览失败: %v", err)
	}
	if otherPreview.TargetCount != 0 {
		t.Fatalf("无权限预览目标数 = %d，期望 0", otherPreview.TargetCount)
	}
	// 清理执行需要强认证：再认证拒绝时不删除任何文件。
	thirdID, _ := env.startAndGenerate(t, env.startRequest(t))
	now = now.Add(DefaultArtifactTTL + DefaultCleanupGracePeriod + time.Minute)
	env.sensitive.denied = true
	if _, err := env.service.CleanupExecute(ctx, CleanupExecuteRequest{
		Caller: caller, Reason: "测试再认证拒绝"}); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("再认证拒绝后清理错误 = %v，期望 ErrAccessDenied", err)
	}
	env.sensitive.denied = false
	if _, found, _ := history.GetHistory(ctx, thirdID, AccessScope{AllData: true}); !found ||
		func() bool {
			record, _, _ := history.GetHistory(ctx, thirdID, AccessScope{AllData: true})
			return record.CleanupState == "cleaned"
		}() {
		t.Fatal("再认证拒绝后仍标记了已清理")
	}
	if len(env.outputEntries(t)) == 0 {
		t.Fatal("再认证拒绝后产物文件被删除")
	}
	// 标记“已清理”失败时如实报告失败，不伪造成功。
	history.failCleaned[thirdID] = errors.New("mark unavailable")
	result, err = env.service.CleanupExecute(ctx, CleanupExecuteRequest{
		Caller: caller, Reason: "验证标记失败"})
	if err != nil {
		t.Fatalf("标记失败时清理返回错误: %v", err)
	}
	if result.FailedCount != 1 || result.CleanedCount != 0 {
		t.Fatalf("标记失败结果 = %+v，期望失败 1 / 成功 0", result)
	}
	if !hasCleanupFailure(result.Failures, thirdID) {
		t.Fatalf("失败列表未包含 %s: %+v", thirdID, result.Failures)
	}
	// 安全 M2：上次删除失败遗留的 pending 记录必须在重跑时继续推进到 cleaned，
	// 不能因为 pending→pending 冲突被永久跳过。
	delete(history.failCleaned, thirdID)
	retryResult, retryErr := env.service.CleanupExecute(ctx, CleanupExecuteRequest{
		Caller: caller, Reason: "重跑清理 pending 记录"})
	if retryErr != nil {
		t.Fatalf("pending 重跑清理失败: %v", retryErr)
	}
	if retryResult.CleanedCount != 1 || retryResult.FailedCount != 0 {
		t.Fatalf("pending 重跑结果 = %+v，期望 cleaned=1 failed=0", retryResult)
	}
	if record, found, _ := history.GetHistory(ctx, thirdID,
		AccessScope{AllData: true}); !found || record.CleanupState != "cleaned" {
		t.Fatalf("pending 重跑后状态 = %+v found=%v，期望 cleaned", record, found)
	}
}

// TestPlanUpdateCrossScopeAuthorization 验证跨范围编辑必须同时对旧/新范围授权，
// 且行版本校验在授权之后（无权者不能探测版本）；改范围后投影/执行计划同步收敛。
func TestPlanUpdateCrossScopeAuthorization(t *testing.T) {
	now := baseTime
	env := newPlanTestEnv(t, &now)
	projections := attachProjectionStore(t, env)
	ctx := context.Background()
	view, err := env.plans.Create(ctx, newPlanRequest(env.caller))
	if err != nil {
		t.Fatalf("创建系统范围计划失败: %v", err)
	}
	// 调用者只有 system 范围权限：改到应用范围必须拒绝（即使行版本错误也不泄露）。
	update := PlanUpdateRequest{PlanCreateRequest: newPlanRequest(env.caller),
		PlanID: view.ID, Version: view.Version, Reason: "尝试跨范围"}
	update.ScopeID = "app_demo1"
	if _, err := env.plans.Update(ctx, update); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("无新范围权限的跨范围编辑错误 = %v，期望 ErrAccessDenied", err)
	}
	wrongVersion := update
	wrongVersion.Version = 999
	if _, err := env.plans.Update(ctx, wrongVersion); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("无权+错误版本编辑错误 = %v，期望先授权失败 ErrAccessDenied", err)
	}
	// 调度器要求 scope 已登记（schedules.scope_id 外键），插入测试应用与 scope 行。
	if _, err := env.raw.DB().ExecContext(ctx, `INSERT INTO applications(
id,name,status,client_type,row_version,created_at_ms,updated_at_ms)
VALUES('app_demo1','测试应用','active','confidential',1,0,0)`); err != nil {
		t.Fatalf("插入测试应用失败: %v", err)
	}
	if _, err := env.raw.DB().ExecContext(ctx, `INSERT INTO scopes(id,kind,app_id)
VALUES('app_demo1','application','app_demo1')`); err != nil {
		t.Fatalf("插入测试 scope 失败: %v", err)
	}
	// 授予应用范围全部报告与计划权限后允许改范围，执行计划与投影同步到新范围。
	for _, permission := range []string{PermissionRead, PermissionGenerate,
		PermissionExport, PermissionScheduleManage} {
		env.authorizer.allow(permission, "app_demo1",
			stats.ScopeGrant{Allowed: true, AllData: true})
	}
	updated, err := env.plans.Update(ctx, update)
	if err != nil {
		t.Fatalf("双范围授权后跨范围编辑失败: %v", err)
	}
	if updated.ScopeID != "app_demo1" || updated.Version != 2 {
		t.Fatalf("跨范围编辑结果 = %+v，期望 scope=app_demo1 version=2", updated)
	}
	schedule, err := env.scheduler.Get(ctx, updated.ScheduleID)
	if err != nil || schedule.ScopeID != "app_demo1" {
		t.Fatalf("跨范围编辑后执行计划范围 = %q err=%v", schedule.ScopeID, err)
	}
	projection, found, _ := projections.GetPlanProjection(ctx, view.ID)
	if !found || projection.ScopeID != "app_demo1" {
		t.Fatalf("跨范围编辑后投影 = %+v found=%v", projection, found)
	}
}

// hasCleanupFailure 判断失败列表是否包含指定报告。
func hasCleanupFailure(failures []CleanupFailure, reportID string) bool {
	for _, failure := range failures {
		if failure.ReportID == reportID {
			return true
		}
	}
	return false
}

// fakeProjectionStore 是 reports.PlanProjectionStore 的内存替身。
type fakeProjectionStore struct {
	mu    sync.Mutex
	plans map[string]PlanProjection
}

// newFakeProjectionStore 构造空投影替身。
func newFakeProjectionStore() *fakeProjectionStore {
	return &fakeProjectionStore{plans: make(map[string]PlanProjection)}
}

// CreatePlanProjection 实现 PlanProjectionStore。
func (f *fakeProjectionStore) CreatePlanProjection(_ context.Context,
	plan PlanProjection) (PlanProjection, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.plans[plan.ID]; exists {
		return PlanProjection{}, ErrConflict
	}
	if plan.Version < 1 {
		plan.Version = 1
	}
	f.plans[plan.ID] = plan
	return plan, nil
}

// GetPlanProjection 实现 PlanProjectionStore。
func (f *fakeProjectionStore) GetPlanProjection(_ context.Context,
	planID string) (PlanProjection, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	plan, found := f.plans[planID]
	return plan, found, nil
}

// UpdatePlanProjection 实现 PlanProjectionStore：行版本 CAS。
func (f *fakeProjectionStore) UpdatePlanProjection(_ context.Context,
	plan PlanProjection, expectedVersion int64) (PlanProjection, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	current, found := f.plans[plan.ID]
	if !found || current.Version != expectedVersion {
		return PlanProjection{}, ErrConflict
	}
	plan.Version = expectedVersion + 1
	f.plans[plan.ID] = plan
	return plan, nil
}

// SetPlanProjectionEnabled 实现 PlanProjectionStore。
func (f *fakeProjectionStore) SetPlanProjectionEnabled(_ context.Context,
	planID string, enabled bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	plan, found := f.plans[planID]
	if !found {
		return ErrNotFound
	}
	plan.Enabled = enabled
	plan.Version++
	f.plans[planID] = plan
	return nil
}

// DeletePlanProjection 实现 PlanProjectionStore。
func (f *fakeProjectionStore) DeletePlanProjection(_ context.Context,
	planID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, found := f.plans[planID]; !found {
		return ErrNotFound
	}
	delete(f.plans, planID)
	return nil
}

// ListPlanProjectionIDs 供对账枚举（可选能力）。
func (f *fakeProjectionStore) ListPlanProjectionIDs(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ids := make([]string, 0, len(f.plans))
	for id := range f.plans {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}

// attachProjectionStore 用投影替身重建计划服务（共用同一真实调度器）。
func attachProjectionStore(t *testing.T, env *planTestEnv) *fakeProjectionStore {
	t.Helper()
	projections := newFakeProjectionStore()
	plans, err := NewPlanService(PlanOptions{
		Schedules: env.scheduler, Authorizer: env.authorizer, Root: &fakeRoot{},
		Audit: env.recorder, Now: env.service.opts.Now, MaxDetailRows: 20,
		Projections: projections,
	})
	if err != nil {
		t.Fatalf("构造带投影的计划服务失败: %v", err)
	}
	env.plans = plans
	return projections
}

// TestPlanProjectionSyncAndUpdateVersion 验证计划管理读模型同步、编辑行版本乐观
// 并发、计划 ID/所有者不变与对账重建。
func TestPlanProjectionSyncAndUpdateVersion(t *testing.T) {
	now := baseTime
	env := newPlanTestEnv(t, &now)
	projections := attachProjectionStore(t, env)
	ctx := context.Background()
	view, err := env.plans.Create(ctx, newPlanRequest(env.caller))
	if err != nil {
		t.Fatalf("创建计划失败: %v", err)
	}
	if view.ID == "" || view.ScheduleID == "" || view.ID == view.ScheduleID {
		t.Fatalf("计划/执行计划编号不正确: %+v", view)
	}
	if view.Version != 1 {
		t.Fatalf("初始行版本 = %d，期望 1", view.Version)
	}
	projection, found, _ := projections.GetPlanProjection(ctx, view.ID)
	if !found || projection.Owner != env.caller.Actor() ||
		projection.Version != 1 || !projection.Enabled {
		t.Fatalf("计划投影不正确: %+v", projection)
	}
	// 载荷带稳定 PlanID，触发链路可关联计划。
	schedule, err := env.scheduler.Get(ctx, view.ScheduleID)
	if err != nil {
		t.Fatalf("读取执行计划失败: %v", err)
	}
	payload, err := decodePlanPayload(schedule.Payload)
	if err != nil || payload.PlanID != view.ID || payload.RowVersion != 1 {
		t.Fatalf("载荷 PlanID/行版本 = %+v, err=%v", payload, err)
	}
	// 过期行版本不得覆盖。
	stale := PlanUpdateRequest{PlanCreateRequest: newPlanRequest(env.caller),
		PlanID: view.ID, Version: 99}
	stale.Name = "被覆盖的名称"
	if _, err := env.plans.Update(ctx, stale); !errors.Is(err, ErrConflict) {
		t.Fatalf("过期版本编辑错误 = %v，期望 ErrConflict", err)
	}
	// 正常编辑：计划 ID 与所有者不变，版本递增，执行计划被替换。
	update := PlanUpdateRequest{PlanCreateRequest: newPlanRequest(env.caller),
		PlanID: view.ID, Version: 1, Reason: "调整统计名称与格式"}
	update.Name = "每周安全摘要"
	update.Formats = []Format{FormatMarkdown}
	updated, err := env.plans.Update(ctx, update)
	if err != nil {
		t.Fatalf("编辑计划失败: %v", err)
	}
	if updated.ID != view.ID || updated.Name != "每周安全摘要" ||
		updated.Version != 2 || updated.Owner != env.caller.Actor() {
		t.Fatalf("编辑结果不正确: %+v", updated)
	}
	if updated.ScheduleID == view.ScheduleID {
		t.Fatal("编辑后执行计划编号未替换")
	}
	if _, err := env.scheduler.Get(ctx, view.ScheduleID); err == nil {
		t.Fatal("编辑后旧执行计划仍存在")
	}
	replacement, err := env.scheduler.Get(ctx, updated.ScheduleID)
	if err != nil {
		t.Fatalf("读取替代执行计划失败: %v", err)
	}
	replacementPayload, err := decodePlanPayload(replacement.Payload)
	if err != nil || replacementPayload.PlanID != view.ID ||
		replacementPayload.RowVersion != 2 || !replacement.Enabled {
		t.Fatalf("替代执行计划载荷 = %+v enabled=%v err=%v",
			replacementPayload, replacement.Enabled, err)
	}
	// 并发编辑：同一旧版本第二次提交必须冲突。
	concurrent := PlanUpdateRequest{PlanCreateRequest: newPlanRequest(env.caller),
		PlanID: view.ID, Version: 1}
	if _, err := env.plans.Update(ctx, concurrent); !errors.Is(err, ErrConflict) {
		t.Fatalf("并发编辑错误 = %v，期望 ErrConflict", err)
	}
	// 停用后编辑保持停用状态，不去暗中提升调度；启停也会推进读模型行版本，
	// 编辑必须使用重新读取后的版本。
	pausedView, err := env.plans.SetEnabled(ctx, env.caller, view.ID, false,
		"暂停", "req-disable")
	if err != nil {
		t.Fatalf("停用计划失败: %v", err)
	}
	if pausedView.Version <= updated.Version {
		t.Fatalf("停用后行版本 = %d，期望大于 %d", pausedView.Version, updated.Version)
	}
	update = PlanUpdateRequest{PlanCreateRequest: newPlanRequest(env.caller),
		PlanID: view.ID, Version: pausedView.Version, Reason: "停用状态下调整"}
	update.Name = "停用计划新名称"
	paused, err := env.plans.Update(ctx, update)
	if err != nil {
		t.Fatalf("停用状态编辑失败: %v", err)
	}
	if paused.Enabled {
		t.Fatal("停用状态编辑后被启用")
	}
	if scheduled, err := env.scheduler.Get(ctx, paused.ScheduleID); err != nil || scheduled.Enabled {
		t.Fatalf("替代执行计划启用状态 = %v, err=%v，期望停用", scheduled.Enabled, err)
	}
	// 对账：投影缺失时从调度事实重建。
	projections.mu.Lock()
	delete(projections.plans, view.ID)
	projections.mu.Unlock()
	repaired, err := env.plans.ReconcilePlans(ctx)
	if err != nil || repaired < 1 {
		t.Fatalf("对账修复 = %d, err=%v，期望至少修复 1 条", repaired, err)
	}
	restored, found, _ := projections.GetPlanProjection(ctx, view.ID)
	if !found || restored.Version != paused.Version || restored.Name != paused.Name {
		t.Fatalf("对账后投影 = %+v found=%v，期望版本 %d", restored, found, paused.Version)
	}
}

// TestLegacyPlanPayloadCompatibility 验证步骤 79 收口前创建的计划（载荷无计划 ID/
// 行版本）仍可查看、显式编辑升级，并触发历史可关联。
func TestLegacyPlanPayloadCompatibility(t *testing.T) {
	now := baseTime
	env := newPlanTestEnv(t, &now)
	projections := attachProjectionStore(t, env)
	ctx := context.Background()
	// 构造旧格式载荷（无 plan_id/row_version）并直接写入调度器。
	legacyPayload, err := task.NewScheduleID()
	if err != nil {
		t.Fatalf("生成旧计划编号失败: %v", err)
	}
	_ = legacyPayload
	raw := []byte(`{"version":1,"name":"旧版计划","scope_id":"system",` +
		`"scope_kind":"system","granularity":"day","window_days":1,` +
		`"formats":["html"],"detail_rows":20,"time_zone":"Asia/Shanghai",` +
		`"owner":{"type":"user","id":"` + testUserID(1) + `"}}`)
	legacy, err := env.scheduler.Create(ctx, task.NewScheduleRequest{
		JobKind: TaskKindPlannedReportGenerate, ScheduleType: task.ScheduleTypeDaily,
		Expression: "09:00", TimeZone: "Asia/Shanghai", Owner: env.caller.Actor(),
		ExecutionActor: env.caller.Actor(), ScopeID: ScopeSystem, Enabled: true,
		MissedPolicy: task.MissedLatest, MaxCatchUp: 1, Payload: raw,
		TimeoutSeconds: 60, MaxAttempts: 1,
	})
	if err != nil {
		t.Fatalf("写入旧格式计划失败: %v", err)
	}
	if repaired, err := env.plans.ReconcilePlans(ctx); err != nil || repaired < 1 {
		t.Fatalf("旧计划对账 = %d, err=%v", repaired, err)
	}
	view, err := env.plans.Get(ctx, env.caller, legacy.ID)
	if err != nil {
		t.Fatalf("旧计划查看失败: %v", err)
	}
	if view.ID != legacy.ID || view.Version != 1 || view.Name != "旧版计划" {
		t.Fatalf("旧计划视图 = %+v，期望兼容旧编号与版本 1", view)
	}
	update := PlanUpdateRequest{PlanCreateRequest: newPlanRequest(env.caller),
		PlanID: view.ID, Version: view.Version, Reason: "升级旧计划"}
	update.Name = "升级后的计划"
	upgraded, err := env.plans.Update(ctx, update)
	if err != nil {
		t.Fatalf("升级旧计划失败: %v", err)
	}
	if upgraded.ID != legacy.ID || upgraded.Version != 2 {
		t.Fatalf("旧计划编辑结果 = %+v，期望计划 ID 不变、版本 2", upgraded)
	}
	schedule, err := env.scheduler.Get(ctx, upgraded.ScheduleID)
	if err != nil {
		t.Fatalf("读取升级后执行计划失败: %v", err)
	}
	payload, err := decodePlanPayload(schedule.Payload)
	if err != nil || payload.PlanID != legacy.ID || payload.RowVersion != 2 {
		t.Fatalf("升级后载荷 = %+v err=%v", payload, err)
	}
	if projection, found, _ := projections.GetPlanProjection(ctx, legacy.ID); !found ||
		projection.Version != 2 {
		t.Fatalf("升级后投影 = %+v found=%v", projection, found)
	}
}

// TestPlanScheduledReportCarriesPlanID 验证计划触发生成的报告与历史携带稳定
// PlanID，且历史状态真实。
func TestPlanScheduledReportCarriesPlanID(t *testing.T) {
	now := baseTime
	env := newPlanTestEnv(t, &now)
	history := newFakeHistoryStore()
	service, err := New(Options{Source: env.service.opts.Source,
		Authorizer: env.authorizer, Root: &fakeRoot{}, Sensitive: &fakeSensitive{},
		Audit: env.recorder, Enqueuer: env.executor, Canceller: env.executor,
		Tasks: env.executor, OutputDir: env.service.opts.OutputDir,
		MaxDetailRows: 20, Now: env.service.opts.Now, History: history})
	if err != nil {
		t.Fatalf("构造带历史的报告服务失败: %v", err)
	}
	env.service = service
	ctx := context.Background()
	view, err := env.plans.Create(ctx, newPlanRequest(env.caller))
	if err != nil {
		t.Fatalf("创建计划失败: %v", err)
	}
	schedule, err := env.scheduler.Get(ctx, view.ScheduleID)
	if err != nil {
		t.Fatalf("读取计划失败: %v", err)
	}
	job := task.Job{ID: "job-plan-history", Kind: TaskKindPlannedReportGenerate,
		Initiator: env.caller.Actor(), ExecutorID: "exec-plan-history",
		Payload: schedule.Payload}
	if err := env.service.GenerateScheduledHandler(ctx, job); err != nil {
		t.Fatalf("计划触发生成失败: %v", err)
	}
	found := false
	for _, reportID := range history.order {
		record := history.records[reportID]
		if record.PlanID != view.ID {
			continue
		}
		found = true
		if record.State != StateSucceeded {
			t.Fatalf("计划历史终态 = %q，期望 succeeded", record.State)
		}
		if len(record.DataScopeJSON) == 0 {
			t.Fatal("计划历史缺少生成时数据范围引用")
		}
	}
	if !found {
		t.Fatal("计划触发生成的历史未携带 PlanID")
	}
}
