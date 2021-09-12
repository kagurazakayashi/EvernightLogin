package reports

// 本文件实现步骤 79 的报告文件保留清理：预览到期目标、强认证后执行删除、真实
// 记录操作者/数量/结果。清理对象只有 internal/reports 受控输出目录中的报告产物
// 文件与 report_history 的清理状态；原始安全审计记录的保留与删除是另一套 root
// 受控流程，本文件不提供入口，也不会触碰审计存储。
//
// 安全不变量：
//   - 预览与执行都按当前调用者在每个作用范围的 reports.cleanup 权限重新授权；
//     执行前再按 reports.cleanup 敏感操作策略做强认证/确认，确认框不是授权。
//   - 执行时重新计算目标，客户端提交的目标数量不能替代服务端计算；目标上限有界。
//   - 只有“产物已到期 + 宽限期已过”的报告文件才会被清理；未到期、权限不足或
//     类型不安全的目标一律跳过并记录真实原因。
//   - 删除失败/标记失败如实返回，不伪造成功；任何失败都不会写成“已清理”。
//   - 清理动作本身写审计（意图 + 结果），审计不可用在删除前拒绝执行（fail-closed）。

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
)

// RetentionPolicy 是报告文件保留策略的公开说明（只读，不含宿主路径）。
type RetentionPolicy struct {
	// ArtifactTTL 是生成后产品可用期（超过后下载不可用）。
	ArtifactTTL time.Duration
	// CleanupGrace 是产物到期后额外保留多久才允许清理。
	CleanupGrace time.Duration
	// EligibleBefore 是本次清理的资格截止时刻（到期早于此值的产物可被清理）。
	EligibleBefore time.Time
	// Source 是策略来源说明。
	Source string
	// HistoryNote/RawAuditNote 分别说明历史报告文件与原始审计的保留边界。
	HistoryNote  string
	RawAuditNote string
}

// CleanupTarget 是一个到期可清理报告文件的预览目标（不含宿主路径）。
type CleanupTarget struct {
	ReportID      string
	PlanID        string
	Name          string
	ScopeID       string
	State         string
	CleanupState  string
	ExpiresAt     time.Time
	Formats       []Format
	ArtifactCount int
	Bytes         int64
}

// CleanupPreview 是清理预览：实际目标、数量、字节与保留说明；它不是授权凭证。
type CleanupPreview struct {
	Policy          RetentionPolicy
	Targets         []CleanupTarget
	TargetCount     int
	TotalBytes      int64
	Scopes          []string
	OldestExpiresAt time.Time
	NewestExpiresAt time.Time
	PreviewedAt     time.Time
	// Note 是当前权限/目标状态的直白说明（例如“当前权限范围内没有到期目标”）。
	Note string
}

// CleanupExecuteRequest 是执行报告文件清理的请求。Caller 必须来自可信上下文；
// 原因必填并进入审计。MaxTargets 为 0 使用默认上限，超过硬上限拒绝。
type CleanupExecuteRequest struct {
	Caller     account.Caller
	Reason     string
	RequestID  string
	MaxTargets int
}

// CleanupFailure 是单个报告目标清理失败的真实原因（不伪造成功）。
type CleanupFailure struct {
	ReportID string
	Reason   string
}

// CleanupResult 是一次报告文件清理的真实结果。
type CleanupResult struct {
	Operator       audit.Actor
	StartedAt      time.Time
	FinishedAt     time.Time
	RequestedCount int
	CleanedCount   int
	FailedCount    int
	DeletedFiles   int
	FreedBytes     int64
	SkippedCount   int
	Failures       []CleanupFailure
	Policy         RetentionPolicy
	// RawAuditNote 明确说明原始审计记录未被删除。
	RawAuditNote string
}

// cleanupPolicy 返回当前保留策略说明。
func (s *Service) cleanupPolicy(cutoff time.Time) RetentionPolicy {
	return RetentionPolicy{
		ArtifactTTL:    s.artifactTTL,
		CleanupGrace:   s.cleanupGrace,
		EligibleBefore: cutoff,
		Source:         "服务端配置（宿主部署时设置，页面只读）",
		HistoryNote: "只删除报告产物文件并把历史记录标记为已清理；报告历史元数据按各自保留策略保留，" +
			"删除后该报告不再可下载或预览。",
		RawAuditNote: "原始安全审计记录不随报告文件清理删除；审计保留与清理是独立的 root 受控流程，本页面不提供该入口。",
	}
}

// cleanupScopes 计算调用者当前有 reports.cleanup 权限的作用范围。
// 返回的 AccessScope 可直接用于仓储 SQL 范围条件；all=false 表示无范围。
func (s *Service) cleanupAccess(ctx context.Context, caller account.Caller) (AccessScope, error) {
	if err := actorCheck(caller); err != nil {
		return AccessScope{}, err
	}
	if s.isRoot(ctx, caller) {
		return AccessScope{AllData: true}, nil
	}
	if !s.historyAvailable() {
		return AccessScope{}, ErrStoreUnavailable
	}
	scopes, err := s.history.ListCleanupCandidateScopes(ctx, s.now().Add(-s.cleanupGrace))
	if err != nil {
		return AccessScope{}, ErrStoreUnavailable
	}
	allowed := make([]string, 0, len(scopes))
	for _, scopeID := range scopes {
		if _, err := s.authorizeQuiet(ctx, caller, PermissionCleanup, scopeID); err != nil {
			continue
		}
		allowed = append(allowed, scopeID)
	}
	return AccessScope{ResourceIDs: allowed}, nil
}

// cleanupCandidates 按调用者当前权限加载到期目标（受上限约束）。
func (s *Service) cleanupCandidates(ctx context.Context, caller account.Caller,
	limit int) ([]HistoryRecord, AccessScope, error) {
	access, err := s.cleanupAccess(ctx, caller)
	if err != nil {
		return nil, AccessScope{}, err
	}
	if !access.AllData && len(access.ResourceIDs) == 0 {
		return nil, access, nil
	}
	if limit < 1 || limit > MaxCleanupBatch {
		limit = DefaultCleanupBatch
	}
	cutoff := s.now().Add(-s.cleanupGrace)
	records, err := s.history.ListCleanupCandidates(ctx, access, cutoff, limit)
	if err != nil {
		return nil, access, ErrStoreUnavailable
	}
	return records, access, nil
}

// cleanupTarget 从历史记录构造受控预览目标；引用无法解析时仍保留目标并让执行
// 阶段如实失败，而不是把“无法解析”当成“没有文件”。
func cleanupTarget(record HistoryRecord) CleanupTarget {
	target := CleanupTarget{
		ReportID: record.ReportID, PlanID: record.PlanID, Name: record.Name,
		ScopeID: record.ScopeID, State: record.State,
		CleanupState: record.CleanupState, ExpiresAt: record.ExpiresAt,
		Formats: append([]Format(nil), record.Formats...),
	}
	for _, ref := range historyArtifacts(record) {
		format := Format(ref.Format)
		if !format.Valid() || !validateArtifactName(ref.Name, format) {
			continue
		}
		target.ArtifactCount++
		target.Bytes += ref.Bytes
	}
	return target
}

// CleanupPreview 返回当前调用者有权清理的到期报告文件预览。它不执行删除、不签发
// 任何凭证；执行时服务端重新计算目标并重新做强认证。
func (s *Service) CleanupPreview(ctx context.Context,
	caller account.Caller) (CleanupPreview, error) {
	if !s.historyAvailable() {
		return CleanupPreview{}, ErrStoreUnavailable
	}
	if err := actorCheck(caller); err != nil {
		return CleanupPreview{}, err
	}
	now := s.now()
	cutoff := now.Add(-s.cleanupGrace)
	preview := CleanupPreview{
		Policy:      s.cleanupPolicy(cutoff),
		Targets:     make([]CleanupTarget, 0, DefaultCleanupBatch),
		PreviewedAt: now,
	}
	records, access, err := s.cleanupCandidates(ctx, caller, DefaultCleanupBatch)
	if err != nil {
		return CleanupPreview{}, err
	}
	if !access.AllData && len(access.ResourceIDs) == 0 {
		preview.Note = "当前权限范围内没有可清理的到期报告文件，或尚未获得 reports.cleanup 权限。"
		return preview, nil
	}
	scopeSet := make(map[string]struct{}, 4)
	for _, record := range records {
		target := cleanupTarget(record)
		preview.Targets = append(preview.Targets, target)
		preview.TargetCount++
		preview.TotalBytes += target.Bytes
		scopeSet[record.ScopeID] = struct{}{}
		if !record.ExpiresAt.IsZero() {
			if preview.OldestExpiresAt.IsZero() || record.ExpiresAt.Before(preview.OldestExpiresAt) {
				preview.OldestExpiresAt = record.ExpiresAt
			}
			if record.ExpiresAt.After(preview.NewestExpiresAt) {
				preview.NewestExpiresAt = record.ExpiresAt
			}
		}
	}
	for scopeID := range scopeSet {
		preview.Scopes = append(preview.Scopes, scopeID)
	}
	sort.Strings(preview.Scopes)
	if preview.TargetCount == 0 {
		preview.Note = "当前权限范围内没有已到期并超过宽限期的报告文件。"
	} else {
		preview.Note = "以上仅为服务端实时预览；执行前需要强认证，且会重新计算目标。原始审计记录不在清理范围。"
	}
	return preview, nil
}

// CleanupExecute 执行报告文件清理：重新授权 → 重算目标 → 强认证 → 写意图审计 →
// 删除受控产物并推进历史清理状态 → 写结果审计。任何失败都如实报告。
func (s *Service) CleanupExecute(ctx context.Context,
	request CleanupExecuteRequest) (CleanupResult, error) {
	if !s.historyAvailable() {
		return CleanupResult{}, ErrStoreUnavailable
	}
	actor := request.Caller.Actor()
	if err := actorCheck(request.Caller); err != nil {
		return CleanupResult{}, err
	}
	reason := strings.TrimSpace(request.Reason)
	if err := validateReason(reason); err != nil {
		return CleanupResult{}, err
	}
	requestID := normalizeRequestID(request.RequestID)
	limit := request.MaxTargets
	if limit == 0 {
		limit = DefaultCleanupBatch
	}
	if limit < 1 || limit > MaxCleanupBatch {
		return CleanupResult{}, fmt.Errorf("%w: 单次清理目标数超出范围", ErrInvalidRequest)
	}
	startedAt := s.now()
	result := CleanupResult{Operator: actor, StartedAt: startedAt,
		RawAuditNote: "原始安全审计记录未删除。"}
	records, access, err := s.cleanupCandidates(ctx, request.Caller, limit)
	if err != nil {
		return CleanupResult{}, err
	}
	cutoff := startedAt.Add(-s.cleanupGrace)
	result.Policy = s.cleanupPolicy(cutoff)
	if !access.AllData && len(access.ResourceIDs) == 0 {
		result.FinishedAt = s.now()
		return result, nil
	}
	// 目标数量/字节/范围摘要进入强认证参数：认证绑定本次真实目标，改参数后旧
	// 认证结果不适用。
	targets := make([]CleanupTarget, 0, len(records))
	var totalBytes int64
	scopeSet := make(map[string]struct{}, 4)
	for _, record := range records {
		target := cleanupTarget(record)
		targets = append(targets, target)
		totalBytes += target.Bytes
		scopeSet[record.ScopeID] = struct{}{}
	}
	scopes := make([]string, 0, len(scopeSet))
	for scopeID := range scopeSet {
		scopes = append(scopes, scopeID)
	}
	sort.Strings(scopes)
	reauthCaller, err := reauth.CallerFromActor(actor)
	if err != nil {
		return CleanupResult{}, ErrAccessDenied
	}
	authResult, err := s.opts.Sensitive.Authorize(ctx, reauthCaller, reauth.Request{
		ScopeID: ScopeSystem, OperationID: OperationCleanup,
		TargetType: "report_cleanup", TargetID: "",
		Params: map[string]string{
			"target_count":    strconv.Itoa(len(targets)),
			"total_bytes":     strconv.FormatInt(totalBytes, 10),
			"scopes":          strings.Join(scopes, ","),
			"eligible_before": strconv.FormatInt(cutoff.UnixMilli(), 10),
		},
		Description: "清理已过期报告文件（不删除原始审计）",
		RequestID:   requestID,
	})
	if err != nil {
		s.recordFailure(ctx, actor, ActionCleanupRequest, "", "cleanup_reauth_denied",
			CodeAccessDenied, requestID, "")
		return CleanupResult{}, fmt.Errorf("%w: %w", ErrAccessDenied, err)
	}
	// 意图审计必须在删除前写入：审计不可用时拒绝执行，避免“文件已删但无记录”。
	intent := audit.Event{
		Actor: actor, AppID: "",
		Action:  ActionCleanupRequest,
		Target:  audit.Target{Type: "report_cleanup", ID: "expired_report_files"},
		Outcome: audit.OutcomeSuccess, RequestID: requestID,
		Changes: []audit.FieldChange{
			{Field: "target_count", After: strconv.Itoa(len(targets))},
			{Field: "total_bytes", After: strconv.FormatInt(totalBytes, 10)},
			{Field: "reason_present", After: "true"},
		},
	}
	if err := s.opts.Audit.Record(ctx, intent); err != nil {
		return CleanupResult{}, fmt.Errorf("%w: 清理意图审计写入失败", ErrAuditUnavailable)
	}
	result.RequestedCount = len(targets)
	for _, record := range records {
		if markErr := s.history.MarkHistoryCleanup(ctx, record.ReportID, "pending"); markErr != nil {
			// 已经是 pending 的记录（上次删除失败遗留）应继续尝试删除，而不是永远
			// 跳过；只有“已 cleaned”等真正不可推进的状态才跳过。
			if errors.Is(markErr, ErrConflict) {
				if record.CleanupState != "pending" {
					result.SkippedCount++
					continue
				}
			} else {
				result.FailedCount++
				result.Failures = append(result.Failures,
					CleanupFailure{ReportID: record.ReportID, Reason: "无法标记待清理状态"})
				continue
			}
		}
		deleted, freed, removeErr := s.removeReportArtifacts(record)
		result.DeletedFiles += deleted
		result.FreedBytes += freed
		if removeErr != nil {
			result.FailedCount++
			result.Failures = append(result.Failures, CleanupFailure{
				ReportID: record.ReportID, Reason: safeToken("artifact_remove_failed")})
			continue
		}
		if markErr := s.history.MarkHistoryCleanup(ctx,
			record.ReportID, "cleaned"); markErr != nil {
			result.FailedCount++
			result.Failures = append(result.Failures, CleanupFailure{
				ReportID: record.ReportID, Reason: "删除后无法标记已清理"})
			continue
		}
		result.CleanedCount++
	}
	result.FinishedAt = s.now()
	outcome := audit.OutcomeSuccess
	if result.FailedCount > 0 {
		outcome = audit.OutcomeFailure
	}
	finish := audit.Event{
		Actor: actor, Action: ActionCleanupFinish,
		Target:  audit.Target{Type: "report_cleanup", ID: "expired_report_files"},
		Outcome: outcome, RequestID: requestID,
		ErrorCode: func() string {
			if result.FailedCount > 0 {
				return string(CodeInternalError)
			}
			return ""
		}(),
		Changes: []audit.FieldChange{
			{Field: "requested_count", After: strconv.Itoa(result.RequestedCount)},
			{Field: "cleaned_count", After: strconv.Itoa(result.CleanedCount)},
			{Field: "failed_count", After: strconv.Itoa(result.FailedCount)},
			{Field: "skipped_count", After: strconv.Itoa(result.SkippedCount)},
			{Field: "deleted_files", After: strconv.Itoa(result.DeletedFiles)},
			{Field: "freed_bytes", After: strconv.FormatInt(result.FreedBytes, 10)},
		},
	}
	if err := s.opts.Audit.Record(ctx, finish); err != nil {
		// 删除已经发生，不能伪造成“全部成功且已审计”：返回真实结果并标记审计失败。
		return result, fmt.Errorf("%w: 清理结果审计写入失败", ErrAuditUnavailable)
	}
	if authResult.OperationID != "" {
		if notifyErr := s.opts.Sensitive.NotifyOutcome(ctx, authResult,
			reauth.OutcomeSuccess); notifyErr != nil {
			s.opts.Logger.Warn("报告清理安全告知未完成", "reason", "notify_unavailable")
		}
	}
	return result, nil
}

// removeReportArtifacts 删除一条历史记录引用的受控报告产物文件，返回删除数、
// 释放字节与错误。只有受控文件名 + 受控目录内的普通文件会被删除；缺失文件视为
// 已不在（仍可推进清理状态），符号链接/目录/名称越界一律失败而不是删除。
func (s *Service) removeReportArtifacts(record HistoryRecord) (int, int64, error) {
	refs := historyArtifacts(record)
	if len(refs) == 0 {
		// 没有可识别产物引用：不删除任何文件，也不伪造删除成功。
		return 0, 0, nil
	}
	deleted := 0
	var freed int64
	for _, ref := range refs {
		format := Format(ref.Format)
		if !format.Valid() || !validateArtifactName(ref.Name, format) {
			return deleted, freed, ErrArtifactUnsafe
		}
		path := filepath.Join(s.outputDir, ref.Name)
		info, err := os.Lstat(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return deleted, freed, err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return deleted, freed, ErrArtifactUnsafe
		}
		if err := os.Remove(path); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return deleted, freed, err
		}
		deleted++
		freed += info.Size()
	}
	return deleted, freed, nil
}
