package userbatch

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// Options 是本包依赖与边界配置；Store/Audit/Authorizer/Sensitive/Accounts/Enqueuer
// 缺失时拒绝构造（fail-closed）。导出还需要 OutputDir（绝对、已存在、非符号链接）。
type Options struct {
	Store      Store
	Audit      AuditRecorder
	Authorizer Authorizer
	// Sensitive 是步骤 38/39 敏感操作执行前校验（生产 *reauth.Service）。
	Sensitive SensitiveRunner
	Accounts  AccountService
	// DataScope 逐用户判定导出数据范围；导出任务缺失时 fail-closed 拒绝构造。
	DataScope UserScopeAuthorizer
	Enqueuer  Enqueuer
	Canceller Canceller
	// OutputDir 是导出 CSV 的宿主受控目录（绝对路径、已存在、非符号链接）。
	OutputDir string
	// MaxFileBytes/MaxImportRows/MaxExportRows/BatchSize/MaxRowDetails 是边界；
	// 0 使用默认值，超过硬上限拒绝构造。
	MaxFileBytes  int64
	MaxImportRows int
	MaxExportRows int
	BatchSize     int
	MaxRowDetails int
	Now           func() time.Time
	Random        io.Reader
	Logger        *slog.Logger
}

// Service 是用户批量导入导出服务：构造后不可变、可并发使用；不启动协程、不提供
// HTTP 路由；异步执行由宿主把 Handler 注册到 internal/task 执行器。
type Service struct {
	opts          Options
	maxFileBytes  int64
	maxImportRows int
	maxExportRows int
	batchSize     int
	maxDetails    int
	outputDir     string
}

// New 校验依赖与边界并构造服务。
func New(options Options) (*Service, error) {
	if isNil(options.Store) || isNil(options.Audit) || isNil(options.Authorizer) ||
		isNil(options.Sensitive) || isNil(options.Accounts) || isNil(options.Enqueuer) {
		return nil, fmt.Errorf("%w: 批量导入导出必需依赖缺失", ErrOptionsInvalid)
	}
	maxFileBytes := options.MaxFileBytes
	if maxFileBytes == 0 {
		maxFileBytes = DefaultMaxFileBytes
	}
	if maxFileBytes < 0 || maxFileBytes > MaxHardFileBytes {
		return nil, fmt.Errorf("%w: 导入文件字节上限超出范围", ErrOptionsInvalid)
	}
	maxImportRows := options.MaxImportRows
	if maxImportRows == 0 {
		maxImportRows = DefaultMaxImportRows
	}
	if maxImportRows < 1 || maxImportRows > MaxHardImportRows {
		return nil, fmt.Errorf("%w: 导入行数上限超出范围", ErrOptionsInvalid)
	}
	maxExportRows := options.MaxExportRows
	if maxExportRows == 0 {
		maxExportRows = DefaultMaxExportRows
	}
	if maxExportRows < 1 || maxExportRows > MaxHardExportRows {
		return nil, fmt.Errorf("%w: 导出行数上限超出范围", ErrOptionsInvalid)
	}
	batchSize := options.BatchSize
	if batchSize == 0 {
		batchSize = DefaultBatchSize
	}
	if batchSize < 1 || batchSize > 1000 {
		return nil, fmt.Errorf("%w: 批大小超出范围", ErrOptionsInvalid)
	}
	maxDetails := options.MaxRowDetails
	if maxDetails == 0 {
		maxDetails = DefaultMaxRowDetails
	}
	if maxDetails < 1 || maxDetails > 100000 {
		return nil, fmt.Errorf("%w: 明细上限超出范围", ErrOptionsInvalid)
	}
	outputDir := ""
	if options.OutputDir != "" {
		absolute, err := filepath.Abs(options.OutputDir)
		if err != nil {
			return nil, fmt.Errorf("%w: 导出目录无效", ErrOptionsInvalid)
		}
		info, statErr := os.Lstat(absolute)
		if statErr != nil || !info.IsDir() {
			return nil, fmt.Errorf("%w: 导出目录必须是已存在的目录", ErrOptionsInvalid)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: 导出目录不能是符号链接", ErrOptionsInvalid)
		}
		outputDir = absolute
	}
	// 导出能力（配置了 OutputDir）必须注入逐用户数据范围授权器，缺失 fail-closed 拒绝构造。
	if outputDir != "" && isNil(options.DataScope) {
		return nil, fmt.Errorf("%w: 导出必须提供数据范围授权器", ErrOptionsInvalid)
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.Logger == nil {
		options.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Service{opts: options, maxFileBytes: maxFileBytes,
		maxImportRows: maxImportRows, maxExportRows: maxExportRows,
		batchSize: batchSize, maxDetails: maxDetails, outputDir: outputDir}, nil
}

// PrecheckImport 只解析/校验文件，不创建任务、不写库。
func (s *Service) PrecheckImport(ctx context.Context, caller account.Caller,
	content []byte) (ParseReport, error) {
	ctx = normalizeContext(ctx)
	if err := s.authorize(ctx, caller, ActionImport); err != nil {
		return ParseReport{}, err
	}
	_, report, err := parseImport(content, s.maxFileBytes, s.maxImportRows)
	if err != nil {
		return report, err
	}
	return report, nil
}

// StartImport 预检查后创建幂等导入任务并入队。文件级错误不创建任务。
func (s *Service) StartImport(ctx context.Context, request ImportRequest) (StartResult, error) {
	ctx = normalizeContext(ctx)
	if err := validateIdempotencyKey(request.IdempotencyKey); err != nil {
		return StartResult{}, err
	}
	if err := s.authorize(ctx, request.Caller, ActionImport); err != nil {
		return StartResult{}, err
	}
	rows, report, err := parseImport(request.Content, s.maxFileBytes, s.maxImportRows)
	if err != nil {
		s.recordFailure(ctx, request.Caller, "user.batch.import_denied", "",
			"file_invalid", CodeReqInvalid, request.RequestID)
		return StartResult{}, err
	}
	if len(rows) == 0 || !report.CanImport {
		return StartResult{}, fmt.Errorf("%w: 导入文件没有可处理的数据行", ErrFileInvalid)
	}
	digest := sha256Digest(request.Content, []byte("import"))
	if guard, err := s.authorizeSensitive(ctx, request.Caller, OperationImport,
		"system", map[string]string{
			"kind": "import", "idempotency_key": request.IdempotencyKey,
			"digest": hex.EncodeToString(digest[:]),
			"rows":   fmt.Sprint(len(rows)), "request_id": request.RequestID,
		}, "批量导入普通用户", request.RequestID); err != nil {
		s.recordFailure(ctx, request.Caller, "user.batch.import_denied", "",
			"reauth_rejected", CodeAccessDenied, request.RequestID)
		return StartResult{}, err
	} else {
		defer s.notifySensitive(ctx, guard)
	}
	now := s.now()
	actor := request.Caller.Actor()
	jobID, idErr := newJobID(s.opts.Random)
	if idErr != nil {
		return StartResult{}, idErr
	}
	record := JobRecord{
		Job: Job{ID: jobID, Kind: KindImport, State: JobQueued,
			OwnerType: actor.Type, OwnerID: actor.ID, ScopeID: "system",
			TotalRows: report.TotalRows, RequestID: request.RequestID,
			CreatedAt: now, UpdatedAt: now},
		IdempotencyKey: request.IdempotencyKey, RequestDigest: digest, InputCSV: request.Content,
	}
	stored, created, err := s.opts.Store.CreateJob(ctx, record, digest, request.Content)
	if err != nil {
		return StartResult{}, err
	}
	if !created {
		if stored.IdempotencyKey != request.IdempotencyKey ||
			stored.RequestDigest != digest ||
			stored.OwnerType != actor.Type || stored.OwnerID != actor.ID {
			return StartResult{}, fmt.Errorf("%w: 幂等键已绑定其他调用者或不同内容", ErrConflict)
		}
		return StartResult{Job: s.jobView(stored), Duplicate: true, Report: report}, nil
	}
	job := stored
	if err := s.enqueue(ctx, &job); err != nil {
		return StartResult{}, err
	}
	s.recordAudit(ctx, actor, "user.batch.import_queued", job, nil, request.RequestID)
	return StartResult{Job: s.jobView(job), Report: report}, nil
}

// StartExport 创建幂等导出任务；字段只能从默认白名单减少。
func (s *Service) StartExport(ctx context.Context, request ExportRequest) (StartResult, error) {
	ctx = normalizeContext(ctx)
	if err := validateIdempotencyKey(request.IdempotencyKey); err != nil {
		return StartResult{}, err
	}
	if s.outputDir == "" {
		return StartResult{}, fmt.Errorf("%w: 未配置导出目录", ErrExportPathUnsafe)
	}
	if err := s.authorize(ctx, request.Caller, ActionExport); err != nil {
		return StartResult{}, err
	}
	fields, err := normalizeExportFields(request.Fields, request.IncludeFreeText)
	if err != nil {
		return StartResult{}, err
	}
	maxRows := request.MaxRows
	if maxRows <= 0 || maxRows > s.maxExportRows {
		maxRows = s.maxExportRows
	}
	optionsDocument, marshalErr := json.Marshal(map[string]any{
		"fields": fields, "free_text": request.IncludeFreeText, "max_rows": maxRows,
	})
	if marshalErr != nil {
		return StartResult{}, fmt.Errorf("%w: 导出选项编码失败", ErrInvalidRequest)
	}
	digest := sha256Digest(optionsDocument, []byte("export"))
	if guard, err := s.authorizeSensitive(ctx, request.Caller, OperationExport,
		"system", map[string]string{
			"kind": "export", "idempotency_key": request.IdempotencyKey,
			"digest": hex.EncodeToString(digest[:]), "fields": strings.Join(fields, ","),
			"request_id": request.RequestID,
		}, "批量导出普通用户资料", request.RequestID); err != nil {
		s.recordFailure(ctx, request.Caller, "user.batch.export_denied", "",
			"reauth_rejected", CodeAccessDenied, request.RequestID)
		return StartResult{}, err
	} else {
		defer s.notifySensitive(ctx, guard)
	}
	now := s.now()
	actor := request.Caller.Actor()
	jobID, idErr := newJobID(s.opts.Random)
	if idErr != nil {
		return StartResult{}, idErr
	}
	record := JobRecord{
		Job: Job{ID: jobID, Kind: KindExport, State: JobQueued,
			OwnerType: actor.Type, OwnerID: actor.ID, ScopeID: "system",
			RequestID: request.RequestID, CreatedAt: now, UpdatedAt: now},
		IdempotencyKey: request.IdempotencyKey, RequestDigest: digest,
	}
	stored, created, err := s.opts.Store.CreateJob(ctx, record, digest, optionsDocument)
	if err != nil {
		return StartResult{}, err
	}
	if !created {
		if stored.IdempotencyKey != request.IdempotencyKey || stored.RequestDigest != digest ||
			stored.OwnerType != actor.Type || stored.OwnerID != actor.ID {
			return StartResult{}, fmt.Errorf("%w: 幂等键已绑定其他调用者或不同内容", ErrConflict)
		}
		return StartResult{Job: s.jobView(stored), Duplicate: true}, nil
	}
	job := stored
	if err := s.enqueue(ctx, &job); err != nil {
		return StartResult{}, err
	}
	s.recordAudit(ctx, actor, "user.batch.export_queued", job, nil, request.RequestID)
	return StartResult{Job: s.jobView(job)}, nil
}

// Handler 是 internal/task 处理器；按任务载荷 job_id 分发导入/导出。
func (s *Service) Handler(ctx context.Context, job task.Job) error {
	var payload struct {
		JobID string `json:"job_id"`
	}
	if err := json.Unmarshal(job.Payload, &payload); err != nil ||
		len(payload.JobID) == 0 || len(payload.JobID) > 64 {
		return task.NonRetryable(fmt.Errorf("%w: 批量任务载荷无效", ErrInvalidRequest))
	}
	readCtx := context.WithoutCancel(ctx)
	record, found, err := s.opts.Store.GetJob(readCtx, payload.JobID)
	if err != nil {
		return err
	}
	if !found {
		return task.NonRetryable(fmt.Errorf("%w: 批量任务不存在", ErrNotFound))
	}
	if record.State.Terminal() {
		return nil
	}
	caller, err := callerFromOwner(record.OwnerType, record.OwnerID)
	if err != nil {
		s.finish(ctx, record, JobFailed, CodeAccessDenied, s.now())
		return task.NonRetryable(err)
	}
	// 只有 queued 能原子迁移到 running；并发执行者/已终态/崩溃遗留 running 都幂等返回，
	// 遗留 running 由宿主启动时 ReconcileInterrupted 收敛为 failed 以便 Retry。
	marked, markErr := s.opts.Store.MarkRunning(readCtx, record.ID, s.now())
	if markErr != nil {
		return markErr
	}
	if !marked {
		return nil
	}
	switch record.Kind {
	case KindImport:
		return s.importHandler(ctx, record, caller)
	case KindExport:
		return s.exportHandler(ctx, record, caller)
	default:
		s.finish(readCtx, record, JobFailed, CodeReqInvalid, s.now())
		return task.NonRetryable(fmt.Errorf("%w: 未知批量任务类型", ErrInvalidRequest))
	}
}

// importHandler 逐行导入：已处理行跳过（重启续跑），每批复验权限。
func (s *Service) importHandler(ctx context.Context, record JobRecord,
	caller account.Caller) error {
	rows, report, err := parseImport(record.InputCSV, s.maxFileBytes, s.maxImportRows)
	if err != nil {
		s.finish(ctx, record, JobFailed, CodeReqInvalid, s.now())
		return task.NonRetryable(fmt.Errorf("%w: 导入文件无法解析", ErrFileInvalid))
	}
	// 任务可能在队列等待期间被撤权：处理首行前必须先复验，撤销则不得先导入任何行。
	if authErr := s.authorize(ctx, caller, ActionImport); authErr != nil {
		s.finish(ctx, record, JobFailed, CodeAccessDenied, s.now())
		return task.NonRetryable(authErr)
	}
	processed := 0
	for _, row := range rows {
		if ctxErr := ctx.Err(); ctxErr != nil {
			if errors.Is(ctxErr, context.DeadlineExceeded) {
				s.finish(ctx, record, JobFailed, CodeTaskTimeout, s.now())
				return task.NonRetryable(ctxErr)
			}
			s.finish(ctx, record, JobCancelled, CodeTaskCancelled, s.now())
			return task.NonRetryable(ctxErr)
		}
		if exists, hasErr := s.opts.Store.HasRow(ctx, record.ID, row.RowNumber); hasErr != nil {
			return hasErr
		} else if exists {
			continue
		}
		// 每批复验调用者资格：权限中途撤销立即停止（已提交行保留）。
		if processed > 0 && processed%s.batchSize == 0 {
			if authErr := s.authorize(ctx, caller, ActionImport); authErr != nil {
				s.finish(ctx, record, JobFailed, CodeAccessDenied, s.now())
				return task.NonRetryable(authErr)
			}
		}
		processed++
		result := s.processImportRow(ctx, caller, row)
		if _, insertErr := s.opts.Store.InsertRow(ctx, RowRecord{
			JobID: record.ID, RowNumber: row.RowNumber, Action: result.action,
			ErrorCode: string(result.errorCode), ReasonCode: result.reasonCode,
			UsernameNormalized: result.normalized, UserID: result.userID,
			CreatedAt: s.now(),
		}); insertErr != nil {
			return insertErr
		}
	}
	s.finishFromRows(ctx, record, report.TotalRows, false, "")
	return nil
}

type rowOutcome struct {
	action     RowAction
	errorCode  ErrorCode
	reasonCode string
	normalized string
	userID     string
}

// processImportRow 处理一行：白名单创建/重复匹配/root 保护；不修改既有用户。
func (s *Service) processImportRow(ctx context.Context, caller account.Caller,
	row importRow) rowOutcome {
	if !row.Valid {
		return rowOutcome{action: RowFailed, errorCode: row.ErrorCode, reasonCode: row.Reason}
	}
	normalized, _, err := account.NormalizeUsername(row.Username)
	if err != nil {
		return rowOutcome{action: RowFailed, errorCode: CodeReqInvalid, reasonCode: "username_invalid"}
	}
	existing, found, lookupErr := s.opts.Store.LookupUserByNormalizedUsername(ctx, normalized)
	if lookupErr != nil {
		return rowOutcome{action: RowFailed, errorCode: CodeDBUnavailable, reasonCode: "store_unavailable"}
	}
	if found {
		if existing.IsRoot {
			return rowOutcome{action: RowDenied, errorCode: CodeAccessDenied,
				reasonCode: "protected_account", normalized: normalized}
		}
		if sameProfile(existing.User, row) {
			return rowOutcome{action: RowSkipped, normalized: normalized,
				userID: existing.User.ID}
		}
		return rowOutcome{action: RowConflict, errorCode: CodeConflict,
			reasonCode: "existing_profile_differs", normalized: normalized,
			userID: existing.User.ID}
	}
	created, createErr := s.opts.Accounts.CreateUser(ctx, caller, account.CreateRequest{
		Username: row.Username, Nickname: row.Nickname, Biography: row.Biography,
		Language: row.Language, Timezone: row.Timezone,
	})
	if createErr != nil {
		if errors.Is(createErr, account.ErrUsernameTaken) {
			// 并发创建/重复行：重新匹配，不产生第二个用户。
			if raced, found, _ := s.opts.Store.LookupUserByNormalizedUsername(ctx, normalized); found {
				if raced.IsRoot {
					return rowOutcome{action: RowDenied, errorCode: CodeAccessDenied,
						reasonCode: "protected_account", normalized: normalized}
				}
				if sameProfile(raced.User, row) {
					return rowOutcome{action: RowSkipped, normalized: normalized,
						userID: raced.User.ID}
				}
				return rowOutcome{action: RowConflict, errorCode: CodeConflict,
					reasonCode: "existing_profile_differs", normalized: normalized,
					userID: raced.User.ID}
			}
		}
		code := CodeFromAccount(createErr)
		return rowOutcome{action: RowFailed, errorCode: code,
			reasonCode: "create_failed", normalized: normalized}
	}
	return rowOutcome{action: RowCreated, normalized: normalized, userID: created.ID}
}

// sameProfile 保守比较既有资料与导入值（不更新既有用户）。
func sameProfile(existing account.User, row importRow) bool {
	return existing.Username == row.Username && existing.Nickname == row.Nickname &&
		existing.Biography == row.Biography && existing.Language == row.Language &&
		existing.Timezone == row.Timezone
}

// exportHandler 分页导出：逐用户经数据范围授权器判定，命中上限置 truncated。
func (s *Service) exportHandler(ctx context.Context, record JobRecord,
	caller account.Caller) error {
	options, optionErr := parseExportOptions(record.InputCSV)
	if optionErr != nil {
		s.finish(ctx, record, JobFailed, CodeReqInvalid, s.now())
		return task.NonRetryable(optionErr)
	}
	fields := options.Fields
	// 任务级局部上限，绝不回写共享 Service 字段（并发任务互不影响）。
	taskLimit := options.MaxRows
	file, err := os.OpenFile(s.exportFilePath(record.ID), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		s.finish(ctx, record, JobFailed, CodeExportPathUnsafe, s.now())
		return task.NonRetryable(fmt.Errorf("%w: 无法创建导出文件", ErrExportPathUnsafe))
	}
	hasher := sha256.New()
	writer := csv.NewWriter(io.MultiWriter(file, hasher))
	if err := writer.Write(fields); err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		s.finish(ctx, record, JobFailed, CodeReportGeneration, s.now())
		return task.NonRetryable(err)
	}
	totalScanned := 0
	exported := 0
	denied := 0
	truncated := false
	offset := 0
	permissions := PermissionExport
	maxScan := taskLimit * 10
	if maxScan < 1000 {
		maxScan = 1000
	}
	if maxScan > 1000000 {
		maxScan = 1000000
	}
	for {
		if ctxErr := ctx.Err(); ctxErr != nil {
			writer.Flush()
			_ = file.Close()
			_ = os.Remove(file.Name())
			if errors.Is(ctxErr, context.DeadlineExceeded) {
				s.finish(ctx, record, JobFailed, CodeTaskTimeout, s.now())
			} else {
				s.finish(ctx, record, JobCancelled, CodeTaskCancelled, s.now())
			}
			return task.NonRetryable(ctxErr)
		}
		// 每页复验整体导出权限：中途撤权 fail-closed 失败（不是跳过或 succeeded）。
		if authErr := s.authorize(ctx, caller, ActionExport); authErr != nil {
			writer.Flush()
			_ = file.Close()
			_ = os.Remove(file.Name())
			s.finish(ctx, record, JobFailed, CodeAccessDenied, s.now())
			return task.NonRetryable(authErr)
		}
		if totalScanned >= maxScan {
			truncated = true
			break
		}
		pageSize := 200
		if remaining := taskLimit - exported; remaining < pageSize {
			pageSize = remaining
		}
		if pageSize <= 0 {
			truncated = true
			break
		}
		page, listErr := s.opts.Accounts.ListUsers(ctx, caller,
			account.ListRequest{Limit: pageSize, Offset: offset})
		if listErr != nil {
			writer.Flush()
			_ = file.Close()
			_ = os.Remove(file.Name())
			s.finish(ctx, record, JobFailed, CodeFromAccount(listErr), s.now())
			return task.NonRetryable(listErr)
		}
		for _, user := range page.Users {
			totalScanned++
			allowed := true
			if !isNil(s.opts.DataScope) {
				var scopeErr error
				allowed, scopeErr = s.opts.DataScope.AuthorizeUser(ctx, caller, permissions, user.ID)
				if scopeErr != nil {
					writer.Flush()
					_ = file.Close()
					_ = os.Remove(file.Name())
					s.finish(ctx, record, JobFailed, CodeReportAccessDenied, s.now())
					return task.NonRetryable(scopeErr)
				}
			} else {
				allowed = false
			}
			if !allowed {
				denied++
				continue
			}
			if exported >= taskLimit {
				truncated = true
				break
			}
			if err := writeExportRecord(writer, fields, user); err != nil {
				writer.Flush()
				_ = file.Close()
				_ = os.Remove(file.Name())
				s.finish(ctx, record, JobFailed, CodeReportGeneration, s.now())
				return task.NonRetryable(err)
			}
			exported++
		}
		writer.Flush()
		if err := writer.Error(); err != nil {
			_ = file.Close()
			_ = os.Remove(file.Name())
			s.finish(ctx, record, JobFailed, CodeReportGeneration, s.now())
			return task.NonRetryable(err)
		}
		if !page.HasMore || truncated || ctx.Err() != nil {
			break
		}
		offset += len(page.Users)
	}
	writer.Flush()
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		s.finish(ctx, record, JobFailed, CodeReportGeneration, s.now())
		return task.NonRetryable(err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(file.Name())
		s.finish(ctx, record, JobFailed, CodeReportGeneration, s.now())
		return task.NonRetryable(err)
	}
	digest := hasher.Sum(nil)
	state := JobSucceeded
	errorCode := ErrorCode("")
	if truncated {
		errorCode = CodeReportIncomplete
	}
	s.finishWithCounts(ctx, record, state, errorCode, FinishJobCommand{
		JobID: record.ID, TotalRows: totalScanned, DeniedRows: denied,
		SkippedRows: exported, Truncated: truncated,
		ExportPath: s.exportFilePath(record.ID), ExportSHA256: digest,
		ExportRows: exported, ErrorCode: errorCode, Now: s.now(),
	})
	return nil
}

// ===== 查询 / 取消 / 重试 =====

// GetJob 按权限读取任务（非 system 调用者只能看自己的任务）。
func (s *Service) GetJob(ctx context.Context, caller account.Caller, jobID string) (Job, error) {
	ctx = normalizeContext(ctx)
	if err := s.authorize(ctx, caller, ActionQuery); err != nil {
		return Job{}, err
	}
	record, found, err := s.opts.Store.GetJob(ctx, jobID)
	if err != nil {
		return Job{}, err
	}
	if !found {
		return Job{}, ErrNotFound
	}
	if !s.ownerVisible(caller, record) {
		return Job{}, fmt.Errorf("%w: 批量任务不在可访问范围", ErrAccessDenied)
	}
	return s.jobView(record), nil
}

// ListJobs 列出调用者可访问范围内的任务（步骤 218：offset 真实在数据源分页，
// 多取一条判定 HasMore；不返回总数）。
func (s *Service) ListJobs(ctx context.Context, caller account.Caller,
	query ListJobsQuery) ([]Job, bool, error) {
	ctx = normalizeContext(ctx)
	if err := s.authorize(ctx, caller, ActionQuery); err != nil {
		return nil, false, err
	}
	actor := caller.Actor()
	if actor.Type != audit.ActorSystem {
		query.OwnerType = actor.Type
		query.OwnerID = actor.ID
	}
	if query.Kind != "" && !query.Kind.Valid() {
		return nil, false, fmt.Errorf("%w: 任务类型无效", ErrInvalidRequest)
	}
	if query.Offset < 0 || query.Offset > 1_000_000 {
		return nil, false, fmt.Errorf("%w: 分页偏移超出范围", ErrInvalidRequest)
	}
	limit := query.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > MaxListLimit {
		return nil, false, fmt.Errorf("%w: 每页条数必须在 1～%d 之间", ErrInvalidRequest,
			MaxListLimit)
	}
	query.Limit = limit + 1 // 多取一条判定 HasMore
	records, err := s.opts.Store.ListJobs(ctx, query)
	if err != nil {
		return nil, false, err
	}
	hasMore := len(records) > limit
	if hasMore {
		records = records[:limit]
	}
	jobs := make([]Job, 0, len(records))
	for _, record := range records {
		jobs = append(jobs, s.jobView(record))
	}
	return jobs, hasMore, nil
}

// ListRows 读取逐行结果（仅任务所有者/系统）。
func (s *Service) ListRows(ctx context.Context, caller account.Caller, jobID string,
	limit int) ([]RowResult, bool, error) {
	ctx = normalizeContext(ctx)
	if err := s.authorize(ctx, caller, ActionQuery); err != nil {
		return nil, false, err
	}
	record, found, err := s.opts.Store.GetJob(ctx, jobID)
	if err != nil {
		return nil, false, err
	}
	if !found {
		return nil, false, ErrNotFound
	}
	if !s.ownerVisible(caller, record) {
		return nil, false, fmt.Errorf("%w: 批量任务不在可访问范围", ErrAccessDenied)
	}
	if limit <= 0 || limit > s.maxDetails {
		limit = s.maxDetails
	}
	// 分页读取到请求上限（SQL 单页上限 MaxListLimit），避免把明细静默截断为 100 行。
	rows := make([]RowResult, 0, limit)
	offset := 0
	for len(rows) < limit {
		pageSize := s.maxDetails
		if pageSize > MaxListLimit {
			pageSize = MaxListLimit
		}
		if remaining := limit - len(rows); remaining < pageSize {
			pageSize = remaining
		}
		records, err := s.opts.Store.ListRows(ctx, jobID, offset, pageSize)
		if err != nil {
			return nil, false, err
		}
		if len(records) == 0 {
			break
		}
		for _, record := range records {
			rows = append(rows, RowResult{RowNumber: record.RowNumber, Action: record.Action,
				ErrorCode: ErrorCode(record.ErrorCode), ReasonCode: record.ReasonCode,
				UsernameNormalized: record.UsernameNormalized, UserID: record.UserID})
		}
		offset += len(records)
		if len(records) < pageSize {
			break
		}
	}
	// truncated 以真实总行数与返回行数比较，而不是传入 limit。
	counts, countErr := s.opts.Store.CountRows(ctx, jobID)
	if countErr != nil {
		return nil, false, countErr
	}
	total := 0
	for _, count := range counts {
		total += count
	}
	truncated := total > len(rows)
	return rows, truncated, nil
}

// ReportCSV 生成逐行结果报告（CSV，公式注入防护，不含原始行/秘密）。
//
// 第二个返回值是报告是否因明细上限而截断：报告每行都带 report_truncated 列显式
// 标记，避免“数据缺失被当成完整”。
func (s *Service) ReportCSV(ctx context.Context, caller account.Caller,
	jobID string) ([]byte, bool, error) {
	rows, truncated, err := s.ListRows(ctx, caller, jobID, s.maxDetails)
	if err != nil {
		return nil, false, err
	}
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	_ = writer.Write([]string{"row_number", "action", "error_code", "reason_code",
		"username_normalized", "user_id", "report_truncated"})
	flag := "false"
	if truncated {
		flag = "true"
	}
	for _, row := range rows {
		_ = writer.Write([]string{
			fmt.Sprint(row.RowNumber), string(row.Action), string(row.ErrorCode),
			escapeReportCell(row.ReasonCode), escapeReportCell(row.UsernameNormalized),
			escapeReportCell(row.UserID), flag,
		})
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, false, fmt.Errorf("%w: 报告生成失败", ErrStoreUnavailable)
	}
	return buffer.Bytes(), truncated, nil
}

// Cancel 请求取消任务；真正取消由任务执行器与 handler 收敛。
func (s *Service) Cancel(ctx context.Context, caller account.Caller, jobID, reason,
	requestID string) error {
	ctx = normalizeContext(ctx)
	if err := s.authorize(ctx, caller, ActionCancel); err != nil {
		return err
	}
	record, found, err := s.opts.Store.GetJob(ctx, jobID)
	if err != nil || !found {
		if err != nil {
			return err
		}
		return ErrNotFound
	}
	if !s.ownerVisible(caller, record) {
		return ErrAccessDenied
	}
	if record.State.Terminal() {
		return fmt.Errorf("%w: 任务已终态", ErrJobState)
	}
	if isNil(s.opts.Canceller) {
		return fmt.Errorf("%w: 未装配任务取消能力", ErrAccessDenied)
	}
	if record.TaskID == "" {
		return ErrJobState
	}
	result, err := s.opts.Canceller.RequestCancel(ctx, task.CancelRequest{
		JobID: record.TaskID, Actor: caller.Actor(), Reason: safeReason(reason),
		RequestID: requestID,
	})
	if err != nil {
		return ErrStoreUnavailable
	}
	if !result.Accepted && !result.AlreadyRequested {
		return fmt.Errorf("%w: 取消请求被拒绝", ErrJobState)
	}
	if record.State == JobQueued {
		_, _ = s.opts.Store.FinishJob(ctx, FinishJobCommand{JobID: record.ID,
			State: JobCancelled, ErrorCode: CodeTaskCancelled, Now: s.now()})
	}
	s.recordAudit(ctx, caller.Actor(), "user.batch.cancel_requested", record, nil, requestID)
	return nil
}

// Retry 对 failed 任务续跑（跳过已处理行）；允许的事件会重新入队。
func (s *Service) Retry(ctx context.Context, caller account.Caller, jobID,
	requestID string) (Job, error) {
	ctx = normalizeContext(ctx)
	if err := s.authorize(ctx, caller, ActionRetry); err != nil {
		return Job{}, err
	}
	record, found, err := s.opts.Store.GetJob(ctx, jobID)
	if err != nil || !found {
		if err != nil {
			return Job{}, err
		}
		return Job{}, ErrNotFound
	}
	if !s.ownerVisible(caller, record) {
		return Job{}, ErrAccessDenied
	}
	if record.State != JobFailed {
		return Job{}, fmt.Errorf("%w: 只有 failed 任务可续跑", ErrJobState)
	}
	// failed 任务保留导入输入；若已被过期清理则无法续跑（需新幂等键重新提交）。
	if record.Kind == KindImport && !record.InputAvailable {
		return Job{}, fmt.Errorf("%w: 导入输入已清理，无法续跑", ErrJobState)
	}
	requeued, err := s.opts.Store.Requeue(ctx, record.ID, s.now())
	if err != nil {
		return Job{}, err
	}
	if !requeued {
		return Job{}, ErrJobState
	}
	record.State = JobQueued
	record.ErrorCode = ""
	if err := s.enqueue(ctx, &record); err != nil {
		return Job{}, err
	}
	s.recordAudit(ctx, caller.Actor(), "user.batch.retry", record, nil, requestID)
	return s.jobView(record), nil
}

// ReconcileInterrupted 是宿主启动时的崩溃遗留对账：把 running 任务条件迁移为
// failed（TASK_TIMEOUT/"interrupted" 原因语义），使受控 Retry 续跑可达；返回收敛数。
func (s *Service) ReconcileInterrupted(ctx context.Context, caller account.Caller) (int, error) {
	ctx = normalizeContext(ctx)
	if err := s.authorize(ctx, caller, ActionQuery); err != nil {
		return 0, err
	}
	actor := caller.Actor()
	reconciled := 0
	for round := 0; round < 1000; round++ {
		query := ListJobsQuery{State: JobRunning, Limit: MaxListLimit}
		if actor.Type != audit.ActorSystem && actor.Type != audit.ActorLocalAdmin {
			query.OwnerType = actor.Type
			query.OwnerID = actor.ID
		}
		records, err := s.opts.Store.ListJobs(ctx, query)
		if err != nil {
			return reconciled, err
		}
		if len(records) == 0 {
			break
		}
		changed := 0
		for _, record := range records {
			ok, failErr := s.opts.Store.FailInterrupted(ctx, record.ID, CodeTaskTimeout, s.now())
			if failErr != nil {
				return reconciled, failErr
			}
			if ok {
				reconciled++
				changed++
				s.recordAudit(ctx, actor, "user.batch.interrupted_reconciled", record, nil,
					"reconcile")
			}
		}
		if changed == 0 {
			break
		}
	}
	return reconciled, nil
}

// CleanupExpiredInputs 清空超过 retention 的 failed 任务导入文件内容（不可续跑后）。
func (s *Service) CleanupExpiredInputs(ctx context.Context, caller account.Caller,
	retention time.Duration) (int64, error) {
	ctx = normalizeContext(ctx)
	if err := s.authorize(ctx, caller, ActionQuery); err != nil {
		return 0, err
	}
	if retention < time.Hour {
		return 0, fmt.Errorf("%w: 清理保留期过短", ErrInvalidRequest)
	}
	return s.opts.Store.CleanupInputs(ctx, s.now().Add(-retention))
}

// ===== 内部辅助 =====

func (s *Service) enqueue(ctx context.Context, record *JobRecord) error {
	payload, err := json.Marshal(map[string]string{"job_id": record.ID})
	if err != nil {
		return ErrStoreUnavailable
	}
	kind := TaskKindUserBatchImport
	if record.Kind == KindExport {
		kind = TaskKindUserBatchExport
	}
	job, enqueueErr := s.opts.Enqueuer.Enqueue(ctx, task.EnqueueRequest{
		Kind: kind, Actor: audit.Actor{Type: audit.ActorSystem, ID: "userbatch"},
		Payload: payload, MutexKey: record.ID, TimeoutSeconds: 300, MaxAttempts: 1,
		RequestID: record.RequestID,
	})
	if enqueueErr != nil {
		_, _ = s.opts.Store.FinishJob(context.WithoutCancel(ctx), FinishJobCommand{
			JobID: record.ID, State: JobFailed, ErrorCode: CodeDBUnavailable, Now: s.now()})
		return ErrStoreUnavailable
	}
	if err := s.opts.Store.SetTask(ctx, record.ID, job.ID, s.now()); err != nil {
		return err
	}
	record.TaskID = job.ID
	return nil
}

// finish 写终态（不做计数，用于失败/取消等待确定终止的场景）。
func (s *Service) finish(ctx context.Context, record JobRecord, state JobState,
	code ErrorCode, now time.Time) {
	writeCtx := context.WithoutCancel(ctx)
	_, _ = s.opts.Store.FinishJob(writeCtx, FinishJobCommand{JobID: record.ID, State: state,
		TotalRows: record.TotalRows, ErrorCode: code, Now: now})
	if shouldClearInput(state) {
		_ = s.opts.Store.ClearInput(writeCtx, record.ID)
	}
	_ = s.opts.Audit.Record(writeCtx, audit.Event{
		Actor:  audit.Actor{Type: audit.ActorSystem, ID: "userbatch"},
		Action: "user.batch.finished", Target: audit.Target{Type: "user_batch_job", ID: record.ID},
		Outcome: audit.OutcomeFailure, ErrorCode: string(code), RequestID: record.RequestID,
	})
}

// finishFromRows 汇总逐行结果写终态。
func (s *Service) finishFromRows(ctx context.Context, record JobRecord, totalRows int,
	truncated bool, overrideCode ErrorCode) {
	writeCtx := context.WithoutCancel(ctx)
	counts, err := s.opts.Store.CountRows(writeCtx, record.ID)
	if err != nil {
		s.finish(writeCtx, record, JobFailed, CodeDBUnavailable, s.now())
		return
	}
	failed := counts[RowFailed] + counts[RowConflict] + counts[RowDenied]
	created := counts[RowCreated]
	skipped := counts[RowSkipped]
	state := JobSucceeded
	code := overrideCode
	if failed > 0 {
		state = JobPartial
		if code == "" {
			code = CodeReportIncomplete
		}
	}
	command := FinishJobCommand{JobID: record.ID, State: state, TotalRows: totalRows,
		CreatedRows: created, SkippedRows: skipped, ConflictRows: counts[RowConflict],
		FailedRows: counts[RowFailed], DeniedRows: counts[RowDenied],
		Truncated: truncated, ErrorCode: code, Now: s.now()}
	_, _ = s.opts.Store.FinishJob(writeCtx, command)
	if shouldClearInput(state) {
		_ = s.opts.Store.ClearInput(writeCtx, record.ID)
	}
	outcome := audit.OutcomeSuccess
	if state != JobSucceeded {
		outcome = audit.OutcomeFailure
	}
	_ = s.opts.Audit.Record(writeCtx, audit.Event{
		Actor:   audit.Actor{Type: audit.ActorSystem, ID: "userbatch"},
		Action:  "user.batch.finished",
		Target:  audit.Target{Type: "user_batch_job", ID: record.ID},
		Outcome: outcome, ErrorCode: string(code), RequestID: record.RequestID,
	})
}

// shouldClearInput 只在不可续跑的终态清理导入文件；failed 保留输入供 Retry/续跑。
func shouldClearInput(state JobState) bool {
	return state == JobSucceeded || state == JobPartial || state == JobCancelled
}

func (s *Service) finishWithCounts(ctx context.Context, record JobRecord, state JobState,
	code ErrorCode, command FinishJobCommand) {
	writeCtx := context.WithoutCancel(ctx)
	command.JobID = record.ID
	command.State = state
	command.ErrorCode = code
	command.Now = s.now()
	_, _ = s.opts.Store.FinishJob(writeCtx, command)
	if shouldClearInput(command.State) {
		_ = s.opts.Store.ClearInput(writeCtx, record.ID)
	}
	outcome := audit.OutcomeSuccess
	if state != JobSucceeded {
		outcome = audit.OutcomeFailure
	}
	_ = s.opts.Audit.Record(writeCtx, audit.Event{
		Actor:   audit.Actor{Type: audit.ActorSystem, ID: "userbatch"},
		Action:  "user.batch.finished",
		Target:  audit.Target{Type: "user_batch_job", ID: record.ID},
		Outcome: outcome, ErrorCode: string(code), RequestID: record.RequestID,
	})
}

func (s *Service) authorize(ctx context.Context, caller account.Caller, action Action) error {
	if !action.Valid() {
		return fmt.Errorf("%w: 未定义动作", ErrAccessDenied)
	}
	if isNil(s.opts.Authorizer) {
		return ErrAccessDenied
	}
	if err := s.opts.Authorizer.Authorize(ctx, caller, action, "system"); err != nil {
		return fmt.Errorf("%w: %v", ErrAccessDenied, err)
	}
	return nil
}

func (s *Service) authorizeSensitive(ctx context.Context, caller account.Caller,
	operationID, scopeID string, params map[string]string, description,
	requestID string) (reauth.Result, error) {
	if isNil(s.opts.Sensitive) {
		return reauth.Result{}, ErrAccessDenied
	}
	reauthCaller, err := reauth.CallerFromActor(caller.Actor())
	if err != nil {
		return reauth.Result{}, ErrAccessDenied
	}
	result, err := s.opts.Sensitive.Authorize(ctx, reauthCaller, reauth.Request{
		ScopeID: scopeID, OperationID: operationID, TargetType: "user_batch",
		TargetID: "system", Params: params, Description: description, RequestID: requestID,
	})
	if err != nil {
		return reauth.Result{}, ErrAccessDenied
	}
	return result, nil
}

func (s *Service) notifySensitive(ctx context.Context, result reauth.Result) {
	if result.OperationID == "" {
		return
	}
	if err := s.opts.Sensitive.NotifyOutcome(ctx, result, reauth.OutcomeSuccess); err != nil {
		s.opts.Logger.Warn("批量操作告知失败", "reason", "notify_unavailable")
	}
}

func (s *Service) recordAudit(ctx context.Context, actor audit.Actor, action string,
	record JobRecord, changes []audit.FieldChange, requestID string) {
	_ = s.opts.Audit.Record(ctx, audit.Event{
		Actor: actor, Action: action,
		Target:  audit.Target{Type: "user_batch_job", ID: record.ID},
		Outcome: audit.OutcomeSuccess, RequestID: requestID, Changes: changes,
	})
}

func (s *Service) recordFailure(ctx context.Context, caller account.Caller, action,
	scopeID, reason string, code ErrorCode, requestID string) {
	_ = s.opts.Audit.RecordFailure(ctx, audit.Event{
		Actor: caller.Actor(), AppID: scopeID, Action: action,
		Target:  audit.Target{Type: "user_batch_job", ID: scopeID},
		Outcome: audit.OutcomeFailure, ErrorCode: string(code),
		ReasonCode: safeReason(reason), RequestID: requestID,
	})
}

// ownerVisible 报告调用者是否可访问该任务：系统全量；其他身份仅本人任务。
func (s *Service) ownerVisible(caller account.Caller, record JobRecord) bool {
	actor := caller.Actor()
	if actor.Type == audit.ActorSystem || actor.Type == audit.ActorLocalAdmin {
		return true
	}
	return record.OwnerType == actor.Type && record.OwnerID == actor.ID
}

func (s *Service) jobView(record JobRecord) Job {
	view := record.Job
	view.InputAvailable = len(record.InputCSV) > 0
	view.ExportSHA256 = record.ExportSHA256
	return view
}

func (s *Service) now() time.Time { return s.opts.Now().UTC().Truncate(time.Millisecond) }

func (s *Service) exportFilePath(jobID string) string {
	return filepath.Join(s.outputDir, "user_export_"+jobID+".csv")
}

// defaultExportFields 返回默认导出字段（按固定顺序；biography 等自由文本默认不含）。
func defaultExportFields() []string {
	return []string{"user_id", "username", "nickname", "language", "timezone",
		"status", "created_at", "updated_at"}
}

func normalizeExportFields(requested []string, includeFreeText bool) ([]string, error) {
	if len(requested) == 0 {
		requested = defaultExportFields()
	}
	allowed := make(map[string]bool, len(exportFields)+1)
	for field := range exportFields {
		allowed[field] = true
	}
	if includeFreeText {
		allowed[freeTextField] = true
	}
	selected := make(map[string]bool, len(requested))
	for _, field := range requested {
		field = strings.TrimSpace(field)
		if field == "" || !allowed[field] {
			return nil, fmt.Errorf("%w: 导出字段 %q 未被允许", ErrInvalidRequest, field)
		}
		selected[field] = true
	}
	// 固定顺序，保证同摘要幂等与稳定列序；只允许默认集合的子集（含可选自由文本）。
	ordered := make([]string, 0, len(selected))
	for _, field := range append(defaultExportFields(), freeTextField) {
		if selected[field] {
			ordered = append(ordered, field)
		}
	}
	if len(ordered) == 0 {
		return nil, fmt.Errorf("%w: 至少选择一个导出字段", ErrInvalidRequest)
	}
	return ordered, nil
}

// exportOptions 是导出任务在任务记录中保存的规范化选项（JSON，不含秘密）。
type exportOptions struct {
	Fields   []string `json:"fields"`
	FreeText bool     `json:"free_text"`
	MaxRows  int      `json:"max_rows"`
}

// parseExportOptions 解析导出任务选项并重新校验字段白名单（不信任持久化内容）。
func parseExportOptions(document []byte) (exportOptions, error) {
	var options exportOptions
	if err := json.Unmarshal(document, &options); err != nil {
		return exportOptions{}, fmt.Errorf("%w: 导出选项无效", ErrInvalidRequest)
	}
	fields, err := normalizeExportFields(options.Fields, options.FreeText)
	if err != nil {
		return exportOptions{}, err
	}
	options.Fields = fields
	if options.MaxRows <= 0 {
		return exportOptions{}, fmt.Errorf("%w: 导出上限无效", ErrInvalidRequest)
	}
	return options, nil
}

// writeExportRecord 写一行导出数据；所有文本单元格均做公式注入防护。
func writeExportRecord(writer *csv.Writer, fields []string, user account.User) error {
	record := make([]string, 0, len(fields))
	for _, field := range fields {
		switch field {
		case "user_id":
			record = append(record, escapeCSVCell(user.ID))
		case "username":
			record = append(record, escapeCSVCell(user.Username))
		case "nickname":
			record = append(record, escapeCSVCell(user.Nickname))
		case "biography":
			record = append(record, escapeCSVCell(user.Biography))
		case "language":
			record = append(record, escapeCSVCell(user.Language))
		case "timezone":
			record = append(record, escapeCSVCell(user.Timezone))
		case "status":
			record = append(record, escapeCSVCell(string(user.Status)))
		case "created_at":
			record = append(record, user.CreatedAt.UTC().Format(time.RFC3339))
		case "updated_at":
			record = append(record, user.UpdatedAt.UTC().Format(time.RFC3339))
		default:
			return fmt.Errorf("%w: 未实现导出字段 %q", ErrInternal, fields)
		}
	}
	return writer.Write(record)
}

// CodeFromAccount 把 account 领域错误映射为根包已登记错误码（用于逐行结果）。
func CodeFromAccount(err error) ErrorCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, account.ErrInvalidRequest):
		return CodeReqInvalid
	case errors.Is(err, account.ErrUsernameTaken):
		return CodeConflict
	case errors.Is(err, account.ErrAccessDenied), errors.Is(err, account.ErrProtectedUser):
		return CodeAccessDenied
	case errors.Is(err, account.ErrStoreUnavailable), errors.Is(err, account.ErrAuditUnavailable):
		return CodeDBUnavailable
	default:
		return CodeInternalError
	}
}

// callerFromOwner 由任务所有者重建可信调用者（system/local_admin/user）。
func callerFromOwner(ownerType audit.ActorKind, ownerID string) (account.Caller, error) {
	switch ownerType {
	case audit.ActorSystem:
		return account.SystemCaller(ownerID)
	case audit.ActorLocalAdmin:
		return account.LocalBootstrapCaller(ownerID)
	case audit.ActorUser:
		return account.UserCaller(ownerID)
	default:
		return account.Caller{}, fmt.Errorf("%w: 任务所有者类型无效", ErrAccessDenied)
	}
}

func validateIdempotencyKey(value string) error {
	value = strings.TrimSpace(value)
	if len(value) < 8 || len(value) > 128 {
		return fmt.Errorf("%w: 幂等键长度必须在 8～128 字节", ErrInvalidRequest)
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character < 0x21 || character > 0x7e {
			return fmt.Errorf("%w: 幂等键只能包含可见 ASCII 字符", ErrInvalidRequest)
		}
	}
	return nil
}

func newJobID(random io.Reader) (string, error) {
	buffer := make([]byte, 16)
	if _, err := io.ReadFull(random, buffer); err != nil {
		return "", fmt.Errorf("%w: 安全随机源不可用", ErrStoreUnavailable)
	}
	return jobIDPrefix + hex.EncodeToString(buffer), nil
}

func safeReason(value string) string {
	if value == "" || len(value) > 64 {
		return "invalid_reason"
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if !(character >= 'a' && character <= 'z') && character != '_' &&
			!(character >= '0' && character <= '9') {
			return "invalid_reason"
		}
	}
	return value
}

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

// ErrInternal 是内部错误哨兵（映射 INTERNAL_ERROR）。
var ErrInternal = errors.New("批量导入导出内部错误")
