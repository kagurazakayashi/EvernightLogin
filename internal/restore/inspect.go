// 本文件实现恢复前预演（Rehearse）：备份解密认证、数据库版本兼容、库外代际
// 一致性、当前数据库有效性、存储容量、外部密钥依赖与真实暂存迁移演练，并输出
// 结构化检查结果与影响范围。预演只写库外临时暂存目录与审计日志，失败不产生持久
// 副作用。
package restore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/backup"
	"github.com/kagurazakayashi/EvernightLogin/internal/fsutil"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

// appliedMigration 是 schema_history 中的一条已应用迁移记录。
type appliedMigration struct {
	Version  string
	Checksum string
}

// currentDatabase 是当前活动数据库的预检结果。
type currentDatabase struct {
	SchemaVersion       string
	SchemaVersionNumber int
	Generation          uint64
}

// stagedDatabase 是暂存数据库再次验证与升级演练后的结果。
type stagedDatabase struct {
	SchemaVersion       string
	SchemaVersionNumber int
	Generation          uint64
	Impact              Impact
}

// Rehearse 执行恢复前预演：调用者授权、备份认证校验、版本/容量/密钥依赖检查与
// 暂存数据库真实迁移演练，返回逐项检查结果与影响范围。预演不进入维护状态、不
// 修改当前数据库、不创建回退备份；仅使用库外临时暂存目录（用后删除）并写库外
// 审计日志。Restorable=false 时返回 nil 错误（具体原因在 Checks/BlockingReasons）。
func (s *Service) Rehearse(ctx context.Context, request Request) (Rehearsal, error) {
	ctx = normalizeContext(ctx)
	actor, err := s.authorize(ctx, request.Caller)
	if err != nil {
		return Rehearsal{}, err
	}
	request, err = s.normalizeRequest(request)
	if err != nil {
		return Rehearsal{}, err
	}
	runID, err := s.newSessionID()
	if err != nil {
		return Rehearsal{}, err
	}
	rehearsal := s.rehearse(ctx, request)
	// 预演审计写库外日志；失败按 fail-closed 拒绝（预演结论必须有据可查）。
	outcome := audit.OutcomeSuccess
	var errorCode string
	if !rehearsal.Restorable {
		outcome = audit.OutcomeFailure
		errorCode = string(CodeOf(ErrPreflightFailed))
	}
	if _, err := s.appendJournal(ctx, journalEvent{
		RestoreID: runID, Actor: actor, Action: ActionPreflight,
		TargetID: rehearsal.Backup.BackupID,
		Outcome:  outcome, ErrorCode: errorCode, RequestID: request.RequestID,
		ReasonCode: "preflight",
		Changes:    rehearsalChanges(rehearsal),
	}); err != nil {
		return Rehearsal{}, err
	}
	return rehearsal, nil
}

// rehearsalChanges 把预演结论折叠为有限审计差异字段（不含备份正文）。
func rehearsalChanges(rehearsal Rehearsal) []audit.FieldChange {
	changes := []audit.FieldChange{
		{Field: "restorable", After: fmt.Sprintf("%t", rehearsal.Restorable)},
		{Field: "schema_version", After: rehearsal.Backup.SchemaVersion},
		{Field: "backup_sha256", After: rehearsal.Backup.FileSHA256},
	}
	if len(rehearsal.BlockingReasons) > 0 {
		changes = append(changes, audit.FieldChange{
			Field: "blocking_checks", After: strings.Join(rehearsal.BlockingReasons, ";")})
	}
	return changes
}

// rehearse 是预演实现；ctx 非法/内部错误通过 error 返回，检查失败写入 Restorable。
func (s *Service) rehearse(ctx context.Context, request Request) Rehearsal {
	rehearsal := Rehearsal{CurrentSchema: s.versionOrder[s.latestNumber-1],
		CompletedAt: s.nowUTC()}
	checks := make([]Check, 0, 12)
	addCheck := func(name, label string, status CheckStatus, code, detail string) {
		checks = append(checks, Check{Name: name, Label: label, Status: status,
			Code: code, Detail: detail})
		if status == CheckFailed {
			rehearsal.BlockingReasons = append(rehearsal.BlockingReasons,
				label+"："+detail)
		}
	}
	fail := func(name, label, code, detail string) Rehearsal {
		addCheck(name, label, CheckFailed, code, detail)
		rehearsal.Checks = checks
		rehearsal.Restorable = false
		return rehearsal
	}

	// 1. 备份文件本身。
	info, err := os.Lstat(request.BackupPath)
	if err != nil || !info.Mode().IsRegular() {
		return fail("backup_file", "备份文件", string(CodeReqInvalid),
			"备份文件不存在或不是普通文件")
	}
	addCheck("backup_file", "备份文件", CheckOK, "", "文件存在且为普通文件")

	// 2. 外部密钥依赖：主密钥环可用且包含备份信封 key_id。
	keyring, err := secrets.LoadKeyring(ctx, s.opts.Keyring)
	if err != nil {
		return fail("keyring", "主密钥依赖", string(CodeBackupDecryptFailed),
			"主密钥环不可用（无法解密备份）")
	}
	inspect, err := backup.InspectFile(ctx, request.BackupPath)
	if err != nil {
		return fail("backup_header", "备份格式", string(CodeBackupInvalid),
			"备份文件头结构无效："+backup.CodeString(err))
	}
	if !keyring.HasKey(inspect.Encryption.KeyID) {
		return fail("keyring", "主密钥依赖", string(CodeBackupDecryptFailed),
			"当前主密钥环不含备份信封所需的密钥版本")
	}
	addCheck("keyring", "主密钥依赖", CheckOK, "",
		"主密钥环可用且包含备份信封密钥版本")

	// 3. 认证解密与完整性（全部条目摘要）。
	report, err := backup.VerifyFile(ctx, request.BackupPath, keyring)
	if err != nil {
		return fail("decrypt_integrity", "解密与完整性", codeForBackupError(err),
			"备份认证校验未通过："+backup.CodeString(err))
	}
	if !report.Authenticated || !report.StructuralValid {
		return fail("decrypt_integrity", "解密与完整性", string(CodeBackupInvalid),
			"备份未通过认证校验")
	}
	rehearsal.Backup = backupSummary(report)
	addCheck("decrypt_integrity", "解密与完整性", CheckOK, "",
		"已用主密钥认证解密并校验全部条目摘要")

	// 4. 备份格式与数据库引擎。
	if report.FormatVersion != backup.FormatVersion {
		return fail("backup_format", "备份格式版本", string(CodeBackupVersionUnsupported),
			"备份格式版本不受当前工具支持")
	}
	if !strings.EqualFold(report.Database.Engine, "sqlite") {
		return fail("backup_format", "数据库引擎", string(CodeBackupVersionUnsupported),
			"当前实现只支持 SQLite 备份恢复")
	}
	addCheck("backup_format", "备份格式版本", CheckOK, "",
		"备份格式与数据库引擎受支持")

	// 5. 数据库版本兼容：禁止降级/未知版本；版本字符串必须与当前迁移定义一致。
	number := report.Database.SchemaVersionNumber
	if number <= 0 {
		return fail("database_version", "数据库版本兼容", string(CodeBackupVersionUnsupported),
			"备份未记录可识别的数据库迁移版本（未知版本）")
	}
	if number > s.latestNumber {
		return fail("database_version", "数据库版本兼容", string(CodeBackupVersionUnsupported),
			fmt.Sprintf("备份数据库版本 %d 高于当前程序支持的 %d（禁止降级）",
				number, s.latestNumber))
	}
	expectedMigration := s.versions[number]
	if expectedMigration.Version != report.Database.SchemaVersion {
		return fail("database_version", "数据库版本兼容", string(CodeBackupVersionUnsupported),
			"备份数据库版本字符串与当前迁移定义不一致")
	}
	rehearsal.TargetSchema = report.Database.SchemaVersion
	addCheck("database_version", "数据库版本兼容", CheckOK, "",
		fmt.Sprintf("备份版本 %s 可升级/兼容到当前 %s", report.Database.SchemaVersion,
			s.versionOrder[s.latestNumber-1]))

	// 6. 当前数据库有效性与恢复代际一致性。
	current, err := s.inspectCurrentDatabase(ctx)
	if err != nil {
		return fail("current_database", "当前数据库", string(CodeDBUnavailable),
			"当前数据库无法通过一致性/版本检查："+errorText(err))
	}
	rehearsal.CurrentSchema = current.SchemaVersion
	rehearsal.DatabaseGeneration = current.Generation
	addCheck("current_database", "当前数据库", CheckOK, "",
		"当前数据库已完成迁移且通过一致性检查")
	reconcile, err := s.controller.Reconcile(ctx, current.Generation)
	if err != nil {
		return fail("generation_authority", "恢复代际", string(CodeDBUnavailable),
			"无法核对库外恢复代际："+errorText(err))
	}
	rehearsal.ExternalGeneration = reconcile.ExternalGeneration
	switch {
	case reconcile.Mismatch && !request.AcknowledgeOutOfBandReplacement:
		return fail("generation_authority", "恢复代际", string(CodeConflict),
			reconcile.Detail+"；如确认是带外回滚，需显式传 --acknowledge-out-of-band-replacement")
	case reconcile.Mismatch:
		rehearsal.Warnings = append(rehearsal.Warnings,
			"操作者已确认带外回滚/替换："+reconcile.Detail)
		addCheck("generation_authority", "恢复代际", CheckOK, "",
			"操作者已显式确认带外回滚/替换")
	case reconcile.IncompletePending:
		rehearsal.Warnings = append(rehearsal.Warnings,
			"存在未完成的恢复尝试（数据库仍是恢复前状态），本次恢复将重新执行："+reconcile.Detail)
		addCheck("generation_authority", "恢复代际", CheckOK, "",
			"存在可重新执行的未完成恢复尝试")
	default:
		addCheck("generation_authority", "恢复代际", CheckOK, "",
			"库外权威代际与数据库记录一致")
	}

	// 7. 存储容量：暂存目录、数据库目录与回退备份输出目录分别检查。
	requiredState, requiredDatabase, requiredBackup := s.requiredBytes(report, info.Size())
	rehearsal.RequiredStateBytes = requiredState
	rehearsal.RequiredDatabaseBytes = requiredDatabase
	rehearsal.RequiredBackupBytes = requiredBackup
	freeState, stateErr := s.opts.FreeBytes(s.stateDir)
	freeDatabase, databaseErr := s.opts.FreeBytes(filepath.Dir(s.databasePath))
	backupOutput := s.opts.BackupOutputDir
	freeBackup, backupErr := s.opts.FreeBytes(backupOutput)
	if stateErr != nil || databaseErr != nil || backupErr != nil {
		return fail("storage_capacity", "存储容量", string(CodeDBUnavailable),
			"无法探测可用磁盘空间，按 fail-closed 拒绝恢复")
	}
	rehearsal.FreeStateBytes = int64(freeState)
	rehearsal.FreeDatabaseBytes = int64(freeDatabase)
	rehearsal.FreeBackupBytes = int64(freeBackup)
	if int64(freeState) < requiredState+MinFreeBytes {
		return fail("storage_capacity", "存储容量", string(CodeDBUnavailable),
			fmt.Sprintf("库外暂存目录可用空间不足（需要约 %d 字节，可用 %d 字节）",
				requiredState+MinFreeBytes, freeState))
	}
	if int64(freeDatabase) < requiredDatabase+MinFreeBytes {
		return fail("storage_capacity", "存储容量", string(CodeDBUnavailable),
			fmt.Sprintf("数据库目录可用空间不足（需要约 %d 字节，可用 %d 字节）",
				requiredDatabase+MinFreeBytes, freeDatabase))
	}
	if int64(freeBackup) < requiredBackup+MinFreeBytes {
		return fail("storage_capacity", "存储容量", string(CodeDBUnavailable),
			fmt.Sprintf("回退备份输出目录可用空间不足（需要约 %d 字节，可用 %d 字节）",
				requiredBackup+MinFreeBytes, freeBackup))
	}
	addCheck("storage_capacity", "存储容量", CheckOK, "",
		"暂存目录、数据库目录与回退备份目录空间充足")

	// 8. 外部依赖：附件/配置范围与回退备份能力。
	if report.Content.Attachments.Status == backup.ContentIncluded {
		if s.opts.AttachmentsDir == "" {
			return fail("attachments_target", "附件恢复目标", string(CodeReqInvalid),
				"备份包含附件但未配置附件受控目录，拒绝恢复出不完整实例")
		}
		if err := probeWritableDirectory(s.opts.AttachmentsDir); err != nil {
			return fail("attachments_target", "附件恢复目标", string(CodeReqInvalid),
				"附件受控目录不可写："+errorText(err))
		}
	}
	if report.Content.Config.Status == backup.ContentIncluded {
		rehearsal.Warnings = append(rehearsal.Warnings,
			"备份包含配置文件快照：恢复流程不会自动应用，会复制到库外待审查目录供操作者人工比对")
	}
	addCheck("external_dependencies", "外部依赖", CheckOK, "",
		"回退备份服务、附件目录与审计存储依赖可用")

	// 9. 暂存数据库真实迁移演练（解密仅数据库条目到临时目录，用后删除）。
	impact, staged, err := s.rehearseStagedDatabase(ctx, request.BackupPath, keyring,
		report.Database.SchemaVersionNumber)
	if err != nil {
		return fail("rehearsal_staging", "暂存迁移演练", codeForStageError(err),
			"暂存数据库迁移/一致性演练失败："+errorText(err))
	}
	rehearsal.Impact = impact
	rehearsal.TargetSchema = staged.SchemaVersion
	addCheck("rehearsal_staging", "暂存迁移演练", CheckOK, "",
		fmt.Sprintf("暂存数据库已通过迁移演练（%s）与完整性/外键检查",
			staged.SchemaVersion))

	rehearsal.Consequences = s.consequences(impact)
	rehearsal.Checks = checks
	rehearsal.Restorable = len(rehearsal.BlockingReasons) == 0
	return rehearsal
}

// requiredBytes 估算预演/执行占用：库外暂存（数据库+附件+配置+审计余量）、数据库
// 目录（暂存数据库副本）与回退备份输出目录（加密备份文件）。
func (s *Service) requiredBytes(report backup.VerifyReport, fileSize int64) (
	stateBytes, databaseBytes, backupBytes int64) {
	var attachments int64
	var config int64
	for _, entry := range report.Entries {
		switch entry.Kind {
		case backup.EntryKindAttachment:
			attachments += entry.SizeBytes
		case backup.EntryKindConfig:
			config += entry.SizeBytes
		}
	}
	databaseBytes = report.Database.SizeBytes + 1<<20
	backupEstimate := report.Encryption.PayloadPlainBytes + 2<<20
	if backupEstimate <= 0 {
		backupEstimate = fileSize + 2<<20
	}
	stateBytes = report.Database.SizeBytes + attachments + config + backupEstimate
	return stateBytes, databaseBytes + backupEstimate, backupEstimate
}

// consequences 生成恢复影响范围的直白说明。
func (s *Service) consequences(impact Impact) []string {
	return []string{
		fmt.Sprintf("恢复后将会话 %d 个、刷新令牌族 %d 个、授权码 %d 条、恢复代码 %d 条、"+
			"验证/找回链接 %d 条、扫码请求 %d 条与一次性凭证 %d 条全部失效",
			impact.Sessions, impact.RefreshFamilies, impact.AuthorizationCodes,
			impact.RecoveryCodes, impact.VerificationTickets+impact.PasswordResets+
				impact.EmailChanges, impact.QRLoginRequests, impact.OneTimeCredentials),
		"令牌签名密钥将全部失效并重新生成：已离线签发的 JWT 在签名校验处被拒绝（客户端缓存公钥的边界见文档）",
		fmt.Sprintf("旧调度计划 %d 个、Webhook 端点 %d 个、在途任务 %d 个、待发邮件 %d 封与待补发通知 %d 条默认暂停/取消，需人工审查后重新启用",
			impact.EnabledSchedules, impact.ActiveWebhooks, impact.PendingJobs,
			impact.PendingMails, impact.PendingNotifications),
		"数据库文件会被整体替换为备份内容；恢复前会创建新的加密回退备份（不覆盖用户原始备份）",
	}
}

// inspectCurrentDatabase 打开当前活动数据库并校验：迁移前缀与校验和、无失败迁移、
// 完整性快速检查、已迁移到当前版本，并读取库内恢复代际记录。
func (s *Service) inspectCurrentDatabase(ctx context.Context) (currentDatabase, error) {
	store, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(s.databasePath))
	if err != nil {
		return currentDatabase{}, fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	defer func() { _ = store.Close() }()
	applied, failures, err := readSchemaHistory(ctx, store)
	if err != nil {
		return currentDatabase{}, err
	}
	if failures > 0 {
		return currentDatabase{}, fmt.Errorf("%w: 当前数据库存在未清理的迁移失败记录",
			ErrStoreUnavailable)
	}
	if err := s.verifySchemaPrefix(applied); err != nil {
		return currentDatabase{}, err
	}
	if len(applied) != s.latestNumber {
		return currentDatabase{}, fmt.Errorf("%w: 当前数据库未迁移到当前版本（%d/%d）",
			ErrStoreUnavailable, len(applied), s.latestNumber)
	}
	var check string
	if err := store.DB().QueryRowContext(ctx, `PRAGMA quick_check(1)`).Scan(&check); err != nil {
		return currentDatabase{}, fmt.Errorf("%w: 当前数据库完整性检查失败", ErrStoreUnavailable)
	}
	if !strings.EqualFold(strings.TrimSpace(check), "ok") {
		return currentDatabase{}, fmt.Errorf("%w: 当前数据库完整性检查未通过", ErrStoreUnavailable)
	}
	generation, err := readDatabaseGeneration(ctx, store)
	if err != nil {
		return currentDatabase{}, err
	}
	return currentDatabase{SchemaVersion: applied[len(applied)-1].Version,
		SchemaVersionNumber: len(applied), Generation: generation}, nil
}

// rehearseStagedDatabase 把备份中的数据库条目解包到库外临时目录，执行版本前缀校验、
// 迁移升级、完整性/外键/关键不变量检查并统计影响范围，最后删除临时目录。
func (s *Service) rehearseStagedDatabase(ctx context.Context, backupPath string,
	keyring *secrets.Keyring, schemaNumber int) (Impact, stagedDatabase, error) {
	directory := filepath.Join(s.stateDir, preflightDirPrefix+s.stagingSuffix())
	if err := os.Mkdir(directory, 0o700); err != nil {
		return Impact{}, stagedDatabase{}, fmt.Errorf("%w: 无法创建预演暂存目录",
			ErrStoreUnavailable)
	}
	// 预演暂存目录含解密后的明文数据库副本，退出时必须清理；瞬时占用用有界
	// 重试吸收，最终失败仍忽略（预演不产生持久副作用）。
	defer func() { _ = fsutil.RemoveAllRetry(directory) }()
	extracted, err := backup.Extract(ctx, backup.ExtractOptions{
		Path: backupPath, Keyring: keyring, Destination: directory,
		OnlyEntries: func(entry backup.ManifestEntry) bool {
			return entry.Kind == backup.EntryKindDatabase
		},
	})
	if err != nil {
		return Impact{}, stagedDatabase{}, fmt.Errorf("%w: %w", ErrStageFailed, err)
	}
	if extracted.DatabasePath == "" {
		return Impact{}, stagedDatabase{}, fmt.Errorf("%w: 备份缺少数据库条目",
			ErrBackupUnusable)
	}
	staged, err := s.prepareStagedDatabase(ctx, extracted.DatabasePath)
	if err != nil {
		return Impact{}, stagedDatabase{}, err
	}
	if staged.SchemaVersionNumber < schemaNumber {
		return Impact{}, stagedDatabase{}, fmt.Errorf(
			"%w: 暂存数据库版本低于备份声明版本", ErrVersionIncompatible)
	}
	return staged.Impact, staged, nil
}

// stagingSuffix 返回本次操作在暂存目录名中的稳定后缀（恢复编号或随机）。
func (s *Service) stagingSuffix() string {
	restoreID, err := s.newRestoreID()
	if err != nil {
		return fmt.Sprintf("pid%d-%d", os.Getpid(), s.nowUTC().UnixNano())
	}
	return strings.TrimPrefix(restoreID, restoreIDPrefix)
}

// prepareStagedDatabase 打开暂存数据库：校验历史前缀与校验和、执行待应用迁移、检查
// 完整性/外键/关键不变量并读取版本、代际与影响范围。返回前关闭数据库（WAL 关闭，
// 无旁文件）。
func (s *Service) prepareStagedDatabase(ctx context.Context, path string) (stagedDatabase, error) {
	options := storagesqlite.Options{Path: path, WAL: false,
		BusyTimeout: storagesqlite.DefaultBusyTimeout}
	store, err := storagesqlite.Open(ctx, options)
	if err != nil {
		return stagedDatabase{}, fmt.Errorf("%w: 暂存数据库无法打开（不是有效 SQLite 库）",
			ErrStageFailed)
	}
	closeStore := func() { _ = store.Close() }
	applied, failures, err := readSchemaHistory(ctx, store)
	if err != nil {
		closeStore()
		return stagedDatabase{}, err
	}
	if failures > 0 {
		closeStore()
		return stagedDatabase{}, fmt.Errorf("%w: 备份数据库存在未清理的迁移失败记录",
			ErrVersionIncompatible)
	}
	if err := s.verifySchemaPrefix(applied); err != nil {
		closeStore()
		return stagedDatabase{}, err
	}
	if len(applied) > 0 {
		declared := applied[len(applied)-1].Version
		if number := parseMigrationNumber(declared); number <= 0 || number > s.latestNumber {
			closeStore()
			return stagedDatabase{}, fmt.Errorf("%w: 备份数据库版本未知", ErrVersionIncompatible)
		}
	}
	result, err := store.Migrate(ctx, s.opts.Migrations)
	if err != nil {
		closeStore()
		return stagedDatabase{}, fmt.Errorf("%w: 备份数据库迁移升级失败",
			ErrVersionIncompatible)
	}
	_ = result
	after, failures, err := readSchemaHistory(ctx, store)
	if err != nil {
		closeStore()
		return stagedDatabase{}, err
	}
	if failures > 0 || len(after) != s.latestNumber {
		closeStore()
		return stagedDatabase{}, fmt.Errorf("%w: 备份数据库迁移后版本不是当前版本",
			ErrVersionIncompatible)
	}
	if err := checkDatabaseIntegrity(ctx, store); err != nil {
		closeStore()
		return stagedDatabase{}, err
	}
	generation, err := readDatabaseGeneration(ctx, store)
	if err != nil {
		closeStore()
		return stagedDatabase{}, err
	}
	impact, err := countImpact(ctx, store)
	if err != nil {
		closeStore()
		return stagedDatabase{}, err
	}
	staged := stagedDatabase{SchemaVersion: after[len(after)-1].Version,
		SchemaVersionNumber: len(after), Generation: generation, Impact: impact}
	if err := store.Close(); err != nil {
		return stagedDatabase{}, fmt.Errorf("%w: 暂存数据库关闭失败", ErrStageFailed)
	}
	return staged, nil
}

// verifySchemaPrefix 校验数据库已应用迁移是当前迁移定义的严格前缀且校验和一致。
func (s *Service) verifySchemaPrefix(applied []appliedMigration) error {
	if len(applied) > len(s.versionOrder) {
		return fmt.Errorf("%w: 数据库已有 %d 条迁移，当前程序只有 %d 条（禁止降级）",
			ErrVersionIncompatible, len(applied), len(s.versionOrder))
	}
	for index, record := range applied {
		number := index + 1
		migration, ok := s.versions[number]
		if !ok || migration.Version != record.Version {
			return fmt.Errorf("%w: 数据库迁移 %s 不在当前程序迁移定义中",
				ErrVersionIncompatible, record.Version)
		}
		if !strings.EqualFold(migration.Checksum, record.Checksum) {
			return fmt.Errorf("%w: 数据库迁移 %s 校验和与当前程序不一致",
				ErrVersionIncompatible, record.Version)
		}
	}
	return nil
}

// readSchemaHistory 读取 schema_history 与 schema_failures 计数。缺少迁移历史说明
// 不是本项目数据库，按版本不兼容 fail-closed。
func readSchemaHistory(ctx context.Context, store *storagesqlite.Store) (
	[]appliedMigration, int, error) {
	exists, err := tableExists(ctx, store, "schema_history")
	if err != nil {
		return nil, 0, err
	}
	if !exists {
		return nil, 0, fmt.Errorf("%w: 数据库缺少迁移历史（不是本项目实例）",
			ErrVersionIncompatible)
	}
	rows, err := store.DB().QueryContext(ctx,
		`SELECT version, source_sha256 FROM schema_history ORDER BY version`)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: 无法读取迁移历史", ErrStoreUnavailable)
	}
	defer rows.Close()
	applied := make([]appliedMigration, 0, 48)
	for rows.Next() {
		var record appliedMigration
		if err := rows.Scan(&record.Version, &record.Checksum); err != nil {
			return nil, 0, fmt.Errorf("%w: 迁移历史记录格式非法", ErrStoreUnavailable)
		}
		applied = append(applied, record)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("%w: 读取迁移历史失败", ErrStoreUnavailable)
	}
	failures := 0
	exists, err = tableExists(ctx, store, "schema_failures")
	if err != nil {
		return nil, 0, err
	}
	if exists {
		if err := store.DB().QueryRowContext(ctx,
			`SELECT COUNT(*) FROM schema_failures`).Scan(&failures); err != nil {
			return nil, 0, fmt.Errorf("%w: 无法读取迁移失败记录", ErrStoreUnavailable)
		}
	}
	return applied, failures, nil
}

// checkDatabaseIntegrity 对数据库执行完整一致性、外键与关键唯一/不变量检查。
func checkDatabaseIntegrity(ctx context.Context, store *storagesqlite.Store) error {
	rows, err := store.DB().QueryContext(ctx, `PRAGMA integrity_check`)
	if err != nil {
		return fmt.Errorf("%w: 数据库完整性检查失败", ErrStageFailed)
	}
	problems := make([]string, 0, 4)
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			rows.Close()
			return fmt.Errorf("%w: 数据库完整性检查结果格式非法", ErrStageFailed)
		}
		if !strings.EqualFold(strings.TrimSpace(line), "ok") {
			problems = append(problems, line)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("%w: 数据库完整性检查失败", ErrStageFailed)
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: 数据库完整性检查未通过（%s）", ErrStageFailed,
			sanitizeDatabaseProblem(problems[0]))
	}
	fkRows, err := store.DB().QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return fmt.Errorf("%w: 数据库外键检查失败", ErrStageFailed)
	}
	violations := 0
	for fkRows.Next() {
		violations++
	}
	fkRows.Close()
	if err := fkRows.Err(); err != nil {
		return fmt.Errorf("%w: 数据库外键检查失败", ErrStageFailed)
	}
	if violations > 0 {
		return fmt.Errorf("%w: 数据库外键约束检查未通过（%d 处）", ErrStageFailed, violations)
	}
	// 关键不变量：唯一 root、system scope 恰好一条、root 初始化记录状态合法。
	var rootCount int
	if err := store.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE is_root=1`).Scan(&rootCount); err != nil {
		return fmt.Errorf("%w: 无法检查 root 唯一约束", ErrStageFailed)
	}
	if rootCount > 1 {
		return fmt.Errorf("%w: 数据库存在多个 root（关键唯一约束不成立）", ErrStageFailed)
	}
	var systemScopes int
	if err := store.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM scopes WHERE id='system' AND kind='system'`).
		Scan(&systemScopes); err != nil {
		return fmt.Errorf("%w: 无法检查系统范围记录", ErrStageFailed)
	}
	if systemScopes != 1 {
		return fmt.Errorf("%w: 系统范围记录缺失或重复（关键不变量不成立）", ErrStageFailed)
	}
	return nil
}

// sanitizeDatabaseProblem 限制数据库问题文本长度并去掉控制字符（用于直白原因）。
func sanitizeDatabaseProblem(line string) string {
	line = strings.TrimSpace(line)
	if len(line) > 160 {
		line = line[:160]
	}
	return strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return ' '
		}
		return character
	}, line)
}

// readDatabaseGeneration 读取库内恢复代际记录；表不存在（0044 之前的备份）按 0。
func readDatabaseGeneration(ctx context.Context, store *storagesqlite.Store) (uint64, error) {
	exists, err := tableExists(ctx, store, "restore_generation")
	if err != nil {
		return 0, err
	}
	if !exists {
		return 0, nil
	}
	var generation int64
	if err := store.DB().QueryRowContext(ctx,
		`SELECT generation FROM restore_generation WHERE id=1`).Scan(&generation); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, nil
		}
		return 0, fmt.Errorf("%w: 无法读取库内恢复代际", ErrStoreUnavailable)
	}
	if generation < 0 {
		return 0, fmt.Errorf("%w: 库内恢复代际非法", ErrStoreUnavailable)
	}
	return uint64(generation), nil
}

// tableExists 报告数据库中是否存在指定表。
func tableExists(ctx context.Context, store *storagesqlite.Store, name string) (bool, error) {
	var count int
	if err := store.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, name).
		Scan(&count); err != nil {
		return false, fmt.Errorf("%w: 无法检查数据库表结构", ErrStoreUnavailable)
	}
	return count > 0, nil
}

// countImpact 统计恢复后处理将影响的凭证与调度对象数量（表不存在按 0）。
func countImpact(ctx context.Context, store *storagesqlite.Store) (Impact, error) {
	var impact Impact
	counter := func(table, where string) (int64, error) {
		exists, err := tableExists(ctx, store, table)
		if err != nil {
			return 0, err
		}
		if !exists {
			return 0, nil
		}
		query := `SELECT COUNT(*) FROM ` + table
		if where != "" {
			query += ` WHERE ` + where
		}
		var count int64
		if err := store.DB().QueryRowContext(ctx, query).Scan(&count); err != nil {
			return 0, fmt.Errorf("%w: 无法统计恢复影响范围", ErrStoreUnavailable)
		}
		return count, nil
	}
	targets := []struct {
		table string
		where string
		field *int64
	}{
		{"sessions", "", &impact.Sessions},
		{"refresh_token_families", "", &impact.RefreshFamilies},
		{"refresh_tokens", "", &impact.RefreshTokens},
		{"oauth_authorization_codes", "", &impact.AuthorizationCodes},
		{"recovery_codes", "", &impact.RecoveryCodes},
		{"recovery_code_groups", "", &impact.RecoveryGroups},
		{"email_verification_tickets", "", &impact.VerificationTickets},
		{"password_reset_requests", "", &impact.PasswordResets},
		{"email_change_requests", "", &impact.EmailChanges},
		{"app_qr_login_requests", "", &impact.QRLoginRequests},
		{"oauth_device_authorizations", "", &impact.DeviceAuthorizations},
		{"one_time_credentials", "", &impact.OneTimeCredentials},
		{"mfa_challenges", "", &impact.MFAChallenges},
		{"webauthn_ceremonies", "", &impact.WebAuthnCeremonies},
		{"invitations", "", &impact.Invitations},
		{"token_signing_keys", "", &impact.SigningKeys},
		{"schedules", "enabled=1", &impact.EnabledSchedules},
		{"webhook_endpoints", "status='active'", &impact.ActiveWebhooks},
		{"jobs", "state IN('queued','running','cancel_requested')", &impact.PendingJobs},
		{"mail_deliveries", "state IN('queued','sending')", &impact.PendingMails},
	}
	for _, target := range targets {
		count, err := counter(target.table, target.where)
		if err != nil {
			return Impact{}, err
		}
		*target.field = count
	}
	reauthChallenges, err := counter("reauth_challenges", "")
	if err != nil {
		return Impact{}, err
	}
	reauthApprovals, err := counter("reauth_approvals", "")
	if err != nil {
		return Impact{}, err
	}
	impact.ReauthItems = reauthChallenges + reauthApprovals
	pendingNotifications, err := counter("backup_notifications", "state='pending'")
	if err != nil {
		return Impact{}, err
	}
	rootPending, err := counter("root_recovery_events", "notification_state='pending'")
	if err != nil {
		return Impact{}, err
	}
	impact.PendingNotifications = pendingNotifications + rootPending
	return impact, nil
}

// probeWritableDirectory 在受控目录创建并删除临时文件，验证可写（不留下残留）。
// 探针文件刚创建即删除，杀软扫描可能短暂持有句柄；用有界重试避免把瞬时占用误报
// 为“目录不可写”，预算耗尽仍如实返回错误。
func probeWritableDirectory(directory string) error {
	file, err := os.CreateTemp(directory, ".restore-probe-*")
	if err != nil {
		return err
	}
	path := file.Name()
	if err := file.Close(); err != nil {
		_ = fsutil.RemoveRetry(path)
		return err
	}
	return fsutil.RemoveRetry(path)
}

// codeForBackupError 把备份域错误映射为恢复预演检查的错误码。
func codeForBackupError(err error) string {
	return string(CodeOf(fmt.Errorf("%w: %w", ErrBackupUnusable, err)))
}

// codeForStageError 把暂存阶段错误映射为预演检查错误码。
func codeForStageError(err error) string {
	if errors.Is(err, ErrVersionIncompatible) {
		return string(CodeBackupVersionUnsupported)
	}
	return string(CodeBackupFailed)
}

// errorText 生成审计/结果用的简短错误文本（不含路径细节时可外部使用）。
func errorText(err error) string {
	if err == nil {
		return ""
	}
	text := err.Error()
	if len(text) > 200 {
		text = text[:200]
	}
	return text
}

// normalizeContext 把 nil ctx 当成 Background。
func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// migrationSetNumbers 供测试断言使用：返回迁移号 -> 版本字符串。
func (s *Service) migrationSetNumbers() map[int]string {
	result := make(map[int]string, len(s.versions))
	for number, migration := range s.versions {
		result[number] = migration.Version
	}
	return result
}

// backupSummary 从认证校验报告生成非秘密摘要。
func backupSummary(report backup.VerifyReport) BackupSummary {
	return BackupSummary{
		BackupID:            report.BackupID,
		FileSHA256:          report.FileSHA256,
		FileSizeBytes:       report.FileSize,
		CreatedAt:           report.CreatedAt,
		Host:                report.Host,
		AppVersion:          report.AppVersion,
		DatabaseEngine:      report.Database.Engine,
		SchemaVersion:       report.Database.SchemaVersion,
		SchemaVersionNumber: report.Database.SchemaVersionNumber,
		AttachmentsIncluded: report.Content.Attachments.Status == backup.ContentIncluded,
		ConfigIncluded:      report.Content.Config.Status == backup.ContentIncluded,
	}
}
