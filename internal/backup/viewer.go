package backup

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/fsutil"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
)

// 离线备份查看器（步骤 83）。它只读取备份文件：认证解密后把数据库条目解包到
// 0700 临时目录，以 mode=ro + PRAGMA query_only 的只读 SQLite 连接预览/导出
// 受限逻辑数据；不启动身份服务器、不联网、不执行备份内脚本、不自动连接或写回
// 生产数据库。关闭 Viewer 会删除临时目录；源备份文件全程只读打开。
const (
	// DefaultViewerExtractBytes 是查看/预览时允许解包的所选条目字节上限。容器
	// 不压缩条目正文，该上限用于阻止异常备份把临时目录写满（解压膨胀防护）。
	DefaultViewerExtractBytes = int64(8) << 30
	// viewerTempPrefix 是受控临时目录前缀；目录由 os.MkdirTemp 以 0700 创建。
	viewerTempPrefix = "login-backup-view-"
)

// ViewOptions 是离线查看器的构造参数。
type ViewOptions struct {
	// Path 是备份文件路径（只读打开，必须已存在）。
	Path string
	// Keyring 是用户提供的主密钥环；缺失或错误时认证解密失败，不绕过加密。
	Keyring *secrets.Keyring
	// TempRoot 是受控临时目录的父目录；为空时使用系统临时目录。查看器只会
	// 在其中新建随机命名的 0700 子目录，并在 Close 时删除。
	TempRoot string
	// MaxExtractedBytes 是所选条目合计解包字节上限；<=0 时使用默认值。
	MaxExtractedBytes int64
}

// Viewer 是已认证解包的离线备份查看器。它不是并发安全的：同一 Viewer 上的
// 预览/导出应顺序执行。
type Viewer struct {
	report       VerifyReport
	tempDir      string
	databasePath string
	db           *sql.DB
	closed       bool
}

// SchemaHistoryEntry 是备份数据库 schema_history 中的一条已应用迁移记录。
type SchemaHistoryEntry struct {
	Version     string    `json:"version"`
	Description string    `json:"description"`
	AppliedAt   time.Time `json:"applied_at"`
}

// SnapshotReport 是备份内 SQLite 快照的版本信息。它来自认证解密后的真实快照，
// 不是明文头部的自述；逻辑数据解析能力按 Supported 明确声明，未支持时给出原因。
type SnapshotReport struct {
	Engine              string               `json:"engine"`
	SchemaVersion       string               `json:"schema_version"`
	SchemaVersionNumber int                  `json:"schema_version_number"`
	SchemaHistory       []SchemaHistoryEntry `json:"schema_history,omitempty"`
	TableCount          int                  `json:"table_count"`
	Supported           bool                 `json:"supported"`
	UnsupportedReason   string               `json:"unsupported_reason,omitempty"`
}

// OpenViewer 认证解密备份并解包数据库条目到新建的 0700 临时目录。
//
// 失败（错误密钥/篡改/损坏清单/截断/超限/输出目录不安全）时不返回 Viewer，
// 并清理已创建的临时目录，不留下明文残留。
func OpenViewer(ctx context.Context, options ViewOptions) (*Viewer, error) {
	if options.Keyring == nil {
		return nil, fmt.Errorf("%w: 未提供主密钥环，无法认证解密备份",
			ErrOptionsInvalid)
	}
	ctx = normalizeContext(ctx)
	maxBytes := options.MaxExtractedBytes
	if maxBytes <= 0 {
		maxBytes = DefaultViewerExtractBytes
	}
	tempRoot := strings.TrimSpace(options.TempRoot)
	if tempRoot != "" {
		info, err := os.Lstat(tempRoot)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, fmt.Errorf("%w: 临时目录父路径必须是已存在的真实目录",
				ErrOutputDirUnsafe)
		}
	}
	tempDir, err := os.MkdirTemp(tempRoot, viewerTempPrefix)
	if err != nil {
		return nil, fmt.Errorf("%w: 无法创建受控临时目录", ErrBackupIO)
	}
	cleanup := func() { _ = fsutil.RemoveAllRetry(tempDir) }
	// os.MkdirTemp 在 Unix 使用 0700；Windows 上 chmod 不改变 ACL，但目录由
	// 宿主临时目录保护且不会被用作共享位置。这里复核它不是符号链接。
	if info, statErr := os.Lstat(tempDir); statErr != nil ||
		info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		cleanup()
		return nil, fmt.Errorf("%w: 受控临时目录不安全", ErrOutputDirUnsafe)
	}
	if !isWindowsPlatform() {
		if chmodErr := os.Chmod(tempDir, 0o700); chmodErr != nil {
			cleanup()
			return nil, fmt.Errorf("%w: 无法收紧临时目录权限", ErrOutputDirUnsafe)
		}
	}
	result, err := Extract(ctx, ExtractOptions{
		Path:               options.Path,
		Keyring:            options.Keyring,
		Destination:        tempDir,
		MaxSelectedBytes:   maxBytes,
		MaxSelectedEntries: 1, // 查看器只解包数据库条目；其余条目只校验不落盘
		OnlyEntries: func(entry ManifestEntry) bool {
			return entry.Kind == EntryKindDatabase
		},
	})
	if err != nil {
		cleanup()
		return nil, err
	}
	if result.DatabasePath == "" {
		cleanup()
		return nil, fmt.Errorf("%w: 备份中缺少数据库条目", ErrIntegrityFailed)
	}
	viewer := &Viewer{report: result.Report, tempDir: tempDir,
		databasePath: result.DatabasePath}
	return viewer, nil
}

// Report 返回认证校验报告（含全部清单条目，不含正文）。
func (v *Viewer) Report() VerifyReport {
	if v == nil {
		return VerifyReport{}
	}
	return v.report
}

// Close 关闭只读数据库连接并删除临时目录。重复调用安全。清理失败会如实返回，
// 不声称已经清理成功。
func (v *Viewer) Close() error {
	if v == nil || v.closed {
		return nil
	}
	v.closed = true
	var errs []error
	if v.db != nil {
		errs = append(errs, v.db.Close())
		v.db = nil
	}
	if v.tempDir != "" {
		errs = append(errs, fsutil.RemoveAllRetry(v.tempDir))
		v.tempDir = ""
	}
	return errors.Join(errs...)
}

// tempDirectoryPath 返回受控临时目录路径（测试用；Close 后为空）。
func (v *Viewer) tempDirectoryPath() string {
	if v == nil {
		return ""
	}
	return v.tempDir
}

// Snapshot 用只读连接读取认证解包后 SQLite 快照的真实 schema_history 与版本，
// 并与明文头部/认证清单声明的数据库版本交叉校验。不一致按完整性失败处理。
//
// 当前容器格式只定义 SQLite 数据库条目；其他引擎（未来版本）明确返回
// ErrDatabaseUnsupported，只支持列出条目与逐项提取原始文件，不伪称解析内部数据。
func (v *Viewer) Snapshot(ctx context.Context) (SnapshotReport, error) {
	ctx = normalizeContext(ctx)
	report := SnapshotReport{
		Engine:              v.report.Database.Engine,
		SchemaVersion:       v.report.Database.SchemaVersion,
		SchemaVersionNumber: v.report.Database.SchemaVersionNumber,
	}
	if v.report.Database.Engine != "sqlite" {
		report.Supported = false
		report.UnsupportedReason = "当前工具只解析 SQLite 备份数据；" +
			"该备份引擎仅支持列出条目与逐项提取原始文件"
		return report, fmt.Errorf("%w: %s", ErrDatabaseUnsupported, report.UnsupportedReason)
	}
	db, err := v.readOnlyDatabase(ctx)
	if err != nil {
		return SnapshotReport{}, err
	}
	rows, err := db.QueryContext(ctx,
		`SELECT version, description, applied_at_ms FROM schema_history ORDER BY version`)
	if err != nil {
		return SnapshotReport{}, fmt.Errorf("%w: 备份数据库缺少 schema_history", ErrIntegrityFailed)
	}
	defer rows.Close()
	var highest string
	for rows.Next() {
		var version string
		var description string
		var appliedAtMS int64
		if err := rows.Scan(&version, &description, &appliedAtMS); err != nil {
			return SnapshotReport{}, fmt.Errorf("%w: 读取 schema_history 失败", ErrIntegrityFailed)
		}
		if highest == "" || version > highest {
			highest = version
		}
		report.SchemaHistory = append(report.SchemaHistory, SchemaHistoryEntry{
			Version: version, Description: description,
			AppliedAt: time.UnixMilli(appliedAtMS).UTC(),
		})
	}
	if err := rows.Err(); err != nil {
		return SnapshotReport{}, fmt.Errorf("%w: 遍历 schema_history 失败", ErrIntegrityFailed)
	}
	if len(report.SchemaHistory) == 0 {
		return SnapshotReport{}, fmt.Errorf("%w: 备份数据库 schema_history 为空", ErrIntegrityFailed)
	}
	if highest != v.report.Database.SchemaVersion {
		return SnapshotReport{}, fmt.Errorf(
			"%w: 快照最高迁移 %s 与头部声明 %s 不一致", ErrIntegrityFailed,
			highest, v.report.Database.SchemaVersion)
	}
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table'`).Scan(&report.TableCount); err != nil {
		return SnapshotReport{}, fmt.Errorf("%w: 读取表数量失败", ErrIntegrityFailed)
	}
	report.Supported = true
	return report, nil
}

// readOnlyDatabase 惰性建立只读 SQLite 连接（mode=ro + immutable + query_only）。
// 只读是双重的：SQLite URI mode=ro 在打开层拒绝写，PRAGMA query_only 在连接层
// 拒绝写；未通过 query_only 复核一律失败（默认拒绝）。
func (v *Viewer) readOnlyDatabase(ctx context.Context) (*sql.DB, error) {
	if v == nil || v.closed {
		return nil, fmt.Errorf("%w: 查看器已关闭", ErrOptionsInvalid)
	}
	if v.report.Database.Engine != "sqlite" {
		return nil, fmt.Errorf("%w: 只支持解析 SQLite 备份数据", ErrDatabaseUnsupported)
	}
	if v.databasePath == "" {
		return nil, fmt.Errorf("%w: 备份数据库条目缺失", ErrIntegrityFailed)
	}
	if v.db != nil {
		return v.db, nil
	}
	db, err := sql.Open("sqlite", readOnlySQLiteDSN(v.databasePath))
	if err != nil {
		return nil, fmt.Errorf("%w: 无法打开备份数据库（只读）", ErrBackupIO)
	}
	// 单连接 + 只读语义：避免连接池中的新连接绕过 PRAGMA query_only 复核。
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	var queryOnly int
	if err := db.QueryRowContext(ctx, "PRAGMA query_only").Scan(&queryOnly); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("%w: 无法验证只读连接", ErrBackupIO)
	}
	if queryOnly != 1 {
		_ = db.Close()
		return nil, fmt.Errorf("%w: 备份数据库连接未处于只读模式", ErrInternal)
	}
	v.db = db
	return db, nil
}

// readOnlySQLiteDSN 构造 modernc.org/sqlite 的只读 DSN：
//
//	file: URI（mode=ro&immutable=1） + _query_only=1
//
// immutable=1 安全的前提是被打开的是查看器自己从认证备份中解包出的私有临时
// 副本（没有 WAL/journal 旁文件、不会被其他进程修改）。路径由查看器生成，
// 不是用户输入；仍然用 net/url 编码 `?`、`#`、空格等字符。
func readOnlySQLiteDSN(path string) string {
	slash := filepath.ToSlash(path)
	uri := url.URL{Scheme: "file", Path: "/" + strings.TrimPrefix(slash, "/")}
	query := url.Values{}
	query.Set("mode", "ro")
	query.Set("immutable", "1")
	query.Set("_query_only", "1")
	query.Set("_busy_timeout", "5000")
	uri.RawQuery = query.Encode()
	return uri.String()
}

// sortStrings 返回去重排序后的字符串副本，用于稳定输出（不修改入参）。
func sortStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
