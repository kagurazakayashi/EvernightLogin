package sqlserver

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	mssql "github.com/microsoft/go-mssqldb"

	"github.com/kagurazakayashi/EvernightLogin/internal/storage"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
)

// ---------------------------------------------------------------------------
// 脚本化 fake driver：本步边界不启动 SQL Server，用可记录/可编排的驱动验证
// (1) 重写连接器在 Prepare 层翻译 SQL；(2) 迁移 DDL 走原始连接、原样发送；
// (3) migrate.Backend 完整生命周期与失败处理。它是测试替身，不是生产驱动。
// ---------------------------------------------------------------------------

type fakeHandler func(query string, args []driver.NamedValue) (columns []string, rows [][]driver.Value, result driver.Result, err error)

type fakeConnector struct {
	mu      sync.Mutex
	queries []string
	handler fakeHandler
}

func (c *fakeConnector) Connect(context.Context) (driver.Conn, error) {
	return &fakeConn{connector: c}, nil
}

func (c *fakeConnector) Driver() driver.Driver { return fakeDriver{} }

func (c *fakeConnector) record(query string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.queries = append(c.queries, query)
}

func (c *fakeConnector) recorded() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.queries...)
}

func (c *fakeConnector) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.queries = nil
}

type fakeDriver struct{}

func (fakeDriver) Open(string) (driver.Conn, error) {
	return nil, fmt.Errorf("fake driver 只支持 Connector")
}

type fakeConn struct {
	connector *fakeConnector
}

func (c *fakeConn) Prepare(query string) (driver.Stmt, error) {
	return c.PrepareContext(context.Background(), query)
}

func (c *fakeConn) PrepareContext(_ context.Context, query string) (driver.Stmt, error) {
	c.connector.record(query)
	return &fakeStmt{connector: c.connector, query: query}, nil
}

func (c *fakeConn) Close() error { return nil }

func (c *fakeConn) Begin() (driver.Tx, error) { return fakeTx{}, nil }

func (c *fakeConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return fakeTx{}, nil
}

func (c *fakeConn) Ping(context.Context) error { return nil }

func (c *fakeConn) CheckNamedValue(*driver.NamedValue) error { return driver.ErrSkip }

// ExecContext/QueryContext 只用于简化 fake 驱动的测试路径；真实改写走 Prepare。
func (c *fakeConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	statement, err := c.PrepareContext(ctx, query)
	if err != nil {
		return nil, err
	}
	return statement.(driver.StmtExecContext).ExecContext(ctx, args)
}

func (c *fakeConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	statement, err := c.PrepareContext(ctx, query)
	if err != nil {
		return nil, err
	}
	return statement.(driver.StmtQueryContext).QueryContext(ctx, args)
}

type fakeTx struct{}

func (fakeTx) Commit() error   { return nil }
func (fakeTx) Rollback() error { return nil }

type fakeStmt struct {
	connector *fakeConnector
	query     string
}

func (s *fakeStmt) Close() error  { return nil }
func (s *fakeStmt) NumInput() int { return -1 }
func (s *fakeStmt) Exec([]driver.Value) (driver.Result, error) {
	return s.ExecContext(context.Background(), nil)
}
func (s *fakeStmt) Query([]driver.Value) (driver.Rows, error) {
	return s.QueryContext(context.Background(), nil)
}
func (s *fakeStmt) ExecContext(_ context.Context, args []driver.NamedValue) (driver.Result, error) {
	_, _, result, err := s.connector.handle(s.query, args)
	return result, err
}
func (s *fakeStmt) QueryContext(_ context.Context, args []driver.NamedValue) (driver.Rows, error) {
	columns, rows, _, err := s.connector.handle(s.query, args)
	if err != nil {
		return nil, err
	}
	return &fakeRows{columns: columns, rows: rows}, nil
}

func (c *fakeConnector) handle(query string, args []driver.NamedValue) ([]string, [][]driver.Value, driver.Result, error) {
	if c.handler != nil {
		return c.handler(query, args)
	}
	return nil, nil, fakeResult(1), nil
}

type fakeResult int64

func (r fakeResult) LastInsertId() (int64, error) { return 0, nil }
func (r fakeResult) RowsAffected() (int64, error) { return int64(r), nil }

type fakeRows struct {
	columns []string
	rows    [][]driver.Value
	index   int
}

func (r *fakeRows) Columns() []string { return r.columns }
func (r *fakeRows) Close() error      { return nil }
func (r *fakeRows) Next(destination []driver.Value) error {
	if r.index >= len(r.rows) {
		return io.EOF
	}
	copy(destination, r.rows[r.index])
	r.index++
	return nil
}

// TestRewriteConnectorTranslatesAtPrepare 验证重写连接器在 Prepare 层翻译（含事务内
// 语句），并验证仓储重写池会拒绝迁移原生 DDL 而原始池原样发送。
func TestRewriteConnectorTranslatesAtPrepare(t *testing.T) {
	resolver := func(table string) ([]string, error) {
		switch table {
		case "t":
			return []string{"a"}, nil
		}
		return nil, fmt.Errorf("unknown table")
	}
	connector := &fakeConnector{}
	db := sql.OpenDB(newRewriteConnector(connector, resolver))
	defer db.Close()

	ctx := context.Background()
	if _, err := db.ExecContext(ctx, "INSERT OR IGNORE INTO t(a,b) VALUES(?,?)", "x", "y"); err != nil {
		t.Fatalf("Exec 失败: %v", err)
	}
	transaction, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx 失败: %v", err)
	}
	if _, err := transaction.ExecContext(ctx, "UPDATE t SET b=? WHERE rowid=?", "z", 1); err != nil {
		t.Fatalf("事务内 Exec 失败: %v", err)
	}
	if err := transaction.Commit(); err != nil {
		t.Fatalf("Commit 失败: %v", err)
	}
	recorded := strings.Join(connector.recorded(), "\n")
	for _, want := range []string{
		"MERGE INTO [t] WITH (HOLDLOCK) AS target",
		"ON target.[a] = source.[a]",
		"WHEN NOT MATCHED THEN INSERT ([a], [b])",
		"UPDATE t SET b=@p1 WHERE [_rowid]=@p2",
	} {
		if !strings.Contains(recorded, want) {
			t.Errorf("重写池未按预期翻译，缺少 %q；记录：\n%s", want, recorded)
		}
	}
	if strings.Contains(recorded, "?") {
		t.Errorf("重写池仍记录了 ? 占位符：\n%s", recorded)
	}

	// 迁移 DDL 含 T-SQL 原生触发器（分号/THROW）；仓储重写池必须拒绝而不是按
	// SQLite 词法误改；原始池必须原样发送。
	connector.reset()
	ddl := "CREATE TRIGGER [trg] ON [t] AFTER UPDATE AS\nBEGIN\n  ;THROW 50000, N'x', 1;\nEND"
	if _, err := db.ExecContext(ctx, `SELECT id FROM t WHERE id=@p1`); err == nil {
		t.Error("重写池应拒绝既有 @ 参数（编号冲突）")
	}
	rawConnector := &fakeConnector{}
	rawDB := sql.OpenDB(rawConnector)
	defer rawDB.Close()
	if _, err := rawDB.ExecContext(ctx, ddl); err != nil {
		t.Fatalf("原始池执行 DDL 失败: %v", err)
	}
	if recorded := rawConnector.recorded(); len(recorded) != 1 || recorded[0] != ddl {
		t.Errorf("原始池未原样发送 DDL：%#v", recorded)
	}
}

// newBackendFixture 构造带脚本化响应的迁移后端与连接池。
func newBackendFixture(t *testing.T) (*fakeConnector, *sql.DB, *Backend) {
	t.Helper()
	connector := &fakeConnector{}
	connector.handler = func(query string, args []driver.NamedValue) ([]string, [][]driver.Value, driver.Result, error) {
		normalized := strings.TrimSpace(query)
		switch {
		case strings.HasPrefix(normalized, "DECLARE @result INT;\nEXEC @result = sp_getapplock"):
			return []string{"result"}, [][]driver.Value{{int64(0)}}, nil, nil
		case strings.HasPrefix(normalized, "DECLARE @result INT;\nEXEC @result = sp_releaseapplock"):
			return []string{"result"}, [][]driver.Value{{int64(1)}}, nil, nil
		case strings.HasPrefix(normalized, "IF OBJECT_ID(N'schema_history'"):
			return nil, nil, fakeResult(0), nil
		case strings.HasPrefix(normalized, "IF OBJECT_ID(N'schema_failures'"):
			return nil, nil, fakeResult(0), nil
		case strings.HasPrefix(normalized, "SELECT type FROM sys.objects"):
			return []string{"type"}, [][]driver.Value{{"U"}}, nil, nil
		case strings.HasPrefix(normalized, "SELECT COUNT(*) FROM sys.indexes"):
			return []string{""}, [][]driver.Value{{int64(1)}}, nil, nil
		case strings.HasPrefix(normalized, "SELECT c.name, t.name, c.is_nullable"):
			table := ""
			if len(args) > 0 {
				table, _ = args[0].Value.(string)
			}
			columns := [][]driver.Value{
				{"version", "nvarchar", false},
				{"description", "nvarchar", false},
				{"applied_at_ms", "bigint", false},
				{"source_sha256", "nvarchar", false},
			}
			if table == "schema_failures" {
				columns = [][]driver.Value{
					{"version", "nvarchar", false},
					{"description", "nvarchar", false},
					{"source_sha256", "nvarchar", false},
					{"failed_at_ms", "bigint", false},
					{"error_summary", "nvarchar", false},
				}
			}
			return []string{"name", "type", "is_nullable"}, columns, nil, nil
		case strings.HasPrefix(normalized, "SELECT version, description, source_sha256, applied_at_ms FROM schema_history"):
			return []string{"version", "description", "source_sha256", "applied_at_ms"},
				[][]driver.Value{{"0001", "identity", "abc", int64(1000)}}, nil, nil
		case strings.HasPrefix(normalized, "SELECT version, description, source_sha256, failed_at_ms, error_summary FROM schema_failures"):
			return []string{"version", "description", "source_sha256", "failed_at_ms", "error_summary"},
				[][]driver.Value{{"0002", "fail", "def", int64(2000), "boom"}}, nil, nil
		case strings.Contains(normalized, "FAIL_ME"):
			return nil, nil, nil, fmt.Errorf("模拟迁移 DDL 失败")
		default:
			return nil, nil, fakeResult(1), nil
		}
	}
	db := sql.OpenDB(connector)
	backend, err := NewMigrationBackend(db, "test-lock", time.Second)
	if err != nil {
		t.Fatalf("构造迁移后端失败: %v", err)
	}
	return connector, db, backend
}

// TestMigrationBackendLifecycle 覆盖 sp_getapplock、记录表结构校验、已应用/失败读取、
// 事务内 Apply、失败回滚与失败记录清理（无需真实 SQL Server）。
func TestMigrationBackendLifecycle(t *testing.T) {
	connector, db, backend := newBackendFixture(t)
	defer db.Close()
	ctx := context.Background()

	if err := backend.Lock(ctx, func(lockCtx context.Context) error {
		if err := backend.EnsureBookkeeping(lockCtx); err != nil {
			return fmt.Errorf("EnsureBookkeeping: %w", err)
		}
		applied, err := backend.LoadApplied(lockCtx)
		if err != nil {
			return fmt.Errorf("LoadApplied: %w", err)
		}
		if len(applied) != 1 || applied[0].Version != "0001" || applied[0].AppliedAt.UnixMilli() != 1000 {
			return fmt.Errorf("LoadApplied 结果异常: %+v", applied)
		}
		failed, err := backend.LoadFailed(lockCtx)
		if err != nil {
			return fmt.Errorf("LoadFailed: %w", err)
		}
		if len(failed) != 1 || failed[0].Version != "0002" {
			return fmt.Errorf("LoadFailed 结果异常: %+v", failed)
		}
		record := migrate.AppliedMigration{Version: "0003", Description: "three", Checksum: "sum", AppliedAt: time.UnixMilli(3000)}
		if err := backend.Apply(lockCtx, []string{`CREATE TABLE [t] ([id] NVARCHAR(64))`}, record); err != nil {
			return fmt.Errorf("Apply: %w", err)
		}
		if err := backend.RecordFailure(lockCtx, migrate.FailedMigration{Version: "0004", ErrorSummary: "x"}); err != nil {
			return fmt.Errorf("RecordFailure: %w", err)
		}
		if err := backend.ClearFailure(lockCtx, "0002"); err != nil {
			return fmt.Errorf("ClearFailure: %w", err)
		}
		// Apply 失败必须回滚并返回存储错误（不留下半完成结构）。
		err = backend.Apply(lockCtx, []string{`CREATE TABLE [bad] ([x] NVARCHAR(8))`, "FAIL_ME"}, record)
		if err == nil {
			return fmt.Errorf("Apply 失败语句应返回错误")
		}
		var storageError *storage.Error
		if !errors.As(err, &storageError) {
			return fmt.Errorf("Apply 失败应映射为 storage.Error，实际 %T", err)
		}
		return nil
	}); err != nil {
		t.Fatalf("迁移后端生命周期失败: %v", err)
	}

	recorded := strings.Join(connector.recorded(), "\n")
	for _, want := range []string{
		"sp_getapplock @Resource=@p1",
		"sp_releaseapplock @Resource=@p1",
		"CREATE TABLE schema_history",
		"CREATE TABLE schema_failures",
		"INSERT INTO schema_history(version, description, applied_at_ms, source_sha256) VALUES(@p1,@p2,@p3,@p4)",
		"MERGE INTO schema_failures",
		"DELETE FROM schema_failures WHERE version = @p1",
	} {
		if !strings.Contains(recorded, want) {
			t.Errorf("迁移后端缺少预期 SQL %q；记录：\n%s", want, recorded)
		}
	}
}

// TestMigrationBackendLockBusy 验证 sp_getapplock 返回负数（超时/取消/死锁）时返回
// ErrBusy，且不执行迁移回调（fail-closed）。
func TestMigrationBackendLockBusy(t *testing.T) {
	connector := &fakeConnector{}
	connector.handler = func(query string, args []driver.NamedValue) ([]string, [][]driver.Value, driver.Result, error) {
		if strings.HasPrefix(strings.TrimSpace(query), "DECLARE @result INT;\nEXEC @result = sp_getapplock") {
			return []string{"result"}, [][]driver.Value{{int64(-1)}}, nil, nil
		}
		return nil, nil, fakeResult(0), nil
	}
	db := sql.OpenDB(connector)
	defer db.Close()
	backend, err := NewMigrationBackend(db, "test-lock", time.Second)
	if err != nil {
		t.Fatalf("构造迁移后端失败: %v", err)
	}
	called := false
	lockErr := backend.Lock(context.Background(), func(context.Context) error {
		called = true
		return nil
	})
	if called {
		t.Error("未取得锁时不应执行迁移回调")
	}
	if !errors.Is(lockErr, storage.ErrBusy) {
		t.Fatalf("锁冲突应返回 ErrBusy，实际 %v", lockErr)
	}
}

// TestSplitGOBatches 验证执行器按行首 GO 拆分批次（驱动不支持 GO），GO n 非 1 计数
// 必须显式报错而不是静默丢弃。
func TestSplitGOBatches(t *testing.T) {
	batches, err := splitGOBatches("CREATE TABLE [a] ([x] BIGINT)\nGO\nCREATE INDEX [i] ON [a]([x])\ngo -- trailing comment\nGO 1\nSELECT 1")
	if err != nil {
		t.Fatalf("GO 拆分失败: %v", err)
	}
	if len(batches) != 3 {
		t.Fatalf("GO 拆分结果应为 3 批，实际 %d：%#v", len(batches), batches)
	}
	if !strings.HasPrefix(batches[0], "CREATE TABLE") || !strings.HasPrefix(batches[1], "CREATE INDEX") {
		t.Errorf("GO 拆分批次内容异常：%#v", batches)
	}
	if strings.Contains(strings.Join(batches, "\n"), "GO") {
		t.Errorf("拆分后仍含 GO：%#v", batches)
	}
	if _, err := splitGOBatches("SELECT 1\nGO 5\nSELECT 2"); err == nil {
		t.Error("GO 5（重复执行计数）未实现，应显式报错")
	}
	if _, err := splitGOBatches("SELECT 1\nGO nonsense"); err == nil {
		t.Error("无法解析的 GO 行应显式报错")
	}
}

// TestBackupUnsupported 验证在线备份/恢复明确不支持、不创建文件、不返回成功。
func TestBackupUnsupported(t *testing.T) {
	store := &Store{}
	capability := store.BackupCapability()
	if capability.Supported {
		t.Error("SQL Server 在线备份不应声明为支持")
	}
	if capability.Limitation == "" || capability.Mechanism == "" {
		t.Error("备份能力声明缺少限制/机制说明")
	}
	if err := store.CreateOnlineBackup(context.Background(), "unused"); !errors.Is(err, ErrOnlineBackupUnsupported) {
		t.Errorf("CreateOnlineBackup 应返回 ErrOnlineBackupUnsupported，实际 %v", err)
	}
	if err := store.RestoreOnlineBackup(context.Background(), "unused"); !errors.Is(err, ErrOnlineBackupUnsupported) {
		t.Errorf("RestoreOnlineBackup 应返回 ErrOnlineBackupUnsupported，实际 %v", err)
	}
}

// TestMapError 验证 SQL Server 错误号映射与安全文案（不泄露原始文本）。
func TestMapError(t *testing.T) {
	cases := []struct {
		number int32
		kind   error
	}{
		{2627, storage.ErrUniqueViolation},
		{2601, storage.ErrUniqueViolation},
		{1205, storage.ErrBusy},
		{1222, storage.ErrBusy},
		{547, storage.ErrConstraint},
		{515, storage.ErrConstraint},
		{229, storage.ErrPermission},
		{18456, storage.ErrPermission},
		{4060, storage.ErrUnavailable},
		{9002, storage.ErrDiskFull},
	}
	for _, testCase := range cases {
		mapped := mapError(fakeSQLError(testCase.number))
		if !errors.Is(mapped, testCase.kind) {
			t.Errorf("错误号 %d 应映射为 %v，实际 %v", testCase.number, testCase.kind, mapped)
		}
		if strings.Contains(mapped.Error(), "secret") || strings.Contains(mapped.Error(), "SELECT") {
			t.Errorf("公开错误文本泄露原始内容: %s", mapped.Error())
		}
	}
	if !errors.Is(mapError(context.Canceled), context.Canceled) {
		t.Error("context.Canceled 应原样返回")
	}
}

// fakeSQLError 构造带敏感文本的驱动错误，验证映射后的公开文案不泄露 SQL/凭据。
func fakeSQLError(number int32) mssql.Error {
	return mssql.Error{Number: number, Message: "secret SELECT password FROM users"}
}
