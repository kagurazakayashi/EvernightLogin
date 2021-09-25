package postgres

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

	"github.com/lib/pq"
	"github.com/lib/pq/pqerror"

	"github.com/kagurazakayashi/EvernightLogin/internal/storage"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
)

// ---------------------------------------------------------------------------
// 脚本化 fake driver：本步边界不启动 PostgreSQL，用可记录/可编排的驱动验证
// (1) 重写连接器在 Prepare 层翻译 SQL；(2) 迁移 DDL 走原始连接、原样发送；
// (3) migrate.Backend 完整生命周期与失败回滚。它是测试替身，不是生产驱动。
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
	columns, _, result, err := s.connector.handle(s.query, args)
	_ = columns
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
	connector := &fakeConnector{}
	db := sql.OpenDB(newRewriteConnector(connector))
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
	recorded := connector.recorded()
	joined := strings.Join(recorded, "\n")
	for _, want := range []string{
		"INSERT INTO t(a,b) VALUES($1,$2) ON CONFLICT DO NOTHING",
		"UPDATE t SET b=$1 WHERE _rowid=$2",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("重写池未按预期翻译，缺少 %q；记录：\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "?") {
		t.Errorf("重写池仍记录了 ? 占位符：\n%s", joined)
	}

	// 迁移 DDL 含 PostgreSQL 原生触发器函数（$body$ 引用），仓储重写池必须拒绝而不是
	// 按 SQLite 词法误改；原始池必须原样发送。
	connector.reset()
	ddl := `CREATE FUNCTION "f"() RETURNS trigger LANGUAGE plpgsql AS $body$ BEGIN RAISE EXCEPTION 'x'; END; $body$`
	if _, err := db.ExecContext(ctx, `SELECT id FROM t WHERE id=$1`); err == nil {
		t.Error("重写池应拒绝既有 $n 占位符（编号冲突）")
	}

	// 原始池（未重写）原样发送同一 DDL，并接受 PostgreSQL 原生语法。
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
		case strings.HasPrefix(normalized, "SET statement_timeout"):
			return nil, nil, fakeResult(0), nil
		case strings.HasPrefix(normalized, "SELECT pg_advisory_lock"):
			return nil, nil, fakeResult(0), nil
		case strings.HasPrefix(normalized, "SELECT pg_advisory_unlock"):
			return []string{"pg_advisory_unlock"}, [][]driver.Value{{true}}, nil, nil
		case strings.HasPrefix(normalized, "SELECT c.relkind::text FROM pg_catalog.pg_class"):
			return []string{"relkind"}, [][]driver.Value{{"r"}}, nil, nil
		case strings.HasPrefix(normalized, "SELECT column_name FROM information_schema.columns"):
			table := ""
			if len(args) > 0 {
				table, _ = args[0].Value.(string)
			}
			columns := []string{"version", "description", "applied_at_ms", "source_sha256"}
			if table == "schema_failures" {
				columns = []string{"version", "description", "source_sha256", "failed_at_ms", "error_summary"}
			}
			rows := make([][]driver.Value, 0, len(columns))
			for _, column := range columns {
				rows = append(rows, []driver.Value{column})
			}
			return []string{"column_name"}, rows, nil, nil
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
	backend, err := NewMigrationBackend(db, 42, "test-lock", time.Second)
	if err != nil {
		t.Fatalf("构造迁移后端失败: %v", err)
	}
	return connector, db, backend
}

// TestMigrationBackendLifecycle 覆盖 advisory lock、记录表结构校验、已应用/失败读取、
// 事务内 Apply、失败回滚与失败记录清理（无需真实 PostgreSQL）。
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
		if err := backend.Apply(lockCtx, []string{`CREATE TABLE "t" ("id" TEXT)`}, record); err != nil {
			return fmt.Errorf("Apply: %w", err)
		}
		if err := backend.RecordFailure(lockCtx, migrate.FailedMigration{Version: "0004", ErrorSummary: "x"}); err != nil {
			return fmt.Errorf("RecordFailure: %w", err)
		}
		if err := backend.ClearFailure(lockCtx, "0002"); err != nil {
			return fmt.Errorf("ClearFailure: %w", err)
		}
		// Apply 失败必须回滚并返回存储错误（不留下半完成结构）。
		err = backend.Apply(lockCtx, []string{`CREATE TABLE "bad" ("x" TEXT)`, "FAIL_ME"}, record)
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
		"pg_advisory_lock($1)",
		"SET statement_timeout = 1000",
		"CREATE TABLE IF NOT EXISTS schema_history",
		"INSERT INTO schema_history(version, description, applied_at_ms, source_sha256) VALUES($1,$2,$3,$4)",
		"INSERT INTO schema_failures",
		"DELETE FROM schema_failures WHERE version = $1",
		"pg_advisory_unlock($1)",
	} {
		if !strings.Contains(recorded, want) {
			t.Errorf("迁移后端缺少预期 SQL %q；记录：\n%s", want, recorded)
		}
	}
}

// TestMigrationBackendLockTimeout 验证阻塞加锁因 statement_timeout 超时（57014）时返回
// ErrBusy，且不执行迁移回调（fail-closed）。
func TestMigrationBackendLockTimeout(t *testing.T) {
	connector := &fakeConnector{}
	connector.handler = func(query string, args []driver.NamedValue) ([]string, [][]driver.Value, driver.Result, error) {
		switch {
		case strings.HasPrefix(strings.TrimSpace(query), "SELECT pg_advisory_lock"):
			return nil, nil, nil, &pq.Error{Code: pqerror.Code("57014"), Message: "canceling statement due to statement timeout"}
		default:
			return nil, nil, fakeResult(0), nil
		}
	}
	db := sql.OpenDB(connector)
	defer db.Close()
	backend, err := NewMigrationBackend(db, 42, "test-lock", time.Second)
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
