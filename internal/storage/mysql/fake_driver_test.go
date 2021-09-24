package mysql

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

	gomysql "github.com/go-sql-driver/mysql"

	"github.com/kagurazakayashi/EvernightLogin/internal/storage"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
)

// fakeState 记录语句并脚本化查询结果；用于不连真实 MySQL 地验证驱动连接器、
// 迁移后端与服务器校验逻辑（M2 修复轮）。
type fakeState struct {
	mu       sync.Mutex
	prepared []string
	executed []string
	queries  []string
	query    func(query string, args []string) (*fakeRows, error)
	exec     func(query string) error
}

func (s *fakeState) lastPrepared() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.prepared) == 0 {
		return ""
	}
	return s.prepared[len(s.prepared)-1]
}

func (s *fakeState) executedSQL() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.executed...)
}

type fakeConnector struct{ state *fakeState }

func (c fakeConnector) Connect(ctx context.Context) (driver.Conn, error) {
	return &fakeConn{state: c.state}, nil
}
func (c fakeConnector) Driver() driver.Driver { return fakeDriver{state: c.state} }

type fakeDriver struct{ state *fakeState }

func (d fakeDriver) Open(string) (driver.Conn, error) { return &fakeConn{state: d.state}, nil }

type fakeConn struct{ state *fakeState }

func (c *fakeConn) Prepare(query string) (driver.Stmt, error) {
	c.state.mu.Lock()
	c.state.prepared = append(c.state.prepared, query)
	c.state.mu.Unlock()
	return &fakeStmt{state: c.state, query: query}, nil
}
func (c *fakeConn) Close() error              { return nil }
func (c *fakeConn) Begin() (driver.Tx, error) { return fakeTx{}, nil }
func (c *fakeConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return fakeTx{}, nil
}
func (c *fakeConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.state.mu.Lock()
	c.state.queries = append(c.state.queries, query)
	handler := c.state.query
	c.state.mu.Unlock()
	if handler == nil {
		return &fakeRows{columns: []string{"value"}, data: [][]driver.Value{{int64(1)}}}, nil
	}
	return handler(query, namedValueStrings(args))
}
func (c *fakeConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	c.state.mu.Lock()
	c.state.executed = append(c.state.executed, query)
	handler := c.state.exec
	c.state.mu.Unlock()
	if handler != nil {
		if err := handler(query); err != nil {
			return nil, err
		}
	}
	return driver.RowsAffected(1), nil
}

type fakeStmt struct {
	state *fakeState
	query string
}

func (s *fakeStmt) Close() error  { return nil }
func (s *fakeStmt) NumInput() int { return -1 }
func (s *fakeStmt) Exec([]driver.Value) (driver.Result, error) {
	return driver.RowsAffected(1), nil
}
func (s *fakeStmt) Query([]driver.Value) (driver.Rows, error) {
	return &fakeRows{columns: []string{"value"}, data: [][]driver.Value{{int64(1)}}}, nil
}

type fakeTx struct{}

func (fakeTx) Commit() error   { return nil }
func (fakeTx) Rollback() error { return nil }

type fakeRows struct {
	columns []string
	data    [][]driver.Value
	index   int
}

func (r *fakeRows) Columns() []string { return r.columns }
func (r *fakeRows) Close() error      { return nil }
func (r *fakeRows) Next(destination []driver.Value) error {
	if r.index >= len(r.data) {
		return io.EOF
	}
	copy(destination, r.data[r.index])
	r.index++
	return nil
}

func namedValueStrings(args []driver.NamedValue) []string {
	values := make([]string, len(args))
	for index, arg := range args {
		values[index] = fmt.Sprint(arg.Value)
	}
	return values
}

// TestRewriteConnectorAppliesTranslation 验证仓储 SQL 经重写连接器进入驱动前已被翻译。
func TestRewriteConnectorAppliesTranslation(t *testing.T) {
	state := &fakeState{}
	db := sql.OpenDB(newRewriteConnector(fakeConnector{state: state}))
	defer db.Close()
	if _, err := db.ExecContext(context.Background(),
		"INSERT INTO users(id,username_normalized) VALUES(?,?) ON CONFLICT(username_normalized) DO NOTHING",
		"u1", "alice"); err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	prepared := state.lastPrepared()
	if !strings.Contains(prepared, "ON DUPLICATE KEY UPDATE") {
		t.Fatalf("重写连接器未翻译 ON CONFLICT: %q", prepared)
	}
	if strings.Contains(strings.ToUpper(prepared), "ON CONFLICT") {
		t.Fatalf("重写后仍含 ON CONFLICT: %q", prepared)
	}
}

// TestMigrationDDLNotTranslated 验证迁移 DDL 走原始连接：JSON_VALID 等 MySQL 原生
// 语法不经过重写器（否则会被当作 SQLite json_valid 拒绝或误改）。
func TestMigrationDDLNotTranslated(t *testing.T) {
	ddl := "CREATE TABLE `x` (`a` VARCHAR(16) NOT NULL, CONSTRAINT `c` CHECK (JSON_VALID(`a`))) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_cs"
	if err := CheckForbiddenSQLiteDialect(ddl); err == nil {
		t.Fatal("DDL 含 JSON_VALID 应被仓储 SQL 检查拒绝，证明不能经过重写器")
	}
	state := &fakeState{query: func(query string, args []string) (*fakeRows, error) {
		return &fakeRows{columns: []string{"value"}, data: [][]driver.Value{{int64(1)}}}, nil
	}}
	rawDB := sql.OpenDB(fakeConnector{state: state})
	defer rawDB.Close()
	backend, err := NewMigrationBackend(rawDB, "evernight_test", "EvernightLogin:migrate:test", time.Second)
	if err != nil {
		t.Fatalf("构造迁移后端失败: %v", err)
	}
	state.exec = func(query string) error { return nil }
	ctx := context.Background()
	err = backend.Lock(ctx, func(lockCtx context.Context) error {
		return backend.Apply(lockCtx, []string{ddl}, migrate.AppliedMigration{
			Version: "0001", Description: "test", Checksum: strings.Repeat("a", 64), AppliedAt: time.Unix(0, 0),
		})
	})
	if err != nil {
		t.Fatalf("迁移 DDL 执行失败: %v", err)
	}
	executed := state.executedSQL()
	found := false
	for _, statement := range executed {
		if statement == ddl {
			found = true
		}
	}
	if !found {
		t.Fatalf("DDL 未原样发送到原始连接，实际执行: %v", executed)
	}
}

// TestMigrationBackendLifecycle 覆盖 GET_LOCK、记录表创建与漂移校验、已应用/失败记录、
// 失败写入与清除；全部使用脚本化 stubbed 驱动，不需要真实 MySQL。
func TestMigrationBackendLifecycle(t *testing.T) {
	columns := map[string][]string{
		"schema_history":  {"version", "description", "applied_at_ms", "source_sha256"},
		"schema_failures": {"version", "description", "source_sha256", "failed_at_ms", "error_summary"},
	}
	state := &fakeState{query: func(query string, args []string) (*fakeRows, error) {
		switch {
		case strings.Contains(strings.ToUpper(query), "GET_LOCK"):
			return &fakeRows{columns: []string{"locked"}, data: [][]driver.Value{{int64(1)}}}, nil
		case strings.Contains(query, "information_schema.COLUMNS"):
			table := ""
			if len(args) > 0 {
				table = args[0]
			}
			rows := &fakeRows{columns: []string{"COLUMN_NAME"}}
			for _, column := range columns[table] {
				rows.data = append(rows.data, []driver.Value{column})
			}
			return rows, nil
		case strings.Contains(query, "FROM schema_history"):
			return &fakeRows{columns: []string{"version", "description", "source_sha256", "applied_at_ms"},
				data: [][]driver.Value{{"0001", "identity", strings.Repeat("a", 64), int64(1)}}}, nil
		case strings.Contains(query, "FROM schema_failures"):
			return &fakeRows{columns: []string{"version", "description", "source_sha256", "failed_at_ms", "error_summary"}}, nil
		default:
			return &fakeRows{columns: []string{"value"}, data: [][]driver.Value{{int64(1)}}}, nil
		}
	}}
	db := sql.OpenDB(fakeConnector{state: state})
	defer db.Close()
	backend, err := NewMigrationBackend(db, "evernight_test", "EvernightLogin:migrate:test", time.Second)
	if err != nil {
		t.Fatalf("构造迁移后端失败: %v", err)
	}
	ctx := context.Background()
	err = backend.Lock(ctx, func(lockCtx context.Context) error {
		if err := backend.EnsureBookkeeping(lockCtx); err != nil {
			return err
		}
		applied, err := backend.LoadApplied(lockCtx)
		if err != nil || len(applied) != 1 || applied[0].Version != "0001" {
			return fmt.Errorf("LoadApplied = %v, %v", applied, err)
		}
		if _, err := backend.LoadFailed(lockCtx); err != nil {
			return err
		}
		if err := backend.RecordFailure(lockCtx, migrate.FailedMigration{
			Version: "0002", Description: "d", Checksum: strings.Repeat("b", 64), FailedAt: time.Unix(0, 0), ErrorSummary: "e",
		}); err != nil {
			return err
		}
		return backend.ClearFailure(lockCtx, "0002")
	})
	if err != nil {
		t.Fatalf("迁移后端生命周期失败: %v", err)
	}
	executed := state.executedSQL()
	joined := strings.Join(executed, "\n")
	for _, want := range []string{"CREATE TABLE IF NOT EXISTS `schema_history`",
		"CREATE TABLE IF NOT EXISTS `schema_failures`", "ON DUPLICATE KEY UPDATE", "DELETE FROM schema_failures"} {
		if !strings.Contains(joined, want) {
			t.Errorf("缺少预期 SQL %q；实际执行: %s", want, joined)
		}
	}
}

// TestApplyFailureMapsError 验证迁移失败路径把驱动错误映射为存储类别并返回错误。
func TestApplyFailureMapsError(t *testing.T) {
	state := &fakeState{
		exec: func(query string) error {
			if strings.Contains(query, "FAIL_STATEMENT") {
				return &gomysql.MySQLError{Number: 1062, Message: "duplicate"}
			}
			return nil
		},
		query: func(query string, args []string) (*fakeRows, error) {
			return &fakeRows{columns: []string{"locked"}, data: [][]driver.Value{{int64(1)}}}, nil
		},
	}
	db := sql.OpenDB(fakeConnector{state: state})
	defer db.Close()
	backend, err := NewMigrationBackend(db, "evernight_test", "lock", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	err = backend.Lock(context.Background(), func(lockCtx context.Context) error {
		applyErr := backend.Apply(lockCtx, []string{"FAIL_STATEMENT"}, migrate.AppliedMigration{
			Version: "0003", Checksum: strings.Repeat("c", 64),
		})
		if applyErr == nil {
			t.Fatal("Apply 应返回错误")
		}
		if !errors.Is(applyErr, storage.ErrUniqueViolation) {
			t.Fatalf("Apply 错误未映射为 ErrUniqueViolation: %v", applyErr)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Lock 失败: %v", err)
	}
}

// TestVerifyServerSettingsRejects 覆盖服务器设置校验的接受/拒绝分支。
func TestVerifyServerSettingsRejects(t *testing.T) {
	baseValues := func() []driver.Value {
		return []driver.Value{"utf8mb4", "utf8mb4_0900_as_cs", "+00:00",
			"STRICT_ALL_TABLES", int64(0), "REPEATABLE-READ"}
	}
	cases := []struct {
		name    string
		version string
		values  []driver.Value
		wantErr bool
	}{
		{"accept", "8.0.36", baseValues(), false},
		{"mariadb", "10.11.0-MariaDB", baseValues(), true},
		{"old", "8.0.15", baseValues(), true},
		{"charset", "8.0.36", []driver.Value{"latin1", "latin1_swedish_ci", "+00:00", "STRICT_ALL_TABLES", int64(0), "REPEATABLE-READ"}, true},
		{"lower_case", "8.0.36", []driver.Value{"utf8mb4", "utf8mb4_0900_as_cs", "+00:00", "STRICT_ALL_TABLES", int64(1), "REPEATABLE-READ"}, true},
		{"timezone", "8.0.36", []driver.Value{"utf8mb4", "utf8mb4_0900_as_cs", "+08:00", "STRICT_ALL_TABLES", int64(0), "REPEATABLE-READ"}, true},
		{"isolation", "8.0.36", []driver.Value{"utf8mb4", "utf8mb4_0900_as_cs", "+00:00", "STRICT_ALL_TABLES", int64(0), "READ-COMMITTED"}, true},
		{"sqlmode", "8.0.36", []driver.Value{"utf8mb4", "utf8mb4_0900_as_cs", "+00:00", "", int64(0), "REPEATABLE-READ"}, true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			values := testCase.values
			state := &fakeState{query: func(query string, args []string) (*fakeRows, error) {
				if strings.Contains(query, "VERSION()") {
					return &fakeRows{columns: []string{"v"}, data: [][]driver.Value{{testCase.version}}}, nil
				}
				return &fakeRows{columns: []string{"a", "b", "c", "d", "e", "f"}, data: [][]driver.Value{values}}, nil
			}}
			db := sql.OpenDB(fakeConnector{state: state})
			defer db.Close()
			err := verifyServerSettings(context.Background(), db, Options{})
			if testCase.wantErr && err == nil {
				t.Fatal("期望拒绝但通过")
			}
			if !testCase.wantErr && err != nil {
				t.Fatalf("期望通过但被拒绝: %v", err)
			}
		})
	}
}
