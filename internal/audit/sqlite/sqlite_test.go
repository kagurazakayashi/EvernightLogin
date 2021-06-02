package sqlite_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// testTime 是测试使用的固定时间。
var testTime = time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)

// openTestDatabase 在临时目录创建数据库并执行全部迁移。
func openTestDatabase(t *testing.T) *storagesqlite.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.db")
	raw, err := storagesqlite.Open(context.Background(), storagesqlite.DefaultOptions(path))
	if err != nil {
		t.Fatalf("打开临时 SQLite 失败: %v", err)
	}
	t.Cleanup(func() {
		_ = raw.Close()
	})
	migrationSet, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移失败: %v", err)
	}
	if _, err := raw.Migrate(context.Background(), migrationSet); err != nil {
		t.Fatalf("执行迁移失败: %v", err)
	}
	return raw
}

// newTestAuditStore 构造 SQLite 审计仓储。
func newTestAuditStore(t *testing.T, raw *storagesqlite.Store) *auditsqlite.Store {
	t.Helper()
	store, err := auditsqlite.New(raw)
	if err != nil {
		t.Fatalf("构造审计仓储失败: %v", err)
	}
	return store
}

// recordingAlerter 记录审计故障告警。
type recordingAlerter struct {
	mu     sync.Mutex
	alarms []audit.Alarm
}

// Alarm 实现 audit.Alerter。
func (a *recordingAlerter) Alarm(_ context.Context, alarm audit.Alarm) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.alarms = append(a.alarms, alarm)
}

// snapshot 返回告警副本。
func (a *recordingAlerter) snapshot() []audit.Alarm {
	a.mu.Lock()
	defer a.mu.Unlock()
	copied := make([]audit.Alarm, len(a.alarms))
	copy(copied, a.alarms)
	return copied
}

// newTestRecorder 构造固定时钟的 Recorder。
func newTestRecorder(t *testing.T, store audit.Store, alerter audit.Alerter) *audit.Recorder {
	t.Helper()
	recorder, err := audit.New(store, audit.Options{
		Now:     func() time.Time { return testTime },
		Alerter: alerter,
	})
	if err != nil {
		t.Fatalf("构造审计 Recorder 失败: %v", err)
	}
	return recorder
}

// testEvent 返回一条未填 ID/时间的测试事件。
func testEvent(action string) audit.Event {
	return audit.Event{
		Actor:   audit.Actor{Type: audit.ActorUser, ID: "user-1"},
		AppID:   "app_1",
		Action:  action,
		Target:  audit.Target{Type: "user", ID: "user-2"},
		Outcome: audit.OutcomeSuccess,
		Changes: []audit.FieldChange{{Field: "status", Before: "active", After: "disabled"}},
	}
}

// queryInt 执行单值整数查询。
func queryInt(t *testing.T, store *storagesqlite.Store, query string, args ...any) int {
	t.Helper()
	rows, err := store.QueryContext(context.Background(), query, args...)
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatalf("查询没有结果: %s", query)
	}
	var value int
	if err := rows.Scan(&value); err != nil {
		t.Fatalf("扫描查询结果失败: %v", err)
	}
	return value
}

// TestMigrationApplied 验证 0001～0006 迁移与审计表结构/索引。
func TestMigrationApplied(t *testing.T) {
	raw := openTestDatabase(t)
	rows, err := raw.QueryContext(context.Background(), `SELECT version FROM schema_history ORDER BY version`)
	if err != nil {
		t.Fatalf("读取迁移历史失败: %v", err)
	}
	defer rows.Close()
	var versions []string
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			t.Fatalf("扫描迁移版本失败: %v", err)
		}
		versions = append(versions, version)
	}
	if len(versions) != 15 || versions[0] != "0001" || versions[1] != "0002" || versions[2] != "0003" || versions[3] != "0004" || versions[4] != "0005" || versions[5] != "0006" || versions[6] != "0007" || versions[7] != "0008" || versions[8] != "0009" || versions[9] != "0010" || versions[10] != "0011" || versions[11] != "0012" || versions[12] != "0013" || versions[13] != "0014" || versions[14] != "0015" {
		t.Fatalf("迁移历史 = %v，期望 [0001 0002 0003 0004 0005 0006 0007 0008 0009 0010 0011 0012 0013 0014 0015]", versions)
	}
	type column struct {
		kind    string
		notNull int
	}
	columns := make(map[string]column)
	infoRows, err := raw.QueryContext(context.Background(), `SELECT name,type,"notnull" FROM pragma_table_info('audit_events')`)
	if err != nil {
		t.Fatalf("读取审计表结构失败: %v", err)
	}
	defer infoRows.Close()
	for infoRows.Next() {
		var name string
		var info column
		if err := infoRows.Scan(&name, &info.kind, &info.notNull); err != nil {
			t.Fatalf("扫描审计表结构失败: %v", err)
		}
		columns[name] = info
	}
	for name, want := range map[string]column{
		"id":              {kind: "TEXT", notNull: 1},
		"occurred_at_ms":  {kind: "INTEGER", notNull: 1},
		"actor_type":      {kind: "TEXT", notNull: 1},
		"app_id_snapshot": {kind: "TEXT", notNull: 0},
		"detail_json":     {kind: "TEXT", notNull: 1},
		"dedupe_key":      {kind: "TEXT", notNull: 0},
	} {
		if got, ok := columns[name]; !ok || got != want {
			t.Errorf("列 %s = %+v，期望 %+v", name, got, want)
		}
	}
	for _, index := range []string{
		"ix_audit_events_occurred_at_ms",
		"ix_audit_events_request_id",
		"ix_audit_events_task_id",
		"ix_audit_events_action_occurred_at_ms",
		"ux_audit_events_dedupe_key",
	} {
		if got := queryInt(t, raw, `SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?`, index); got != 1 {
			t.Errorf("缺失索引 %s", index)
		}
	}
}

// TestAppendStoresRedactedEvent 验证事件字段持久化与敏感差异脱敏。
func TestAppendStoresRedactedEvent(t *testing.T) {
	raw := openTestDatabase(t)
	store := newTestAuditStore(t, raw)
	recorder := newTestRecorder(t, store, &recordingAlerter{})
	event := testEvent("users.update_profile")
	event.Changes = []audit.FieldChange{
		{Field: "display_name", Before: "旧名称", After: "新名称"},
		{Field: "password", Before: "OldSecret123", After: "NewSecret456"},
		{Field: "email_token", Before: "tok-1", After: "tok-2"},
	}
	event.RequestID = "req_1234"
	event.TaskID = "task_1234"
	event.DedupeKey = "users.update_profile/user-2/v1"
	if err := recorder.Record(context.Background(), event); err != nil {
		t.Fatalf("Record 失败: %v", err)
	}
	rows, err := raw.QueryContext(context.Background(),
		`SELECT actor_type,actor_id,app_id_snapshot,action,target_type,target_id,outcome,request_id,task_id,detail_json FROM audit_events WHERE action=?`, event.Action)
	if err != nil {
		t.Fatalf("查询审计事件失败: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatal("审计事件未写入")
	}
	var (
		actorType, actorID, appID, action, targetType, targetID, outcome string
		requestID, taskID                                                sql.NullString
		detailJSON                                                       string
	)
	if err := rows.Scan(&actorType, &actorID, &appID, &action, &targetType, &targetID, &outcome, &requestID, &taskID, &detailJSON); err != nil {
		t.Fatalf("扫描审计事件失败: %v", err)
	}
	if actorType != "user" || actorID != "user-1" || appID != "app_1" || action != event.Action ||
		targetType != "user" || targetID != "user-2" || outcome != "success" {
		t.Fatalf("事件身份/目标字段错误: %+v", []string{actorType, actorID, appID, action, targetType, targetID, outcome})
	}
	if !requestID.Valid || requestID.String != "req_1234" || !taskID.Valid || taskID.String != "task_1234" {
		t.Fatalf("request/task 关联字段错误: %+v %+v", requestID, taskID)
	}
	for _, secret := range []string{"OldSecret123", "NewSecret456", "tok-1", "tok-2"} {
		if strings.Contains(detailJSON, secret) {
			t.Fatalf("detail_json 泄露秘密 %q: %s", secret, detailJSON)
		}
	}
	if !strings.Contains(detailJSON, "[REDACTED]") {
		t.Fatalf("detail_json 缺少脱敏标记: %s", detailJSON)
	}
	var parsed struct {
		Version int `json:"v"`
		Changes []struct {
			Field  string `json:"field"`
			Before string `json:"before"`
			After  string `json:"after"`
		} `json:"changes"`
	}
	if err := json.Unmarshal([]byte(detailJSON), &parsed); err != nil || parsed.Version != 1 || len(parsed.Changes) != 3 {
		t.Fatalf("detail_json 结构错误: %v %s", err, detailJSON)
	}
	if parsed.Changes[0].Before != "旧名称" || parsed.Changes[0].After != "新名称" {
		t.Fatalf("普通差异未原样保存: %+v", parsed.Changes[0])
	}
}

// TestIdentityKindsStored 验证四类可信身份与匿名不得携带 ID。
func TestIdentityKindsStored(t *testing.T) {
	raw := openTestDatabase(t)
	store := newTestAuditStore(t, raw)
	recorder := newTestRecorder(t, store, &recordingAlerter{})
	actors := []audit.Actor{
		{Type: audit.ActorUser, ID: "user-1"},
		{Type: audit.ActorSystem, ID: "scheduler"},
		{Type: audit.ActorLocalAdmin, ID: "DOMAIN\\admin"},
		{Type: audit.ActorAnonymous, ID: ""},
	}
	for index, actor := range actors {
		event := testEvent("audit.identity_test")
		event.Actor = actor
		event.Target = audit.Target{Type: "system", ID: ""}
		event.DedupeKey = "identity/" + string(rune('a'+index))
		if err := recorder.Record(context.Background(), event); err != nil {
			t.Fatalf("记录身份 %+v 失败: %v", actor, err)
		}
	}
	rows, err := raw.QueryContext(context.Background(),
		`SELECT actor_type,actor_id FROM audit_events ORDER BY dedupe_key`)
	if err != nil {
		t.Fatalf("查询身份失败: %v", err)
	}
	defer rows.Close()
	index := 0
	for rows.Next() {
		var actorType string
		var actorID sql.NullString
		if err := rows.Scan(&actorType, &actorID); err != nil {
			t.Fatalf("扫描身份失败: %v", err)
		}
		if actorType != string(actors[index].Type) {
			t.Fatalf("第 %d 个身份类型 = %q，期望 %q", index, actorType, actors[index].Type)
		}
		if actors[index].ID == "" {
			if actorID.Valid {
				t.Fatalf("匿名事件 actor_id 应为 NULL，实际 %q", actorID.String)
			}
		} else if !actorID.Valid || actorID.String != actors[index].ID {
			t.Fatalf("第 %d 个身份 ID = %+v，期望 %q", index, actorID, actors[index].ID)
		}
		index++
	}
	if index != len(actors) {
		t.Fatalf("身份事件数量 = %d", index)
	}

	// 匿名携带 ID 必须被拒绝，且不落库。
	fake := testEvent("audit.anonymous_fake")
	fake.Actor = audit.Actor{Type: audit.ActorAnonymous, ID: "pretend-root"}
	if err := recorder.Record(context.Background(), fake); !errors.Is(err, audit.ErrInvalidEvent) {
		t.Fatalf("匿名伪造身份错误 = %v", err)
	}
	if got := queryInt(t, raw, `SELECT COUNT(*) FROM audit_events WHERE action='audit.anonymous_fake'`); got != 0 {
		t.Fatalf("伪造匿名事件被写入 %d 条", got)
	}
}

// TestDuplicateDedupeKey 验证幂等键唯一：重复事件只保存一次。
func TestDuplicateDedupeKey(t *testing.T) {
	raw := openTestDatabase(t)
	store := newTestAuditStore(t, raw)
	recorder := newTestRecorder(t, store, &recordingAlerter{})
	event := testEvent("audit.dedupe")
	event.DedupeKey = "dedupe-1"
	if err := recorder.Record(context.Background(), event); err != nil {
		t.Fatalf("首次记录失败: %v", err)
	}
	if err := recorder.Record(context.Background(), event); !errors.Is(err, audit.ErrDuplicateEvent) {
		t.Fatalf("重复记录错误 = %v，期望 ErrDuplicateEvent", err)
	}
	if got := queryInt(t, raw, `SELECT COUNT(*) FROM audit_events WHERE dedupe_key='dedupe-1'`); got != 1 {
		t.Fatalf("幂等键事件数量 = %d，期望 1", got)
	}
}

// insertApplication 是独立测试操作：在事务中写入一条应用记录。
func insertApplication(ctx context.Context, tx audit.Tx, appID string) error {
	_, err := tx.ExecContext(ctx,
		`INSERT INTO applications(id,name,client_type,status,created_at_ms,updated_at_ms) VALUES(?,?,'confidential','active',?,?)`,
		appID, "审计测试应用", testTime.UnixMilli(), testTime.UnixMilli())
	return err
}

// TestExecuteCriticalSuccessConsistentCommit 验证关键变更与成功审计一致提交。
func TestExecuteCriticalSuccessConsistentCommit(t *testing.T) {
	raw := openTestDatabase(t)
	store := newTestAuditStore(t, raw)
	recorder := newTestRecorder(t, store, &recordingAlerter{})
	event := testEvent("applications.create")
	event.Actor = audit.Actor{Type: audit.ActorSystem, ID: "admin-service"}
	event.Target = audit.Target{Type: "application", ID: "app_audit_1"}
	event.DedupeKey = "applications.create/app_audit_1"
	request := audit.CriticalRequest{Event: event}
	err := recorder.ExecuteCritical(context.Background(), request, func(ctx context.Context, tx audit.Tx) error {
		return insertApplication(ctx, tx, "app_audit_1")
	})
	if err != nil {
		t.Fatalf("关键变更失败: %v", err)
	}
	if got := queryInt(t, raw, `SELECT COUNT(*) FROM applications WHERE id='app_audit_1'`); got != 1 {
		t.Fatalf("业务记录数 = %d", got)
	}
	if got := queryInt(t, raw, `SELECT COUNT(*) FROM audit_events WHERE action='applications.create' AND outcome='success'`); got != 1 {
		t.Fatalf("成功审计事件数 = %d", got)
	}
}

// TestBusinessFailureAuditSurvivesRollback 验证业务失败回滚后失败审计仍保存。
func TestBusinessFailureAuditSurvivesRollback(t *testing.T) {
	raw := openTestDatabase(t)
	store := newTestAuditStore(t, raw)
	alerter := &recordingAlerter{}
	recorder := newTestRecorder(t, store, alerter)
	event := testEvent("applications.create")
	event.Target = audit.Target{Type: "application", ID: "app_audit_2"}
	event.DedupeKey = "applications.create/app_audit_2"
	request := audit.CriticalRequest{
		Event:             event,
		FailureErrorCode:  "CONFLICT",
		FailureReasonCode: "duplicate_application",
	}
	businessErr := errors.New("业务唯一性冲突")
	err := recorder.ExecuteCritical(context.Background(), request, func(ctx context.Context, tx audit.Tx) error {
		if err := insertApplication(ctx, tx, "app_audit_2"); err != nil {
			return err
		}
		return businessErr
	})
	if !errors.Is(err, businessErr) {
		t.Fatalf("错误 = %v，期望业务错误", err)
	}
	if got := queryInt(t, raw, `SELECT COUNT(*) FROM applications WHERE id='app_audit_2'`); got != 0 {
		t.Fatalf("业务事务回滚后仍存在记录: %d", got)
	}
	rows, err := raw.QueryContext(context.Background(),
		`SELECT outcome,error_code,reason_code FROM audit_events WHERE action='applications.create'`)
	if err != nil {
		t.Fatalf("查询失败审计失败: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatal("业务失败后失败审计未保存")
	}
	var outcome string
	var errorCode, reasonCode sql.NullString
	if err := rows.Scan(&outcome, &errorCode, &reasonCode); err != nil {
		t.Fatalf("扫描失败审计失败: %v", err)
	}
	if outcome != "failure" || !errorCode.Valid || errorCode.String != "CONFLICT" || !reasonCode.Valid || reasonCode.String != "duplicate_application" {
		t.Fatalf("失败审计字段 = %s %+v %+v", outcome, errorCode, reasonCode)
	}
	if len(alerter.snapshot()) != 0 {
		t.Fatal("业务失败但审计成功时不应告警")
	}
}

// TestAuditFailureRejectsChangeAndAlarms 用触发器注入成功审计写入故障，验证业务
// 回滚、错误类型、告警与失败审计仍保存；修复后重试成功。
func TestAuditFailureRejectsChangeAndAlarms(t *testing.T) {
	raw := openTestDatabase(t)
	store := newTestAuditStore(t, raw)
	alerter := &recordingAlerter{}
	recorder := newTestRecorder(t, store, alerter)
	if _, err := raw.ExecContext(context.Background(),
		`CREATE TRIGGER audit_inject_success_failure BEFORE INSERT ON audit_events
		 WHEN NEW.outcome='success' BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END`); err != nil {
		t.Fatalf("创建故障触发器失败: %v", err)
	}
	event := testEvent("applications.create")
	event.Target = audit.Target{Type: "application", ID: "app_audit_3"}
	event.DedupeKey = "applications.create/app_audit_3"
	request := audit.CriticalRequest{
		Event:             event,
		FailureErrorCode:  "AUDIT_WRITE_FAILED",
		FailureReasonCode: "audit_unavailable",
	}
	err := recorder.ExecuteCritical(context.Background(), request, func(ctx context.Context, tx audit.Tx) error {
		return insertApplication(ctx, tx, "app_audit_3")
	})
	if !errors.Is(err, audit.ErrAuditUnavailable) {
		t.Fatalf("审计故障错误 = %v，期望 ErrAuditUnavailable", err)
	}
	if got := queryInt(t, raw, `SELECT COUNT(*) FROM applications WHERE id='app_audit_3'`); got != 0 {
		t.Fatalf("审计故障时业务变更未回滚，记录数 = %d", got)
	}
	if got := queryInt(t, raw, `SELECT COUNT(*) FROM audit_events WHERE action='applications.create' AND outcome='failure'`); got != 1 {
		t.Fatalf("失败审计事件数 = %d，期望 1", got)
	}
	alarms := alerter.snapshot()
	if len(alarms) == 0 || alarms[0].Kind != audit.AlarmAuditWriteFailed {
		t.Fatalf("未触发审计故障告警: %+v", alarms)
	}

	// 移除故障后，同一幂等键重试成功且只产生一条成功事件。
	if _, err := raw.ExecContext(context.Background(), `DROP TRIGGER audit_inject_success_failure`); err != nil {
		t.Fatalf("删除故障触发器失败: %v", err)
	}
	if err := recorder.ExecuteCritical(context.Background(), request, func(ctx context.Context, tx audit.Tx) error {
		return insertApplication(ctx, tx, "app_audit_3")
	}); err != nil {
		t.Fatalf("修复后重试失败: %v", err)
	}
	if got := queryInt(t, raw, `SELECT COUNT(*) FROM applications WHERE id='app_audit_3'`); got != 1 {
		t.Fatalf("重试后业务记录数 = %d", got)
	}
	if got := queryInt(t, raw, `SELECT COUNT(*) FROM audit_events WHERE action='applications.create' AND outcome='success'`); got != 1 {
		t.Fatalf("重试后成功审计事件数 = %d", got)
	}
}

// TestDuplicateCriticalDoesNotRunChange 验证幂等键已存在时不执行关键变更。
func TestDuplicateCriticalDoesNotRunChange(t *testing.T) {
	raw := openTestDatabase(t)
	store := newTestAuditStore(t, raw)
	recorder := newTestRecorder(t, store, &recordingAlerter{})
	event := testEvent("applications.create")
	event.Target = audit.Target{Type: "application", ID: "app_audit_4"}
	event.DedupeKey = "applications.create/app_audit_4"
	request := audit.CriticalRequest{Event: event}
	if err := recorder.ExecuteCritical(context.Background(), request, func(ctx context.Context, tx audit.Tx) error {
		return insertApplication(ctx, tx, "app_audit_4")
	}); err != nil {
		t.Fatalf("首次关键变更失败: %v", err)
	}
	changeCalled := false
	if err := recorder.ExecuteCritical(context.Background(), request, func(ctx context.Context, tx audit.Tx) error {
		changeCalled = true
		return insertApplication(ctx, tx, "app_audit_4_second")
	}); !errors.Is(err, audit.ErrDuplicateEvent) {
		t.Fatalf("重复关键变更错误 = %v，期望 ErrDuplicateEvent", err)
	}
	if changeCalled {
		t.Fatal("幂等重放仍执行了关键变更")
	}
	if got := queryInt(t, raw, `SELECT COUNT(*) FROM applications WHERE id='app_audit_4_second'`); got != 0 {
		t.Fatalf("幂等重放写入了业务记录: %d", got)
	}
	if got := queryInt(t, raw, `SELECT COUNT(*) FROM audit_events WHERE dedupe_key='applications.create/app_audit_4'`); got != 1 {
		t.Fatalf("幂等键事件数量 = %d", got)
	}
}

// TestRecordFailureSurvivesCanceledContext 验证调用方取消后失败审计仍落库。
func TestRecordFailureSurvivesCanceledContext(t *testing.T) {
	raw := openTestDatabase(t)
	store := newTestAuditStore(t, raw)
	recorder := newTestRecorder(t, store, &recordingAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	event := testEvent("auth.login")
	event.Outcome = audit.OutcomeFailure
	event.Actor = audit.Actor{Type: audit.ActorAnonymous, ID: ""}
	event.ErrorCode = "AUTH_FAILED"
	event.ReasonCode = "bad_credentials"
	if err := recorder.RecordFailure(ctx, event); err != nil {
		t.Fatalf("RecordFailure 失败: %v", err)
	}
	if got := queryInt(t, raw, `SELECT COUNT(*) FROM audit_events WHERE action='auth.login' AND outcome='failure' AND actor_type='anonymous'`); got != 1 {
		t.Fatalf("取消后的失败审计数 = %d", got)
	}
}

// TestClosedAuditStoreAlarms 验证审计存储关闭后写入失败、返回错误并告警。
func TestClosedAuditStoreAlarms(t *testing.T) {
	raw := openTestDatabase(t)
	store := newTestAuditStore(t, raw)
	alerter := &recordingAlerter{}
	recorder := newTestRecorder(t, store, alerter)
	if err := raw.Close(); err != nil {
		t.Fatalf("关闭数据库失败: %v", err)
	}
	if err := recorder.Record(context.Background(), testEvent("audit.closed")); !errors.Is(err, audit.ErrAuditUnavailable) {
		t.Fatalf("关闭后 Record 错误 = %v", err)
	}
	if len(alerter.snapshot()) == 0 {
		t.Fatal("关闭后审计失败未告警")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := recorder.RecordFailure(ctx, testEvent("audit.closed_failure")); !errors.Is(err, audit.ErrAuditUnavailable) {
		t.Fatalf("关闭后 RecordFailure 错误 = %v", err)
	}
}

// TestInvalidEventNotStored 验证超限/非法事件在写库前被拒绝。
func TestInvalidEventNotStored(t *testing.T) {
	raw := openTestDatabase(t)
	store := newTestAuditStore(t, raw)
	recorder := newTestRecorder(t, store, &recordingAlerter{})
	event := testEvent("audit.invalid")
	event.Changes = []audit.FieldChange{{Field: "note", Before: strings.Repeat("x", audit.MaxDiffValueBytes+1)}}
	if err := recorder.Record(context.Background(), event); !errors.Is(err, audit.ErrInvalidEvent) {
		t.Fatalf("超长差异错误 = %v", err)
	}
	if got := queryInt(t, raw, `SELECT COUNT(*) FROM audit_events WHERE action='audit.invalid'`); got != 0 {
		t.Fatalf("非法事件被写入 %d 条", got)
	}
}

// TestCancelledRecordDoesNotWrite 验证普通记录在取消时不写库。
func TestCancelledRecordDoesNotWrite(t *testing.T) {
	raw := openTestDatabase(t)
	store := newTestAuditStore(t, raw)
	recorder := newTestRecorder(t, store, &recordingAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := recorder.Record(ctx, testEvent("audit.cancelled")); !errors.Is(err, context.Canceled) {
		t.Fatalf("取消错误 = %v", err)
	}
	if got := queryInt(t, raw, `SELECT COUNT(*) FROM audit_events WHERE action='audit.cancelled'`); got != 0 {
		t.Fatalf("取消后仍写入 %d 条审计事件", got)
	}
}

// TestConcurrentAuditAppends 验证 6 路并发追加事件全部成功且不丢失。
func TestConcurrentAuditAppends(t *testing.T) {
	raw := openTestDatabase(t)
	store := newTestAuditStore(t, raw)
	recorder := newTestRecorder(t, store, &recordingAlerter{})
	const goroutines = 6
	var waitGroup sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, goroutines)
	for worker := 0; worker < goroutines; worker++ {
		waitGroup.Add(1)
		go func(worker int) {
			defer waitGroup.Done()
			<-start
			event := testEvent("audit.concurrent")
			event.Actor = audit.Actor{Type: audit.ActorSystem, ID: "worker-" + string(rune('0'+worker))}
			event.DedupeKey = "concurrent-" + string(rune('0'+worker))
			errs <- recorder.Record(context.Background(), event)
		}(worker)
	}
	close(start)
	waitGroup.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("并发审计写入失败: %v", err)
		}
	}
	if got := queryInt(t, raw, `SELECT COUNT(*) FROM audit_events WHERE action='audit.concurrent'`); got != goroutines {
		t.Fatalf("并发审计事件数 = %d，期望 %d", got, goroutines)
	}
}

// TestConcurrentCriticalDedupe 验证同一个幂等键的并发关键变更只有一个成功，
// 业务记录与审计事件都只产生一次。
func TestConcurrentCriticalDedupe(t *testing.T) {
	raw := openTestDatabase(t)
	store := newTestAuditStore(t, raw)
	recorder := newTestRecorder(t, store, &recordingAlerter{})
	event := testEvent("applications.create")
	event.Target = audit.Target{Type: "application", ID: "app_concurrent"}
	event.DedupeKey = "applications.create/app_concurrent"
	request := audit.CriticalRequest{Event: event}

	const goroutines = 6
	var waitGroup sync.WaitGroup
	start := make(chan struct{})
	results := make(chan error, goroutines)
	for worker := 0; worker < goroutines; worker++ {
		waitGroup.Add(1)
		go func(worker int) {
			defer waitGroup.Done()
			<-start
			appID := "app_concurrent_" + string(rune('0'+worker))
			results <- recorder.ExecuteCritical(context.Background(), request, func(ctx context.Context, tx audit.Tx) error {
				return insertApplication(ctx, tx, appID)
			})
		}(worker)
	}
	close(start)
	waitGroup.Wait()
	close(results)
	successes := 0
	duplicates := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, audit.ErrDuplicateEvent):
			duplicates++
		default:
			t.Fatalf("并发关键变更出现未预期错误: %v", err)
		}
	}
	if successes != 1 || duplicates != goroutines-1 {
		t.Fatalf("并发结果 = 成功 %d / 重复 %d", successes, duplicates)
	}
	if got := queryInt(t, raw, `SELECT COUNT(*) FROM applications WHERE id LIKE 'app_concurrent%'`); got != 1 {
		t.Fatalf("并发关键变更业务记录数 = %d，期望 1", got)
	}
	if got := queryInt(t, raw, `SELECT COUNT(*) FROM audit_events WHERE dedupe_key='applications.create/app_concurrent'`); got != 1 {
		t.Fatalf("并发幂等键审计事件数 = %d，期望 1", got)
	}
}
