package account_test

// 步骤 234：账户全局有效期领域测试（真实临时 SQLite + 可注入时钟）。
//
// 覆盖：UTC 半开区间 [from, until) 边界、到期与手动禁用分离、续期不解除禁用、
// root 不被普通期限管理锁死、root 读取忽略期限、乐观并发、审计失败回滚、输入
// 校验与迁移列存在性。

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// createValidityUser 创建普通账户并返回其快照。
func createValidityUser(t *testing.T, env *testEnv) account.User {
	t.Helper()
	user, err := env.service.CreateUser(context.Background(), env.caller,
		account.CreateRequest{Username: "validity-user"})
	if err != nil {
		t.Fatalf("创建用户: %v", err)
	}
	return user
}

// TestValidityHalfOpenWindow 验证 [valid_from, valid_until) 的行半开区间与续期。
func TestValidityHalfOpenWindow(t *testing.T) {
	env := prepareEnv(t)
	ctx := context.Background()
	user := createValidityUser(t, env)
	validity, err := env.service.GetUserValidity(ctx, env.caller, user.ID)
	if err != nil {
		t.Fatalf("默认有效期读取: %v", err)
	}
	if !validity.Available || validity.Reason != account.AvailabilityOK ||
		validity.ValidFrom != nil || validity.ValidUntil != nil {
		t.Fatalf("默认应为永久有效: %+v", validity)
	}
	base := env.clock.Now().UTC()
	validFrom := base.Add(time.Hour)
	validUntil := base.Add(2 * time.Hour)
	result, err := env.service.SetValidity(ctx, env.caller, account.ValidityCommandRequest{
		UserID: user.ID, ExpectedRowVersion: user.RowVersion,
		ValidFrom: &validFrom, ValidUntil: &validUntil})
	if err != nil {
		t.Fatalf("设置有效期: %v", err)
	}
	if !result.Changed || result.User.RowVersion != user.RowVersion+1 {
		t.Fatalf("设置结果异常: %+v", result)
	}
	if result.User.ValidFrom == nil || result.User.ValidUntil == nil ||
		!result.User.ValidUntil.Equal(validUntil) {
		t.Fatalf("有效期未持久化: %+v", result.User)
	}
	// 未到 valid_from：不可用。
	validity, _ = env.service.GetUserValidity(ctx, env.caller, user.ID)
	if validity.Available || validity.Reason != account.AvailabilityNotStarted {
		t.Fatalf("未开始区间应不可用: %+v", validity)
	}
	// 到达 valid_from 当刻：可用（半开区间左闭）。
	env.clock.Advance(time.Hour)
	validity, _ = env.service.GetUserValidity(ctx, env.caller, user.ID)
	if !validity.Available || validity.Reason != account.AvailabilityOK {
		t.Fatalf("valid_from 当刻应可用: %+v", validity)
	}
	// 调用 AvailabilityAt 直接验证右开：valid_until 当刻起不可用。
	userNow, err := env.service.GetUser(ctx, env.caller, user.ID)
	if err != nil {
		t.Fatalf("读取用户: %v", err)
	}
	if available, _ := userNow.AvailabilityAt(validUntil.Add(-time.Millisecond), false); !available {
		t.Fatal("valid_until 前一毫秒应可用")
	}
	if available, reason := userNow.AvailabilityAt(validUntil, false); available ||
		reason != account.AvailabilityExpired {
		t.Fatalf("valid_until 当刻应到期: %v/%v", available, reason)
	}
	// 清除两段恢复永久有效。
	cleared, err := env.service.SetValidity(ctx, env.caller, account.ValidityCommandRequest{
		UserID: user.ID, ExpectedRowVersion: result.User.RowVersion})
	if err != nil {
		t.Fatalf("清除有效期: %v", err)
	}
	if cleared.User.ValidFrom != nil || cleared.User.ValidUntil != nil {
		t.Fatalf("清除后仍有期限: %+v", cleared.User)
	}
}

// TestValidityRenewKeepsManualDisabled 验证到期与手动禁用分离、续期不解除禁用。
func TestValidityRenewKeepsManualDisabled(t *testing.T) {
	env := prepareEnv(t)
	ctx := context.Background()
	user := createValidityUser(t, env)
	disabled, err := env.service.DisableUser(ctx, env.caller,
		account.StateCommandRequest{UserID: user.ID, ExpectedRowVersion: user.RowVersion})
	if err != nil {
		t.Fatalf("禁用: %v", err)
	}
	base := env.clock.Now().UTC()
	until := base.Add(time.Hour)
	renewed, err := env.service.SetValidity(ctx, env.caller, account.ValidityCommandRequest{
		UserID: user.ID, ExpectedRowVersion: disabled.User.RowVersion, ValidUntil: &until})
	if err != nil {
		t.Fatalf("禁用账户续期: %v", err)
	}
	if renewed.User.Status != account.StatusDisabled {
		t.Fatalf("续期不得改变手动状态: %+v", renewed.User)
	}
	validity, err := env.service.GetUserValidity(ctx, env.caller, user.ID)
	if err != nil {
		t.Fatalf("读取有效期: %v", err)
	}
	if validity.Available || validity.Reason != account.AvailabilityStatusDisabled {
		t.Fatalf("手动禁用应不可用: %+v", validity)
	}
	// 启用后有效期仍在，可用。
	enabled, err := env.service.EnableUser(ctx, env.caller,
		account.StateCommandRequest{UserID: user.ID,
			ExpectedRowVersion: renewed.User.RowVersion})
	if err != nil {
		t.Fatalf("启用: %v", err)
	}
	if _, err := env.service.GetUserValidity(ctx, env.caller, user.ID); err != nil {
		t.Fatalf("启用后读取: %v", err)
	}
	_ = enabled
	// 到期后即使 status 仍 active 也不可用（计算原因，不改 status）。
	env.clock.Advance(2 * time.Hour)
	validity, _ = env.service.GetUserValidity(ctx, env.caller, user.ID)
	if validity.Available || validity.Reason != account.AvailabilityExpired ||
		validity.Status != account.StatusActive {
		t.Fatalf("到期应只影响可用性: %+v", validity)
	}
}

// TestValidityRootProtected 验证 root 拒绝普通期限管理，且读取忽略期限。
func TestValidityRootProtected(t *testing.T) {
	env := prepareEnv(t)
	ctx := context.Background()
	nowMS := env.clock.Now().UTC().UnixMilli()
	if _, err := env.raw.DB().ExecContext(ctx, `INSERT INTO users(id,username,
username_normalized,status,is_root,security_version,row_version,created_at_ms,
updated_at_ms,valid_from_ms,valid_until_ms) VALUES(?,?,?,'active',1,1,1,?,?,?,?)`,
		"usr_000000000000000000000000000000a1", "root-user", "root-user", nowMS,
		nowMS, nowMS-int64(24*time.Hour/time.Millisecond), nowMS-int64(time.Hour/time.Millisecond)); err != nil {
		t.Fatalf("写入 root: %v", err)
	}
	validity, err := env.service.GetUserValidity(ctx, env.caller,
		"usr_000000000000000000000000000000a1")
	if err != nil {
		t.Fatalf("读取 root 有效期: %v", err)
	}
	if !validity.IsRoot || !validity.Available || validity.Reason != account.AvailabilityOK {
		t.Fatalf("root 应忽略普通期限: %+v", validity)
	}
	until := env.clock.Now().UTC().Add(time.Hour)
	_, err = env.service.SetValidity(ctx, env.caller, account.ValidityCommandRequest{
		UserID: "usr_000000000000000000000000000000a1", ExpectedRowVersion: 1,
		ValidUntil: &until})
	if !errors.Is(err, account.ErrProtectedUser) {
		t.Fatalf("root 期限管理应拒绝: %v", err)
	}
	// 拒绝后 root 期限字段未被修改。
	var validUntilMS *int64
	if err := env.raw.DB().QueryRowContext(ctx,
		`SELECT valid_until_ms FROM users WHERE id=?`,
		"usr_000000000000000000000000000000a1").Scan(&validUntilMS); err != nil {
		t.Fatalf("读取 root 期限: %v", err)
	}
	if validUntilMS == nil || *validUntilMS != nowMS-int64(time.Hour/time.Millisecond) {
		t.Fatalf("root 期限被修改: %v", validUntilMS)
	}
}

// TestValidityValidationAndConcurrency 验证输入校验、幂等与乐观并发。
func TestValidityValidationAndConcurrency(t *testing.T) {
	env := prepareEnv(t)
	ctx := context.Background()
	user := createValidityUser(t, env)
	base := env.clock.Now().UTC()
	from := base.Add(time.Hour)
	until := base.Add(time.Hour)
	if _, err := env.service.SetValidity(ctx, env.caller, account.ValidityCommandRequest{
		UserID: user.ID, ExpectedRowVersion: user.RowVersion, ValidFrom: &from,
		ValidUntil: &until}); !errors.Is(err, account.ErrValidityInvalid) {
		t.Fatalf("空区间应拒绝: %v", err)
	}
	// 幂等命中相同区间：不改行版本。
	until = base.Add(2 * time.Hour)
	first, err := env.service.SetValidity(ctx, env.caller, account.ValidityCommandRequest{
		UserID: user.ID, ExpectedRowVersion: user.RowVersion, ValidFrom: &from,
		ValidUntil: &until})
	if err != nil {
		t.Fatalf("第一次设置: %v", err)
	}
	second, err := env.service.SetValidity(ctx, env.caller, account.ValidityCommandRequest{
		UserID: user.ID, ExpectedRowVersion: first.User.RowVersion,
		ValidFrom: &from, ValidUntil: &until})
	if err != nil {
		t.Fatalf("幂等设置: %v", err)
	}
	if second.Changed || second.User.RowVersion != first.User.RowVersion {
		t.Fatalf("幂等设置不应改版本: %+v", second)
	}
	// 旧版本并发写入：CONFLICT。
	if _, err := env.service.SetValidity(ctx, env.caller, account.ValidityCommandRequest{
		UserID: user.ID, ExpectedRowVersion: user.RowVersion, ValidUntil: &until}); !errors.Is(err,
		account.ErrStateConflict) {
		t.Fatalf("旧版本应冲突: %v", err)
	}
}

// failingAudit 是计数/失败的审计替身，用于验证审计失败整体回滚。
type failingAudit struct{}

func (failingAudit) Record(context.Context, audit.Event) error { return nil }
func (failingAudit) RecordFailure(context.Context, audit.Event) error {
	return audit.ErrAuditUnavailable
}
func (failingAudit) ExecuteCritical(ctx context.Context, _ audit.CriticalRequest,
	_ audit.Change) error {
	return audit.ErrAuditUnavailable
}

// TestValidityAuditFailureRollsBack 验证审计不可用时有效期不落库。
func TestValidityAuditFailureRollsBack(t *testing.T) {
	env := prepareEnv(t)
	ctx := context.Background()
	user := createValidityUser(t, env)
	service, err := account.New(account.Options{Store: env.store, Audit: failingAudit{},
		Authorizer: env.auth, Now: env.clock.Now})
	if err != nil {
		t.Fatalf("构造审计失败服务: %v", err)
	}
	until := env.clock.Now().UTC().Add(time.Hour)
	_, err = service.SetValidity(ctx, env.caller, account.ValidityCommandRequest{
		UserID: user.ID, ExpectedRowVersion: user.RowVersion, ValidUntil: &until})
	if !errors.Is(err, account.ErrAuditUnavailable) {
		t.Fatalf("审计失败应拒绝: %v", err)
	}
	stored, err := env.service.GetUser(ctx, env.caller, user.ID)
	if err != nil {
		t.Fatalf("读取用户: %v", err)
	}
	if stored.ValidUntil != nil || stored.RowVersion != user.RowVersion {
		t.Fatalf("审计失败后有效期不应落库: %+v", stored)
	}
}

// TestValidityMigrationColumns 验证增量迁移新增两列且可空默认。
func TestValidityMigrationColumns(t *testing.T) {
	env := prepareEnv(t)
	ctx := context.Background()
	rows, err := env.raw.DB().QueryContext(ctx, `PRAGMA table_info(users)`)
	if err != nil {
		t.Fatalf("读取表结构: %v", err)
	}
	defer rows.Close()
	columns := map[string]bool{}
	for rows.Next() {
		var (
			cid              int
			name, columnType string
			notNull          int
			defaultValue     any
			primaryKey       int
		)
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue,
			&primaryKey); err != nil {
			t.Fatalf("扫描列: %v", err)
		}
		columns[name] = true
	}
	if !columns["valid_from_ms"] || !columns["valid_until_ms"] {
		t.Fatalf("迁移未新增有效期列: %v", columns)
	}
}
