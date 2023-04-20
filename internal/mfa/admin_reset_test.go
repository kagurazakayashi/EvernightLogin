// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightMail is licensed under Mulan PSL v2.

package mfa_test

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	"github.com/kagurazakayashi/EvernightLogin/internal/mfa"
	mfasqlite "github.com/kagurazakayashi/EvernightLogin/internal/mfa/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

type adminResetBackendStub struct {
	checkErr error
	totp     int
	passkeys int
	groups   int
	version  int64
}

func (s *adminResetBackendStub) CheckAdminResetTarget(context.Context, string) error {
	return s.checkErr
}
func (s *adminResetBackendStub) ResetTOTP(context.Context, audit.Tx, string, time.Time) (int, error) {
	return s.totp, nil
}
func (s *adminResetBackendStub) RevokePasskeys(context.Context, audit.Tx, string, string, time.Time) (int, error) {
	return s.passkeys, nil
}
func (s *adminResetBackendStub) RevokeRecoveryGroups(context.Context, audit.Tx, string, time.Time) (int, error) {
	return s.groups, nil
}
func (s *adminResetBackendStub) IncrementSecurityVersion(context.Context, audit.Tx, string, time.Time) (int64, error) {
	return s.version, nil
}

type noopTOTP struct{}

func (noopTOTP) HasActive(context.Context, string) (bool, error) { return false, nil }
func (noopTOTP) VerifyLoginCode(context.Context, string, string) error {
	return nil
}

type noopSession struct{}

func (noopSession) Login(context.Context, session.LoginRequest) (session.IssuedSession, error) {
	return session.IssuedSession{}, nil
}
func (noopSession) Validate(context.Context, string) (session.Session, error) {
	return session.Session{}, nil
}

type noopMailer struct{}

func (noopMailer) Send(context.Context, mailer.Message) error { return nil }

// TestAdminResetFactorsBoundary 验证最小受控 MFA 重置 API 的调用者、目标保护、
// 未装配后端 fail-closed 与结果摘要；使用真实 SQLite/审计和真实 mfa 服务构造，
// 后端使用受控桩验证 API 契约（真实 serverapp 后端/执行器链路另行集成测试）。
func TestAdminResetFactorsBoundary(t *testing.T) {
	ctx := context.Background()
	raw, err := storagesqlite.Open(ctx,
		storagesqlite.DefaultOptions(filepath.Join(testutil.TempDir(t), "mfa-admin-reset.sqlite")))
	if err != nil {
		t.Fatalf("打开临时库: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	migrationSet, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移: %v", err)
	}
	if _, err := raw.Migrate(ctx, migrationSet); err != nil {
		t.Fatalf("执行迁移: %v", err)
	}
	store, err := mfasqlite.New(raw)
	if err != nil {
		t.Fatalf("MFA 存储: %v", err)
	}
	auditStore, err := auditsqlite.New(raw)
	if err != nil {
		t.Fatalf("审计存储: %v", err)
	}
	recorder, err := audit.New(auditStore, audit.Options{Now: time.Now})
	if err != nil {
		t.Fatalf("审计记录器: %v", err)
	}
	const target = "usr_11111111111111111111111111111111"
	backend := &adminResetBackendStub{totp: 1, passkeys: 2, groups: 1, version: 2}
	guardCalls := 0
	baseOptions := mfa.Options{Store: store, Audit: recorder,
		Credentials: &credential.Service{}, Sessions: noopSession{}, TOTP: noopTOTP{},
		Mailer: noopMailer{}, FromAddress: "noreply@example.test",
		AdminResetBackend: backend,
		AdminResetTargetGuard: func(context.Context, string) error {
			guardCalls++
			return nil
		},
		Now: time.Now, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	service, err := mfa.New(baseOptions)
	if err != nil {
		t.Fatalf("MFA 服务: %v", err)
	}
	caller, err := mfa.SystemCaller("manual-recovery-executor")
	if err != nil {
		t.Fatalf("系统调用者: %v", err)
	}
	result, err := service.AdminResetFactors(ctx, caller, mfa.AdminResetRequest{
		TargetUserID: target, Reason: "人工核验恢复", RequestID: "req-mfa-admin-reset-1"})
	if err != nil {
		t.Fatalf("受控 MFA 重置失败: %v", err)
	}
	if guardCalls != 1 || result.TOTPFactorsRemoved != 1 || result.PasskeyCredentialsGone != 2 ||
		result.RecoveryGroupsRevoked != 1 || result.SecurityVersion != 2 {
		t.Fatalf("重置结果/目标保护不符: guard=%d %+v", guardCalls, result)
	}
	userCaller, _ := mfa.UserCaller(target)
	if _, err := service.AdminResetFactors(ctx, userCaller, mfa.AdminResetRequest{
		TargetUserID: target, Reason: "非法", RequestID: "req-mfa-admin-reset-2"}); err == nil {
		t.Fatal("普通用户不得调用管理员 MFA 重置")
	}
	blockedBackend := &adminResetBackendStub{checkErr: mfa.ErrAccessDenied}
	blockedOptions := baseOptions
	blockedOptions.AdminResetBackend = blockedBackend
	blockedOptions.AdminResetTargetGuard = blockedBackend.CheckAdminResetTarget
	blockedService, err := mfa.New(blockedOptions)
	if err != nil {
		t.Fatalf("受保护目标服务: %v", err)
	}
	if _, err := blockedService.AdminResetFactors(ctx, caller, mfa.AdminResetRequest{
		TargetUserID: target, Reason: "受保护", RequestID: "req-mfa-admin-reset-3"}); err == nil {
		t.Fatal("受保护目标必须拒绝")
	}
	emptyOptions := baseOptions
	emptyOptions.AdminResetBackend = nil
	emptyService, err := mfa.New(emptyOptions)
	if err != nil {
		t.Fatalf("未装配后端服务: %v", err)
	}
	if _, err := emptyService.AdminResetFactors(ctx, caller, mfa.AdminResetRequest{
		TargetUserID: target, Reason: "未装配", RequestID: "req-mfa-admin-reset-4"}); err == nil {
		t.Fatal("未装配后端必须 fail-closed")
	}
}
