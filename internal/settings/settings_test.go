// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package settings_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/settings"
)

type testAuditor struct {
	fail bool
	last audit.Event
}

func (a *testAuditor) Record(_ context.Context, event audit.Event) error {
	a.last = event
	if a.fail {
		return errors.New("audit down")
	}
	return nil
}

func newCore(t *testing.T, yaml string, auditor *testAuditor) (*settings.Service, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "login.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := login.Load(login.LoadOptions{YAMLFile: path})
	if err != nil {
		t.Fatalf("加载测试配置: %v", err)
	}
	service, err := settings.New(settings.Options{ConfigPath: path,
		Effective: func() login.Config { return cfg }, Audit: auditor,
		Now: func() time.Time { return time.Unix(0, 0).UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	return service, path
}

func TestCoreFieldsMasksSecretsAndMarksRootOnly(t *testing.T) {
	service, _ := newCore(t, "logging:\n  level: info\n", &testAuditor{})
	view, err := service.Fields(context.Background(), false)
	if err != nil {
		t.Fatalf("Fields: %v", err)
	}
	if view.Version == "" || view.EffectiveVersion == "" {
		t.Fatalf("版本为空: %+v", view)
	}
	var secret, rootOnly settings.Field
	for _, field := range view.Fields {
		switch field.Field {
		case "mail.smtp.password":
			secret = field
		case "server.trusted_proxies":
			rootOnly = field
		}
	}
	if !secret.Secret || secret.Writable || strings.Contains(secret.Value, "env:") {
		t.Fatalf("秘密字段必须遮盖且不可写: %+v", secret)
	}
	if !rootOnly.RootOnly || rootOnly.Writable {
		t.Fatalf("普通权限下 root-only 字段不可写: %+v", rootOnly)
	}
	rootView, err := service.Fields(context.Background(), true)
	if err != nil {
		t.Fatalf("Fields root: %v", err)
	}
	for _, field := range rootView.Fields {
		if field.Field == "server.trusted_proxies" && !field.Writable {
			t.Fatal("受信权限下 root-only 字段应可写")
		}
	}
}

func TestCoreUpdateVersionConflictAtomicAndAuditRollback(t *testing.T) {
	auditor := &testAuditor{}
	service, path := newCore(t, "logging:\n  level: info\n", auditor)
	view, err := service.Fields(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	old := view.Version
	result, err := service.Update(context.Background(), settings.UpdateInput{
		ExpectedVersion: old, Changes: map[string]string{"logging.level": "debug"},
		Reason: "test", Actor: audit.Actor{Type: audit.ActorUser, ID: "u1"},
		RequestID: "req_core_update"})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if result.Version == old || !result.HostReloadNeeded || result.AppliedNow {
		t.Fatalf("结果异常: %+v", result)
	}
	if _, err := service.Update(context.Background(), settings.UpdateInput{
		ExpectedVersion: old, Changes: map[string]string{"logging.format": "json"},
		RequestID: "req_core_conflict"}); settings.CodeOf(err) != settings.CodeConflict {
		t.Fatalf("旧版本必须 CONFLICT，得到 %v", err)
	}
	// 秘密字段/非法值/root-only 越权均拒绝且不改文件。
	before, _ := os.ReadFile(path)
	if _, err := service.Update(context.Background(), settings.UpdateInput{
		ExpectedVersion: result.Version,
		Changes:         map[string]string{"mail.smtp.password": "__MASKED__"},
		RequestID:       "req_core_secret"}); err == nil {
		t.Fatal("秘密字段必须拒绝")
	}
	if _, err := service.Update(context.Background(), settings.UpdateInput{
		ExpectedVersion: result.Version,
		Changes:         map[string]string{"logging.level": "not-a-level"},
		RequestID:       "req_core_invalid"}); err == nil {
		t.Fatal("非法配置必须拒绝")
	}
	if _, err := service.Update(context.Background(), settings.UpdateInput{
		ExpectedVersion: result.Version,
		Changes:         map[string]string{"server.listen_addr": "127.0.0.1:18080"},
		RequestID:       "req_core_root_only"}); settings.CodeOf(err) != settings.CodeAccessDenied {
		t.Fatalf("root-only 字段应 ACCESS_DENIED，得到 %v", err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("失败更新不得修改文件")
	}
	// 审计失败回滚。
	auditor.fail = true
	current, _ := service.Fields(context.Background(), false)
	if _, err := service.Update(context.Background(), settings.UpdateInput{
		ExpectedVersion: current.Version,
		Changes:         map[string]string{"logging.format": "json"},
		RequestID:       "req_core_audit"}); settings.CodeOf(err) != settings.CodeAuditWriteFailed {
		t.Fatalf("审计失败应 AUDIT_WRITE_FAILED，得到 %v", err)
	}
	afterAudit, _ := os.ReadFile(path)
	if string(afterAudit) != string(after) {
		t.Fatal("审计失败后必须恢复旧配置")
	}
}

func TestCoreStatusReportsDiskVsEffective(t *testing.T) {
	service, _ := newCore(t, "logging:\n  level: info\n", &testAuditor{})
	status, err := service.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !status.Configured || status.Version == "" || status.EffectiveVersion == "" {
		t.Fatalf("状态异常: %+v", status)
	}
}

func TestCoreFieldPolicyFailClosed(t *testing.T) {
	rootOnly := []string{
		"registration.enabled", "registration.require_review",
		"registration.require_email_verification", "protocol.device_code_enabled",
		"app_qr_login.enabled", "app_qr_login.allowed_client_ids",
		"server.public_base_url", "server.path_prefix", "server.listen_addr",
		"mail.enabled", "mail.from.address", "mail.delivery.max_attempts",
		"mail.smtp.timeout_seconds", "passkey.enabled", "database.path",
		"secrets.master_key", "custom.unknown.future_field",
	}
	for _, field := range rootOnly {
		if !settings.RootOnly(field) {
			t.Fatalf("字段 %q 必须 root-only（fail-closed）", field)
		}
	}
	for _, field := range []string{"logging.level", "logging.format",
		"server.shutdown_timeout_seconds"} {
		if settings.RootOnly(field) {
			t.Fatalf("字段 %q 应保留普通 settings.manage 可写", field)
		}
	}
}
