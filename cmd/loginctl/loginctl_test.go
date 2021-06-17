package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/rootrecovery"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const cliRootID = "usr_00000000000000000000000000000001"

const cliNewPassword = "Quasar-Meadow-Velvet-Nimbus"

type cliPrompter struct {
	confirmRecovery bool
	confirmPasskey  bool
	passwords       []string
	readIndex       int
}

func (p *cliPrompter) ConfirmRecovery(scope rootrecovery.ScopeSummary) (bool, error) {
	return p.confirmRecovery, nil
}

func (p *cliPrompter) ReadNewPassword() ([]byte, error) {
	if p.readIndex >= len(p.passwords) {
		return nil, errors.New("没有更多测试密码")
	}
	password := p.passwords[p.readIndex]
	p.readIndex++
	return []byte(password), nil
}

func (p *cliPrompter) ConfirmPasskeyRevocation() (bool, error) {
	return p.confirmPasskey, nil
}

// seedProjectDatabase 创建临时 SQLite 实例并种入唯一 root（可登录状态）。
func seedProjectDatabase(t *testing.T) (string, *storagesqlite.Store) {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "login.db")
	storage, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(path))
	if err != nil {
		t.Fatalf("打开数据库: %v", err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	list, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移: %v", err)
	}
	if _, err := storage.Migrate(ctx, list); err != nil {
		t.Fatalf("执行迁移: %v", err)
	}
	now := time.Now().UTC().UnixMilli()
	if _, err := storage.DB().ExecContext(ctx, `INSERT INTO users(
id,username,username_normalized,nickname,biography,avatar_ref,language,timezone,status,
is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,'','','',NULL,'zh-CN','Asia/Shanghai','active',1,2,1,?,?)`,
		cliRootID, "root", now, now); err != nil {
		t.Fatalf("种子 root: %v", err)
	}
	if _, err := storage.DB().ExecContext(ctx, `INSERT INTO root_initializations(
singleton,root_user_id,state,setup_credential_id,started_by,created_at_ms,updated_at_ms,
verified_at_ms,ready_at_ms) VALUES(1,?,'ready',NULL,'local:seed',?,?,?,?)`,
		cliRootID, now, now, now, now); err != nil {
		t.Fatalf("种子初始化状态: %v", err)
	}
	hash, err := authn.HashPassword("Old-Root-Password-9", authn.DefaultParams(), nil)
	if err != nil {
		t.Fatalf("种子密码: %v", err)
	}
	if _, err := storage.DB().ExecContext(ctx, `INSERT INTO password_credentials(
user_id,hash_scheme,hash_version,password_hash,must_change,row_version,created_at_ms,
updated_at_ms,changed_at_ms) VALUES(?,'argon2id',19,?,0,1,?,?,?)`,
		cliRootID, hash, now, now, now); err != nil {
		t.Fatalf("种子密码凭证: %v", err)
	}
	return path, storage
}

// TestRunRootRecoverHappyPath 真实运行 CLI 驱动（注入交互）：MFA 重置成功、退出码 0，
// 输出不含密码，数据库安全版本递增并进入 setup_verified。
func TestRunRootRecoverHappyPath(t *testing.T) {
	path, storage := seedProjectDatabase(t)
	var stdout, stderr bytes.Buffer
	prompter := &cliPrompter{confirmRecovery: true}
	code := Run([]string{
		"root-recover", "--database", path, "--reason", "root 验证器丢失后的本地恢复",
		"--service-stopped", "--reset-mfa",
	}, strings.NewReader(""), &stdout, &stderr, func(_ io.Reader, _ io.Writer) rootrecovery.Prompter { return prompter })
	if code != ExitOK {
		t.Fatalf("退出码 = %d，stderr=%s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "password") || strings.Contains(stdout.String(), cliNewPassword) {
		t.Fatalf("输出泄露密码相关内容: %s", stdout.String())
	}
	var version int64
	if err := storage.DB().QueryRowContext(context.Background(),
		`SELECT security_version FROM users WHERE id=?`, cliRootID).Scan(&version); err != nil {
		t.Fatalf("读取安全版本: %v", err)
	}
	if version != 3 {
		t.Fatalf("security_version = %d，期望 3", version)
	}
	var state string
	if err := storage.DB().QueryRowContext(context.Background(),
		`SELECT state FROM root_initializations WHERE singleton=1`).Scan(&state); err != nil {
		t.Fatalf("读取 root 状态: %v", err)
	}
	if state != "setup_verified" {
		t.Fatalf("root 状态 = %q，期望 setup_verified", state)
	}
}

// TestRunRootRecoverPasswordAndOutputSafety 覆盖密码重置路径：隐藏输入来自交互器而非
// 参数，输出不包含新密码；数据库中新密码可用。
func TestRunRootRecoverPasswordAndOutputSafety(t *testing.T) {
	path, storage := seedProjectDatabase(t)
	var stdout, stderr bytes.Buffer
	prompter := &cliPrompter{confirmRecovery: true,
		passwords: []string{cliNewPassword, cliNewPassword}}
	code := Run([]string{
		"root-recover", "--database", path, "--reason", "root 密码遗忘",
		"--maintenance", "--reset-password",
	}, strings.NewReader(""), &stdout, &stderr, func(_ io.Reader, _ io.Writer) rootrecovery.Prompter { return prompter })
	if code != ExitOK {
		t.Fatalf("退出码 = %d，stderr=%s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), cliNewPassword) || strings.Contains(stderr.String(), cliNewPassword) {
		t.Fatal("CLI 输出泄露新密码")
	}
	var hash string
	if err := storage.DB().QueryRowContext(context.Background(),
		`SELECT password_hash FROM password_credentials WHERE user_id=?`, cliRootID).Scan(&hash); err != nil {
		t.Fatalf("读取密码哈希: %v", err)
	}
	result, err := authn.VerifyPassword(hash, cliNewPassword)
	if err != nil || !result.Matched {
		t.Fatalf("新密码未生效: %v", err)
	}
}

// TestRunCancelNoChanges 覆盖取消确认：退出码 3 且数据库无任何修改。
func TestRunCancelNoChanges(t *testing.T) {
	path, storage := seedProjectDatabase(t)
	var stdout, stderr bytes.Buffer
	prompter := &cliPrompter{confirmRecovery: false}
	code := Run([]string{
		"root-recover", "--database", path, "--reason", "取消测试",
		"--service-stopped", "--reset-mfa",
	}, strings.NewReader(""), &stdout, &stderr, func(_ io.Reader, _ io.Writer) rootrecovery.Prompter { return prompter })
	if code != ExitCancelled {
		t.Fatalf("退出码 = %d，期望 %d", code, ExitCancelled)
	}
	var version int64
	if err := storage.DB().QueryRowContext(context.Background(),
		`SELECT security_version FROM users WHERE id=?`, cliRootID).Scan(&version); err != nil {
		t.Fatalf("读取安全版本: %v", err)
	}
	if version != 2 {
		t.Fatalf("取消后 security_version 被修改: %d", version)
	}
}

// TestRunRejectsNonTerminalDefaultPrompter 验证默认交互器拒绝非 TTY：管道/重定向输入
// 不能自动确认固定确认词跑完恢复；拒绝发生在任何数据库写入之前。
func TestRunRejectsNonTerminalDefaultPrompter(t *testing.T) {
	path, storage := seedProjectDatabase(t)
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"root-recover", "--database", path, "--reason", "非TTY拒绝测试",
		"--service-stopped", "--reset-mfa",
	}, strings.NewReader("RECOVER\n"), &stdout, &stderr, nil)
	if code != ExitUsage {
		t.Fatalf("非 TTY 默认交互器退出码 = %d，期望 %d", code, ExitUsage)
	}
	if !strings.Contains(stderr.String(), "终端") {
		t.Fatalf("非 TTY 错误应说明需要终端: %s", stderr.String())
	}
	var version int64
	if err := storage.DB().QueryRowContext(context.Background(),
		`SELECT security_version FROM users WHERE id=?`, cliRootID).Scan(&version); err != nil {
		t.Fatalf("读取安全版本: %v", err)
	}
	if version != 2 {
		t.Fatalf("非 TTY 拒绝后不应修改数据库: %d", version)
	}
	var events int64
	if err := storage.DB().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM root_recovery_events`).Scan(&events); err != nil {
		t.Fatalf("读取恢复记录: %v", err)
	}
	if events != 0 {
		t.Fatalf("非 TTY 拒绝后不应写恢复记录: %d", events)
	}
}

// TestRunUsageAndInvalidDatabase 覆盖参数错误与错误数据库：稳定退出码，错误库不被修改。
func TestRunUsageAndInvalidDatabase(t *testing.T) {
	var stdout, stderr bytes.Buffer
	factory := func(_ io.Reader, _ io.Writer) rootrecovery.Prompter {
		return &cliPrompter{confirmRecovery: true}
	}
	cases := [][]string{
		{},
		{"root-recover"},
		{"root-recover", "--database", "x.db", "--reason", "r", "--reset-mfa"},
		{"root-recover", "--database", "x.db", "--reason", "r", "--service-stopped"},
		{"unknown-command"},
	}
	for _, args := range cases {
		stdout.Reset()
		stderr.Reset()
		if code := Run(args, strings.NewReader(""), &stdout, &stderr, factory); code != ExitUsage {
			t.Fatalf("参数 %v 退出码 = %d，期望 %d", args, code, ExitUsage)
		}
	}
	// 错误数据库：执行失败但不创建/修改任何文件。
	dir := t.TempDir()
	foreign := filepath.Join(dir, "foreign.db")
	if err := os.WriteFile(foreign, []byte("not sqlite"), 0o600); err != nil {
		t.Fatalf("写入错误库: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	code := Run([]string{"root-recover", "--database", foreign, "--reason", "错误库",
		"--service-stopped", "--reset-mfa"}, strings.NewReader(""), &stdout, &stderr, factory)
	if code != ExitError {
		t.Fatalf("错误数据库退出码 = %d，期望 %d", code, ExitError)
	}
	if info, err := os.Stat(foreign); err != nil || info.Size() != int64(len("not sqlite")) {
		t.Fatalf("CLI 不应修改错误数据库: %v %v", info, err)
	}
}

// TestRunRootRecoverPasskeyConfirmation 覆盖显式撤销 Passkey 的二次确认：拒绝时零修改。
func TestRunRootRecoverPasskeyConfirmation(t *testing.T) {
	path, storage := seedProjectDatabase(t)
	var stdout, stderr bytes.Buffer
	prompter := &cliPrompter{confirmRecovery: true, confirmPasskey: false}
	code := Run([]string{"root-recover", "--database", path, "--reason", "撤销凭证",
		"--service-stopped", "--reset-mfa", "--revoke-login-passkeys"},
		strings.NewReader(""), &stdout, &stderr, func(_ io.Reader, _ io.Writer) rootrecovery.Prompter { return prompter })
	if code != ExitCancelled {
		t.Fatalf("Passkey 二次确认取消退出码 = %d，期望 %d", code, ExitCancelled)
	}
	var version int64
	if err := storage.DB().QueryRowContext(context.Background(),
		`SELECT security_version FROM users WHERE id=?`, cliRootID).Scan(&version); err != nil {
		t.Fatalf("读取安全版本: %v", err)
	}
	if version != 2 {
		t.Fatalf("取消 Passkey 撤销后 security_version 被修改: %d", version)
	}
}
