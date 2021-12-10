package managecli

// 本文件是 managecli 测试共用的隔离环境构造：临时 SQLite（真实迁移）、临时配置
// 文件、受保护的密钥环/会话文件与 CLI 调用包装。所有测试只用 t.TempDir()，
// 不接触 database/login.db、不启动监听端口、不联网。

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	sessionsqlite "github.com/kagurazakayashi/EvernightLogin/internal/session/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
	"go.yaml.in/yaml/v3"
)

// testNow 是测试使用的固定时钟。
var testNow = time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)

// testUserID 生成格式合法的稳定用户 ID。
func testUserID(index int) string {
	return fmt.Sprintf("usr_%032x", index)
}

// newTestDatabase 在临时目录创建真实 SQLite 数据库并执行全部内嵌迁移。
func newTestDatabase(t *testing.T) (string, *storagesqlite.Store) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "login.db")
	store, err := storagesqlite.Open(context.Background(),
		storagesqlite.DefaultOptions(path))
	if err != nil {
		t.Fatalf("打开临时数据库: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	list, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移: %v", err)
	}
	if _, err := store.Migrate(context.Background(), list); err != nil {
		t.Fatalf("执行迁移: %v", err)
	}
	return path, store
}

// writeConfigFile 写入最小有效 YAML 配置（SQLite 路径 + 日志级别）。
func writeConfigFile(t *testing.T, directory, databasePath string) string {
	t.Helper()
	data, err := yaml.Marshal(map[string]any{
		"logging":  map[string]any{"level": "info"},
		"database": map[string]any{"driver": "sqlite", "path": databasePath},
	})
	if err != nil {
		t.Fatalf("编码配置: %v", err)
	}
	path := filepath.Join(directory, "login.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("写入配置: %v", err)
	}
	return path
}

// runCLI 以隔离的输入/输出调用命令；测试环境变量为空。
func runCLI(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	exit := RunWithOptions(args, strings.NewReader(""), &stdout, &stderr,
		Options{Now: func() time.Time { return testNow },
			LookupEnv: func(string) (string, bool) { return "", false }})
	return stdout.String(), stderr.String(), exit
}

// decodeEnvelope 解析 --json 输出外壳。
func decodeEnvelope(t *testing.T, output string) map[string]any {
	t.Helper()
	var envelope map[string]any
	if err := json.Unmarshal([]byte(output), &envelope); err != nil {
		t.Fatalf("JSON 输出无法解析: %v\n输出：%s", err, output)
	}
	return envelope
}

// envelopeErrorCode 读取失败外壳的 error.code。
func envelopeErrorCode(t *testing.T, envelope map[string]any) string {
	t.Helper()
	failure, ok := envelope["error"].(map[string]any)
	if !ok {
		t.Fatalf("缺少 error 字段: %v", envelope)
	}
	code, _ := failure["code"].(string)
	return code
}

// seedUser 直接写入一个 active 用户行（测试夹具；业务操作仍经真实服务）。
func seedUser(t *testing.T, store *storagesqlite.Store, id, username string,
	isRoot bool) {
	t.Helper()
	nowMS := testNow.UnixMilli()
	rootValue := 0
	if isRoot {
		rootValue = 1
	}
	_, err := store.DB().ExecContext(context.Background(), `INSERT INTO users(
id,username,username_normalized,nickname,biography,language,timezone,status,is_root,
security_version,row_version,created_at_ms,updated_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		id, username, username, username, "", "", "", "active", rootValue, 1, 1, nowMS, nowMS)
	if err != nil {
		t.Fatalf("写入用户夹具: %v", err)
	}
}

// newProtectedKeyringFile 生成主密钥环文件并用 secrets.ProtectFile 收紧权限。
// 返回内存密钥环与文件路径；测试结束后由 t.Cleanup 删除。
func newProtectedKeyringFile(t *testing.T) (*secrets.Keyring, string) {
	t.Helper()
	ring, err := secrets.GenerateKeyring("k1", testNow)
	if err != nil {
		t.Fatalf("生成密钥环: %v", err)
	}
	document, err := ring.Document()
	if err != nil {
		t.Fatalf("编码密钥环: %v", err)
	}
	path := filepath.Join(t.TempDir(), "keyring.json")
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatalf("写入密钥环文件: %v", err)
	}
	if err := secrets.ProtectFile(path); err != nil {
		t.Fatalf("收紧密钥环文件权限: %v", err)
	}
	return ring, path
}

// issueTestSessionForCLI 用真实会话服务为已存在用户签发普通会话，写出的秘密文件
// 已调用 secrets.ProtectFile 收紧权限，供 CLI 从受保护文件读取。
func issueTestSessionForCLI(t *testing.T, store *storagesqlite.Store,
	ring *secrets.Keyring, userID string) string {
	t.Helper()
	auditStore, err := auditsqlite.New(store)
	if err != nil {
		t.Fatalf("构造审计存储: %v", err)
	}
	recorder, err := audit.New(auditStore, audit.Options{
		Now: func() time.Time { return testNow }})
	if err != nil {
		t.Fatalf("构造审计写入器: %v", err)
	}
	sessionStore, err := sessionsqlite.New(store)
	if err != nil {
		t.Fatalf("构造会话存储: %v", err)
	}
	service, err := session.New(sessionStore, session.Options{Store: sessionStore,
		Audit: recorder, Keyring: ring, Now: func() time.Time { return testNow }})
	if err != nil {
		t.Fatalf("构造会话服务: %v", err)
	}
	issued, err := service.Login(context.Background(), session.LoginRequest{
		Result: loginResult(userID, 1), RequestID: "req_test"})
	if err != nil {
		t.Fatalf("签发测试会话: %v", err)
	}
	path := filepath.Join(t.TempDir(), "session.secret")
	if err := os.WriteFile(path, []byte(issued.Secret.Reveal()), 0o600); err != nil {
		t.Fatalf("写入会话秘密文件: %v", err)
	}
	if err := secrets.ProtectFile(path); err != nil {
		t.Fatalf("收紧会话文件权限: %v", err)
	}
	return path
}

// loginResult 构造测试用完整密码认证结果（真实服务仍会复核账户状态/安全版本）。
func loginResult(userID string, securityVersion int64) authn.AuthenticateResult {
	return authn.AuthenticateResult{UserID: userID, Username: "user",
		Outcome:          authn.OutcomeComplete,
		CompletedMethods: []authn.Method{authn.MethodPassword},
		CompletedAt:      testNow,
		SecurityVersion:  securityVersion}
}
