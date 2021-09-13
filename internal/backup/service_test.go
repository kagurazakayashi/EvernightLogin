package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/avatar"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	appmigrations "github.com/kagurazakayashi/EvernightLogin/migrations"
)

// 测试基础时间：固定时钟使清单时间可断言；随机源仍使用 crypto/rand 以保证
// 备份编号/载荷密钥真实随机。
var backupTestTime = time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)

// testCaller 构造合法格式的普通用户调用者；授权由测试授权器控制。
func testCaller(t *testing.T) account.Caller {
	t.Helper()
	caller, err := account.UserCaller("usr_" + strings.Repeat("ab", 16))
	if err != nil {
		t.Fatalf("构造测试调用者失败：%v", err)
	}
	return caller
}

// fakeAuthorizer 是可控制授予结果的授权替身；只用于验证服务端授权调用语义，
// 不进入生产装配。
type fakeAuthorizer struct {
	mu     sync.Mutex
	grants map[string]stats.ScopeGrant
	err    error
}

// AuthorizeScope 实现 stats.Authorizer。
func (f *fakeAuthorizer) AuthorizeScope(_ context.Context, _ account.Caller,
	permissionKey, scopeID string) (stats.ScopeGrant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return stats.ScopeGrant{}, f.err
	}
	return f.grants[permissionKey+"|"+scopeID], nil
}

// allow 授予某权限的系统范围访问。
func (f *fakeAuthorizer) allow(permissionKey string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.grants == nil {
		f.grants = make(map[string]stats.ScopeGrant)
	}
	f.grants[permissionKey+"|"+ScopeSystem] = stats.ScopeGrant{Allowed: true, AllData: true}
}

// fakeRecorder 是可控制失败时机的审计替身，用于验证 fail-closed 路径。
type fakeRecorder struct {
	mu         sync.Mutex
	events     []audit.Event
	failAction string
	recordErr  error
	failureErr error
}

// Record 实现 AuditRecorder。
func (f *fakeRecorder) Record(_ context.Context, event audit.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, event)
	if f.failAction != "" && event.Action == f.failAction {
		return errors.New("测试注入的审计失败")
	}
	return f.recordErr
}

// RecordFailure 实现 AuditRecorder。
func (f *fakeRecorder) RecordFailure(_ context.Context, event audit.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, event)
	if f.failureErr != nil {
		return f.failureErr
	}
	return nil
}

// actions 返回已记录动作序列。
func (f *fakeRecorder) actions() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	result := make([]string, 0, len(f.events))
	for _, event := range f.events {
		result = append(result, event.Action)
	}
	return result
}

// countAction 返回指定动作的事件数量。
func (f *fakeRecorder) countAction(action string) int {
	count := 0
	for _, recorded := range f.actions() {
		if recorded == action {
			count++
		}
	}
	return count
}

// testEnv 是使用真实临时 SQLite、真实审计与真实在线备份适配器的测试环境。
type testEnv struct {
	store      *storagesqlite.Store
	dbPath     string
	outputDir  string
	ring       *secrets.Keyring
	authorizer *fakeAuthorizer
	recorder   *audit.Recorder
	service    *Service
	avatars    *avatar.LocalStorage
	now        func() time.Time
}

// newTestEnv 构造测试环境：临时数据库执行全部迁移，审计写入真实 audit_events。
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "login.db")
	store, err := storagesqlite.Open(context.Background(),
		storagesqlite.DefaultOptions(dbPath))
	if err != nil {
		t.Fatalf("打开临时数据库失败：%v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	migrations, err := migrate.LoadMigrations(appmigrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移失败：%v", err)
	}
	if _, err := store.Migrate(context.Background(), migrations); err != nil {
		t.Fatalf("执行迁移失败：%v", err)
	}
	auditStore, err := auditsqlite.New(store)
	if err != nil {
		t.Fatalf("构造审计存储失败：%v", err)
	}
	recorder, err := audit.New(auditStore, audit.Options{
		Now: func() time.Time { return backupTestTime },
	})
	if err != nil {
		t.Fatalf("构造审计写入器失败：%v", err)
	}
	ring, err := secrets.GenerateKeyring("k1", backupTestTime)
	if err != nil {
		t.Fatalf("生成测试密钥环失败：%v", err)
	}
	authorizer := &fakeAuthorizer{}
	authorizer.allow(PermissionCreate)
	authorizer.allow(PermissionCancel)
	avatarDir := filepath.Join(t.TempDir(), "avatars")
	avatarStorage, err := avatar.NewLocalStorage(avatarDir)
	if err != nil {
		t.Fatalf("构造头像存储失败：%v", err)
	}
	env := &testEnv{
		store: store, dbPath: dbPath, outputDir: t.TempDir(), ring: ring,
		authorizer: authorizer, recorder: recorder, avatars: avatarStorage,
		now: func() time.Time { return backupTestTime },
	}
	env.service = env.newService(t, nil)
	return env
}

// newService 用测试环境依赖构造服务，可注入额外选项。
func (e *testEnv) newService(t *testing.T, configure func(*Options)) *Service {
	t.Helper()
	snapshotter, err := NewSQLiteSnapshotter(e.store)
	if err != nil {
		t.Fatalf("构造 SQLite 快照器失败：%v", err)
	}
	options := Options{
		Snapshotter: snapshotter,
		Keyring: secrets.ProviderFunc(func(ctx context.Context) ([]byte, error) {
			return e.ring.Document()
		}),
		Authorizer: e.authorizer,
		Audit:      e.recorder,
		OutputDir:  e.outputDir,
		Hostname:   "test-host",
		AppVersion: "test-version",
		Now:        e.now,
	}
	if configure != nil {
		configure(&options)
	}
	service, err := New(options)
	if err != nil {
		t.Fatalf("构造备份服务失败：%v", err)
	}
	return service
}

// insertUser 插入一个最小合法用户行（供头像外键使用）。
func (e *testEnv) insertUser(t *testing.T, userID string) {
	t.Helper()
	_, err := e.store.ExecContext(context.Background(), `INSERT INTO users(
id, username, username_normalized, created_at_ms, updated_at_ms)
VALUES(?,?,?,?,?)`, userID, "user-"+userID[len(userID)-4:],
		"user-"+userID[len(userID)-4:], backupTestTime.UnixMilli(), backupTestTime.UnixMilli())
	if err != nil {
		t.Fatalf("插入测试用户失败：%v", err)
	}
}

// insertAvatar 在受控头像存储写入真实文件并插入 avatars 行；返回存储键与内容。
func (e *testEnv) insertAvatar(t *testing.T, userID string, content []byte) string {
	t.Helper()
	key, err := e.avatars.Save(context.Background(), content, "png")
	if err != nil {
		t.Fatalf("写入测试头像失败：%v", err)
	}
	digest := sha256.Sum256(content)
	_, err = e.store.ExecContext(context.Background(), `INSERT INTO avatars(
id, user_id, storage_key, media_type, byte_size, width, height, content_sha256,
source_kind, created_at_ms, updated_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		"avt_"+strings.Repeat("cd", 16), userID, key, "image/png", len(content),
		16, 16, digest[:], "upload", backupTestTime.UnixMilli(), backupTestTime.UnixMilli())
	if err != nil {
		t.Fatalf("插入测试头像记录失败：%v", err)
	}
	return key
}

// writeConfig 写入测试 YAML 配置并返回配置源。
func (e *testEnv) writeConfig(t *testing.T) ConfigSource {
	t.Helper()
	path := filepath.Join(t.TempDir(), "login.yaml")
	data := []byte("server:\n  listen_addr: 127.0.0.1:8080\nlogging:\n  level: info\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("写入测试配置失败：%v", err)
	}
	source, err := NewFileConfigSource(path, 0)
	if err != nil {
		t.Fatalf("构造配置快照源失败：%v", err)
	}
	return source
}

// listOutputFiles 返回输出目录中的非目录条目名。
func (e *testEnv) listOutputFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(e.outputDir)
	if err != nil {
		t.Fatalf("读取输出目录失败：%v", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

// assertCleanOutput 断言输出目录只留下了指定的最终备份文件（没有临时文件/暂存
// 目录/明文快照残留）。
func (e *testEnv) assertCleanOutput(t *testing.T, expected ...string) {
	t.Helper()
	files := e.listOutputFiles(t)
	if len(files) != len(expected) {
		t.Fatalf("输出目录条目 = %v，期望仅 %v", files, expected)
	}
	for index, name := range expected {
		if files[index] != name {
			t.Fatalf("输出目录条目 = %v，期望 %v", files, expected)
		}
	}
}

// auditActionsInDB 从真实审计表读取动作序列（按发生时间）。
func (e *testEnv) auditActionsInDB(t *testing.T) []string {
	t.Helper()
	rows, err := e.store.QueryContext(context.Background(),
		`SELECT action FROM audit_events ORDER BY occurred_at_ms, id`)
	if err != nil {
		t.Fatalf("查询审计事件失败：%v", err)
	}
	defer rows.Close()
	var actions []string
	for rows.Next() {
		var action string
		if err := rows.Scan(&action); err != nil {
			t.Fatalf("读取审计动作失败：%v", err)
		}
		actions = append(actions, action)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("遍历审计事件失败：%v", err)
	}
	return actions
}

// containsAction 报告动作序列是否包含指定动作。
func containsAction(actions []string, target string) bool {
	for _, action := range actions {
		if action == target {
			return true
		}
	}
	return false
}

// verifyWithEnv 用测试密钥环认证校验备份。
func (e *testEnv) verifyWithEnv(t *testing.T, path string) VerifyReport {
	t.Helper()
	report, err := VerifyFile(context.Background(), path, e.ring)
	if err != nil {
		t.Fatalf("校验备份失败：%v", err)
	}
	return report
}

// extractEntry 使用内部格式函数从备份中取出指定条目原文（仅测试使用，模拟步骤
// 82 的离线恢复/解析能力证明数据库快照内容真实可读）。
func extractEntry(t *testing.T, path string, ring *secrets.Keyring, name string) []byte {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("打开备份失败：%v", err)
	}
	defer file.Close()
	header, headerRaw, _, err := readHeaderFrom(file)
	if err != nil {
		t.Fatalf("读取备份头部失败：%v", err)
	}
	wrapped, err := base64.StdEncoding.DecodeString(header.Encryption.WrappedDataKey)
	if err != nil {
		t.Fatalf("解码载荷密钥失败：%v", err)
	}
	dataKey, err := unwrapDataKey(ring, header.BackupID, header.Encryption.KeyID, wrapped)
	if err != nil {
		t.Fatalf("解封载荷密钥失败：%v", err)
	}
	digest := headerHash(headerRaw)
	var plaintext []byte
	limited := &io.LimitedReader{R: file, N: header.Encryption.PayloadCipherBytes}
	if _, err := decryptPayload(limited, header.Encryption, dataKey, digest,
		func(chunk []byte) error {
			plaintext = append(plaintext, chunk...)
			return nil
		}); err != nil {
		t.Fatalf("解密备份载荷失败：%v", err)
	}
	if len(plaintext) < 4 {
		t.Fatal("备份载荷过短")
	}
	manifestLength := int(binary.BigEndian.Uint32(plaintext[:4]))
	manifestStart := 4
	manifestEnd := manifestStart + manifestLength
	if manifestEnd > len(plaintext) {
		t.Fatal("备份清单长度越界")
	}
	manifest, err := decodeManifest(plaintext[manifestStart:manifestEnd])
	if err != nil {
		t.Fatalf("解析备份清单失败：%v", err)
	}
	offset := manifestEnd
	for _, entry := range manifest.Entries {
		end := offset + int(entry.SizeBytes)
		if end > len(plaintext) {
			t.Fatalf("条目 %s 越界", entry.Name)
		}
		if entry.Name == name {
			return append([]byte(nil), plaintext[offset:end]...)
		}
		offset = end
	}
	t.Fatalf("备份中不存在条目 %s", name)
	return nil
}

// readOnlySnapshot 打开 SQLite 快照并执行检查。
func readOnlySnapshot(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path+"?_query_only=1&_busy_timeout=5000")
	if err != nil {
		t.Fatalf("打开数据库快照失败：%v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestCreateBackupWithAttachmentsAndConfig 覆盖手动备份主路径：真实 SQLite 在线
// 快照 + 头像附件 + YAML 配置，认证加密、清单、独立校验、真实审计与无残留发布。
func TestCreateBackupWithAttachmentsAndConfig(t *testing.T) {
	env := newTestEnv(t)
	env.service = env.newService(t, func(options *Options) {
		options.Attachments = mustAvatarSource(t, env.avatars)
		options.Config = env.writeConfig(t)
	})
	userID := "usr_" + strings.Repeat("11", 16)
	env.insertUser(t, userID)
	avatarContent := []byte("fake-png-avatar-content-for-backup-test")
	env.insertAvatar(t, userID, avatarContent)

	result, err := env.service.Create(context.Background(), CreateRequest{
		Caller: testCaller(t), RequestID: "req_backup_success_001"})
	if err != nil {
		t.Fatalf("创建备份失败：%v", err)
	}
	if result.BackupID == "" || result.Path == "" || result.FileName == "" {
		t.Fatalf("备份结果缺少编号/路径/文件名：%+v", result)
	}
	if !strings.HasSuffix(result.FileName, ".elnbak") {
		t.Fatalf("备份文件名后缀错误：%s", result.FileName)
	}
	if result.SizeBytes <= 0 || result.SHA256 == "" || result.PayloadBytes <= 0 {
		t.Fatalf("备份大小/摘要/载荷长度不合法：%+v", result)
	}
	if result.Content.Attachments.Status != ContentIncluded ||
		result.Content.Attachments.Count != 1 {
		t.Fatalf("附件内容范围未真实记录：%+v", result.Content.Attachments)
	}
	if result.Content.Config.Status != ContentIncluded {
		t.Fatalf("配置内容范围未真实记录：%+v", result.Content.Config)
	}
	if len(result.Entries) != 3 {
		t.Fatalf("清单条目数 = %d，期望 3（数据库/附件/配置）", len(result.Entries))
	}
	// 文件真实存在且权限收紧。
	info, err := os.Stat(result.Path)
	if err != nil {
		t.Fatalf("备份文件不存在：%v", err)
	}
	if info.Size() != result.SizeBytes {
		t.Fatalf("备份文件大小 = %d，结果记录 %d", info.Size(), result.SizeBytes)
	}
	// 独立校验：正确密钥通过，内容与清单一致。
	report := env.verifyWithEnv(t, result.Path)
	if !report.Authenticated || !report.ManifestAvailable {
		t.Fatalf("校验报告未标记认证通过：%+v", report)
	}
	if report.BackupID != result.BackupID || report.Database.SchemaVersionNumber != 42 {
		t.Fatalf("校验报告元数据不一致：%+v", report)
	}
	if len(report.Entries) != 3 {
		t.Fatalf("校验条目数 = %d，期望 3", len(report.Entries))
	}
	// 无密钥结构检查：明确未认证。
	inspect, err := InspectFile(context.Background(), result.Path)
	if err != nil {
		t.Fatalf("无密钥结构检查失败：%v", err)
	}
	if inspect.Authenticated || !inspect.StructuralValid {
		t.Fatalf("无密钥检查结果语义错误：%+v", inspect)
	}
	// 数据库条目可被独立解析，说明备份的是真实 SQLite 快照。
	raw := extractEntry(t, result.Path, env.ring, databaseEntryName)
	snapshotPath := filepath.Join(t.TempDir(), "extracted.db")
	if err := os.WriteFile(snapshotPath, raw, 0o600); err != nil {
		t.Fatalf("写入提取的数据库快照失败：%v", err)
	}
	snapshot := readOnlySnapshot(t, snapshotPath)
	var version string
	if err := snapshot.QueryRow(
		`SELECT version FROM schema_history ORDER BY version DESC LIMIT 1`).Scan(&version); err != nil {
		t.Fatalf("读取提取快照迁移版本失败：%v", err)
	}
	if !strings.HasPrefix(version, "0042") {
		t.Fatalf("提取快照最高迁移 = %s，期望 0042", version)
	}
	var integrity string
	if err := snapshot.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		t.Fatalf("提取快照完整性检查失败：%q %v", integrity, err)
	}
	// 真实审计：请求/开始/成功都落库。
	actions := env.auditActionsInDB(t)
	for _, expected := range []string{ActionRequest, ActionStarted, ActionFinish} {
		if !containsAction(actions, expected) {
			t.Fatalf("审计缺少动作 %s，实际=%v", expected, actions)
		}
	}
	env.assertCleanOutput(t, result.FileName)
}

// mustAvatarSource 构造头像附件源并断言成功。
func mustAvatarSource(t *testing.T, storage avatar.Storage) AttachmentSource {
	t.Helper()
	source, err := NewAvatarAttachmentSource(storage)
	if err != nil {
		t.Fatalf("构造头像附件源失败：%v", err)
	}
	return source
}

// TestBackupConsistentUnderConcurrentWrites 验证数据库持续写入时备份仍是一致的
// 单点快照：写入事务同步递增两行计数，备份文件中的两行必须相等且 integrity ok。
func TestBackupConsistentUnderConcurrentWrites(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	if _, err := env.store.ExecContext(ctx, `CREATE TABLE backup_invariant(
id INTEGER PRIMARY KEY, value INTEGER NOT NULL)`); err != nil {
		t.Fatalf("创建一致性表失败：%v", err)
	}
	if _, err := env.store.ExecContext(ctx,
		`INSERT INTO backup_invariant(id, value) VALUES(1,0),(2,0)`); err != nil {
		t.Fatalf("初始化一致性表失败：%v", err)
	}
	var stop atomic.Bool
	var writes atomic.Int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			writeErr := env.store.Transaction(ctx, func(txCtx context.Context, tx *sql.Tx) error {
				_, execErr := tx.ExecContext(txCtx,
					`UPDATE backup_invariant SET value=value+1 WHERE id IN (1,2)`)
				return execErr
			})
			if writeErr != nil {
				continue
			}
			writes.Add(1)
		}
	}()
	result, err := env.service.Create(ctx, CreateRequest{Caller: testCaller(t)})
	stop.Store(true)
	wg.Wait()
	if err != nil {
		t.Fatalf("并发写入下创建备份失败：%v", err)
	}
	if writes.Load() == 0 {
		t.Fatal("并发写入测试没有发生写入，无法证明一致性")
	}
	raw := extractEntry(t, result.Path, env.ring, databaseEntryName)
	snapshotPath := filepath.Join(t.TempDir(), "concurrent.db")
	if err := os.WriteFile(snapshotPath, raw, 0o600); err != nil {
		t.Fatalf("写入提取快照失败：%v", err)
	}
	snapshot := readOnlySnapshot(t, snapshotPath)
	var left, right int64
	if err := snapshot.QueryRow(`SELECT value FROM backup_invariant WHERE id=1`).Scan(&left); err != nil {
		t.Fatalf("读取快照 id=1 失败：%v", err)
	}
	if err := snapshot.QueryRow(`SELECT value FROM backup_invariant WHERE id=2`).Scan(&right); err != nil {
		t.Fatalf("读取快照 id=2 失败：%v", err)
	}
	if left != right {
		t.Fatalf("并发写入下快照不一致：left=%d right=%d", left, right)
	}
	var integrity string
	if err := snapshot.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		t.Fatalf("并发写入下快照完整性失败：%q %v", integrity, err)
	}
}

// TestVerifyWrongKeyTamperAndTruncate 验证错误密钥、密文篡改与截断都明确失败，
// 且无密钥结构检查能发现密文位翻转/截断。
func TestVerifyWrongKeyTamperAndTruncate(t *testing.T) {
	env := newTestEnv(t)
	result, err := env.service.Create(context.Background(), CreateRequest{Caller: testCaller(t)})
	if err != nil {
		t.Fatalf("创建备份失败：%v", err)
	}
	original, err := os.ReadFile(result.Path)
	if err != nil {
		t.Fatalf("读取备份文件失败：%v", err)
	}
	otherRing, err := secrets.GenerateKeyring("k2", backupTestTime)
	if err != nil {
		t.Fatalf("生成另一密钥环失败：%v", err)
	}
	if _, err := VerifyFile(context.Background(), result.Path, otherRing); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("错误密钥错误 = %v，期望 ErrDecryptFailed", err)
	}
	tampered := append([]byte(nil), original...)
	tampered[len(tampered)-TrailerBytes-1] ^= 0xff
	tamperedPath := filepath.Join(t.TempDir(), "tampered.elnbak")
	if err := os.WriteFile(tamperedPath, tampered, 0o600); err != nil {
		t.Fatalf("写入篡改文件失败：%v", err)
	}
	if _, err := VerifyFile(context.Background(), tamperedPath, env.ring); err == nil {
		t.Fatal("密文篡改未被认证解密拒绝")
	}
	if _, err := InspectFile(context.Background(), tamperedPath); err == nil {
		t.Fatal("密文篡改未被无密钥结构检查发现")
	}
	truncatedPath := filepath.Join(t.TempDir(), "truncated.elnbak")
	if err := os.WriteFile(truncatedPath, original[:len(original)-TrailerBytes-32], 0o600); err != nil {
		t.Fatalf("写入截断文件失败：%v", err)
	}
	if _, err := VerifyFile(context.Background(), truncatedPath, env.ring); err == nil {
		t.Fatal("截断文件未被校验拒绝")
	}
	// 清单内部不一致：把清单条目摘要改坏后重新用同一载荷密钥加密，校验必须失败。
	crafted := craftManifestMismatchBackup(t, result.Path, env.ring)
	if _, err := VerifyFile(context.Background(), crafted, env.ring); !errors.Is(err, ErrIntegrityFailed) {
		t.Fatalf("清单摘要不一致错误 = %v，期望 ErrIntegrityFailed", err)
	}
	// 正确文件仍可通过（确认篡改测试没有破坏原文件）。
	env.verifyWithEnv(t, result.Path)
}

// craftManifestMismatchBackup 用内部格式函数重新加密一份“清单被篡改”的备份：
// 修改数据库条目声明摘要并同步更新头部清单摘要与载荷密钥，使认证解密成功但清单
// 交叉校验失败，证明校验器不只看文件能否解密。
func craftManifestMismatchBackup(t *testing.T, sourcePath string, ring *secrets.Keyring) string {
	t.Helper()
	file, err := os.Open(sourcePath)
	if err != nil {
		t.Fatalf("打开源备份失败：%v", err)
	}
	defer file.Close()
	header, headerRaw, _, err := readHeaderFrom(file)
	if err != nil {
		t.Fatalf("读取源备份头部失败：%v", err)
	}
	wrapped, err := base64.StdEncoding.DecodeString(header.Encryption.WrappedDataKey)
	if err != nil {
		t.Fatalf("解码源载荷密钥失败：%v", err)
	}
	dataKey, err := unwrapDataKey(ring, header.BackupID, header.Encryption.KeyID, wrapped)
	if err != nil {
		t.Fatalf("解封源载荷密钥失败：%v", err)
	}
	var plaintext []byte
	limited := &io.LimitedReader{R: file, N: header.Encryption.PayloadCipherBytes}
	if _, err := decryptPayload(limited, header.Encryption, dataKey, headerHash(headerRaw),
		func(chunk []byte) error {
			plaintext = append(plaintext, chunk...)
			return nil
		}); err != nil {
		t.Fatalf("解密源备份载荷失败：%v", err)
	}
	manifestLength := int(binary.BigEndian.Uint32(plaintext[:4]))
	manifestStart := 4
	manifestEnd := manifestStart + manifestLength
	manifest, err := decodeManifest(plaintext[manifestStart:manifestEnd])
	if err != nil {
		t.Fatalf("解析源清单失败：%v", err)
	}
	if len(manifest.Entries) == 0 {
		t.Fatal("源清单没有条目")
	}
	declared := manifest.Entries[0].SHA256
	replacement := byte('0')
	if declared[0] == '0' {
		replacement = byte('1')
	}
	manifest.Entries[0].SHA256 = string(replacement) + declared[1:]
	newManifestRaw, err := marshalManifest(manifest)
	if err != nil {
		t.Fatalf("序列化篡改清单失败：%v", err)
	}
	if len(newManifestRaw) != manifestLength {
		t.Fatalf("篡改清单长度变化：%d → %d", manifestLength, len(newManifestRaw))
	}
	newPlain := make([]byte, 0, len(plaintext))
	lengthField := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthField, uint32(len(newManifestRaw)))
	newPlain = append(newPlain, lengthField...)
	newPlain = append(newPlain, newManifestRaw...)
	newPlain = append(newPlain, plaintext[manifestEnd:]...)
	if int64(len(newPlain)) != header.Encryption.PayloadPlainBytes {
		t.Fatalf("篡改载荷长度变化：%d → %d", header.Encryption.PayloadPlainBytes, len(newPlain))
	}
	manifestDigest := sha256.Sum256(newManifestRaw)
	header.ManifestSHA256 = hex.EncodeToString(manifestDigest[:])
	newDataKey, err := generateDataKey(nil)
	if err != nil {
		t.Fatalf("生成新载荷密钥失败：%v", err)
	}
	keyID, wrappedKey, err := wrapDataKey(ring, header.BackupID, newDataKey)
	if err != nil {
		t.Fatalf("封装修改载荷密钥失败：%v", err)
	}
	header.Encryption.KeyID = keyID
	header.Encryption.WrappedDataKey = base64.StdEncoding.EncodeToString(wrappedKey)
	noncePrefix, err := base64.StdEncoding.DecodeString(header.Encryption.NoncePrefix)
	if err != nil {
		t.Fatalf("解码 nonce 前缀失败：%v", err)
	}
	newHeaderRaw, err := marshalHeader(header)
	if err != nil {
		t.Fatalf("序列化修改头部失败：%v", err)
	}
	var cipherBuffer bytes.Buffer
	cipherBytes, cipherDigest, err := encryptPayload(&cipherBuffer, bytes.NewReader(newPlain),
		int64(len(newPlain)), header.Encryption.ChunkSizeBytes, newDataKey,
		noncePrefix, headerHash(newHeaderRaw))
	if err != nil {
		t.Fatalf("重新加密篡改载荷失败：%v", err)
	}
	if cipherBytes != header.Encryption.PayloadCipherBytes {
		t.Fatalf("篡改后密文长度 = %d，头部声明 %d", cipherBytes, header.Encryption.PayloadCipherBytes)
	}
	var output bytes.Buffer
	output.Write(filePrefix(newHeaderRaw))
	output.Write(cipherBuffer.Bytes())
	output.Write(cipherDigest[:])
	craftedPath := filepath.Join(t.TempDir(), "crafted.elnbak")
	if err := os.WriteFile(craftedPath, output.Bytes(), 0o600); err != nil {
		t.Fatalf("写入篡改备份失败：%v", err)
	}
	return craftedPath
}

// blockingSnapshotter 包装真实快照器并在开始后阻塞，用于确定性验证取消/超时竞争。
type blockingSnapshotter struct {
	inner   Snapshotter
	started chan struct{}
	release chan struct{}
	waitCtx bool
}

// Snapshot 实现 Snapshotter：先报告开始，再等待放行或 ctx 结束，最后执行真实快照。
func (b *blockingSnapshotter) Snapshot(ctx context.Context, destination string,
	progress func(donePages, totalPages int)) (SnapshotInfo, error) {
	if progress != nil {
		progress(1, 2)
	}
	select {
	case b.started <- struct{}{}:
	default:
	}
	if b.waitCtx {
		<-ctx.Done()
		return SnapshotInfo{}, ctx.Err()
	}
	select {
	case <-b.release:
	case <-ctx.Done():
		return SnapshotInfo{}, ctx.Err()
	}
	return b.inner.Snapshot(ctx, destination, progress)
}

// flakyAttachmentSource 第一次 List 返回可重试的附件不一致，之后透传真实来源。
type flakyAttachmentSource struct {
	inner AttachmentSource
	once  sync.Once
}

// List 实现 AttachmentSource。
func (f *flakyAttachmentSource) List(ctx context.Context,
	snapshotPath string) ([]AttachmentInfo, error) {
	var result []AttachmentInfo
	var listErr error
	failed := false
	f.once.Do(func() { failed = true })
	if failed {
		return nil, fmt.Errorf("%w: 测试注入的并发不一致", ErrAttachmentInconsistent)
	}
	if f.inner != nil {
		result, listErr = f.inner.List(ctx, snapshotPath)
	}
	return result, listErr
}

// Open 实现 AttachmentSource。
func (f *flakyAttachmentSource) Open(ctx context.Context,
	entryName string) (io.ReadCloser, error) {
	return f.inner.Open(ctx, entryName)
}

// TestCancelRequestHonored 验证取消请求被接受后由执行器真实终止，并分别记录取消
// 请求与实际取消/最终终止事件；不留下临时文件。
func TestCancelRequestHonored(t *testing.T) {
	env := newTestEnv(t)
	snapshotter, err := NewSQLiteSnapshotter(env.store)
	if err != nil {
		t.Fatalf("构造真实快照器失败：%v", err)
	}
	blocker := &blockingSnapshotter{inner: snapshotter,
		started: make(chan struct{}, 1), release: make(chan struct{})}
	env.service = env.newService(t, func(options *Options) {
		options.Snapshotter = blocker
	})
	type outcome struct {
		result Result
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, createErr := env.service.Create(context.Background(),
			CreateRequest{Caller: testCaller(t)})
		done <- outcome{result: result, err: createErr}
	}()
	select {
	case <-blocker.started:
	case <-time.After(10 * time.Second):
		t.Fatal("等待备份进入快照阶段超时")
	}
	// 找到活动备份编号（服务内部登记表），模拟外部按编号取消。
	var backupID string
	env.service.runs.mu.Lock()
	for id := range env.service.runs.runs {
		backupID = id
	}
	env.service.runs.mu.Unlock()
	if backupID == "" {
		t.Fatal("没有找到活动备份登记")
	}
	cancelResult, err := env.service.RequestCancel(context.Background(), CancelRequest{
		Caller: testCaller(t), BackupID: backupID, Reason: "测试取消"})
	if err != nil {
		t.Fatalf("取消请求未被接受：%v", err)
	}
	if cancelResult.BackupID != backupID || cancelResult.RequestedAt.IsZero() {
		t.Fatalf("取消结果不完整：%+v", cancelResult)
	}
	close(blocker.release)
	select {
	case final := <-done:
		if !errors.Is(final.err, ErrCancelled) {
			t.Fatalf("取消后 Create 错误 = %v，期望 ErrCancelled", final.err)
		}
		if final.result.Path != "" {
			t.Fatalf("取消的备份不应发布文件：%+v", final.result)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("等待备份终止超时")
	}
	actions := env.auditActionsInDB(t)
	for _, expected := range []string{ActionCancelRequest, ActionCancelled} {
		if !containsAction(actions, expected) {
			t.Fatalf("审计缺少动作 %s，实际=%v", expected, actions)
		}
	}
	env.assertCleanOutput(t)
	// 已结束任务再次取消按冲突拒绝。
	if _, err := env.service.RequestCancel(context.Background(), CancelRequest{
		Caller: testCaller(t), BackupID: backupID, Reason: "再次取消"}); !errors.Is(err, ErrCancelConflict) {
		t.Fatalf("重复取消错误 = %v，期望 ErrCancelConflict", err)
	}
}

// TestCancelAfterFinishRejected 验证完成后的取消请求被拒绝并写拒绝审计。
func TestCancelAfterFinishRejected(t *testing.T) {
	env := newTestEnv(t)
	result, err := env.service.Create(context.Background(), CreateRequest{Caller: testCaller(t)})
	if err != nil {
		t.Fatalf("创建备份失败：%v", err)
	}
	if _, err := env.service.RequestCancel(context.Background(), CancelRequest{
		Caller: testCaller(t), BackupID: result.BackupID, Reason: "完成后取消"}); !errors.Is(err, ErrCancelConflict) {
		t.Fatalf("完成后取消错误 = %v，期望 ErrCancelConflict", err)
	}
	if !containsAction(env.auditActionsInDB(t), ActionCancelRejected) {
		t.Fatal("取消被拒绝未写审计")
	}
	env.assertCleanOutput(t, result.FileName)
}

// TestCancelPermissionDenied 验证无取消权限时请求被拒绝且不改变任务状态。
func TestCancelPermissionDenied(t *testing.T) {
	env := newTestEnv(t)
	snapshotter, err := NewSQLiteSnapshotter(env.store)
	if err != nil {
		t.Fatalf("构造真实快照器失败：%v", err)
	}
	blocker := &blockingSnapshotter{inner: snapshotter,
		started: make(chan struct{}, 1), release: make(chan struct{})}
	env.service = env.newService(t, func(options *Options) { options.Snapshotter = blocker })
	env.authorizer = &fakeAuthorizer{}
	env.authorizer.allow(PermissionCreate)
	env.service.opts.Authorizer = env.authorizer
	done := make(chan error, 1)
	go func() {
		_, createErr := env.service.Create(context.Background(),
			CreateRequest{Caller: testCaller(t)})
		done <- createErr
	}()
	<-blocker.started
	var backupID string
	env.service.runs.mu.Lock()
	for id := range env.service.runs.runs {
		backupID = id
	}
	env.service.runs.mu.Unlock()
	if _, err := env.service.RequestCancel(context.Background(), CancelRequest{
		Caller: testCaller(t), BackupID: backupID, Reason: "无权取消"}); !errors.Is(err, ErrCancelForbidden) {
		t.Fatalf("无权取消错误 = %v，期望 ErrCancelForbidden", err)
	}
	close(blocker.release)
	if err := <-done; err != nil {
		t.Fatalf("备份在没有取消的情况下失败：%v", err)
	}
}

// TestTimeoutIsolatedFromCancel 验证内部墙钟超时映射 TASK_TIMEOUT，且与人工取消
// 分开记录。测试在包内把超时下调到毫秒级，仅为缩短测试时间，不改变生产下限。
func TestTimeoutIsolatedFromCancel(t *testing.T) {
	env := newTestEnv(t)
	snapshotter, err := NewSQLiteSnapshotter(env.store)
	if err != nil {
		t.Fatalf("构造真实快照器失败：%v", err)
	}
	blocker := &blockingSnapshotter{inner: snapshotter,
		started: make(chan struct{}, 1), release: make(chan struct{}), waitCtx: true}
	env.service = env.newService(t, func(options *Options) { options.Snapshotter = blocker })
	env.service.opts.Timeout = 150 * time.Millisecond
	started := time.Now()
	_, err = env.service.Create(context.Background(), CreateRequest{Caller: testCaller(t)})
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("超时错误 = %v，期望 ErrTimeout", err)
	}
	if time.Since(started) > 5*time.Second {
		t.Fatalf("超时未按时生效：%s", time.Since(started))
	}
	actions := env.auditActionsInDB(t)
	if !containsAction(actions, ActionFailed) || containsAction(actions, ActionCancelled) {
		t.Fatalf("超时审计语义错误：%v", actions)
	}
	env.assertCleanOutput(t)
}

// TestAuditUnavailableFailClosed 验证审计不可用时创建请求/成功审计都 fail-closed，
// 且不留下成功但未审计的备份文件。
func TestAuditUnavailableFailClosed(t *testing.T) {
	env := newTestEnv(t)
	requestRecorder := &fakeRecorder{failAction: ActionRequest}
	service := env.newService(t, func(options *Options) { options.Audit = requestRecorder })
	if _, err := service.Create(context.Background(),
		CreateRequest{Caller: testCaller(t)}); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("请求审计失败错误 = %v，期望 ErrAuditUnavailable", err)
	}
	env.assertCleanOutput(t)

	finishRecorder := &fakeRecorder{failAction: ActionFinish}
	service = env.newService(t, func(options *Options) { options.Audit = finishRecorder })
	if _, err := service.Create(context.Background(),
		CreateRequest{Caller: testCaller(t)}); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("成功审计失败错误 = %v，期望 ErrAuditUnavailable", err)
	}
	// 成功审计失败必须删除已发布文件，不能留下“成功但无审计”的备份。
	env.assertCleanOutput(t)
	if finishRecorder.countAction(ActionFinish) == 0 {
		t.Fatal("成功审计失败路径未被触发")
	}
}

// TestCapacityLimitCleanFailure 验证容量上限触发明确失败并清理临时文件（有界
// writer 模拟磁盘/容量不足；真实 ENOSPC 由驱动错误映射为 BACKUP_FAILED）。
func TestCapacityLimitCleanFailure(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	if _, err := env.store.ExecContext(ctx,
		`CREATE TABLE backup_big(id INTEGER PRIMARY KEY, payload BLOB NOT NULL)`); err != nil {
		t.Fatalf("创建大表失败：%v", err)
	}
	if _, err := env.store.ExecContext(ctx,
		`INSERT INTO backup_big(payload) VALUES(randomblob(2*1024*1024))`); err != nil {
		t.Fatalf("写入大对象失败：%v", err)
	}
	service := env.newService(t, func(options *Options) {
		options.MaxBackupBytes = MinMaxBackupBytes
	})
	_, err := service.Create(ctx, CreateRequest{Caller: testCaller(t)})
	if err == nil {
		t.Fatal("超过容量上限的备份未失败")
	}
	// 容量上限失败映射为 BACKUP_FAILED（BACKUP_INVALID 只表示文件校验失败）。
	if CodeOf(err) != CodeBackupFailed {
		t.Fatalf("容量超限错误码 = %s，期望 BACKUP_FAILED（错误：%v）", CodeOf(err), err)
	}
	env.assertCleanOutput(t)
}

// TestStaleTempCleanup 验证进程中断遗留的旧临时文件/暂存目录在下一次备份开始时
// 被清理，而新的临时文件不会被误删。
func TestStaleTempCleanup(t *testing.T) {
	env := newTestEnv(t)
	staleFile := filepath.Join(env.outputDir, tempFilePrefix+"old"+tempFileSuffix)
	if err := os.WriteFile(staleFile, []byte("stale"), 0o600); err != nil {
		t.Fatalf("写入遗留临时文件失败：%v", err)
	}
	oldTime := time.Now().Add(-72 * time.Hour)
	if err := os.Chtimes(staleFile, oldTime, oldTime); err != nil {
		t.Fatalf("设置遗留文件时间失败：%v", err)
	}
	staleDir := filepath.Join(env.outputDir, stagingDirPrefix+"old")
	if err := os.MkdirAll(staleDir, 0o700); err != nil {
		t.Fatalf("创建遗留暂存目录失败：%v", err)
	}
	if err := os.Chtimes(staleDir, oldTime, oldTime); err != nil {
		t.Fatalf("设置遗留目录时间失败：%v", err)
	}
	recentFile := filepath.Join(env.outputDir, tempFilePrefix+"recent"+tempFileSuffix)
	if err := os.WriteFile(recentFile, []byte("active"), 0o600); err != nil {
		t.Fatalf("写入新临时文件失败：%v", err)
	}
	result, err := env.service.Create(context.Background(), CreateRequest{Caller: testCaller(t)})
	if err != nil {
		t.Fatalf("创建备份失败：%v", err)
	}
	if _, err := os.Stat(staleFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("遗留临时文件未被清理：%v", err)
	}
	if _, err := os.Stat(staleDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("遗留暂存目录未被清理：%v", err)
	}
	if _, err := os.Stat(recentFile); err != nil {
		t.Fatalf("新临时文件被误删：%v", err)
	}
	_ = os.Remove(recentFile)
	env.assertCleanOutput(t, result.FileName)
}

// TestRetryOnTransientAttachmentInconsistency 验证可重试的瞬时不一致会重试并成功，
// 且重试写入真实审计。
func TestRetryOnTransientAttachmentInconsistency(t *testing.T) {
	env := newTestEnv(t)
	userID := "usr_" + strings.Repeat("22", 16)
	env.insertUser(t, userID)
	env.insertAvatar(t, userID, []byte("avatar-for-retry-test"))
	realSource := mustAvatarSource(t, env.avatars)
	env.service = env.newService(t, func(options *Options) {
		options.Attachments = &flakyAttachmentSource{inner: realSource}
		options.MaxAttempts = 2
		options.RetryDelay = time.Millisecond
	})
	result, err := env.service.Create(context.Background(), CreateRequest{Caller: testCaller(t)})
	if err != nil {
		t.Fatalf("重试后创建备份失败：%v", err)
	}
	if result.Attempts != 2 {
		t.Fatalf("尝试次数 = %d，期望 2", result.Attempts)
	}
	actions := env.auditActionsInDB(t)
	if !containsAction(actions, ActionRetry) || !containsAction(actions, ActionFinish) {
		t.Fatalf("重试审计缺失：%v", actions)
	}
	env.assertCleanOutput(t, result.FileName)
}

// TestProgressCallback 验证进度回调覆盖真实阶段且快照进度来自 SQLite 页数。
func TestProgressCallback(t *testing.T) {
	env := newTestEnv(t)
	var mu sync.Mutex
	var progresses []Progress
	env.service = env.newService(t, func(options *Options) {
		options.Progress = func(progress Progress) {
			mu.Lock()
			progresses = append(progresses, progress)
			mu.Unlock()
		}
	})
	result, err := env.service.Create(context.Background(), CreateRequest{Caller: testCaller(t)})
	if err != nil {
		t.Fatalf("创建备份失败：%v", err)
	}
	mu.Lock()
	snapshotSeen := false
	doneSeen := false
	for _, progress := range progresses {
		if progress.Phase == "snapshot" && progress.Total > 0 {
			snapshotSeen = true
		}
		if progress.Phase == "done" {
			doneSeen = true
		}
	}
	mu.Unlock()
	if !snapshotSeen {
		t.Fatalf("进度回调缺少带页数的 snapshot 阶段：%+v", progresses)
	}
	if !doneSeen {
		t.Fatalf("进度回调缺少 done 阶段：%+v", progresses)
	}
	env.assertCleanOutput(t, result.FileName)
}

// TestNewRejectsUnsafeOptions 验证缺失依赖/非法边界/不安全输出目录 fail-closed。
func TestNewRejectsUnsafeOptions(t *testing.T) {
	env := newTestEnv(t)
	snapshotter, err := NewSQLiteSnapshotter(env.store)
	if err != nil {
		t.Fatalf("构造快照器失败：%v", err)
	}
	keyProvider := secrets.ProviderFunc(func(ctx context.Context) ([]byte, error) {
		return env.ring.Document()
	})
	base := Options{Snapshotter: snapshotter, Keyring: keyProvider,
		Authorizer: env.authorizer, Audit: env.recorder, OutputDir: env.outputDir}
	outputFile := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(outputFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("写入测试文件失败：%v", err)
	}
	cases := []struct {
		name   string
		mutate func(*Options)
	}{
		{"缺少快照器", func(o *Options) { o.Snapshotter = nil }},
		{"缺少密钥", func(o *Options) { o.Keyring = nil }},
		{"缺少授权器", func(o *Options) { o.Authorizer = nil }},
		{"缺少审计", func(o *Options) { o.Audit = nil }},
		{"输出目录为空", func(o *Options) { o.OutputDir = "" }},
		{"输出目录不存在", func(o *Options) { o.OutputDir = filepath.Join(t.TempDir(), "missing") }},
		{"输出目录是文件", func(o *Options) { o.OutputDir = outputFile }},
		{"超时过短", func(o *Options) { o.Timeout = time.Second }},
		{"尝试次数超限", func(o *Options) { o.MaxAttempts = MaxAllowedAttempts + 1 }},
		{"重试间隔为负", func(o *Options) { o.RetryDelay = -time.Second }},
		{"容量上限过小", func(o *Options) { o.MaxBackupBytes = 1 }},
		{"清理门槛过小", func(o *Options) { o.StaleTempAge = time.Minute }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			options := base
			testCase.mutate(&options)
			if _, err := New(options); err == nil {
				t.Fatalf("%s 未按 fail-closed 拒绝", testCase.name)
			}
		})
	}
	if !unsafeDirectoryMode(0o770) || !unsafeDirectoryMode(0o707) ||
		unsafeDirectoryMode(0o700) {
		t.Fatal("输出目录权限判断逻辑错误")
	}
}

// TestCreateAccessDenied 验证缺少 backups.create 权限时创建被拒绝、不执行快照、
// 不产出文件，并写权限拒绝审计。
func TestCreateAccessDenied(t *testing.T) {
	env := newTestEnv(t)
	env.authorizer = &fakeAuthorizer{}
	env.service = env.newService(t, nil)
	if _, err := env.service.Create(context.Background(),
		CreateRequest{Caller: testCaller(t)}); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("无权限创建错误 = %v，期望 ErrAccessDenied", err)
	}
	env.assertCleanOutput(t)
	if !containsAction(env.auditActionsInDB(t), ActionAccessDenied) {
		t.Fatal("权限拒绝未写审计")
	}
}

// TestCreateAmbiguousScopeDenied 验证授权通过但数据范围不覆盖 system 时仍拒绝
// （fail-closed，不接受应用范围伪装系统备份）。
func TestCreateAmbiguousScopeDenied(t *testing.T) {
	env := newTestEnv(t)
	env.authorizer = &fakeAuthorizer{}
	env.authorizer.mu.Lock()
	env.authorizer.grants = map[string]stats.ScopeGrant{
		PermissionCreate + "|" + ScopeSystem: {Allowed: true, AllData: false,
			ResourceIDs: []string{"app_demo"}},
	}
	env.authorizer.mu.Unlock()
	env.service = env.newService(t, nil)
	if _, err := env.service.Create(context.Background(),
		CreateRequest{Caller: testCaller(t)}); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("范围不足创建错误 = %v，期望 ErrAccessDenied", err)
	}
	env.assertCleanOutput(t)
}

// TestStrongKillResidueCleanedImmediately 验证强杀（进程崩溃）留下的明文暂存目录与
// 临时文件在**下一次 Create 开始时立即清理**，不依赖默认年龄门槛；同时恢复被删
// 锁文件。模拟方式：直接构造合法编号命名的残留条目与无持有者的锁文件。
func TestStrongKillResidueCleanedImmediately(t *testing.T) {
	env := newTestEnv(t)
	backupID := "bkp_" + strings.Repeat("0a", 16)
	stagingDir := filepath.Join(env.outputDir, stagingDirPrefix+safeName(backupID)+"-123456")
	if err := os.MkdirAll(stagingDir, 0o700); err != nil {
		t.Fatalf("创建模拟残留暂存目录失败：%v", err)
	}
	plainSnapshot := filepath.Join(stagingDir, "database.sqlite")
	if err := os.WriteFile(plainSnapshot, []byte("plain-db-snapshot"), 0o600); err != nil {
		t.Fatalf("创建模拟明文快照失败：%v", err)
	}
	tempFile := filepath.Join(env.outputDir, tempFilePrefix+safeName(backupID)+tempFileSuffix)
	if err := os.WriteFile(tempFile, []byte("partial"), 0o600); err != nil {
		t.Fatalf("创建模拟临时文件失败：%v", err)
	}
	// 强杀后锁文件可能仍存在但无持有者；也可能已被系统清理。两种情形都必须能立即回收。
	staleLockPath := lockFilePath(env.outputDir, backupID)
	if err := os.WriteFile(staleLockPath, nil, 0o600); err != nil {
		t.Fatalf("创建模拟遗留锁文件失败：%v", err)
	}
	result, err := env.service.Create(context.Background(), CreateRequest{Caller: testCaller(t)})
	if err != nil {
		t.Fatalf("残留清理后创建备份失败：%v", err)
	}
	for _, path := range []string{stagingDir, tempFile, staleLockPath} {
		if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("强杀残留未被立即清理：%s（%v）", path, statErr)
		}
	}
	env.assertCleanOutput(t, result.FileName)
}

// TestActiveBackupResidueProtected 验证安全清理不会误删仍在活动的备份暂存目录：
// 另一个服务实例扫描同一输出目录时，活动运行的锁应使其跳过。
func TestActiveBackupResidueProtected(t *testing.T) {
	env := newTestEnv(t)
	snapshotter, err := NewSQLiteSnapshotter(env.store)
	if err != nil {
		t.Fatalf("构造真实快照器失败：%v", err)
	}
	blocker := &blockingSnapshotter{inner: snapshotter,
		started: make(chan struct{}, 1), release: make(chan struct{})}
	env.service = env.newService(t, func(options *Options) { options.Snapshotter = blocker })
	done := make(chan error, 1)
	go func() {
		_, createErr := env.service.Create(context.Background(),
			CreateRequest{Caller: testCaller(t)})
		done <- createErr
	}()
	<-blocker.started
	// 活动备份已创建暂存目录与运行锁；另一个服务实例（同一输出目录）执行安全清理。
	other := env.newService(t, nil)
	other.cleanupStaleTemps(context.Background())
	entries, err := os.ReadDir(env.outputDir)
	if err != nil {
		t.Fatalf("读取输出目录失败：%v", err)
	}
	stagingSeen := false
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), stagingDirPrefix) {
			stagingSeen = true
		}
	}
	if !stagingSeen {
		t.Fatal("安全清理误删了活动备份的暂存目录")
	}
	close(blocker.release)
	if err := <-done; err != nil {
		t.Fatalf("活动备份失败：%v", err)
	}
}

// TestCorruptSourceDatabaseRejected 验证损坏的源数据库不会产出“成功”备份
// （创建前 PRAGMA quick_check(1) fail-closed）。
func TestCorruptSourceDatabaseRejected(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "corrupt-source.db")
	store, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(dbPath))
	if err != nil {
		t.Fatalf("打开测试数据库失败：%v", err)
	}
	migrations, err := migrate.LoadMigrations(appmigrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移失败：%v", err)
	}
	if _, err := store.Migrate(ctx, migrations); err != nil {
		t.Fatalf("执行迁移失败：%v", err)
	}
	if _, err := store.ExecContext(ctx,
		`CREATE TABLE corrupt_probe(id INTEGER PRIMARY KEY, payload BLOB NOT NULL)`); err != nil {
		t.Fatalf("创建测试表失败：%v", err)
	}
	if _, err := store.ExecContext(ctx,
		`INSERT INTO corrupt_probe(payload) VALUES(randomblob(8192))`); err != nil {
		t.Fatalf("写入测试数据失败：%v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("关闭测试数据库失败：%v", err)
	}
	data, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("读取测试数据库失败：%v", err)
	}
	if len(data) < 4*4096 {
		t.Fatalf("测试数据库过小（%d 字节）", len(data))
	}
	// 破坏数据页（保留第 1 页头部/schema 以便能打开数据库），使 quick_check 必报错。
	for offset := 2 * 4096; offset < 3*4096; offset++ {
		data[offset] = 0xff
	}
	if err := os.WriteFile(dbPath, data, 0o600); err != nil {
		t.Fatalf("写回损坏数据库失败：%v", err)
	}
	reopened, openErr := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(dbPath))
	if openErr != nil {
		// 打开阶段即拒绝同样属于 fail-closed，测试目标（不产出成功备份）已满足。
		return
	}
	defer func() { _ = reopened.Close() }()
	snapshotter, err := NewSQLiteSnapshotter(reopened)
	if err != nil {
		t.Fatalf("构造快照器失败：%v", err)
	}
	destination := filepath.Join(t.TempDir(), "snapshot.db")
	if _, err := snapshotter.Snapshot(ctx, destination, nil); err == nil {
		t.Fatal("损坏源数据库未被拒绝，生成了“成功”快照")
	}
}
