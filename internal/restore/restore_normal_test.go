package restore

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/avatar"
	"github.com/kagurazakayashi/EvernightLogin/internal/backup"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

// listDirHashes 返回目录中普通文件的 SHA-256 映射（用于证明用户原始备份未被改写）。
func listDirHashes(t *testing.T, directory string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("读取目录失败：%v", err)
	}
	hashes := make(map[string]string, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		hashes[entry.Name()] = fileSHA256(t, filepath.Join(directory, entry.Name()))
	}
	return hashes
}

// insertAvatar 写入真实附件文件并插入 avatars 引用行，返回存储键。
func (e *testEnv) insertAvatar(t *testing.T, store *storagesqlite.Store, userID string,
	content []byte) string {
	t.Helper()
	storage, err := avatar.NewLocalStorage(e.avatarsDir)
	if err != nil {
		t.Fatalf("构造附件存储失败：%v", err)
	}
	key, err := storage.Save(context.Background(), content, "png")
	if err != nil {
		t.Fatalf("写入测试附件失败：%v", err)
	}
	digest := sha256.Sum256(content)
	nowMS := e.clock().UnixMilli()
	if _, err := store.ExecContext(context.Background(), `INSERT INTO avatars(
id,user_id,storage_key,media_type,byte_size,width,height,content_sha256,
source_kind,created_at_ms,updated_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		"avt_restore_test", userID, key, "image/png", len(content), 16, 16,
		digest[:], "upload", nowMS, nowMS); err != nil {
		t.Fatalf("插入附件引用行失败：%v", err)
	}
	return key
}

// TestRestoreReplacesDatabaseAndRevokesCredentials 覆盖恢复主路径：预演通过后进入
// 维护、创建回退备份、暂存验证、切换、凭证失效、旧调度/Webhook/任务暂停、审计
// 独立保存并合并、退出维护；数据库回到备份时间点，恢复前/备份中的凭证均不复活。
func TestRestoreReplacesDatabaseAndRevokesCredentials(t *testing.T) {
	env := newTestEnv(t)
	env.withAttach = true
	env.withConfig = true
	store := env.openStore(t, true)
	env.mustMigrate(t, store)
	ids := env.seedDatabase(t, store)
	avatarKey := env.insertAvatar(t, store, ids.userID, []byte("avatar-v1"))
	backupResult := env.createBackup(t)
	env.mutateAfterBackup(t, store)
	// 备份后把附件升级为 v2 并同步数据库引用（保持当前状态自洽，使回退备份可创建）；
	// 从较旧备份恢复后必须回退到备份时的 v1 内容与引用摘要。
	avatarPath := filepath.Join(env.avatarsDir, avatarKey)
	avatarV2 := []byte("avatar-v2-after-backup")
	if err := os.WriteFile(avatarPath, avatarV2, 0o600); err != nil {
		t.Fatalf("修改备份后附件失败：%v", err)
	}
	digestV2 := sha256.Sum256(avatarV2)
	if _, err := store.ExecContext(context.Background(), `UPDATE avatars
SET content_sha256=?, byte_size=? WHERE storage_key=?`,
		digestV2[:], len(avatarV2), avatarKey); err != nil {
		t.Fatalf("更新备份后附件引用失败：%v", err)
	}
	closeStore(t, store)

	beforeBackups := listDirHashes(t, env.backupDir)
	preRestoreDatabaseHash := fileSHA256(t, env.dbPath)

	service := env.newRestoreService(t, nil)
	ctx := context.Background()
	request := Request{Caller: env.caller(t), BackupPath: backupResult.Path,
		Reason: "测试正常恢复", RequestID: "req_restore_normal"}
	result, err := service.Execute(ctx, request)
	assertNoError(t, err, "正常恢复失败")
	if result.Generation != 1 {
		t.Fatalf("恢复代际 = %d，期望 1", result.Generation)
	}
	if !result.MaintenanceExited {
		t.Fatal("成功恢复后应退出维护状态")
	}
	if result.Revoked.Sessions != 1 || result.Revoked.RefreshFamilies != 1 ||
		result.Revoked.RefreshTokens != 1 || result.Revoked.AuthorizationCodes != 1 ||
		result.Revoked.RecoveryCodes != 1 || result.Revoked.VerificationTickets != 1 ||
		result.Revoked.QRLoginRequests != 1 || result.Revoked.SigningKeys != 1 {
		t.Fatalf("凭证失效计数不符合期望：%+v", result.Revoked)
	}
	if result.Paused.Schedules != 1 || result.Paused.Webhooks != 1 ||
		result.Paused.WebhookDeliveries != 1 ||
		result.Paused.Jobs != 1 || result.Paused.MailDeliveries != 1 {
		t.Fatalf("恢复后暂停计数不符合期望：%+v", result.Paused)
	}
	if result.AuditMerged <= 0 {
		t.Fatalf("恢复审计合并条数 = %d，期望大于 0", result.AuditMerged)
	}
	if result.RollbackBackupPath == "" || result.RollbackBackupSHA256 == "" {
		t.Fatal("缺少恢复前回退备份结果")
	}
	if fileSHA256(t, result.RollbackBackupPath) != result.RollbackBackupSHA256 {
		t.Fatal("回退备份文件摘要与结果不一致")
	}
	if result.PendingConfigPath == "" {
		t.Fatal("备份包含配置时应复制到待审查目录")
	}

	// 外部状态：维护已退出、库外代际为 1。
	state := service.State()
	if state.Mode != "normal" || state.Generation != 1 || state.Pending != nil {
		t.Fatalf("库外状态 = %+v，期望 normal/1/无 pending", state)
	}

	live := env.openLive(t)
	// 数据库回到备份时间点：备份后新增的用户与修改消失。
	if got := queryInt64(t, live,
		`SELECT COUNT(*) FROM users WHERE id='usr_post_backup'`); got != 0 {
		t.Fatal("备份后新增用户未被恢复覆盖")
	}
	if got := queryString(t, live,
		`SELECT nickname FROM users WHERE username='alice'`); got != "" {
		t.Fatalf("备份后修改的用户字段未被恢复：%q", got)
	}
	// 全部代表凭证表清空（旧备份中的凭证不复活）。
	for _, table := range []string{"sessions", "refresh_token_families",
		"refresh_tokens", "oauth_authorization_codes", "oauth_authorization_requests",
		"recovery_codes", "recovery_code_groups", "email_verification_tickets",
		"password_reset_requests", "app_qr_login_requests",
		"oauth_device_authorizations", "token_signing_keys",
		"manual_recovery_requests", "manual_recovery_approvals",
		"manual_recovery_executions", "registration_reviews"} {
		if got := tableCount(t, live, table); got != 0 {
			t.Fatalf("恢复后凭证表 %s 仍有 %d 行", table, got)
		}
	}
	// 旧调度计划/Webhook/任务/邮件默认暂停。
	if got := queryInt64(t, live, `SELECT COUNT(*) FROM schedules WHERE enabled=1`); got != 0 {
		t.Fatalf("恢复后仍有 %d 个启用中的调度计划", got)
	}
	if got := queryInt64(t, live,
		`SELECT COUNT(*) FROM webhook_endpoints WHERE status='active'`); got != 0 {
		t.Fatalf("恢复后仍有 %d 个活动 Webhook 端点", got)
	}
	if got := queryInt64(t, live,
		`SELECT COUNT(*) FROM jobs WHERE state NOT IN('cancelled')`); got != 0 {
		t.Fatalf("恢复后仍有 %d 个非取消状态任务", got)
	}
	if got := queryInt64(t, live,
		`SELECT COUNT(*) FROM mail_deliveries WHERE state NOT IN('cancelled')`); got != 0 {
		t.Fatalf("恢复后仍有 %d 封未取消邮件", got)
	}
	if got := queryInt64(t, live,
		`SELECT COUNT(*) FROM webhook_deliveries WHERE state NOT IN('cancelled')`); got != 0 {
		t.Fatalf("恢复后仍有 %d 条未取消 Webhook 投递", got)
	}
	// 恢复运行记录、代际与暂停清单。
	if got := queryInt64(t, live, `SELECT generation FROM restore_generation WHERE id=1`); got != 1 {
		t.Fatalf("库内恢复代际 = %d，期望 1", got)
	}
	if got := queryInt64(t, live,
		`SELECT COUNT(*) FROM restore_runs WHERE status='completed' AND operator_type='local_admin'`); got != 1 {
		t.Fatalf("恢复运行记录数 = %d，期望 1 条 completed/local_admin", got)
	}
	if got := queryInt64(t, live, `SELECT COUNT(*) FROM restore_paused_items`); got < 4 {
		t.Fatalf("恢复暂停清单条数 = %d，期望至少 4", got)
	}
	// 审计：备份中的旧审计保留，恢复过程审计已合并且去重键幂等。
	for _, action := range []string{"test.pre_restore_audit", ActionPreflight,
		ActionStarted, ActionCompleted, ActionAuditMerged} {
		if got := queryInt64(t, live,
			`SELECT COUNT(*) FROM audit_events WHERE action=?`, action); got < 1 {
			t.Fatalf("恢复后审计缺少动作 %s", action)
		}
	}
	// 旧备份中的取消审计与真实取消执行者身份仍在（恢复不删除/改写历史审计）。
	if got := queryInt64(t, live, `SELECT COUNT(*) FROM audit_events
WHERE action='backup.cancelled' AND actor_type='local_admin'
AND actor_id='os:tester@test-host'`); got != 1 {
		t.Fatalf("恢复后丢失历史取消审计/取消身份：%d", got)
	}
	// 恢复过程审计的 actor 是真实本地应急管理员，而不是匿名或系统占位。
	if got := queryInt64(t, live, `SELECT COUNT(*) FROM audit_events
WHERE action=? AND actor_type='local_admin'`, ActionStarted); got < 1 {
		t.Fatal("恢复审计缺少真实本地管理员执行者")
	}
	// 附件恢复到备份版本。
	restoredAvatar, err := os.ReadFile(avatarPath)
	if err != nil {
		t.Fatalf("读取恢复后附件失败：%v", err)
	}
	if string(restoredAvatar) != "avatar-v1" {
		t.Fatalf("附件未恢复到备份版本：%q", restoredAvatar)
	}
	// 待审查配置存在但不自动应用。
	configData, err := os.ReadFile(result.PendingConfigPath)
	if err != nil {
		t.Fatalf("读取待审查配置失败：%v", err)
	}
	if !strings.Contains(string(configData), "listen_addr") {
		t.Fatalf("待审查配置内容不一致：%q", configData)
	}

	// 用户原始备份未被改写：原有文件摘要保持不变，新增的是回退备份文件。
	afterBackups := listDirHashes(t, env.backupDir)
	for name, hash := range beforeBackups {
		if afterBackups[name] != hash {
			t.Fatalf("用户原始备份 %s 被改写", name)
		}
	}
	if len(afterBackups) != len(beforeBackups)+1 {
		t.Fatalf("回退备份目录条目数 = %d，期望原 %d + 1 份回退备份",
			len(afterBackups), len(beforeBackups))
	}
	if fileSHA256(t, env.dbPath) == preRestoreDatabaseHash {
		t.Fatal("数据库文件在恢复后不应与恢复前完全相同（本测试已修改数据）")
	}
	// 回退备份可被认证校验（真实可恢复，不是空文件）。
	if _, err := backup.VerifyFile(ctx, result.RollbackBackupPath, env.ring); err != nil {
		t.Fatalf("回退备份无法通过认证校验：%v", err)
	}

	// 恢复后处置：清单可读、审查可标记、受控重新启用旧计划与 Webhook。
	disposition, err := service.Disposition(ctx, env.caller(t))
	assertNoError(t, err, "读取恢复后处置清单失败")
	if disposition.RestoreID == "" || len(disposition.Items) < 4 || !disposition.ReviewRequired {
		t.Fatalf("恢复后处置清单不符合期望：%+v", disposition)
	}
	reviewed, err := service.ReviewDisposition(ctx, ReviewRequest{
		Caller: env.caller(t), RequestID: "req_review_1"})
	assertNoError(t, err, "标记恢复处置审查失败")
	if reviewed < 4 {
		t.Fatalf("标记审查条数 = %d，期望至少 4", reviewed)
	}
	reenabled, err := service.ReenablePaused(ctx, ReenableRequest{
		Caller: env.caller(t), RequestID: "req_reenable_1", Reason: "人工审查后恢复计划"})
	assertNoError(t, err, "受控重新启用失败")
	if reenabled.Schedules != 1 || reenabled.Webhooks != 1 {
		t.Fatalf("重新启用结果不符合期望：%+v", reenabled)
	}
	if got := queryInt64(t, live, `SELECT COUNT(*) FROM schedules WHERE enabled=1`); got != 1 {
		t.Fatalf("重新启用后启用计划数 = %d，期望 1", got)
	}
	if got := queryInt64(t, live,
		`SELECT COUNT(*) FROM webhook_endpoints WHERE status='active'`); got != 1 {
		t.Fatalf("重新启用后活动 Webhook 数 = %d，期望 1", got)
	}

	// 恢复流程要求宿主释放数据库句柄（Windows 上打开中的文件无法改名）。
	closeStore(t, live)

	// 再次从同一旧备份恢复：代际前进，旧凭证仍不能复活（证明旧备份不能复活凭证）。
	result2, err := service.Execute(ctx, Request{Caller: env.caller(t),
		BackupPath: backupResult.Path, Reason: "再次恢复同一旧备份",
		RequestID: "req_restore_normal_2"})
	assertNoError(t, err, "第二次恢复失败")
	if result2.Generation != 2 {
		t.Fatalf("第二次恢复代际 = %d，期望 2", result2.Generation)
	}
	live2 := env.openLive(t)
	defer closeStore(t, live2)
	if got := tableCount(t, live2, "sessions"); got != 0 {
		t.Fatalf("第二次恢复后会话表仍有 %d 行", got)
	}
	if got := queryInt64(t, live2, `SELECT generation FROM restore_generation WHERE id=1`); got != 2 {
		t.Fatalf("第二次恢复后库内代际 = %d，期望 2", got)
	}
	entries, err := service.JournalEntries()
	assertNoError(t, err, "读取库外恢复审计日志失败")
	if len(entries) < 10 {
		t.Fatalf("库外审计日志条目数 = %d，期望不少于 10", len(entries))
	}
	for index, entry := range entries {
		if entry.Seq != int64(index+1) {
			t.Fatalf("库外审计日志序号不连续：第 %d 条为 %d", index+1, entry.Seq)
		}
	}
}
