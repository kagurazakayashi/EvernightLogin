package sqlite_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
	credentialsqlite "github.com/kagurazakayashi/EvernightLogin/internal/credential/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// testVerifierHash 返回可预测的测试摘要（不是真实凭证摘要）。
func testVerifierHash(fill byte) []byte {
	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = fill + byte(i)
	}
	return hash
}

// testRecord 构造一条测试凭证记录。
func testRecord(id, purpose, target, appID string, hash []byte, keyID string, maxAttempts int, createdAt, expiresAt time.Time) credential.Record {
	return credential.Record{
		ID:           id,
		Purpose:      purpose,
		Target:       target,
		AppID:        appID,
		VerifierHash: hash,
		KeyID:        keyID,
		ContextJSON:  `{"v":1}`,
		MaxAttempts:  maxAttempts,
		CreatedAt:    createdAt.UTC(),
		ExpiresAt:    expiresAt.UTC(),
	}
}

// TestMigrationUpgradeFromCoreToCredentials 验证已执行 0001 的数据库可以继续追加
// 执行 0002，不需要重建数据库。
func TestMigrationUpgradeFromCoreToCredentials(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "upgrade.sqlite")
	store, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(dbPath))
	if err != nil {
		t.Fatalf("打开临时数据库失败: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})
	migrationSet, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移失败: %v", err)
	}
	if len(migrationSet) != 42 {
		t.Fatalf("迁移数量 = %d，期望 42", len(migrationSet))
	}
	// 第一次只执行到 0001，模拟步骤 08 已部署的数据库。
	if _, err := store.Migrate(ctx, migrationSet[:1]); err != nil {
		t.Fatalf("执行 0001 失败: %v", err)
	}
	// 第二次执行完整迁移，应追加 0002～0006 并保持已应用记录。
	result, err := store.Migrate(ctx, migrationSet)
	if err != nil {
		t.Fatalf("追加执行 0002 失败: %v", err)
	}
	if result.UpToDate {
		t.Fatal("追加迁移后结果仍为 UpToDate")
	}
	rows, err := store.QueryContext(ctx, `SELECT version FROM schema_history ORDER BY version`)
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
	if len(versions) != 42 || versions[0] != "0001" || versions[1] != "0002" || versions[2] != "0003" || versions[3] != "0004" || versions[4] != "0005" || versions[5] != "0006" || versions[6] != "0007" || versions[7] != "0008" || versions[8] != "0009" || versions[9] != "0010" || versions[10] != "0011" || versions[11] != "0012" || versions[12] != "0013" || versions[13] != "0014" || versions[14] != "0015" || versions[15] != "0016" || versions[16] != "0017" || versions[17] != "0018" || versions[18] != "0019" || versions[19] != "0020" || versions[20] != "0021" || versions[21] != "0022" || versions[22] != "0023" || versions[23] != "0024" || versions[24] != "0025" || versions[25] != "0026" || versions[26] != "0027" || versions[27] != "0028" || versions[28] != "0029" || versions[29] != "0030" || versions[30] != "0031" || versions[31] != "0032" || versions[32] != "0033" || versions[33] != "0034" || versions[34] != "0035" || versions[35] != "0036" || versions[36] != "0037" || versions[37] != "0038" || versions[38] != "0039" || versions[39] != "0040" || versions[40] != "0041" || versions[41] != "0042" {
		t.Fatalf("升级后迁移历史 = %v", versions)
	}
}

// TestNewRejectsNilStore 验证构造拒绝空存储。
func TestNewRejectsNilStore(t *testing.T) {
	if _, err := credentialsqlite.New(nil); !errors.Is(err, credential.ErrOptionsInvalid) {
		t.Fatalf("nil 存储错误 = %v", err)
	}
}

// TestMigrationApplied 验证 0001 与 0002 迁移已应用，且一次性凭证表结构符合约定。
func TestMigrationApplied(t *testing.T) {
	env := newTestEnv(t, envConfig{})
	rows, err := env.sqliteStore.QueryContext(context.Background(),
		`SELECT version FROM schema_history ORDER BY version`)
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
	if len(versions) != 42 || versions[0] != "0001" || versions[1] != "0002" || versions[2] != "0003" || versions[3] != "0004" || versions[4] != "0005" || versions[5] != "0006" || versions[6] != "0007" || versions[7] != "0008" || versions[8] != "0009" || versions[9] != "0010" || versions[10] != "0011" || versions[11] != "0012" || versions[12] != "0013" || versions[13] != "0014" || versions[14] != "0015" || versions[15] != "0016" || versions[16] != "0017" || versions[17] != "0018" || versions[18] != "0019" || versions[19] != "0020" || versions[20] != "0021" || versions[21] != "0022" || versions[22] != "0023" || versions[23] != "0024" || versions[24] != "0025" || versions[25] != "0026" || versions[26] != "0027" || versions[27] != "0028" || versions[28] != "0029" || versions[29] != "0030" || versions[30] != "0031" || versions[31] != "0032" || versions[32] != "0033" || versions[33] != "0034" || versions[34] != "0035" || versions[35] != "0036" || versions[36] != "0037" || versions[37] != "0038" || versions[38] != "0039" || versions[39] != "0040" || versions[40] != "0041" || versions[41] != "0042" {
		t.Fatalf("迁移历史 = %v，期望 [0001 0002 0003 0004 0005 0006 0007 0008 0009 0010 0011 0012]", versions)
	}

	infoRows, err := env.sqliteStore.QueryContext(context.Background(),
		`SELECT name,type,"notnull" FROM pragma_table_info('one_time_credentials')`)
	if err != nil {
		t.Fatalf("读取表结构失败: %v", err)
	}
	defer infoRows.Close()
	type columnInfo struct {
		kind    string
		notNull int
	}
	columns := make(map[string]columnInfo)
	for infoRows.Next() {
		var name string
		var info columnInfo
		if err := infoRows.Scan(&name, &info.kind, &info.notNull); err != nil {
			t.Fatalf("扫描表结构失败: %v", err)
		}
		columns[name] = info
	}
	if info, ok := columns["verifier_hash"]; !ok || info.kind != "BLOB" || info.notNull != 1 {
		t.Fatalf("verifier_hash 列 = %+v，期望 BLOB NOT NULL", info)
	}
	if info, ok := columns["subject_id"]; !ok || info.kind != "TEXT" || info.notNull != 1 {
		t.Fatalf("subject_id 列 = %+v，期望 TEXT NOT NULL", info)
	}
	if _, ok := columns["key_id"]; !ok {
		t.Fatal("缺少 key_id 列")
	}
}

// TestInsertAndLoadRoundTrip 验证记录写入与读取的字段往返，以及摘要唯一约束。
func TestInsertAndLoadRoundTrip(t *testing.T) {
	env := newTestEnv(t, envConfig{})
	createdAt := testBaseTime
	expiresAt := testBaseTime.Add(10 * time.Minute)
	record := testRecord("otc_00000000000000000000000000000001", "email.verify", "user-1", "",
		testVerifierHash(1), "k1", 5, createdAt, expiresAt)
	if err := env.store.Insert(context.Background(), record); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	loaded, found, err := env.store.LoadByID(context.Background(), record.ID)
	if err != nil || !found {
		t.Fatalf("读取失败: found=%v err=%v", found, err)
	}
	if loaded.Purpose != record.Purpose || loaded.Target != record.Target ||
		loaded.AppID != "" || loaded.KeyID != "k1" ||
		loaded.Attempts != 0 || loaded.MaxAttempts != 5 {
		t.Fatalf("读取字段不一致: %+v", loaded)
	}
	if !loaded.CreatedAt.Equal(createdAt) || !loaded.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("读取时间不一致: %s %s", loaded.CreatedAt, loaded.ExpiresAt)
	}
	if loaded.ConsumedAt != nil || loaded.RevokedAt != nil {
		t.Fatal("新记录不应有消费/撤销时间")
	}
	// 相同摘要重复写入必须失败（唯一约束）。
	if err := env.store.Insert(context.Background(), record); err == nil {
		t.Fatal("重复摘要写入未被拒绝")
	}
	// 不存在的记录返回 found=false 而不是错误。
	if _, found, err := env.store.LoadByID(context.Background(), "otc_000000000000000000000000000000ff"); err != nil || found {
		t.Fatalf("不存在记录 = found %v, err %v", found, err)
	}
}

// TestApplicationForeignKeyCascade 验证应用绑定外键在删除应用时级联清理凭证。
func TestApplicationForeignKeyCascade(t *testing.T) {
	env := newTestEnv(t, envConfig{})
	env.insertApplication(testAppA)
	record := testRecord("otc_00000000000000000000000000000002", "email.verify", "user-1", testAppA,
		testVerifierHash(2), "k1", 5, testBaseTime, testBaseTime.Add(time.Hour))
	if err := env.store.Insert(context.Background(), record); err != nil {
		t.Fatalf("写入带应用绑定凭证失败: %v", err)
	}
	if _, found, err := env.store.LoadByID(context.Background(), record.ID); err != nil || !found {
		t.Fatalf("读取失败: found=%v err=%v", found, err)
	}
	if _, err := env.sqliteStore.ExecContext(context.Background(), `DELETE FROM applications WHERE id=?`, testAppA); err != nil {
		t.Fatalf("删除测试应用失败: %v", err)
	}
	if _, found, err := env.store.LoadByID(context.Background(), record.ID); err != nil || found {
		t.Fatalf("删除应用后凭证仍存在: found=%v err=%v", found, err)
	}
}

// TestReplaceActiveAndInsert 验证替换在事务内撤销同作用域旧凭证并插入新记录。
func TestReplaceActiveAndInsert(t *testing.T) {
	env := newTestEnv(t, envConfig{})
	scope := struct{ purpose, target, appID string }{"email.verify", "user-1", ""}
	oldOne := testRecord("otc_00000000000000000000000000000003", scope.purpose, scope.target, scope.appID,
		testVerifierHash(3), "", 5, testBaseTime, testBaseTime.Add(time.Hour))
	oldTwo := testRecord("otc_00000000000000000000000000000004", scope.purpose, scope.target, scope.appID,
		testVerifierHash(4), "", 5, testBaseTime, testBaseTime.Add(time.Hour))
	otherScope := testRecord("otc_00000000000000000000000000000005", scope.purpose, "user-2", "",
		testVerifierHash(5), "", 5, testBaseTime, testBaseTime.Add(time.Hour))
	for _, record := range []credential.Record{oldOne, oldTwo, otherScope} {
		if err := env.store.Insert(context.Background(), record); err != nil {
			t.Fatalf("写入旧凭证失败: %v", err)
		}
	}
	newRecord := testRecord("otc_00000000000000000000000000000006", scope.purpose, scope.target, scope.appID,
		testVerifierHash(6), "", 5, testBaseTime, testBaseTime.Add(time.Hour))
	if err := env.store.ReplaceActiveAndInsert(context.Background(), newRecord, testBaseTime); err != nil {
		t.Fatalf("替换写入失败: %v", err)
	}
	for _, id := range []string{oldOne.ID, oldTwo.ID} {
		loaded, found, err := env.store.LoadByID(context.Background(), id)
		if err != nil || !found {
			t.Fatalf("读取旧凭证失败: %v %v", found, err)
		}
		if loaded.RevokedAt == nil {
			t.Fatalf("旧凭证 %s 未被撤销", id)
		}
	}
	if other, found, err := env.store.LoadByID(context.Background(), otherScope.ID); err != nil || !found || other.RevokedAt != nil {
		t.Fatalf("其它作用域凭证被错误撤销: %+v %v %v", other, found, err)
	}
	if loaded, found, err := env.store.LoadByID(context.Background(), newRecord.ID); err != nil || !found || loaded.RevokedAt != nil {
		t.Fatalf("新凭证状态错误: %+v %v %v", loaded, found, err)
	}
}

// TestConsumeConditional 验证条件消费只在活动、未过期且绑定一致时成功一次。
func TestConsumeConditional(t *testing.T) {
	env := newTestEnv(t, envConfig{})
	record := testRecord("otc_00000000000000000000000000000007", "email.verify", "user-1", "",
		testVerifierHash(7), "", 5, testBaseTime, testBaseTime.Add(time.Hour))
	if err := env.store.Insert(context.Background(), record); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	condition := credential.ConsumeCondition{ID: record.ID, Purpose: record.Purpose, Target: record.Target, Now: testBaseTime}
	ok, err := env.store.Consume(context.Background(), condition)
	if err != nil || !ok {
		t.Fatalf("首次消费 = %v, %v", ok, err)
	}
	ok, err = env.store.Consume(context.Background(), condition)
	if err != nil || ok {
		t.Fatalf("重复消费 = %v, %v", ok, err)
	}
	wrongBinding := condition
	wrongBinding.Target = "user-2"
	if ok, err := env.store.Consume(context.Background(), wrongBinding); err != nil || ok {
		t.Fatalf("错误绑定消费 = %v, %v", ok, err)
	}

	expired := testRecord("otc_00000000000000000000000000000008", "email.verify", "user-3", "",
		testVerifierHash(8), "", 5, testBaseTime.Add(-2*time.Hour), testBaseTime.Add(-time.Hour))
	if err := env.store.Insert(context.Background(), expired); err != nil {
		t.Fatalf("写入过期凭证失败: %v", err)
	}
	if ok, err := env.store.Consume(context.Background(), credential.ConsumeCondition{
		ID: expired.ID, Purpose: expired.Purpose, Target: expired.Target, Now: testBaseTime,
	}); err != nil || ok {
		t.Fatalf("过期凭证消费 = %v, %v", ok, err)
	}
}

// TestRecordFailedAttemptBounded 验证失败尝试在数据库层有界，不超过 max_attempts。
func TestRecordFailedAttemptBounded(t *testing.T) {
	env := newTestEnv(t, envConfig{})
	record := testRecord("otc_00000000000000000000000000000009", "email.verify", "user-1", "",
		testVerifierHash(9), "k1", 2, testBaseTime, testBaseTime.Add(time.Hour))
	if err := env.store.Insert(context.Background(), record); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	first, err := env.store.RecordFailedAttempt(context.Background(), record.ID, testBaseTime)
	if err != nil || first.Remaining != 1 || !first.Active {
		t.Fatalf("第一次失败尝试 = %+v, %v", first, err)
	}
	second, err := env.store.RecordFailedAttempt(context.Background(), record.ID, testBaseTime)
	if err != nil || second.Remaining != 0 || second.Active {
		t.Fatalf("第二次失败尝试 = %+v, %v", second, err)
	}
	third, err := env.store.RecordFailedAttempt(context.Background(), record.ID, testBaseTime)
	if err != nil || third.Remaining != 0 || third.Active {
		t.Fatalf("超限后失败尝试 = %+v, %v", third, err)
	}
	if attempts, maxAttempts, _, _, _ := env.rowState(record.ID); attempts != 2 || maxAttempts != 2 {
		t.Fatalf("尝试次数 = %d/%d，期望 2/2", attempts, maxAttempts)
	}
}

// TestRevokeConditional 验证撤销只在活动且绑定一致时成功一次。
func TestRevokeConditional(t *testing.T) {
	env := newTestEnv(t, envConfig{})
	record := testRecord("otc_00000000000000000000000000000010", "email.verify", "user-1", "",
		testVerifierHash(10), "", 5, testBaseTime, testBaseTime.Add(time.Hour))
	if err := env.store.Insert(context.Background(), record); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	wrong := credential.RevokeCondition{ID: record.ID, Purpose: record.Purpose, Target: "user-2", Now: testBaseTime}
	if ok, err := env.store.Revoke(context.Background(), wrong); err != nil || ok {
		t.Fatalf("错误绑定撤销 = %v, %v", ok, err)
	}
	right := credential.RevokeCondition{ID: record.ID, Purpose: record.Purpose, Target: record.Target, Now: testBaseTime}
	if ok, err := env.store.Revoke(context.Background(), right); err != nil || !ok {
		t.Fatalf("正确撤销 = %v, %v", ok, err)
	}
	if ok, err := env.store.Revoke(context.Background(), right); err != nil || ok {
		t.Fatalf("重复撤销 = %v, %v", ok, err)
	}
	// 已过期凭证不再属于可撤销的活动凭证。
	expired := testRecord("otc_00000000000000000000000000000013", "email.verify", "user-3", "",
		testVerifierHash(13), "", 5, testBaseTime.Add(-2*time.Hour), testBaseTime.Add(-time.Hour))
	if err := env.store.Insert(context.Background(), expired); err != nil {
		t.Fatalf("写入过期凭证失败: %v", err)
	}
	expiredCondition := credential.RevokeCondition{
		ID: expired.ID, Purpose: expired.Purpose, Target: expired.Target, Now: testBaseTime,
	}
	if ok, err := env.store.Revoke(context.Background(), expiredCondition); err != nil || ok {
		t.Fatalf("过期凭证撤销 = %v, %v", ok, err)
	}
}

// TestDeleteExpired 验证清理只删除过期时间不晚于截止时间的记录。
func TestDeleteExpired(t *testing.T) {
	env := newTestEnv(t, envConfig{})
	expired := testRecord("otc_00000000000000000000000000000011", "email.verify", "user-1", "",
		testVerifierHash(11), "", 5, testBaseTime.Add(-2*time.Hour), testBaseTime.Add(-time.Hour))
	active := testRecord("otc_00000000000000000000000000000012", "email.verify", "user-2", "",
		testVerifierHash(12), "", 5, testBaseTime, testBaseTime.Add(time.Hour))
	for _, record := range []credential.Record{expired, active} {
		if err := env.store.Insert(context.Background(), record); err != nil {
			t.Fatalf("写入失败: %v", err)
		}
	}
	deleted, err := env.store.DeleteExpired(context.Background(), testBaseTime)
	if err != nil || deleted != 1 {
		t.Fatalf("清理结果 = %d, %v", deleted, err)
	}
	if _, found, err := env.store.LoadByID(context.Background(), expired.ID); err != nil || found {
		t.Fatalf("过期凭证未被删除: found=%v err=%v", found, err)
	}
	if _, found, err := env.store.LoadByID(context.Background(), active.ID); err != nil || !found {
		t.Fatalf("活动凭证被误删: found=%v err=%v", found, err)
	}
	deleted, err = env.store.DeleteExpired(context.Background(), testBaseTime)
	if err != nil || deleted != 0 {
		t.Fatalf("重复清理结果 = %d, %v", deleted, err)
	}
}
