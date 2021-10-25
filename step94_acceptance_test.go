package login_test

// 步骤 94 验收探针：受控故障注入下的关键管理变更 fail-closed 规则。
//
// 注入方式（均在临时 SQLite + 全部迁移的隔离副本上，不碰 database/login.db）：
//  1. 数据库锁：从同一连接池取一条独立连接执行 BEGIN IMMEDIATE，模拟另一进程持有
//     写锁；对真实 role.Service 发起关键变更（创建应用角色）。
//  2. 数据库不可用：显式关闭底层存储后发起同一关键变更。
//
// 期望（关键安全保证）：
//   - 关键变更返回可诊断错误，不 panic、不伪造成功；
//   - 故障期间数据库真实状态不变（没有半提交角色），也没有虚假的成功审计记录；
//   - 锁释放后同一变更可以正常提交（证明失败来自注入的暂时故障，而非实现假失败）。
//
// 边界：测试进程内真实 role/audit/存储实现；未部署独立服务、不杀无关进程、不访问网络。

import (
	"context"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/role"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

// step94RoleKey 是本探针创建的唯一角色机器标识。
const step94RoleKey = "step94_fault_probe_role"

// countStep94Role 统计指定角色键在应用 A 下真实存在的行数。
func countStep94Role(t *testing.T, env *step91Env) int {
	t.Helper()
	return env.dbCount(t, `SELECT COUNT(*) FROM roles WHERE scope_id=? AND role_key=?`,
		env.appA, step94RoleKey)
}

// countStep94RoleCreateSuccess 统计 role.create 成功审计条数（用于证明故障期间
// 没有“无真实变更却成功”的审计记录）。
func countStep94RoleCreateSuccess(t *testing.T, env *step91Env) int {
	t.Helper()
	return env.auditCount(t, string(role.ActionCreateRole), "success")
}

// step94CreateRequest 构造创建应用 A 角色的合法请求。
func step94CreateRequest() role.CreateRequest {
	return role.CreateRequest{ScopeID: "PLACEHOLDER", Key: step94RoleKey,
		Name: "步骤94 故障注入探针角色", Description: "仅测试", Limits: "仅步骤94 故障注入测试使用"}
}

// TestStep94DatabaseLockBlocksCriticalChangeFailClosed 验证数据库写锁下关键管理
// 变更 fail-closed：错误可诊断、无半提交、无虚假成功审计；释放锁后正常提交。
func TestStep94DatabaseLockBlocksCriticalChangeFailClosed(t *testing.T) {
	env := newStep91Env(t)
	caller := mustStep91RoleUserCaller(t, env.adminA)

	if got := countStep94Role(t, env); got != 0 {
		t.Fatalf("前置：角色键不应存在，实际 %d 行", got)
	}
	successBefore := countStep94RoleCreateSuccess(t, env)

	// 模拟另一持有者取得 SQLite 写锁（WAL 下 IMMEDIATE 即写锁；读仍可继续）。
	conn, err := env.storage.DB().Conn(env.ctx)
	if err != nil {
		t.Fatalf("获取锁连接失败：%v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(env.ctx, `BEGIN IMMEDIATE`); err != nil {
		t.Fatalf("取得写锁失败：%v", err)
	}
	locked := true
	release := func() {
		if !locked {
			return
		}
		locked = false
		if _, err := conn.ExecContext(context.Background(), `ROLLBACK`); err != nil {
			t.Errorf("释放写锁失败：%v", err)
		}
	}
	defer release()

	// 故障期间：真实 role.Service 关键变更必须在有界时间内失败（不做无限重试）。
	attemptCtx, cancel := context.WithTimeout(env.ctx, 3*time.Second)
	defer cancel()
	started := time.Now()
	request := step94CreateRequest()
	request.ScopeID = env.appA
	_, err = env.roles.CreateRole(attemptCtx, caller, request)
	elapsed := time.Since(started)
	if err == nil {
		t.Fatalf("数据库被写锁占用时创建角色仍然成功（应 fail-closed）")
	}
	t.Logf("锁注入下关键变更被拒绝：elapsed=%v err=%v", elapsed.Round(time.Millisecond), err)
	// 有界说明：业务请求 ctx 3s 到期 + 失败审计独立补写 DefaultFailureAuditTimeout=5s，
	// 合计约 8s；这是设计上的有界 fail-closed（失败审计用 WithoutCancel 存活于取消之后），
	// 不是无界重试。此处给 15s 上限防止未来退化为无界等待。
	if elapsed > 15*time.Second {
		t.Fatalf("锁等待 %v 超过有界上限，存在无界重试风险", elapsed)
	}

	// 真实状态不变：没有半提交角色、没有虚假成功审计。
	if got := countStep94Role(t, env); got != 0 {
		t.Fatalf("故障期间出现半提交角色：%d 行", got)
	}
	if got := countStep94RoleCreateSuccess(t, env); got != successBefore {
		t.Fatalf("故障期间出现虚假成功审计：前 %d 条，后 %d 条", successBefore, got)
	}

	// 释放锁后同一变更必须正常提交（排除参数/权限等其它失败原因）。
	release()
	created, err := env.roles.CreateRole(env.ctx, caller, request)
	if err != nil {
		t.Fatalf("锁释放后同一关键变更仍失败：%v", err)
	}
	if created.ScopeID != env.appA || created.Key != step94RoleKey {
		t.Fatalf("创建结果异常：scope=%q key=%q", created.ScopeID, created.Key)
	}
	if got := countStep94Role(t, env); got != 1 {
		t.Fatalf("成功创建后角色行数 = %d，期望 1", got)
	}
	if got := countStep94RoleCreateSuccess(t, env); got != successBefore+1 {
		t.Fatalf("成功创建后 role.create 成功审计 = %d，期望 %d", got, successBefore+1)
	}
}

// TestStep94DatabaseUnavailableCriticalChangeFailClosed 验证数据库不可用时关键
// 管理变更 fail-closed：返回可诊断错误、无半提交、无虚假成功审计；库恢复后可提交。
func TestStep94DatabaseUnavailableCriticalChangeFailClosed(t *testing.T) {
	env := newStep91Env(t)
	caller := mustStep91RoleUserCaller(t, env.adminA)

	// 关闭前从真实连接读取库文件路径，供关闭后重开同一隔离副本校验。
	var dbPath string
	rows, err := env.storage.DB().QueryContext(env.ctx, `PRAGMA database_list`)
	if err != nil {
		t.Fatalf("读取数据库路径失败：%v", err)
	}
	for rows.Next() {
		var seq int
		var name, file string
		if err := rows.Scan(&seq, &name, &file); err != nil {
			_ = rows.Close()
			t.Fatalf("扫描数据库路径失败：%v", err)
		}
		if name == "main" {
			dbPath = file
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		t.Fatalf("遍历数据库路径失败：%v", err)
	}
	_ = rows.Close()
	if dbPath == "" {
		t.Fatalf("未能取得主库文件路径")
	}

	successBefore := countStep94RoleCreateSuccess(t, env)
	if err := env.storage.Close(); err != nil {
		t.Fatalf("关闭存储以注入不可用失败：%v", err)
	}

	request := step94CreateRequest()
	request.ScopeID = env.appA
	if _, err := env.roles.CreateRole(env.ctx, caller, request); err == nil {
		t.Fatalf("数据库不可用时创建角色仍然成功（应 fail-closed）")
	} else {
		t.Logf("不可用注入下关键变更被拒绝：err=%v", err)
	}

	// 重开同一数据库副本校验真实状态：没有半提交与虚假成功审计。
	reopened, err := storagesqlite.Open(context.Background(),
		storagesqlite.DefaultOptions(dbPath))
	if err != nil {
		t.Fatalf("重新打开隔离副本失败：%v", err)
	}
	defer func() { _ = reopened.Close() }()
	var roleRows, successAudit int
	if err := reopened.DB().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM roles WHERE scope_id=? AND role_key=?`,
		env.appA, step94RoleKey).Scan(&roleRows); err != nil {
		t.Fatalf("查询角色行数失败：%v", err)
	}
	if err := reopened.DB().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM audit_events WHERE action=? AND outcome='success'`,
		string(role.ActionCreateRole)).Scan(&successAudit); err != nil {
		t.Fatalf("查询审计条数失败：%v", err)
	}
	if roleRows != 0 {
		t.Fatalf("数据库不可用期间出现半提交角色：%d 行", roleRows)
	}
	if successAudit != successBefore {
		t.Fatalf("数据库不可用期间出现虚假成功审计：前 %d 条，后 %d 条", successBefore, successAudit)
	}

	// 同一连接池关闭后服务不得被悄悄“复活”；错误应可诊断而非静默成功。
	if _, err := env.roles.CreateRole(env.ctx, caller, request); err == nil {
		t.Fatalf("已关闭存储仍报告成功")
	} else {
		t.Logf("已关闭存储重复请求仍被拒绝（期望）：%v", err)
	}
}
