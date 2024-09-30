// Package e2e 是步骤 274 的自包含安全回归套件（Windows 短测试）。
//
// 目的：用**公开 Go 门面**（app.Open / Runtime.* / HTTP Handler）执行本轮直接管理与恢复
// 授权矩阵，覆盖已提交步骤；不导入被测领域包的内部状态来替代断言，更不绕过权限/会话/
// 两步验证。仅少数观测（如 pending 找回请求状态、OAuth 撤销 outbox）通过同一临时库的
// SQL 只读/夹具方式确认，因为公开门面暂未暴露相应查询入口。
//
// 原则：
//   - 全进程使用临时 SQLite + 临时主密钥，结束后由 t.TempDir 自动清理；
//   - 可控时钟用于 TOTP 与期限类断言，不等待真实时间；
//   - TOTP 验证码由本包按 RFC 6238 独立计算（等价用户的验证器 App），不使用测试旁路；
//   - 不输出任何口令、种子、会话秘密或令牌；失败消息只引用变量名。
//
// 分阶段：258/259/260（HTTP/CLI 直接管理入口、页面）合入后在本包追加对应入口矩阵；
// 当前阶段已覆盖公开 Go 门面的主体矩阵，未覆盖项在报告中列明。
package e2e

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	loginapp "github.com/kagurazakayashi/EvernightLogin/app"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

// testClock 是可推进的确定性时钟，供应用装配与 TOTP 计算共用。
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock(at time.Time) *testClock { return &testClock{now: at} }

// Now 实现 func() time.Time。
func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance 推进测试时钟。
func (c *testClock) Advance(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(duration)
}

// testConfig 返回启用自建注册、邮件关闭的默认配置（只用于临时库）。
func testConfig() login.Config {
	cfg := login.Default()
	cfg.Registration.Enabled = true
	cfg.Registration.RequireReview = false
	cfg.Registration.RequireEmailVerification = false
	return cfg
}

// harnessEnv 是一个自包含测试运行时的路径与句柄。
type harnessEnv struct {
	Runtime   *loginapp.Runtime
	Clock     *testClock
	Dir       string
	DBPath    string
	MasterKey string
	Config    login.Config
}

// openEnv 在独立临时目录打开真实运行时（临时 SQLite + 临时主密钥 + 可控时钟）。
func openEnv(t *testing.T) *harnessEnv {
	t.Helper()
	clock := newTestClock(time.Date(2026, 11, 26, 6, 0, 0, 0, time.UTC))
	dir := t.TempDir()
	cfg := testConfig()
	dbPath := filepath.Join(dir, "login.db")
	masterKey := filepath.Join(dir, "master.key")
	runtime, err := loginapp.Open(context.Background(), loginapp.Options{
		Config: &cfg, DatabasePath: dbPath, MasterKeyFile: masterKey,
		CreateMasterKey: true, Migrate: true, OperatorID: "step274-e2e-operator",
		Logger: slog.New(slog.NewTextHandler(io.Discard,
			&slog.HandlerOptions{Level: slog.LevelError + 1})),
		Now: clock.Now,
	})
	if err != nil {
		t.Fatalf("打开测试运行时: %v", err)
	}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	return &harnessEnv{Runtime: runtime, Clock: clock, Dir: dir, DBPath: dbPath,
		MasterKey: masterKey, Config: cfg}
}

// openRuntime 是 openEnv 的便捷包装：运行时、可控时钟与临时数据库路径。
func openRuntime(t *testing.T) (*loginapp.Runtime, *testClock, string) {
	t.Helper()
	env := openEnv(t)
	return env.Runtime, env.Clock, env.DBPath
}

// ensureRoot 完成首次 root 初始化并返回 root 用户。
func ensureRoot(t *testing.T, runtime *loginapp.Runtime) loginapp.RootResult {
	t.Helper()
	root, err := runtime.Bootstrap().EnsureRoot(context.Background(), loginapp.RootRequest{
		DisplayName: "Root", Password: "V7!qZ2#Lm9@Tp4$x",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("root 初始化: %v", err)
	}
	return root
}

// createUser 创建普通用户并返回脱敏用户视图。
func createUser(t *testing.T, runtime *loginapp.Runtime, username, password string) loginapp.User {
	t.Helper()
	user, err := runtime.Users().Create(context.Background(), loginapp.CreateUserRequest{
		Username: username, Password: password, Nickname: username,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建用户 %s: %v", username, err)
	}
	return user
}

// loginFull 用密码登录；无第二因素时返回完整会话。
func loginFull(t *testing.T, runtime *loginapp.Runtime, username, password string) loginapp.LoginResult {
	t.Helper()
	result, err := runtime.Auth().Login(context.Background(), loginapp.LoginRequest{
		Username: username, Password: password, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("登录 %s: %v", username, err)
	}
	return result
}

// loginWithTOTP 用已绑定 TOTP 的账户登录并完成第二因素，返回完整会话秘密。
func loginWithTOTP(t *testing.T, runtime *loginapp.Runtime, clock *testClock,
	username, password, totpSecret string) []byte {
	t.Helper()
	ctx := context.Background()
	clock.Advance(30 * time.Second)
	result, err := runtime.Auth().Login(ctx, loginapp.LoginRequest{
		Username: username, Password: password, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("登录 %s: %v", username, err)
	}
	if !result.Restricted && len(result.SessionSecret) > 0 {
		return result.SessionSecret
	}
	if result.SecondFactor == nil {
		t.Fatalf("登录 %s 受限但缺少第二因素挑战: %+v", username, result)
	}
	verified, err := runtime.Auth().VerifySecondFactor(ctx, loginapp.VerifySecondFactorRequest{
		SessionSecret: result.SessionSecret,
		ChallengeID:   result.SecondFactor.ChallengeID,
		AttemptToken:  result.SecondFactor.AttemptToken,
		Code:          totpCode(t, clock, totpSecret), RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("验证 %s 第二因素: %v", username, err)
	}
	return verified.SessionSecret
}

// enrollTOTP 创建用户、真实完成 TOTP 绑定并返回用户与种子。
func enrollTOTP(t *testing.T, runtime *loginapp.Runtime, clock *testClock,
	username, password string) (loginapp.User, string) {
	t.Helper()
	ctx := context.Background()
	user := createUser(t, runtime, username, password)
	result := loginFull(t, runtime, username, password)
	if result.Restricted || len(result.SessionSecret) == 0 {
		t.Fatalf("无因素账户首次登录应得到完整会话: %+v", result)
	}
	start, err := runtime.Security().BeginTOTPBinding(ctx, loginapp.TOTPBindingBeginRequest{
		SessionSecret: result.SessionSecret, Password: password,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("开始绑定 TOTP: %v", err)
	}
	if start.Secret == "" || start.BindingID == "" {
		t.Fatalf("TOTP 绑定开始结果不完整: %+v", start)
	}
	if _, err := runtime.Security().ConfirmTOTPBinding(ctx,
		loginapp.TOTPBindingConfirmRequest{SessionSecret: result.SessionSecret,
			BindingID: start.BindingID, Code: totpCode(t, clock, start.Secret),
			RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("确认 TOTP 绑定: %v", err)
	}
	return user, start.Secret
}

// totpCode 按 RFC 6238（SHA-1/6 位/30 秒）从种子计算当前验证码。
func totpCode(t *testing.T, clock *testClock, encodedSecret string) string {
	t.Helper()
	normalized := strings.ToUpper(strings.TrimSpace(encodedSecret))
	normalized = strings.TrimRight(normalized, "=")
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(normalized)
	if err != nil {
		t.Fatalf("解码测试 TOTP 种子: %v", err)
	}
	counter := uint64(clock.Now().Unix() / 30)
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)
	mac := hmac.New(sha1.New, secret)
	mac.Write(counterBytes[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[offset])&0x7f)<<24 | uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 | uint32(sum[offset+3])
	return fmt.Sprintf("%06d", code%1000000)
}

// executeSQL 在临时库执行夹具 SQL（仅测试准备，不作为断言旁路）。
func executeSQL(t *testing.T, dbPath string, queries ...string) {
	t.Helper()
	ctx := context.Background()
	store, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(dbPath))
	if err != nil {
		t.Fatalf("打开测试数据库: %v", err)
	}
	defer func() { _ = store.Close() }()
	for _, query := range queries {
		if _, err := store.DB().ExecContext(ctx, query); err != nil {
			t.Fatalf("夹具 SQL 失败: %v", err)
		}
	}
}

// queryOne 在临时库执行单行查询并把结果扫描到目标。
func queryOne(t *testing.T, dbPath, query string, args []any, dest ...any) {
	t.Helper()
	ctx := context.Background()
	store, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(dbPath))
	if err != nil {
		t.Fatalf("打开测试数据库: %v", err)
	}
	defer func() { _ = store.Close() }()
	if err := store.DB().QueryRowContext(ctx, query, args...).Scan(dest...); err != nil {
		t.Fatalf("观测查询失败: %v", err)
	}
}

// userRowVersion 读取目标用户资料行版本（更名乐观并发要求；公开 AdminUser 不暴露）。
func userRowVersion(t *testing.T, dbPath, userID string) int64 {
	t.Helper()
	var version int64
	queryOne(t, dbPath, `SELECT row_version FROM users WHERE id=?`,
		[]any{userID}, &version)
	return version
}

// changeUsername 用当前行版本执行直接改名（把“读取版本+调用”收敛到一个夹具助手）。
func changeUsername(t *testing.T, runtime *loginapp.Runtime, dbPath string,
	caller loginapp.AdminCaller, targetUserID, newUsername, reason, proofToken string) (
	loginapp.AdminUserProfile, error) {
	t.Helper()
	return runtime.DirectUserManagement().ChangeUserUsername(context.Background(),
		loginapp.AdminChangeUserUsernameRequest{Caller: caller, TargetUserID: targetUserID,
			NewUsername: newUsername, ExpectedRowVersion: userRowVersion(t, dbPath, targetUserID),
			Reason: reason, ProofToken: proofToken, RequestID: login.NewRequestID()})
}

// effectivePermissionContains 分页读取有效权限并判断是否包含指定权限键。
func effectivePermissionContains(t *testing.T, runtime *loginapp.Runtime, userID,
	scopeID, wantKey string) bool {
	t.Helper()
	for offset := 0; offset < 2000; offset += 100 {
		effective, err := runtime.Admin().EffectivePermissions(context.Background(),
			loginapp.AdminPermissionQuery{Caller: runtime.LocalAdmin(), UserID: userID,
				ScopeID: scopeID, Limit: 100, Offset: offset,
				RequestID: login.NewRequestID()})
		if err != nil {
			t.Fatalf("EffectivePermissions(%s,%s) offset=%d: %v", userID, wantKey, offset, err)
		}
		if effective.DeniedCode != "" {
			t.Fatalf("有效权限查询被拒绝: %s", effective.DeniedCode)
		}
		for _, permission := range effective.Permissions {
			if permission.Key == wantKey {
				return true
			}
		}
		if len(effective.Permissions) < 100 {
			return false
		}
	}
	return false
}

// findOrCreateSystemPermission 查找或登记系统范围权限（预设可能已登记），返回权限视图。
func findOrCreateSystemPermission(t *testing.T, runtime *loginapp.Runtime,
	key string) loginapp.AdminPermission {
	t.Helper()
	ctx := context.Background()
	local := runtime.LocalAdmin()
	admin := runtime.Admin()
	find := func() (loginapp.AdminPermission, bool) {
		for offset := 0; offset < 2000; offset += 100 {
			list, listErr := admin.ListPermissions(ctx,
				loginapp.AdminListPermissionsRequest{Caller: local, ScopeID: "system",
					Page:      loginapp.AdminPage{Limit: 100, Offset: offset},
					RequestID: login.NewRequestID()})
			if listErr != nil {
				return loginapp.AdminPermission{}, false
			}
			for _, permission := range list.Permissions {
				if permission.Key == key {
					return permission, true
				}
			}
			if len(list.Permissions) < 100 {
				return loginapp.AdminPermission{}, false
			}
		}
		return loginapp.AdminPermission{}, false
	}
	if permission, ok := find(); ok {
		return permission
	}
	created, err := admin.CreatePermission(ctx, loginapp.AdminCreatePermissionRequest{
		Caller: local, ScopeID: "system", Key: key, Name: "步骤274回归权限",
		Description: "步骤274安全回归用权限", Limits: "仅用于测试",
		RequestID: login.NewRequestID()})
	if err != nil {
		// 并发或已存在：再查一次（避免测试因登记顺序产生误失败）。
		if permission, ok := find(); ok {
			return permission
		}
		t.Fatalf("登记系统权限 %s: %v", key, err)
	}
	return created
}

// grantSystemPermissions 通过受信管理通道创建角色并把指定权限授予用户。
func grantSystemPermissions(t *testing.T, runtime *loginapp.Runtime, userID string,
	roleKey string, permissionKeys ...string) loginapp.AdminRole {
	t.Helper()
	ctx := context.Background()
	local := runtime.LocalAdmin()
	admin := runtime.Admin()
	role, err := admin.CreateRole(ctx, loginapp.AdminCreateRoleRequest{
		Caller: local, ScopeID: "system", Key: roleKey, Name: "步骤274回归角色",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建角色 %s: %v", roleKey, err)
	}
	for _, key := range permissionKeys {
		permission := findOrCreateSystemPermission(t, runtime, key)
		if err := admin.AddRolePermission(ctx, loginapp.AdminRolePermissionRequest{
			Caller: local, RoleID: role.ID, PermissionID: permission.ID,
			RequestID: login.NewRequestID()}); err != nil {
			t.Fatalf("角色 %s 组合权限 %s: %v", roleKey, key, err)
		}
	}
	if err := admin.GrantApplicationRole(ctx, loginapp.GrantRoleRequest{
		Caller: local, UserID: userID, RoleID: role.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("授予用户 %s 角色 %s: %v", userID, roleKey, err)
	}
	return role
}

// checkPermission 通过公开管理查询判定权限（LocalAdmin 作为查询者）。
func checkPermission(t *testing.T, runtime *loginapp.Runtime, userID, permission string) bool {
	t.Helper()
	decision, err := runtime.Admin().CheckPermission(context.Background(),
		loginapp.AdminPermissionCheck{Caller: runtime.LocalAdmin(), UserID: userID,
			ScopeID: "system", Permission: permission, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("CheckPermission(%s): %v", permission, err)
	}
	return decision.Allowed
}

// accessAllowed 通过公开授权检查判定主体是否可用某权限。
func accessAllowed(t *testing.T, runtime *loginapp.Runtime, userID, permission string) bool {
	t.Helper()
	decision, err := runtime.Access().Check(context.Background(),
		loginapp.AccessRequest{UserID: userID, Permission: permission,
			RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("Access.Check(%s): %v", permission, err)
	}
	return decision.Allowed
}

// beginUsernameProof 通过公开证明门面完成一次“直接改他人用户名”的两步验证，返回证明令牌。
func beginUsernameProof(t *testing.T, runtime *loginapp.Runtime, clock *testClock,
	operatorSession []byte, operatorTOTPSecret, targetUserID, newUsername string) string {
	t.Helper()
	ctx := context.Background()
	proof := runtime.OperationProof()
	caller := runtime.AdminSession(operatorSession)
	challenge, err := proof.Begin(ctx, loginapp.OperationProofBeginRequest{
		Caller: caller, TargetUserID: targetUserID,
		Operation: loginapp.OperationProofUsernameChange, NewUsername: newUsername,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("发起直接改名证明: %v", err)
	}
	clock.Advance(30 * time.Second)
	grant, err := proof.Confirm(ctx, loginapp.OperationProofConfirmRequest{
		Caller: caller, ChallengeID: challenge.ChallengeID,
		Password: operatorPassword, TOTPCode: totpCode(t, clock, operatorTOTPSecret),
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("完成直接改名两步验证: %v", err)
	}
	return grant.ProofToken
}

// beginPasswordProof 通过公开证明门面完成一次“直接重置他人密码”的两步验证，返回证明令牌。
func beginPasswordProof(t *testing.T, runtime *loginapp.Runtime, clock *testClock,
	operatorSession []byte, operatorTOTPSecret, targetUserID, newPassword string) string {
	t.Helper()
	ctx := context.Background()
	proof := runtime.OperationProof()
	caller := runtime.AdminSession(operatorSession)
	challenge, err := proof.Begin(ctx, loginapp.OperationProofBeginRequest{
		Caller: caller, TargetUserID: targetUserID,
		Operation: loginapp.OperationProofPasswordReset, NewPassword: newPassword,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("发起直接重置口令证明: %v", err)
	}
	clock.Advance(30 * time.Second)
	grant, err := proof.Confirm(ctx, loginapp.OperationProofConfirmRequest{
		Caller: caller, ChallengeID: challenge.ChallengeID,
		Password: operatorPassword, TOTPCode: totpCode(t, clock, operatorTOTPSecret),
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("完成直接重置口令两步验证: %v", err)
	}
	return grant.ProofToken
}

// 合成测试口令（失败消息只引用变量名，不展开口令值）。
const (
	operatorPassword = "K8$wR3!nB6@yF1#v"
	targetPassword   = "M4$tY7!bN2@xQ9#p"
	directPasswordA  = "Qz7!vN9#Lp2@Rm5"
	directPasswordB  = "Ht5!cK8#Wn3@Pv6"
	weakPassword     = "password"
	finalPassword    = "Jr9!xB4#Ms7@Qd2"
)

var _ = fmt.Sprintf
