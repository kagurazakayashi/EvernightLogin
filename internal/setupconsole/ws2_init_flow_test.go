package setupconsole

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/config"
)

type ws2TestTerminal struct {
	width, height int
	writes        strings.Builder
	keys          []Key
	index         int
}

func (terminal *ws2TestTerminal) Init() error  { return nil }
func (terminal *ws2TestTerminal) Close() error { return nil }
func (terminal *ws2TestTerminal) Size() (int, int) {
	return terminal.width, terminal.height
}
func (terminal *ws2TestTerminal) Write(frame string) error {
	terminal.writes.WriteString(frame)
	return nil
}
func (terminal *ws2TestTerminal) ReadKey() (Key, error) {
	if terminal.index >= len(terminal.keys) {
		return Key{}, io.EOF
	}
	key := terminal.keys[terminal.index]
	terminal.index++
	return key, nil
}

func ws2TestDetection(cfg config.Config, configPath string) Detection {
	return Detection{Kind: StateReady, ConfigPath: configPath, ConfigLoaded: true,
		Config: cfg, DatabasePath: cfg.Database.Path}
}

func ws2TestConfigPath(instanceDir string) string {
	return filepath.Join(instanceDir, "login.yaml")
}

func TestInitializeRootAndReentry(t *testing.T) {
	instanceDir, cfg := setupWS2TempDB(t)
	configPath := ws2TestConfigPath(instanceDir)
	options := RootInitOptions{ConfigPath: configPath, InstanceDir: instanceDir,
		OperatorID: "test-operator", Purpose: "测试 root 创建"}
	result, err := InitializeRoot(context.Background(), cfg, RootInitRequest{GeneratePassword: true}, options)
	if err != nil {
		t.Fatalf("创建 root 失败: %v", err)
	}
	if !result.Created || !result.RootExists {
		t.Fatalf("应真实创建 root: %+v", result)
	}
	if result.GeneratedPassword == "" {
		t.Fatal("自动生成密码应一次性返回")
	}
	if !result.PendingStrongAuth || !result.StrongAuthRequired {
		t.Fatalf("强认证未配置时应保持受限: %+v", result)
	}
	if result.RootUsername != "root" {
		t.Fatalf("root 保留用户名应为 root，得到 %s", result.RootUsername)
	}
	// 再次进入但不重设：只读返回，不重新生成密码。
	second, err := InitializeRoot(context.Background(), cfg,
		RootInitRequest{GeneratePassword: true}, options)
	if err != nil {
		t.Fatalf("重入 root 状态失败: %v", err)
	}
	if !second.Reentry || second.GeneratedPassword != "" {
		t.Fatalf("重入应为只读且不回显旧密码: %+v", second)
	}
	// 明确重设密码：允许并重新一次性展示。
	reset, err := InitializeRoot(context.Background(), cfg,
		RootInitRequest{GeneratePassword: true, ResetExistingPassword: true}, options)
	if err != nil {
		t.Fatalf("本地重设 root 密码失败: %v", err)
	}
	if !reset.PasswordReset || reset.GeneratedPassword == "" {
		t.Fatalf("重设应返回新一次性密码: %+v", reset)
	}
}

func TestInitializeRootRejectsCustomUsername(t *testing.T) {
	instanceDir, cfg := setupWS2TempDB(t)
	_, err := InitializeRoot(context.Background(), cfg,
		RootInitRequest{Username: "another-root", GeneratePassword: true},
		RootInitOptions{ConfigPath: ws2TestConfigPath(instanceDir), InstanceDir: instanceDir,
			OperatorID: "test-operator"})
	if !errors.Is(err, ErrRootUsernameFixed) {
		t.Fatalf("应拒绝自定义 root 用户名，实际: %v", err)
	}
}

func TestInitializeRootRejectsWeakPassword(t *testing.T) {
	instanceDir, cfg := setupWS2TempDB(t)
	_, err := InitializeRoot(context.Background(), cfg,
		RootInitRequest{Password: "short"},
		RootInitOptions{ConfigPath: ws2TestConfigPath(instanceDir), InstanceDir: instanceDir,
			OperatorID: "test-operator"})
	if !errors.Is(err, ErrRootPasswordWeak) {
		t.Fatalf("应拒绝弱密码，实际: %v", err)
	}
}

func TestRecommendationProfilesAndApply(t *testing.T) {
	profiles := RecommendationProfiles()
	if len(profiles) != 3 {
		t.Fatalf("应有 3 套推荐方案，得到 %d", len(profiles))
	}
	instanceDir := t.TempDir()
	configPath := ws2TestConfigPath(instanceDir)
	plan, err := PlanRecommendation(configPath, "local")
	if err != nil {
		t.Fatalf("生成推荐计划失败: %v", err)
	}
	if !plan.Report.Valid {
		t.Fatalf("推荐配置应通过校验: %v", plan.Issues)
	}
	if !strings.Contains(string(plan.Raw), "127.0.0.1:8080") {
		t.Fatalf("本机方案应默认回环监听: %s", string(plan.Raw))
	}
	operatorID := "test-operator"
	result, err := ApplyRecommendation(context.Background(), plan, RecommendationApplyOptions{
		ConflictPolicy: ConflictFail, CreateBackup: true, InitializeDatabase: true,
		DBInit: DBInitOptions{InstanceDir: instanceDir, CreateMasterKey: true,
			OperatorID: operatorID, Purpose: "测试应用推荐配置"}})
	if err != nil {
		t.Fatalf("应用推荐配置失败: %v", err)
	}
	if !result.Saved || !result.DatabaseInited {
		t.Fatalf("应保存配置并完成数据库迁移: %+v", result)
	}
	if _, statErr := os.Stat(configPath); statErr != nil {
		t.Fatalf("配置文件应存在: %v", statErr)
	}
	assertNoRelativeDBArtifact(t)
	expectedDB := filepath.Join(instanceDir, "database", "login.db")
	if result.DBResult.DatabasePath != expectedDB {
		t.Fatalf("推荐配置数据库应落在实例临时目录，实际 %s", result.DBResult.DatabasePath)
	}
	if _, statErr := os.Stat(expectedDB); statErr != nil {
		t.Fatalf("实例目录内数据库应存在: %v", statErr)
	}
	// 重复应用必须幂等：保存后重新生成计划以匹配当前文件摘要。
	replanned, err := PlanRecommendation(configPath, "local")
	if err != nil {
		t.Fatalf("保存后重新生成推荐计划失败: %v", err)
	}
	second, err := ApplyRecommendation(context.Background(), replanned, RecommendationApplyOptions{
		ConflictPolicy: ConflictFail, CreateBackup: true, InitializeDatabase: true,
		DBInit: DBInitOptions{InstanceDir: instanceDir, CreateMasterKey: true,
			OperatorID: operatorID}})
	if err != nil {
		t.Fatalf("重复应用推荐配置失败: %v", err)
	}
	if !second.DBResult.AlreadyMigrated {
		t.Fatalf("重复应用迁移应幂等: %+v", second.DBResult)
	}
}

func TestRegisterWS2RegistersScreens(t *testing.T) {
	terminal := &ws2TestTerminal{width: 100, height: 30}
	app := NewApp(terminal, filepath.Join(t.TempDir(), "login.yaml"), nil)
	if err := RegisterWS2(app, WithWS2OperatorID("test-operator")); err != nil {
		t.Fatalf("注册 WS2 画面失败: %v", err)
	}
	for _, id := range []string{"ws2-database", "ws2-root", "ws2-accounts", "ws2-recommend"} {
		if err := app.OpenScreen(id); err != nil {
			t.Fatalf("打开画面 %s 失败: %v", id, err)
		}
	}
	if err := RegisterWS2(app); !errors.Is(err, ErrScreenAlreadyInUse) {
		t.Fatalf("重复注册应返回已占用错误，实际: %v", err)
	}
	// 画面渲染不 panic 且包含标题。
	ctx := context.WithValue(context.Background(), struct{}{}, time.Now())
	_ = ctx
}

func TestEnsurePresetsAndCreateAccounts(t *testing.T) {
	instanceDir, cfg := setupWS2TempDB(t)
	configPath := ws2TestConfigPath(instanceDir)
	operatorID := "test-operator"
	if _, err := InitializeRoot(context.Background(), cfg, RootInitRequest{GeneratePassword: true},
		RootInitOptions{ConfigPath: configPath, InstanceDir: instanceDir,
			OperatorID: operatorID, Purpose: "测试 root 创建"}); err != nil {
		t.Fatalf("创建 root 失败: %v", err)
	}
	installed, err := EnsureSystemPresets(context.Background(), cfg, PresetInstallOptions{
		ConfigPath: configPath, InstanceDir: instanceDir, OperatorID: operatorID,
		Purpose: "测试预设安装"})
	if err != nil {
		t.Fatalf("安装系统预设失败: %v", err)
	}
	if !installed.Initialized && !installed.Upgraded && !installed.UpToDate {
		t.Fatalf("预设安装应返回真实状态: %+v", installed)
	}
	detection := ws2TestDetection(cfg, configPath)
	first, err := ApplyAccountScheme(context.Background(), detection,
		[]AccountDraft{{Username: "admin-one", SchemeKey: "system_admin", GeneratePassword: true}},
		AccountApplyOptions{ConfigPath: configPath, InstanceDir: instanceDir,
			OperatorID: operatorID, Purpose: "测试账户方案"})
	if err != nil {
		t.Fatalf("创建账户失败: %v", err)
	}
	if len(first.Accounts) != 1 || !first.Accounts[0].Created {
		t.Fatalf("应真实创建账户: %+v", first)
	}
	if first.Accounts[0].GeneratedPassword == "" {
		t.Fatal("自动生成临时密码应一次性返回")
	}
	if !first.Accounts[0].RequireChange {
		t.Fatal("临时密码必须要求首次登录改密")
	}
	if first.Accounts[0].UserID == "" || len(first.Accounts[0].RoleKeys) == 0 {
		t.Fatalf("账户应有稳定 ID 与角色: %+v", first.Accounts[0])
	}
	// 重复执行不覆盖已有口令/角色，只报告已存在。
	second, err := ApplyAccountScheme(context.Background(), detection,
		[]AccountDraft{{Username: "admin-one", SchemeKey: "system_admin", GeneratePassword: true}},
		AccountApplyOptions{ConfigPath: configPath, InstanceDir: instanceDir,
			OperatorID: operatorID})
	if err != nil {
		t.Fatalf("重复创建应幂等跳过: %v", err)
	}
	if len(second.Accounts) != 1 || !second.Accounts[0].SkippedExisting ||
		second.Accounts[0].GeneratedPassword != "" {
		t.Fatalf("重复执行应跳过且不回显新的临时密码: %+v", second)
	}
}

func TestAccountSchemeUnavailableDoesNotFakeRole(t *testing.T) {
	instanceDir, cfg := setupWS2TempDB(t)
	configPath := ws2TestConfigPath(instanceDir)
	operatorID := "test-operator"
	if _, err := InitializeRoot(context.Background(), cfg, RootInitRequest{GeneratePassword: true},
		RootInitOptions{ConfigPath: configPath, InstanceDir: instanceDir,
			OperatorID: operatorID}); err != nil {
		t.Fatalf("创建 root 失败: %v", err)
	}
	detection := ws2TestDetection(cfg, configPath)
	_, err := ApplyAccountScheme(context.Background(), detection,
		[]AccountDraft{{Username: "support-direct", SchemeKey: "support_direct_rename",
			GeneratePassword: true}},
		AccountApplyOptions{ConfigPath: configPath, InstanceDir: instanceDir,
			OperatorID: operatorID})
	if !errors.Is(err, ErrAccountSchemeUnavailable) {
		t.Fatalf("缺失角色模板方案必须明确不可用，实际: %v", err)
	}
}

func TestAllRecommendationProfilesApply(t *testing.T) {
	cases := []struct {
		key           string
		listen        string
		pendingNeeded bool
	}{
		{"local", "127.0.0.1:8080", false},
		{"intranet", "0.0.0.0:8080", true},
		{"embedding", "127.0.0.1:8080", true},
	}
	for _, testCase := range cases {
		t.Run(testCase.key, func(t *testing.T) {
			instanceDir := t.TempDir()
			configPath := ws2TestConfigPath(instanceDir)
			plan, err := PlanRecommendation(configPath, testCase.key)
			if err != nil {
				t.Fatalf("生成推荐计划失败: %v", err)
			}
			if !plan.Report.Valid {
				t.Fatalf("推荐配置必须通过正式校验: %v", plan.Issues)
			}
			if !strings.Contains(string(plan.Raw), testCase.listen) {
				t.Fatalf("方案监听地址应包含 %s: %s", testCase.listen, string(plan.Raw))
			}
			if testCase.pendingNeeded && len(plan.Pending) == 0 {
				t.Fatalf("方案 %s 应明确列出待配置项", testCase.key)
			}
			if testCase.key == "embedding" {
				joined := strings.Join(plan.Notes, " ")
				if !strings.Contains(joined, "不自动监听") {
					t.Fatalf("嵌入方案应说明不自动监听: %v", plan.Notes)
				}
			}
			result, err := ApplyRecommendation(context.Background(), plan,
				RecommendationApplyOptions{ConflictPolicy: ConflictFail, CreateBackup: true,
					InitializeDatabase: true,
					DBInit: DBInitOptions{InstanceDir: instanceDir, CreateMasterKey: true,
						OperatorID: "test-operator", Purpose: "测试推荐方案应用"}})
			if err != nil {
				t.Fatalf("应用推荐方案失败: %v", err)
			}
			if !result.Saved || !result.DatabaseInited {
				t.Fatalf("推荐方案应保存配置并完成数据库迁移: %+v", result)
			}
			report := LoadConfigReport(configPath)
			if !report.Valid {
				t.Fatalf("应用后配置文件应可重新加载: %+v", report.Issues)
			}
			if report.Config.Database.Driver != config.DatabaseDriverSQLite {
				t.Fatalf("推荐方案默认应为 SQLite: %s", report.Config.Database.Driver)
			}
			if _, statErr := os.Stat(configPath); statErr != nil {
				t.Fatalf("配置文件应存在: %v", statErr)
			}
			assertNoRelativeDBArtifact(t)
			expectedDB := filepath.Join(instanceDir, "database", "login.db")
			if result.DBResult.DatabasePath != expectedDB {
				t.Fatalf("推荐方案数据库应落在实例临时目录，实际 %s", result.DBResult.DatabasePath)
			}
			if _, statErr := os.Stat(expectedDB); statErr != nil {
				t.Fatalf("实例目录内数据库应存在: %v", statErr)
			}
		})
	}
}
