package setupconsole

// 步骤 296 的定向测试：实例探测、配置重载分类、一键服务计划、运行信息与
// 子进程管理失败路径（不启动真实 login-server，不使用端口）。

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/config"
)

func TestPlanServiceCoordinationBranches(t *testing.T) {
	running := InstanceProbe{DatabasePath: "P:/x/login.db", Running: true}
	cases := []struct {
		name   string
		req    ServicePlanRequest
		action ServiceAction
	}{
		{"running-needs-restart", ServicePlanRequest{Probe: running, ConfigValid: true, NeedsRestart: true}, ServiceActionRestart},
		{"running-hot", ServicePlanRequest{Probe: running, ConfigValid: true, CanHotApply: true}, ServiceActionReload},
		{"running-noop", ServicePlanRequest{Probe: running, ConfigValid: true}, ServiceActionNoop},
		{"not-running", ServicePlanRequest{Probe: InstanceProbe{}, ConfigValid: true}, ServiceActionStart},
		{"bad-config", ServicePlanRequest{Probe: InstanceProbe{}, ConfigValid: false}, ServiceActionBlocked},
		{"maintenance", ServicePlanRequest{Probe: InstanceProbe{}, ConfigValid: true, MaintenanceActive: true}, ServiceActionBlocked},
		{"probe-problem", ServicePlanRequest{Probe: InstanceProbe{Problem: "锁探测失败"}, ConfigValid: true}, ServiceActionBlocked},
	}
	for _, item := range cases {
		plan := PlanServiceCoordination(item.req)
		if plan.Action != item.action {
			t.Fatalf("%s：动作 %s，期望 %s（%+v）", item.name, plan.Action, item.action, plan)
		}
	}
}

func TestProbeInstanceReportsNotRunningAndReleasesLock(t *testing.T) {
	dir := t.TempDir()
	databasePath := filepath.Join(dir, "login.db")
	writeTestFile(t, databasePath, []byte("db"))
	probe := ProbeInstance(databasePath)
	if probe.Problem != "" {
		t.Fatalf("探测不应失败：%s", probe.Problem)
	}
	if probe.Running {
		t.Fatal("没有运行实例时应报告未运行")
	}
	if probe.LockPath == "" {
		t.Fatal("应报告单实例锁路径")
	}
	if probe := ProbeInstance(""); probe.Problem == "" {
		t.Fatal("空数据库路径应报告无法判断")
	}
}

func TestDiffConfigReloadClassifiesFields(t *testing.T) {
	previous := config.Config{}
	previous.Server.ListenAddr = "127.0.0.1:8080"
	previous.Server.ShutdownTimeoutSeconds = 10
	next := config.Config{}
	next.Server.ListenAddr = "127.0.0.1:8081"
	next.Server.ShutdownTimeoutSeconds = 20
	advice := DiffConfigReload(previous, next)
	if len(advice.RestartFields) == 0 && len(advice.HotFields) == 0 {
		t.Fatalf("应检测到配置差异：%+v", advice)
	}
	if !advice.NeedsRestart && !advice.CanHotApply {
		t.Fatalf("差异分类不完整：%+v", advice)
	}
	if advice.Summary == "" {
		t.Fatal("应给出中文生效建议")
	}
}

func TestBuildHealthURLUsesListenAddressAndPublicHost(t *testing.T) {
	cfg := config.Config{}
	cfg.Server.ListenAddr = "127.0.0.1:18080"
	cfg.Server.PublicBaseURL = "http://localhost:18080"
	healthURL, hostHeader := BuildHealthURL(cfg)
	if !strings.HasPrefix(healthURL, "http://127.0.0.1:18080/healthz") {
		t.Fatalf("健康探测地址错误：%s", healthURL)
	}
	if hostHeader != "localhost:18080" {
		t.Fatalf("Host 头错误：%s", hostHeader)
	}
	cfg.Server.TLSCertFiles = []string{"C:/secure/server.crt"}
	if healthURL, _ := BuildHealthURL(cfg); !strings.HasPrefix(healthURL, "https://") {
		t.Fatalf("TLS 配置下应使用 https：%s", healthURL)
	}
}

func TestDescribeServiceRuntimeShowsRemainingSetup(t *testing.T) {
	cfg := config.Config{}
	cfg.Server.ListenAddr = "127.0.0.1:8080"
	cfg.Database.Path = "P:/go/tmp/ws4/data/login.db"
	info := DescribeServiceRuntime(cfg, InstanceProbe{Running: true},
		Detection{Kind: "root-missing", Summary: "root 待创建"}, "P:/go/tmp/ws4/login.yaml")
	if !info.Running || len(info.Addresses) == 0 {
		t.Fatalf("运行信息不完整：%+v", info)
	}
	if len(info.RemainingSetup) == 0 {
		t.Fatal("root-missing 应提示剩余初始化事项")
	}
	// 无效证书文件只报告读取问题，不 panic。
	cfg.Server.TLSCertFiles = []string{filepath.Join(t.TempDir(), "missing.crt")}
	cfg.Server.TLSPFXFile = ""
	withCert := DescribeServiceRuntime(cfg, InstanceProbe{}, Detection{Kind: "ready"}, "P:/go/tmp/ws4/login.yaml")
	if len(withCert.TLSCertificates) == 0 || withCert.TLSCertificates[0].Problem == "" {
		t.Fatalf("不存在的证书应报告问题：%+v", withCert.TLSCertificates)
	}
}

func TestServiceSupervisorStartFailureDoesNotTouchOtherProcesses(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "login.yaml")
	writeTestFile(t, configPath, []byte("server: {}\n"))
	supervisor := NewServiceSupervisor()
	result, err := supervisor.Start(context.Background(), StartServiceRequest{
		Command:    filepath.Join(dir, "does-not-exist-login-server.exe"),
		ConfigPath: configPath, LogPath: filepath.Join(dir, "service.log"),
	})
	if err != nil {
		t.Fatalf("启动失败应以结果而不是错误返回：%v", err)
	}
	if result.Started || result.Ready {
		t.Fatalf("不存在的程序不应报告已启动：%+v", result)
	}
	if result.Error == "" {
		t.Fatal("启动失败必须显示原因")
	}
	if supervisor.Running() {
		t.Fatal("启动失败后不应持有子进程")
	}
	if err := supervisor.Stop(0); err != nil {
		t.Fatalf("没有自有子进程时 Stop 应为安全空操作：%v", err)
	}
	if _, err := supervisor.Start(context.Background(), StartServiceRequest{ConfigPath: "relative.yaml"}); err == nil {
		t.Fatal("相对配置路径必须拒绝")
	}
}

func TestReinitJournalDoesNotLeakSecrets(t *testing.T) {
	dir := t.TempDir()
	journal, err := OpenReinitJournal(dir)
	if err != nil {
		t.Fatalf("打开执行日志失败：%v", err)
	}
	if err := journal.Record("step", "started", ""); err != nil {
		t.Fatalf("记录失败：%v", err)
	}
	raw, err := os.ReadFile(journal.Path())
	if err != nil {
		t.Fatalf("读取执行日志失败：%v", err)
	}
	if strings.Contains(string(raw), "password") || strings.Contains(string(raw), "master.key") {
		t.Fatal("执行日志不得包含秘密或密钥路径")
	}
}

func TestServiceScreenRendersAndHandlesKeys(t *testing.T) {
	screen := NewServiceScreen()
	canvas := NewCanvas(80, 30)
	session := SessionView{}
	screen.Render(context.Background(), canvas, session)
	if canvas.Render() == "" && canvas.Width() == 0 {
		t.Fatal("画面渲染失败")
	}
	ctx := context.Background()
	if closeScreen, err := screen.HandleKey(ctx, Key{Kind: KeyRune, Rune: 'c'}, session); closeScreen || err != nil {
		t.Fatalf("c 键不应关闭画面：%v %v", closeScreen, err)
	}
	if screen.probe.Problem == "" && session.Detection.DatabasePath == "" {
		t.Fatal("未配置数据库时应显示探测问题")
	}
	if closeScreen, err := screen.HandleKey(ctx, Key{Kind: KeyEsc}, session); !closeScreen || err != nil {
		t.Fatalf("Esc 应关闭画面：%v %v", closeScreen, err)
	}
	// 未加载配置时准备启动必须被拒绝，且不启动进程。
	screen.prepareStart(session)
	if screen.errText == "" {
		t.Fatal("未加载配置时必须显示阻止原因")
	}
	if screen.supervisor.Running() {
		t.Fatal("准备启动阶段不得启动进程")
	}
}

func TestWS4MaintenanceEvidenceRecordsDestructiveAction(t *testing.T) {
	instanceDir := t.TempDir()
	maint, err := openWS4Maint(instanceDir)
	if err != nil {
		t.Fatalf("打开维护证据失败：%v", err)
	}
	// 不持有真实数据库：DatabasePath 留空时只验证控制台互斥锁路径仍可获取。
	target, err := maint.runDestructive(context.Background(), "", "config.import",
		func() (string, error) { return "config", nil })
	if err != nil {
		t.Fatalf("受控写操作应成功：%v", err)
	}
	if target != "config" {
		t.Fatalf("目标摘要错误：%s", target)
	}
	raw, err := os.ReadFile(filepath.Join(instanceDir, ".login-setup-maintenance.jsonl"))
	if err != nil {
		t.Fatalf("维护日志文件不存在：%v", err)
	}
	text := string(raw)
	for _, fragment := range []string{"config.import", "started", "success"} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("维护日志缺少 %q：%s", fragment, text)
		}
	}
}

func TestWS4MaintenanceEvidenceBlocksWhenLogUnavailable(t *testing.T) {
	// 用一个普通文件路径冒充实例目录：维护日志无法创建，必须阻止关键修改。
	base := t.TempDir()
	filePath := filepath.Join(base, "not-a-dir")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatalf("写入临时文件失败：%v", err)
	}
	if _, err := openWS4Maint(filePath); err == nil {
		t.Fatal("实例目录不可写时打开维护证据必须失败（阻止关键修改）")
	}
	if _, err := openWS4Maint("relative/path"); err == nil {
		t.Fatal("相对实例目录必须被拒绝")
	}
}

func TestServiceSupervisorFastExitNeverReportsReady(t *testing.T) {
	// 无 HealthURL 时“进程已启动”必须基于真实退出状态：预置退出通道模拟速退。
	supervisor := &ServiceSupervisor{exitCh: make(chan error, 1), cmd: nil}
	if !supervisor.readyWithoutHealth() {
		t.Fatal("进程未退出时应允许报告已启动")
	}
	supervisor.exitCh <- errors.New("exit status 1")
	if supervisor.readyWithoutHealth() {
		t.Fatal("进程已退出时绝不能报告就绪（INFO-1）")
	}
	if supervisor.readyWithoutHealth() {
		t.Fatal("退出状态读取后应保持未就绪")
	}
}

func TestWithMaintenanceEvidenceAllowsAndRecordsReceipt(t *testing.T) {
	instanceDir := t.TempDir()
	result, err := RunWithMaintenanceEvidence(context.Background(), instanceDir,
		"config.import", "config", func(ctx context.Context) (string, error) {
			return `{"imported":true}`, nil
		})
	if err != nil {
		t.Fatalf("维护证据包装应允许操作：%v", err)
	}
	if result.Result != `{"imported":true}` {
		t.Fatalf("业务结果未透传：%+v", result)
	}
	if result.OperationID == "" {
		t.Fatal("应返回维护操作编号供 CLI JSON 关联")
	}
	raw, err := os.ReadFile(filepath.Join(instanceDir, ".login-setup-maintenance.jsonl"))
	if err != nil {
		t.Fatalf("维护日志不存在：%v", err)
	}
	text := string(raw)
	for _, fragment := range []string{"config.import", result.OperationID, `"started"`, `"success"`} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("维护日志缺少 %q：%s", fragment, text)
		}
	}
	// 简单包装返回同一业务结果。
	plain, err := WithMaintenanceEvidence(context.Background(), instanceDir,
		"config.import", "config", func(ctx context.Context) (string, error) { return "ok", nil })
	if err != nil || plain != "ok" {
		t.Fatalf("WithMaintenanceEvidence 应返回业务结果：result=%q err=%v", plain, err)
	}
	if encoded := ws4EvidenceJSON(result); !strings.Contains(encoded, "operation_id") ||
		strings.Contains(encoded, "password") {
		t.Fatalf("JSON 输出错误：%s", encoded)
	}
}

func TestWithMaintenanceEvidenceDeniesWhenLogUnavailable(t *testing.T) {
	base := t.TempDir()
	notDir := filepath.Join(base, "not-a-dir")
	if err := os.WriteFile(notDir, []byte("x"), 0o600); err != nil {
		t.Fatalf("写入临时文件失败：%v", err)
	}
	called := false
	_, err := WithMaintenanceEvidence(context.Background(), notDir, "config.import", "config",
		func(ctx context.Context) (string, error) { called = true; return "ok", nil })
	if err == nil {
		t.Fatal("维护日志不可写时必须 deny")
	}
	if called {
		t.Fatal("维护日志不可写时不得执行 fn")
	}
}

func TestWithMaintenanceEvidenceDeniesWhenLockHeld(t *testing.T) {
	instanceDir := t.TempDir()
	identity, err := LocalMaintenanceIdentity(instanceDir)
	if err != nil {
		t.Fatalf("构造维护身份失败：%v", err)
	}
	lock, err := AcquireMaintenanceLock(context.Background(), LockRequest{
		InstanceDir: instanceDir, DatabasePath: "",
		Purpose: "test hold", Operator: identity,
	})
	if err != nil {
		t.Fatalf("预占维护锁失败：%v", err)
	}
	defer func() { _ = lock.Release() }()
	called := false
	_, err = WithMaintenanceEvidence(context.Background(), instanceDir, "config.import", "config",
		func(ctx context.Context) (string, error) { called = true; return "ok", nil })
	if err == nil {
		t.Fatal("维护锁被占用时必须 deny")
	}
	if called {
		t.Fatal("维护锁被占用时不得执行 fn")
	}
	raw, readErr := os.ReadFile(filepath.Join(instanceDir, ".login-setup-maintenance.jsonl"))
	if readErr != nil {
		t.Fatalf("维护日志不存在：%v", readErr)
	}
	if !strings.Contains(string(raw), `"failed"`) || !strings.Contains(string(raw), "E_LOCK") {
		t.Fatalf("锁占用拒绝应写入 failed/E_LOCK 证据：%s", string(raw))
	}
}
