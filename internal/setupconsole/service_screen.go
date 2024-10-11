package setupconsole

// 步骤 296 的服务协调画面（WS4）：只读状态 + 受控一键启动/停止本控制台子进程。
//
// 安全要点：
//   - 运行中状态来自单实例锁探测（serverapp 共享协议），不靠 PID 文件；
//   - 启动前要求配置有效且协调计划动作是 start；启动动作需二次按键确认；
//   - 停止只作用于本控制台自己启动的子进程，从不按 PID 停止其他进程；
//   - 任何失败都显示原因并保持停止，不自动对外开放。

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ServiceScreen 是服务状态与一键启动画面。
type ServiceScreen struct {
	supervisor *ServiceSupervisor
	probe      InstanceProbe
	info       ServiceRuntimeInfo
	message    string
	errText    string
	// pendingStart 表示已请求启动，等待再次按 s 确认（防止误触）。
	pendingStart bool
	// originalRunning 记录执行协调动作前的真实运行状态，便于失败后说明原状态。
	originalRunning bool
}

// NewServiceScreen 创建服务协调画面。
func NewServiceScreen() *ServiceScreen {
	return &ServiceScreen{supervisor: NewServiceSupervisor()}
}

// Title 实现 ScreenController。
func (s *ServiceScreen) Title() string { return "服务状态与一键启动（步骤 296）" }

// Render 实现 ScreenController：只写画布，不直接读写终端。
func (s *ServiceScreen) Render(ctx context.Context, canvas *Canvas, session SessionView) {
	width := canvas.Width()
	if width < 40 {
		width = 40
	}
	y := 0
	line := func(text string) {
		if y < canvas.Height() {
			canvas.Text(0, y, ws4ClipText(text, width))
			y++
		}
	}
	canvas.Clear()
	detection := session.Detection
	line("实例配置：" + ws4ValueOr(detection.ConfigPath, session.ConfigPath))
	line("数据库：" + ws4ValueOr(detection.DatabasePath, "（未检测到）"))
	runningText := "未知"
	if s.probe.Problem == "" {
		if s.probe.Running {
			runningText = "运行中（单实例锁被占用）"
		} else {
			runningText = "未运行"
		}
	}
	line("运行状态：" + runningText)
	if s.probe.Problem != "" {
		line("探测问题：" + s.probe.Problem)
	}
	if s.info.PublicURL != "" {
		line("公开地址：" + s.info.PublicURL)
	}
	if len(s.info.Addresses) > 0 {
		line("监听地址：" + strings.Join(s.info.Addresses, ", "))
	}
	tlsText := "未启用"
	if s.info.TLSEnabled {
		tlsText = "已启用"
	}
	line("TLS：" + tlsText)
	for _, cert := range s.info.TLSCertificates {
		if cert.Problem != "" {
			line("证书：" + cert.File + "（" + cert.Problem + "）")
			continue
		}
		line("证书：" + cert.File + " 到期 " + cert.NotAfter.Format("2006-01-02"))
	}
	for _, remaining := range s.info.RemainingSetup {
		line("剩余初始化：" + remaining)
	}
	for _, note := range s.info.Notes {
		line("提示：" + note)
	}
	if s.supervisor.Running() {
		line("控制台子进程：已启动（停止只作用于该子进程）")
	} else {
		if s.originalRunning {
			line("原启停状态：进入本画面前实例处于运行中")
		} else {
			line("原启停状态：进入本画面前实例未运行")
		}
		line("控制台子进程：无")
	}
	line(strings.Repeat("-", ws4MinInt(width, 60)))
	if s.errText != "" {
		line("错误：" + s.errText)
	}
	if s.message != "" {
		line(s.message)
	}
	if s.pendingStart {
		line("再次按 s 确认启动 login-server（其他键取消）")
	}
	line("c 检查实例状态；s 启动；x 停止本控制台子进程；Esc 返回")
}

// HandleKey 实现 ScreenController。
func (s *ServiceScreen) HandleKey(ctx context.Context, key Key, session SessionView) (bool, error) {
	if key.Kind == KeyEsc {
		return true, nil
	}
	if key.Kind != KeyRune {
		if s.pendingStart {
			s.pendingStart = false
			s.message = "已取消启动"
		}
		return false, nil
	}
	switch key.Rune {
	case 'c', 'C':
		s.pendingStart = false
		s.check(session)
	case 's', 'S':
		if s.pendingStart {
			s.pendingStart = false
			s.start(ctx, session)
			return false, nil
		}
		s.prepareStart(session)
	case 'x', 'X':
		s.pendingStart = false
		s.stop()
	}
	return false, nil
}

func (s *ServiceScreen) check(session SessionView) {
	s.errText = ""
	detection := session.Detection
	previous := s.probe
	s.probe = ProbeInstance(detection.DatabasePath)
	if previous.Problem == "" && previous.DatabasePath != "" {
		s.originalRunning = previous.Running
	} else {
		s.originalRunning = s.probe.Running
	}
	if detection.ConfigLoaded {
		s.info = DescribeServiceRuntime(detection.Config, s.probe, detection, detection.ConfigPath)
		if healthURL, hostHeader := BuildHealthURL(detection.Config); healthURL != "" {
			s.message = "健康探测地址：" + healthURL + ws4HostNote(hostHeader)
		}
	} else {
		s.info = ServiceRuntimeInfo{Running: s.probe.Running,
			ConfigPath: detection.ConfigPath, DatabasePath: detection.DatabasePath}
	}
}

func (s *ServiceScreen) prepareStart(session SessionView) {
	s.errText = ""
	detection := session.Detection
	probe := ProbeInstance(detection.DatabasePath)
	s.probe = probe
	if !detection.ConfigLoaded {
		s.errText = "配置未成功加载：禁止用坏配置启动；请先修复/编辑配置"
		return
	}
	plan := PlanServiceCoordination(ServicePlanRequest{
		Probe: probe, ConfigValid: detection.ConfigLoaded,
	})
	if plan.Action != ServiceActionStart {
		s.errText = "当前不建议启动：" + strings.Join(plan.Reasons, "；")
		if len(plan.Blocking) > 0 {
			s.errText += "（" + strings.Join(plan.Blocking, "；") + "）"
		}
		return
	}
	if findLoginServerExecutable() == "" {
		s.errText = "未找到 login-server 可执行文件（应与 login-setup 位于同一目录）"
		return
	}
	s.pendingStart = true
	s.message = "启动将使用当前配置并等待 /healthz 就绪"
}

func (s *ServiceScreen) start(ctx context.Context, session SessionView) {
	s.errText = ""
	detection := session.Detection
	if !detection.ConfigLoaded {
		s.errText = "配置未成功加载：禁止启动"
		return
	}
	executable := findLoginServerExecutable()
	if executable == "" {
		s.errText = "未找到 login-server 可执行文件"
		return
	}
	maint, maintErr := s.serviceEvidence(session)
	if maintErr != nil {
		s.errText = "维护日志不可写，已阻止启动：" + ws4SafeErrorText(maintErr)
		return
	}
	if recordErr := maint.record(ctx, "service.start", "login-server", "started", ""); recordErr != nil {
		s.errText = "写入维护日志失败，已阻止启动：" + ws4SafeErrorText(recordErr)
		return
	}
	healthURL, hostHeader := BuildHealthURL(detection.Config)
	logPath := ""
	if detection.ConfigPath != "" {
		logPath = filepath.Join(filepath.Dir(detection.ConfigPath), "login-setup-service.log")
	}
	result, err := s.supervisor.Start(ctx, StartServiceRequest{
		Command: executable, ConfigPath: detection.ConfigPath,
		HealthURL: healthURL, HostHeader: hostHeader, LogPath: logPath,
	})
	if err != nil {
		s.errText = ws4SafeErrorText(err)
		return
	}
	if result.Error != "" {
		// 启动失败安全停止：若已产生本控制台子进程则终止它，保持停止状态。
		_ = s.supervisor.Stop(serviceStopDefaultGrace)
		_ = maint.record(ctx, "service.start", "login-server", "failed", "E_START")
		s.errText = result.Error
		return
	}
	_ = maint.record(ctx, "service.start", "login-server", "success", "")
	s.probe.Running = true
	s.message = "服务已启动并等待就绪：" + ws4ValueOr(healthURL, detection.ConfigPath)
}

func (s *ServiceScreen) stop() {
	s.errText = ""
	if !s.supervisor.Running() {
		s.message = "本控制台没有已启动的服务子进程"
		return
	}
	maint, maintErr := s.serviceEvidence(SessionView{})
	if err := s.supervisor.Stop(serviceStopDefaultGrace); err != nil {
		s.errText = ws4SafeErrorText(err)
		return
	}
	s.probe.Running = false
	s.message = "已停止本控制台启动的服务子进程（未触碰其他进程）"
	if maintErr != nil {
		s.message += "；维护日志不可写，停止证据未记录（停止动作已执行）"
		return
	}
	_ = maint.record(context.Background(), "service.stop", "login-server", "success", "")
}

// serviceEvidence 打开维护日志以记录服务启停证据；不持维护锁（启停需要允许主服务运行）。
func (s *ServiceScreen) serviceEvidence(session SessionView) (*ws4Maint, error) {
	configPath := session.Detection.ConfigPath
	if configPath == "" && s.info.ConfigPath != "" {
		configPath = s.info.ConfigPath
	}
	instanceDir, err := ws4InstanceDirForConfig(configPath)
	if err != nil {
		return nil, err
	}
	return openWS4Maint(instanceDir)
}

func ws4HostNote(hostHeader string) string {
	if strings.TrimSpace(hostHeader) == "" {
		return ""
	}
	return "（Host: " + hostHeader + "）"
}

// findLoginServerExecutable 在 login-setup 同目录寻找 login-server。
func findLoginServerExecutable() string {
	executable, err := os.Executable()
	if err != nil {
		return ""
	}
	dir := filepath.Dir(executable)
	name := "login-server"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	candidate := filepath.Join(dir, name)
	if info, statErr := os.Lstat(candidate); statErr == nil && info.Mode().IsRegular() {
		return candidate
	}
	return ""
}
