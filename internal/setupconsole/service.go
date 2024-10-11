package setupconsole

// 步骤 296：配置应用后的服务协调与一键启动（WS4）。
//
// 职责与边界：
//   - 识别目标实例是否正在运行：复用 serverapp 的单实例数据库锁
//     （<db>.server.lock）做非破坏性探测；不依赖 PID 文件、不扫描/终止无关进程；
//   - 配置差异：复用 config.DiffReload 区分热重载项与必须重启项，分别返回结果；
//   - 一键启动/停止：只管理本控制台自己启动的子进程（持有 *exec.Cmd），停止只
//     作用于该子进程；无法确认归属的进程一律不杀；
//   - 失败安全：启动失败展示原因并保持停止；重载失败保留最后有效配置（保存由
//     WS1 280 负责）；维护失败不自动对外开放；
//   - 运行信息：实际监听地址、TLS/证书状态、配置/数据库位置与剩余初始化事项。

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/config"
	"github.com/kagurazakayashi/EvernightLogin/internal/serverapp"
)

const (
	// serviceStartupDefaultTimeout 是等待服务就绪的默认上限。
	serviceStartupDefaultTimeout = 20 * time.Second
	// serviceHealthProbeInterval 是就绪探测间隔。
	serviceHealthProbeInterval = 300 * time.Millisecond
	// serviceStopDefaultGrace 是停止子进程的默认等待上限。
	serviceStopDefaultGrace = 8 * time.Second
	// serviceLogMaxBytes 限制控制台捕获的服务日志大小。
	serviceLogMaxBytes int64 = 2 << 20
)

// InstanceProbe 是目标实例的运行状态探测结果。
type InstanceProbe struct {
	DatabasePath string `json:"database_path"`
	// Running 表示同一数据库已被另一个 login-server 实例占用。
	Running bool `json:"running"`
	// LockPath 是单实例锁路径（存在或预期路径）。
	LockPath string `json:"lock_path,omitempty"`
	// Problem 非空表示无法确定状态（例如路径/权限异常）。
	Problem string `json:"problem,omitempty"`
}

// ProbeInstance 非破坏性探测目标数据库是否已被运行中的实例占用。
//
// 实现复用 serverapp.AcquireInstanceLock：能取得锁说明当前无运行实例（立即释放）；
// 返回 ErrInstanceLocked 说明有实例在运行。探测失败只报告不确定，不当作“未运行”。
func ProbeInstance(databasePath string) InstanceProbe {
	trimmed := strings.TrimSpace(databasePath)
	probe := InstanceProbe{DatabasePath: trimmed}
	if trimmed == "" {
		probe.Problem = "未配置数据库路径，无法判断实例是否运行"
		return probe
	}
	if !filepath.IsAbs(trimmed) {
		probe.Problem = "数据库路径不是绝对路径，无法判断实例是否运行"
		return probe
	}
	probe.LockPath = filepath.Clean(trimmed) + serverapp.InstanceLockSuffix
	lock, err := serverapp.AcquireInstanceLock(filepath.Clean(trimmed))
	if err != nil {
		if errors.Is(err, serverapp.ErrInstanceLocked) {
			probe.Running = true
			return probe
		}
		probe.Problem = "实例锁探测失败：" + ws4SafeErrorText(err)
		return probe
	}
	lock.Release()
	return probe
}

// ReloadAdvice 是配置变化后的生效建议（文件保存与服务生效分别报告）。
type ReloadAdvice struct {
	HotFields     []string `json:"hot_fields,omitempty"`
	RestartFields []string `json:"restart_fields,omitempty"`
	// NeedsRestart 表示存在必须重启才能生效的字段。
	NeedsRestart bool `json:"needs_restart"`
	// CanHotApply 表示只有可热更新字段变化（仍需实际重载动作）。
	CanHotApply bool   `json:"can_hot_apply"`
	Summary     string `json:"summary"`
}

// DiffConfigReload 比较两份有效配置，区分热重载/必须重启字段。
func DiffConfigReload(previous, next config.Config) ReloadAdvice {
	diff := config.DiffReload(previous, next)
	advice := ReloadAdvice{
		HotFields:     append([]string(nil), diff.HotFields...),
		RestartFields: append([]string(nil), diff.RestartFields...),
		NeedsRestart:  len(diff.RestartFields) > 0,
		CanHotApply:   len(diff.RestartFields) == 0 && len(diff.HotFields) > 0,
	}
	switch {
	case diff.Empty():
		advice.Summary = "配置无变化：无需重载或重启"
	case advice.NeedsRestart:
		advice.Summary = "配置已保存，但包含必须重启才能生效的字段（重启前运行值仍是最后有效配置）"
	default:
		advice.Summary = "配置已保存；变更字段可热更新，仍需执行受控重载后才生效"
	}
	return advice
}

// ServiceAction 是一键服务的建议动作。
type ServiceAction string

const (
	ServiceActionNoop    ServiceAction = "noop"
	ServiceActionStart   ServiceAction = "start"
	ServiceActionRestart ServiceAction = "restart"
	ServiceActionReload  ServiceAction = "reload"
	ServiceActionBlocked ServiceAction = "blocked"
)

// ServicePlanRequest 是生成服务协调计划的输入。
type ServicePlanRequest struct {
	Probe InstanceProbe
	// ConfigValid 表示当前配置文件通过校验；坏配置不得启动第二个实例。
	ConfigValid bool
	// NeedsRestart 表示配置差异包含必须重启字段。
	NeedsRestart bool
	// CanHotApply 表示配置差异仅包含可热更新字段。
	CanHotApply bool
	// MaintenanceActive 表示当前处于维护状态（恢复/重新初始化等）。
	MaintenanceActive bool
}

// ServicePlan 是一键服务/重载建议与阻塞原因。
type ServicePlan struct {
	Action   ServiceAction `json:"action"`
	Reasons  []string      `json:"reasons"`
	Blocking []string      `json:"blocking,omitempty"`
	// RequiredSteps 是执行该动作的安全前置步骤。
	RequiredSteps []string `json:"required_steps,omitempty"`
}

// PlanServiceCoordination 依据实例探测、配置校验与维护状态给出安全动作建议。
//
// 不启动进程；只负责判断“该做什么/不能做什么”，执行由 ServiceSupervisor 与
// 集成层完成。
func PlanServiceCoordination(request ServicePlanRequest) ServicePlan {
	plan := ServicePlan{}
	if request.Probe.Problem != "" {
		plan.Action = ServiceActionBlocked
		plan.Blocking = append(plan.Blocking, "无法确认实例运行状态："+request.Probe.Problem)
		return plan
	}
	if request.MaintenanceActive {
		plan.Action = ServiceActionBlocked
		plan.Blocking = append(plan.Blocking,
			"实例处于维护状态：请先退出维护并完成恢复/初始化流程，再启动服务")
		return plan
	}
	if !request.ConfigValid {
		plan.Action = ServiceActionBlocked
		plan.Blocking = append(plan.Blocking,
			"配置未通过校验：禁止用坏配置启动第二个实例；请先修复配置")
		return plan
	}
	switch {
	case request.Probe.Running && request.NeedsRestart:
		plan.Action = ServiceActionRestart
		plan.Reasons = append(plan.Reasons,
			"实例正在运行且配置包含必须重启项：需受控停止本实例后重启")
		plan.RequiredSteps = []string{
			"确认停止的是目标实例（单实例锁/维护协议），不凭 PID 杀无关进程",
			"记录原启停状态；停止失败保持原状态并展示原因",
			"重启后探测 /healthz 并展示实际问题（地址/证书/剩余初始化）",
		}
	case request.Probe.Running && request.CanHotApply:
		plan.Action = ServiceActionReload
		plan.Reasons = append(plan.Reasons,
			"实例正在运行且仅有可热更新字段变化：执行受控重载，不重启进程")
		plan.RequiredSteps = []string{
			"通过服务自身受保护的重载入口触发，不直接改写运行中进程的内存配置",
			"重载失败保留最后有效配置并展示错误来源",
		}
	case request.Probe.Running:
		plan.Action = ServiceActionNoop
		plan.Reasons = append(plan.Reasons, "实例正在运行且配置无变化：无需操作")
	default:
		plan.Action = ServiceActionStart
		plan.Reasons = append(plan.Reasons, "未检测到运行实例：可一键启动")
		plan.RequiredSteps = []string{
			"校验配置与数据库可用性后启动",
			"等待 /healthz 就绪并展示实际访问地址；失败展示原因并保持停止",
		}
	}
	return plan
}

// ServiceSupervisor 管理由本控制台启动的 login-server 子进程。
//
// 只持有自己启动的 *exec.Cmd；停止只作用于该子进程。外部已有实例（单实例锁被
// 占用）不会被本类型停止或重启。
type ServiceSupervisor struct {
	mu        sync.Mutex
	cmd       *exec.Cmd
	exitCh    chan error
	exitErr   error
	startedAt time.Time
	address   string
	healthURL string
	logPath   string
}

// NewServiceSupervisor 创建服务进程管理器（尚未启动任何进程）。
func NewServiceSupervisor() *ServiceSupervisor { return &ServiceSupervisor{} }

// StartServiceRequest 是一键启动请求。
type StartServiceRequest struct {
	// Command 是 login-server 可执行文件路径（绝对路径或可解析命令）。
	Command string
	// ConfigPath 是实例配置绝对路径。
	ConfigPath string
	// MasterKeyFile 可选：配置未内联主密钥时传给 serve。
	MasterKeyFile string
	// ExtraArgs 是额外 serve 参数（显式列表，不经过 shell）。
	ExtraArgs []string
	// HealthURL 是就绪探测地址（通常由 BuildHealthURL 生成）。
	HealthURL string
	// LogPath 是捕获 stdout/stderr 的日志文件路径；空则丢弃输出。
	LogPath string
	// StartupTimeout 是等待就绪上限；0 使用默认值。
	StartupTimeout time.Duration
	// HostHeader 是探测时使用的 Host（配置了 public_base_url 时用它避免 Host 白名单拒绝）。
	HostHeader string
}

// StartServiceResult 是一键启动结果（脱敏）。
type StartServiceResult struct {
	Started   bool          `json:"started"`
	Ready     bool          `json:"ready"`
	PID       int           `json:"pid,omitempty"`
	Address   string        `json:"address,omitempty"`
	StartedAt time.Time     `json:"started_at,omitempty"`
	Elapsed   time.Duration `json:"elapsed_ms"`
	LogPath   string        `json:"log_path,omitempty"`
	// Error 是启动/就绪失败原因（脱敏单行）。
	Error string `json:"error,omitempty"`
}

// BuildHealthURL 根据配置生成本机就绪探测地址。
//
// 监听地址优先；配置了公开地址时用它构造 Host 头（避免 Host 白名单拒绝），但
// 连接仍走本机监听地址。TLS 监听使用 https。
func BuildHealthURL(cfg config.Config) (healthURL, hostHeader string) {
	addresses := []string{cfg.Server.ListenAddr}
	addresses = append(addresses, cfg.Server.ExtraListenAddrs...)
	address := "127.0.0.1:8080"
	for _, candidate := range addresses {
		if strings.TrimSpace(candidate) != "" {
			address = strings.TrimSpace(candidate)
			break
		}
	}
	scheme := "http"
	if len(cfg.Server.TLSCertFiles) > 0 || len(cfg.Server.TLSKeyFiles) > 0 || cfg.Server.TLSPFXFile != "" {
		scheme = "https"
	}
	hostHeader = ""
	if strings.TrimSpace(cfg.Server.PublicBaseURL) != "" {
		if parsed, err := parsePublicURLHost(cfg.Server.PublicBaseURL); err == nil {
			hostHeader = parsed
		}
	}
	return scheme + "://" + address + "/healthz", hostHeader
}

func parsePublicURLHost(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("空地址")
	}
	// 不引入 net/url 解析只取 host:port；公开地址已在配置加载时校验过形状。
	withoutScheme := trimmed
	if index := strings.Index(withoutScheme, "://"); index >= 0 {
		withoutScheme = withoutScheme[index+3:]
	}
	if index := strings.IndexAny(withoutScheme, "/?#"); index >= 0 {
		withoutScheme = withoutScheme[:index]
	}
	if withoutScheme == "" {
		return "", errors.New("地址缺少主机")
	}
	return withoutScheme, nil
}

// Start 启动 login-server 子进程并等待 /healthz 就绪。
//
// 已持有自己启动的子进程时拒绝重复启动；启动失败会终止本次创建的子进程并保持
// 停止，绝不触碰其他进程。
func (s *ServiceSupervisor) Start(ctx context.Context, request StartServiceRequest) (StartServiceResult, error) {
	if s == nil {
		return StartServiceResult{}, errors.New("ServiceSupervisor 未初始化")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd != nil {
		return StartServiceResult{}, errors.New("本控制台已启动一个服务子进程；请先停止")
	}
	if strings.TrimSpace(request.Command) == "" {
		return StartServiceResult{}, errors.New("未指定 login-server 可执行文件")
	}
	if !filepath.IsAbs(request.ConfigPath) {
		return StartServiceResult{}, errors.New("配置路径必须是绝对路径")
	}
	startedAt := time.Now()
	args := []string{"serve", "--config", filepath.Clean(request.ConfigPath)}
	if strings.TrimSpace(request.MasterKeyFile) != "" {
		if !filepath.IsAbs(request.MasterKeyFile) {
			return StartServiceResult{}, errors.New("主密钥文件必须是绝对路径")
		}
		args = append(args, "--master-key-file", filepath.Clean(request.MasterKeyFile))
	}
	args = append(args, request.ExtraArgs...)
	command := exec.Command(request.Command, args...)
	command.Dir = filepath.Dir(filepath.Clean(request.ConfigPath))
	var logFile *os.File
	if strings.TrimSpace(request.LogPath) != "" {
		if !filepath.IsAbs(request.LogPath) {
			return StartServiceResult{}, errors.New("服务日志路径必须是绝对路径")
		}
		file, err := os.OpenFile(filepath.Clean(request.LogPath),
			os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return StartServiceResult{}, fmt.Errorf("打开服务日志失败：%w", err)
		}
		logFile = file
		if info, statErr := file.Stat(); statErr == nil && info.Size() > serviceLogMaxBytes {
			_ = file.Truncate(0)
		}
		command.Stdout = file
		command.Stderr = file
	}
	if err := command.Start(); err != nil {
		if logFile != nil {
			_ = logFile.Close()
		}
		return StartServiceResult{StartedAt: startedAt, Elapsed: time.Since(startedAt),
			LogPath: request.LogPath, Error: "启动失败：" + ws4SafeErrorText(err)}, nil
	}
	if logFile != nil {
		_ = logFile.Close()
	}
	s.cmd = command
	s.exitCh = make(chan error, 1)
	// 单独 goroutine 负责 Wait 并上报退出，供就绪循环与 Stop 共享真实退出状态。
	go func(exitCh chan error, running *exec.Cmd) {
		exitCh <- running.Wait()
	}(s.exitCh, command)
	s.startedAt = startedAt
	s.healthURL = request.HealthURL
	s.logPath = request.LogPath
	result := StartServiceResult{Started: true, PID: command.Process.Pid,
		StartedAt: startedAt, LogPath: request.LogPath, Address: request.HealthURL}
	timeout := request.StartupTimeout
	if timeout <= 0 {
		timeout = serviceStartupDefaultTimeout
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s.processExited() {
			result.Error = "服务进程在就绪前退出：请查看日志"
			result.Elapsed = time.Since(startedAt)
			s.cmd = nil
			return result, nil
		}
		if request.HealthURL != "" {
			if status, err := probeHealth(ctx, request.HealthURL, request.HostHeader); err == nil && status == http.StatusOK {
				result.Ready = true
				result.Elapsed = time.Since(startedAt)
				return result, nil
			}
		}
		select {
		case <-ctx.Done():
			result.Error = "等待服务就绪被取消"
			result.Elapsed = time.Since(startedAt)
			return result, nil
		case <-time.After(serviceHealthProbeInterval):
		}
	}
	if request.HealthURL == "" {
		// 未提供探测地址时只能报告“进程已启动”；进程已速退则绝不能 Ready=true。
		if !s.readyWithoutHealth() {
			result.Error = "服务进程已退出" + ws4ExitDetail(s.exitErr)
			result.Elapsed = time.Since(startedAt)
			return result, nil
		}
		result.Ready = true
	}
	result.Error = "服务未在期限内通过 /healthz 就绪探测（进程仍在运行）"
	result.Elapsed = time.Since(startedAt)
	return result, nil
}

// Stop 停止本控制台自己启动的子进程；没有自有子进程时不动作。
func (s *ServiceSupervisor) Stop(grace time.Duration) error {
	if s == nil {
		return errors.New("ServiceSupervisor 未初始化")
	}
	s.mu.Lock()
	command := s.cmd
	if command == nil {
		s.mu.Unlock()
		return nil
	}
	s.cmd = nil
	s.mu.Unlock()
	if command.Process == nil {
		return nil
	}
	if grace <= 0 {
		grace = serviceStopDefaultGrace
	}
	s.mu.Lock()
	exitCh := s.exitCh
	s.mu.Unlock()
	_ = command.Process.Kill()
	if exitCh == nil {
		return nil
	}
	select {
	case <-exitCh:
		return nil
	case <-time.After(grace):
		return errors.New("子进程停止超时（仅针对本控制台启动的进程）")
	}
}

// Running 报告本控制台是否持有已启动的子进程。
func (s *ServiceSupervisor) Running() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cmd != nil
}

func (s *ServiceSupervisor) processExited() bool {
	if s.exitCh == nil {
		return s.cmd == nil
	}
	select {
	case err := <-s.exitCh:
		s.exitErr = err
		s.exitCh = nil
		return true
	default:
		return false
	}
}

// readyWithoutHealth 在未提供 /healthz 探测地址时判断“进程已启动”是否可信：
// 进程已退出则绝不能报告就绪。
func (s *ServiceSupervisor) readyWithoutHealth() bool {
	return !s.processExited()
}

// ws4ExitDetail 返回退出原因的单行脱敏摘要。
func ws4ExitDetail(err error) string {
	if err == nil {
		return "（退出状态未知）"
	}
	return "：" + ws4SafeErrorText(err)
}

func probeHealth(ctx context.Context, healthURL, hostHeader string) (int, error) {
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		}},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		return 0, err
	}
	if hostHeader != "" {
		request.Host = hostHeader
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	return response.StatusCode, nil
}

// ServiceRuntimeInfo 是“运行信息”展示数据。
type ServiceRuntimeInfo struct {
	Running         bool         `json:"running"`
	Addresses       []string     `json:"addresses,omitempty"`
	PublicURL       string       `json:"public_url,omitempty"`
	TLSEnabled      bool         `json:"tls_enabled"`
	TLSCertificates []CertExpiry `json:"tls_certificates,omitempty"`
	ConfigPath      string       `json:"config_path,omitempty"`
	DatabasePath    string       `json:"database_path,omitempty"`
	AttachmentsDir  string       `json:"attachments_dir,omitempty"`
	RemainingSetup  []string     `json:"remaining_setup,omitempty"`
	Notes           []string     `json:"notes,omitempty"`
}

// CertExpiry 是证书到期信息。
type CertExpiry struct {
	File     string    `json:"file"`
	Subject  string    `json:"subject,omitempty"`
	NotAfter time.Time `json:"not_after,omitempty"`
	Problem  string    `json:"problem,omitempty"`
}

// DescribeServiceRuntime 汇总实际访问地址、TLS/证书状态、配置/数据位置与剩余
// 初始化事项（只读，不探测网络）。
func DescribeServiceRuntime(cfg config.Config, probe InstanceProbe, detection Detection, configPath string) ServiceRuntimeInfo {
	info := ServiceRuntimeInfo{
		Running: probe.Running, PublicURL: cfg.Server.PublicBaseURL,
		ConfigPath: filepath.Clean(configPath), DatabasePath: cfg.Database.Path,
	}
	if strings.TrimSpace(cfg.Server.ListenAddr) != "" {
		info.Addresses = append(info.Addresses, cfg.Server.ListenAddr)
	}
	info.Addresses = append(info.Addresses, cfg.Server.ExtraListenAddrs...)
	info.TLSEnabled = len(cfg.Server.TLSCertFiles) > 0 || len(cfg.Server.TLSKeyFiles) > 0 ||
		cfg.Server.TLSPFXFile != ""
	for _, certFile := range cfg.Server.TLSCertFiles {
		info.TLSCertificates = append(info.TLSCertificates, readCertExpiry(certFile))
	}
	if info.PublicURL == "" {
		info.Notes = append(info.Notes, "尚未配置公开访问地址（public_base_url）：对外访问前请核对地址/Host/TLS")
	}
	if info.TLSEnabled && len(info.TLSCertificates) == 0 {
		info.Notes = append(info.Notes, "已配置 TLS 但未读取到服务器证书到期时间（PFX 或读取失败）")
	}
	switch detection.Kind {
	case "root-missing":
		info.RemainingSetup = append(info.RemainingSetup, "唯一 root 尚未创建：完成初始化后才能正常登录")
	case "migration-pending":
		info.RemainingSetup = append(info.RemainingSetup, "数据库迁移待执行：在维护状态执行正式迁移")
	case "db-missing", "db-unreachable", "db-not-configured":
		info.RemainingSetup = append(info.RemainingSetup, "数据库不可用：完成数据库设置/初始化")
	case "no-config", "config-invalid", "config-unreadable":
		info.RemainingSetup = append(info.RemainingSetup, "配置不可用：先修复配置")
	case "ready":
		// 无剩余初始化事项
	default:
		if detection.Summary != "" {
			info.Notes = append(info.Notes, detection.Summary)
		}
	}
	return info
}

func readCertExpiry(path string) CertExpiry {
	entry := CertExpiry{File: path}
	raw, err := os.ReadFile(path)
	if err != nil {
		entry.Problem = "读取证书失败：" + ws4SafeErrorText(err)
		return entry
	}
	rest := raw
	for {
		block, remainder := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remainder
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			entry.Problem = "解析证书失败：" + ws4SafeErrorText(err)
			return entry
		}
		entry.Subject = cert.Subject.CommonName
		entry.NotAfter = cert.NotAfter.UTC()
		return entry
	}
	entry.Problem = "文件中未找到 PEM 证书"
	return entry
}
