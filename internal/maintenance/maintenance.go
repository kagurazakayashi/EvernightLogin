// Package maintenance 实现维护状态、库外恢复代际与排他恢复锁（步骤 82）。
//
// 信任边界与设计要点：
//   - 本包只服务于本地运维：备份恢复必须让服务进入维护状态并在排他锁下执行，本包
//     不提供 HTTP 路由、不联网、不启动后台协程。
//   - 恢复代际（generation）的**权威副本**保存在库外受控目录的
//     restore-state.json；数据库内的 restore_generation 只是可查询记录。两者不一致
//     说明发生了带外回滚/替换，恢复前检查必须 fail-closed；不能仅凭会被一起回滚的
//     库内记录判断代际（AGENTS.md §13、需求 §7.4.5）。
//   - restore-state.json 使用原子替换（临时文件 + fsync + rename）写入，非 Windows
//     同时 fsync 目录；文件由主密钥按用途域 HMAC 封装并保存 key_id（支持轮换），缺失/
//     损坏/被截断/校验失败一律 fail-closed，不得静默重建。
//   - 排他锁 restore.lock 在受控目录内，Windows 使用 LockFileEx、Unix 使用 flock，
//     进程被强杀时由操作系统释放；跨进程与跨 Controller 实例都互斥，保证同一时刻
//     只有一个恢复流程。
//   - Gate 是进程内写入门闸：维护状态激活时新的写入被拒绝（ErrMaintenanceActive），
//     在途写入通过 WaitIdle 有界收束。宿主把 Gate.Guard 接到存储写路径（见
//     internal/storage/sqlite.Options.WriteGuard）即可阻止新写请求；未接线的宿主
//     必须自行停止服务（文档明确该边界）。
//   - 代际与状态文件是本地受控文件，安全边界是操作系统文件权限（非 Windows 目录
//     0700，Windows 由 NTFS ACL 约束；README 给出 icacls 指引）。本包不承诺对抗
//     拥有该目录写权限的主机管理员。
package maintenance

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
)

// 受控文件名与稳定取值。修改文件名/格式必须同步文档与迁移（库内记录）。
const (
	// StateFileName 是库外恢复状态与代际权威文件。
	StateFileName = "restore-state.json"
	// LockFileName 是恢复排他锁文件名。
	LockFileName = "restore.lock"
	// StateVersion 是 restore-state.json 的格式版本。版本 2 起使用主密钥 HMAC 封装，
	// 缺失或校验失败必须 fail-closed（不得静默重建）。
	StateVersion = 2
	// stateMACDomain 是恢复状态 HMAC 的用途域（经内部 secrets 主密钥环 HMACDigest
	// 按用途 HKDF 派生，不与其它秘密用途共用）。
	stateMACDomain = "maintenance.restore-state.v1"
	// ModeNormal 表示服务正常对外（默认）。
	ModeNormal = "normal"
	// ModeMaintenance 表示服务处于维护状态：拒绝新写入，等待在途操作收束。
	ModeMaintenance = "maintenance"
	// DefaultDrainTimeout 是等待在途写入收束的默认墙钟上限。
	DefaultDrainTimeout = 30 * time.Second
	// MinDrainTimeout/MaxDrainTimeout 是允许的收束等待范围。
	MinDrainTimeout = time.Second
	MaxDrainTimeout = 10 * time.Minute
	// MaxStateBytes 是状态文件上限，防止异常文件被整体读入内存。
	MaxStateBytes = 64 * 1024
	// MaxReasonRunes 是维护/恢复原因的最大字符数。
	MaxReasonRunes = 500
	// MaxOperatorIDBytes 是操作者标识上限。
	MaxOperatorIDBytes = 128
	// MaxMachineBytes 是机器名标识上限。
	MaxMachineBytes = 128
	// MaxRestoreIDBytes 是恢复编号上限（与迁移 CHECK 一致）。
	MaxRestoreIDBytes = 64
)

// 领域错误哨兵。错误文本不包含秘密、备份正文或宿主绝对路径。
var (
	// ErrOptionsInvalid 表示构造参数非法（fail-closed）。
	ErrOptionsInvalid = errors.New("维护状态配置无效")
	// ErrStateInvalid 表示库外状态文件损坏、被篡改或格式不支持（fail-closed）。
	ErrStateInvalid = errors.New("库外恢复状态文件无效")
	// ErrMaintenanceActive 表示维护状态激活，新的写入被拒绝。
	ErrMaintenanceActive = errors.New("服务处于维护状态，暂停新的写入")
	// ErrRestoreLocked 表示恢复排他锁被其他流程持有。
	ErrRestoreLocked = errors.New("恢复排他锁已被占用")
	// ErrPendingRestore 表示存在未完成的恢复尝试，必须先处置。
	ErrPendingRestore = errors.New("存在未完成的恢复尝试")
	// ErrDrainTimeout 表示在途写入未能在墙钟上限内收束。
	ErrDrainTimeout = errors.New("等待在途写入收束超时")
	// ErrNotMaintenance 表示操作要求维护状态但当前不是维护状态。
	ErrNotMaintenance = errors.New("当前不在维护状态")
	// ErrGenerationMismatch 表示库外代际与数据库记录不一致（疑似带外回滚/替换）。
	ErrGenerationMismatch = errors.New("库外恢复代际与数据库记录不一致")
	// ErrStoreUnavailable 表示状态目录/锁文件不可用。
	ErrStoreUnavailable = errors.New("维护状态存储暂时不可用")
	// ErrStateMissing 表示库外恢复状态文件不存在：不得静默重建，必须显式初始化。
	ErrStateMissing = errors.New("库外恢复状态未初始化")
	// ErrKeyringUnavailable 表示用于状态完整性校验的主密钥环不可用。
	ErrKeyringUnavailable = errors.New("维护状态完整性密钥不可用")
)

// ErrLockBusy 是排他文件锁被其它进程/句柄占用的哨兵；同进程的其他组件（例如恢复
// 审计日志）可复用同一实现保证跨进程互斥。
var ErrLockBusy = errLockBusy

// AcquireFileLock 在指定路径上创建/打开锁文件并取得非阻塞排他锁，返回幂等释放
// 函数。锁被占用时返回 ErrLockBusy；文件不可用返回其他错误（调用方 fail-closed）。
func AcquireFileLock(path string) (func(), error) {
	lock, err := acquireLock(path)
	if err != nil {
		return nil, err
	}
	return lock.Release, nil
}

// SyncDirectory 对目录执行 fsync（Unix 真实同步；Windows 无操作，见平台实现注释）。
func SyncDirectory(directory string) { syncDirectory(directory) }

// Operator 是维护/恢复操作者的真实身份（本地应急管理员或 root 用户），只进入审计
// 与状态文件，不接受请求参数自称角色。
type Operator struct {
	// Type 是操作者类别：local_admin、user 或 system。
	Type string
	// ID 是稳定操作者标识（如 os:user@host 或用户 ID）。
	ID string
	// Machine 是机器名标识。
	Machine string
}

// Validate 校验操作者类别与标识。匿名操作者不允许进入恢复流程。
func (o Operator) Validate() error {
	switch o.Type {
	case "local_admin", "user", "system":
	default:
		return fmt.Errorf("%w: 操作者类别未知", ErrOptionsInvalid)
	}
	if strings.TrimSpace(o.ID) == "" || len(o.ID) > MaxOperatorIDBytes {
		return fmt.Errorf("%w: 操作者标识不能为空且不超过 %d 字节", ErrOptionsInvalid, MaxOperatorIDBytes)
	}
	if len(o.Machine) > MaxMachineBytes {
		return fmt.Errorf("%w: 机器名标识过长", ErrOptionsInvalid)
	}
	for _, value := range []string{o.ID, o.Machine} {
		if strings.ContainsFunc(value, unicode.IsControl) {
			return fmt.Errorf("%w: 操作者标识不能包含控制字符", ErrOptionsInvalid)
		}
	}
	return nil
}

// LocalOperator 从操作系统环境推导本地应急管理员身份；失败时退化为保守占位标识。
func LocalOperator() Operator {
	username := "local-admin"
	if current, err := user.Current(); err == nil && strings.TrimSpace(current.Username) != "" {
		username = current.Username
	}
	machine := "unknown-host"
	if hostname, err := os.Hostname(); err == nil && strings.TrimSpace(hostname) != "" {
		machine = hostname
	}
	operator := Operator{Type: "local_admin", ID: "os:" + username + "@" + machine, Machine: machine}
	if err := operator.Validate(); err != nil {
		return Operator{Type: "local_admin", ID: "os:local-admin@unknown-host", Machine: "unknown-host"}
	}
	return operator
}

// PendingRestore 是一次尚未完成（或已完成数据库侧但尚未确认库外状态）的恢复尝试。
// 它先于数据库切换写入库外状态文件，因此中断后重新运行或显式处置都能被识别。
type PendingRestore struct {
	// RestoreID 是本次恢复尝试的稳定编号。
	RestoreID string `json:"restore_id"`
	// NextGeneration 是本次恢复成功后应使用的恢复代际。
	NextGeneration uint64 `json:"next_generation"`
	// BackupSHA256 是待恢复备份文件的 SHA-256（只用于关联，不含内容）。
	BackupSHA256 string `json:"backup_sha256,omitempty"`
	// OperatorID 是发起本次恢复的操作者标识。
	OperatorID string `json:"operator_id"`
	// StartedAt 是尝试开始时间。
	StartedAt time.Time `json:"started_at"`
}

// State 是库外维护状态与恢复代际的完整内容。Generation 只随**成功完成**的恢复前进。
type State struct {
	// Version 是状态文件格式版本。
	Version int `json:"version"`
	// Mode 是 normal 或 maintenance。
	Mode string `json:"mode"`
	// Generation 是最近一次成功完成的恢复代际（0 表示从未恢复）。
	Generation uint64 `json:"generation"`
	// Pending 是未完成的恢复尝试；nil 表示没有遗留尝试。
	Pending *PendingRestore `json:"pending,omitempty"`
	// OperatorID/Machine/Reason 是最近一次进入维护状态的可追溯信息。
	OperatorID string `json:"operator_id,omitempty"`
	Machine    string `json:"machine,omitempty"`
	Reason     string `json:"reason,omitempty"`
	// EnteredAt 是最近一次进入维护状态的时间。
	EnteredAt time.Time `json:"entered_at,omitzero"`
	// UpdatedAt 是状态文件最后写入时间。
	UpdatedAt time.Time `json:"updated_at"`
	// JournalSeq/JournalHash 是库外恢复审计日志的链末锚点（与状态同受 HMAC 保护），
	// 用于检测日志尾部截断或整链重写。
	JournalSeq  int64  `json:"journal_seq"`
	JournalHash string `json:"journal_hash,omitempty"`
}

// stateDocument 是带完整性校验的状态文件外层。校验值只防损坏/误改，不承担对抗
// 拥有目录写权限者的密码学认证（该边界由 OS 文件权限约束）。
type stateDocument struct {
	Payload json.RawMessage `json:"payload"`
	// KeyID 是签名所用的主密钥版本；校验时按历史 key 版本复核，支持密钥轮换。
	KeyID string `json:"key_id"`
	// MAC 是主密钥环按用途域对 payload 的 HMAC-SHA256 十六进制文本。
	MAC string `json:"mac"`
}

// Gate 是进程内维护写入门闸。Guard 在维护状态激活时拒绝新写入；在途写入通过
// WaitIdle 有界收束。它只覆盖显式接入的写路径，未接线的进程必须自行停止服务。
type Gate struct {
	mu       sync.Mutex
	active   bool
	inflight int
	waiters  []chan struct{}
}

// newGate 构造未激活的门闸。
func newGate() *Gate { return &Gate{} }

// Active 报告维护状态是否激活（门闸视角）。
func (g *Gate) Active() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.active
}

// Inflight 返回当前在途写入数量（用于诊断与测试）。
func (g *Gate) Inflight() int {
	if g == nil {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.inflight
}

// Guard 开始一次受门闸保护的写入：维护状态激活时立即返回 ErrMaintenanceActive；
// 否则登记一个在途写入并返回幂等释放函数。调用方必须在写入完成后调用释放函数。
func (g *Gate) Guard(ctx context.Context) (func(), error) {
	if g == nil {
		return func() {}, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if g.active {
		return nil, ErrMaintenanceActive
	}
	g.inflight++
	released := false
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			defer g.mu.Unlock()
			if released {
				return
			}
			released = true
			if g.inflight > 0 {
				g.inflight--
			}
			g.notifyLocked()
		})
	}, nil
}

// setActive 由 Controller 在状态转换时调用；激活时通知等待者。
func (g *Gate) setActive(active bool) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.active = active
	g.notifyLocked()
}

// WaitIdle 有界等待在途写入数归零；超时返回 ErrDrainTimeout。
func (g *Gate) WaitIdle(ctx context.Context, timeout time.Duration) error {
	if g == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		timeout = DefaultDrainTimeout
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		ch := make(chan struct{})
		g.mu.Lock()
		if g.inflight == 0 {
			g.mu.Unlock()
			return nil
		}
		g.waiters = append(g.waiters, ch)
		g.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("%w: %s 内仍有在途写入", ErrDrainTimeout, timeout)
		case <-ch:
		}
	}
}

// notifyLocked 唤醒所有等待者；调用方必须持有 g.mu。
func (g *Gate) notifyLocked() {
	for _, ch := range g.waiters {
		close(ch)
	}
	g.waiters = nil
}

// Options 是维护状态控制器的构造参数。
type Options struct {
	// StateDir 是库外受控目录：保存 restore-state.json 与排他锁。必须与数据库目录
	// 不同（推荐独立目录/卷），不能被数据库回滚覆盖。
	StateDir string
	// DatabasePath 是当前活动数据库文件路径，用于基本一致性校验与诊断。
	DatabasePath string
	// Now 是可注入时钟；nil 使用 time.Now。
	Now func() time.Time
	// DrainTimeout 是等待在途写入收束的墙钟上限；0 使用默认 30 秒。
	DrainTimeout time.Duration
	// Logger 是运行日志器；不得记录秘密或备份正文。
	Logger *slog.Logger
	// Keyring 是主密钥环提供者，用于库外状态/审计锚点的 HMAC 封装。必填；不可用或
	// 不匹配时状态加载/写入 fail-closed，不静默降级为无密钥校验。
	Keyring secrets.Provider
}

// Controller 是维护状态与恢复代际的唯一进程内入口。它不启动协程；Close 释放持锁。
type Controller struct {
	opts        Options
	mu          sync.Mutex
	state       State
	statePath   string
	gate        *Gate
	now         func() time.Time
	logger      *slog.Logger
	sessionMu   sync.Mutex
	session     *fileLock
	sessionHeld bool
	keyring     secrets.Provider
	missing     bool
}

// New 校验参数并加载库外状态；文件不存在时创建初始 normal/0 状态。它不会创建备份、
// 不会连接数据库、不会进入维护状态。
func New(options Options) (*Controller, error) {
	stateDir := strings.TrimSpace(options.StateDir)
	if stateDir == "" {
		return nil, fmt.Errorf("%w: 状态目录不能为空", ErrOptionsInvalid)
	}
	absoluteState, err := filepath.Abs(stateDir)
	if err != nil {
		return nil, fmt.Errorf("%w: 状态目录路径无效", ErrOptionsInvalid)
	}
	databasePath, err := filepath.Abs(strings.TrimSpace(options.DatabasePath))
	if err != nil || strings.TrimSpace(options.DatabasePath) == "" {
		return nil, fmt.Errorf("%w: 数据库路径无效", ErrOptionsInvalid)
	}
	if samePath(absoluteState, filepath.Dir(databasePath)) {
		return nil, fmt.Errorf("%w: 状态目录不能就是数据库目录（恢复代际不能随数据库回滚）",
			ErrOptionsInvalid)
	}
	if containsPath(absoluteState, filepath.Dir(databasePath)) {
		return nil, fmt.Errorf("%w: 状态目录不能位于数据库目录内", ErrOptionsInvalid)
	}
	if err := ensureControlledDir(absoluteState); err != nil {
		return nil, err
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	if options.DrainTimeout == 0 {
		options.DrainTimeout = DefaultDrainTimeout
	}
	if options.DrainTimeout < MinDrainTimeout || options.DrainTimeout > MaxDrainTimeout {
		return nil, fmt.Errorf("%w: 收束等待上限必须在 %s～%s 之间",
			ErrOptionsInvalid, MinDrainTimeout, MaxDrainTimeout)
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard,
			&slog.HandlerOptions{Level: slog.LevelError + 1}))
	}
	keyring := options.Keyring
	if keyring == nil || (reflect.ValueOf(keyring).Kind() == reflect.Ptr &&
		reflect.ValueOf(keyring).IsNil()) {
		return nil, fmt.Errorf("%w: 缺少主密钥环（状态完整性校验 fail-closed）",
			ErrOptionsInvalid)
	}
	controller := &Controller{
		opts:      options,
		statePath: filepath.Join(absoluteState, StateFileName),
		gate:      newGate(),
		now:       now,
		logger:    logger,
		keyring:   keyring,
	}
	state, missing, err := controller.loadState()
	if err != nil {
		return nil, err
	}
	controller.state = state
	controller.missing = missing
	if missing {
		// 不静默重建：调用方必须显式 Initialize（root/本地应急管理员确认 + 审计）。
		controller.state = State{Version: StateVersion, Mode: ModeNormal,
			UpdatedAt: now().UTC()}
	}
	if state.Mode == ModeMaintenance {
		controller.gate.setActive(true)
	}
	return controller, nil
}

// Missing 报告库外恢复状态是否尚未初始化（缺失时所有恢复/维护操作 fail-closed）。
func (c *Controller) Missing() bool {
	if c == nil {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.missing
}

// InitializeRequest 是显式初始化库外恢复状态的请求。
type InitializeRequest struct {
	Operator Operator
	Reason   string
}

// Initialize 显式创建签名版初始状态（normal/代际 0）。状态已存在时拒绝覆盖，避免
// 用“重新初始化”绕过代际/审计锚点；必须由 root 或受控本地应急管理员确认后调用。
func (c *Controller) Initialize(ctx context.Context, request InitializeRequest) error {
	if c == nil {
		return ErrOptionsInvalid
	}
	if err := request.Operator.Validate(); err != nil {
		return err
	}
	reason, err := validReason(request.Reason)
	if err != nil {
		return err
	}
	release, err := c.LockRestore(ctx)
	if err != nil {
		if errors.Is(err, ErrRestoreLocked) {
			return ErrRestoreLocked
		}
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	defer release()
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.missing {
		return fmt.Errorf("%w: 库外恢复状态已存在，拒绝重新初始化", ErrStateInvalid)
	}
	now := c.now().UTC()
	state := State{Version: StateVersion, Mode: ModeNormal, Generation: 0,
		OperatorID: request.Operator.ID, Machine: request.Operator.Machine,
		Reason: reason, UpdatedAt: now}
	if err := c.writeStateFile(state); err != nil {
		return err
	}
	c.state = state
	c.missing = false
	return nil
}

// JournalAnchor 返回库外审计日志链末锚点；未初始化或尚无锚点时 ok=false。
func (c *Controller) JournalAnchor() (int64, string, bool) {
	if c == nil {
		return 0, "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.missing || c.state.JournalSeq <= 0 {
		return 0, "", false
	}
	return c.state.JournalSeq, c.state.JournalHash, true
}

// UpdateJournalAnchor 把审计日志链末锚点写入受 HMAC 保护的状态文件；失败返回
// ErrAuditUnavailable 语义的存储错误，调用方必须 fail-closed。
func (c *Controller) UpdateJournalAnchor(ctx context.Context, seq int64, hash string) error {
	return c.withLock(ctx, func() error {
		if seq <= 0 || len(hash) != 64 || !validHex(hash) {
			return fmt.Errorf("%w: 审计日志锚点非法", ErrStateInvalid)
		}
		state := c.State()
		state.JournalSeq = seq
		state.JournalHash = hash
		state.UpdatedAt = c.now().UTC()
		if err := c.writeStateLocked(state); err != nil {
			return err
		}
		c.mu.Lock()
		c.state = state
		c.mu.Unlock()
		return nil
	})
}

// validHex 报告字符串是否为小写/大写十六进制。
func validHex(value string) bool {
	if value == "" {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if !((character >= '0' && character <= '9') ||
			(character >= 'a' && character <= 'f') ||
			(character >= 'A' && character <= 'F')) {
			return false
		}
	}
	return true
}

// State 返回当前状态副本。
func (c *Controller) State() State {
	if c == nil {
		return State{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return cloneState(c.state)
}

// Generation 返回库外权威恢复代际。
func (c *Controller) Generation() uint64 { return c.State().Generation }

// Mode 返回当前模式（normal/maintenance）。
func (c *Controller) Mode() string { return c.State().Mode }

// Gate 返回进程内写入门闸，供存储写路径接线。
func (c *Controller) Gate() *Gate {
	if c == nil {
		return nil
	}
	return c.gate
}

// StatePath 返回库外状态文件的绝对路径（诊断与运维显示用，不含秘密）。
func (c *Controller) StatePath() string {
	if c == nil {
		return ""
	}
	return c.statePath
}

// EnterRequest 是进入维护状态的请求。
type EnterRequest struct {
	Operator Operator
	Reason   string
	// RequestID 是可选的关联编号。
	RequestID string
}

// EnterMaintenance 进入维护状态：先持久化库外状态，再关闭门闸，然后有界等待在途
// 写入收束。收束超时返回 ErrDrainTimeout，但**保持维护状态**（保守失败，不自动放行）。
func (c *Controller) EnterMaintenance(ctx context.Context, request EnterRequest) error {
	return c.withLock(ctx, func() error {
		if err := request.Operator.Validate(); err != nil {
			return err
		}
		reason, err := validReason(request.Reason)
		if err != nil {
			return err
		}
		now := c.now().UTC()
		state := c.State()
		state.Mode = ModeMaintenance
		state.OperatorID = request.Operator.ID
		state.Machine = request.Operator.Machine
		state.Reason = reason
		state.EnteredAt = now
		state.UpdatedAt = now
		if err := c.writeStateLocked(state); err != nil {
			return err
		}
		c.mu.Lock()
		c.state = state
		c.mu.Unlock()
		// 门闸在状态持久化之后关闭：即使进程在此刻崩溃，下一次启动仍从文件恢复
		// 维护状态，不会把新写入误认为已放行。
		c.gate.setActive(true)
		if err := c.gate.WaitIdle(ctx, c.opts.DrainTimeout); err != nil {
			return err
		}
		return nil
	})
}

// ExitRequest 是退出维护状态的请求。
type ExitRequest struct {
	Operator Operator
	Reason   string
	// Force 表示在存在未完成恢复尝试时仍显式退出维护状态；必须由操作者明确选择，
	// 退出后旧凭证可能未按恢复规则失效（文档已标注风险）。
	Force bool
}

// ExitMaintenance 退出维护状态。存在未完成恢复尝试时必须显式 Force；否则按
// ErrPendingRestore 拒绝，避免把半完成的恢复误认为正常状态。
func (c *Controller) ExitMaintenance(ctx context.Context, request ExitRequest) error {
	return c.withLock(ctx, func() error {
		if err := request.Operator.Validate(); err != nil {
			return err
		}
		reason, err := validReason(request.Reason)
		if err != nil {
			return err
		}
		state := c.State()
		if state.Mode != ModeMaintenance {
			return ErrNotMaintenance
		}
		if state.Pending != nil && !request.Force {
			return fmt.Errorf("%w：恢复尝试 %s 未完成，需先完成或显式 Force 退出",
				ErrPendingRestore, state.Pending.RestoreID)
		}
		if err := c.gate.WaitIdle(ctx, c.opts.DrainTimeout); err != nil {
			return err
		}
		now := c.now().UTC()
		state.Mode = ModeNormal
		state.Pending = nil
		state.OperatorID = request.Operator.ID
		state.Machine = request.Operator.Machine
		state.Reason = reason
		state.UpdatedAt = now
		if err := c.writeStateLocked(state); err != nil {
			return err
		}
		c.mu.Lock()
		c.state = state
		c.mu.Unlock()
		c.gate.setActive(false)
		return nil
	})
}

// BeginRequest 是登记一次恢复尝试的请求；必须在维护状态下调用。
type BeginRequest struct {
	RestoreID    string
	BackupSHA256 string
	Operator     Operator
}

// Token 是一次已登记的恢复尝试凭据；重新运行恢复时核对其编号。
type Token struct {
	RestoreID      string
	Generation     uint64
	NextGeneration uint64
	StartedAt      time.Time
}

// BeginRestore 在库外状态中登记恢复尝试并写入下一恢复代际。它不切换数据库；调用方
// 必须持有恢复会话锁（Execute 内部完成）。重复运行同一/新的恢复尝试会替换旧 pending。
func (c *Controller) BeginRestore(ctx context.Context, request BeginRequest) (Token, error) {
	var token Token
	err := c.withLock(ctx, func() error {
		if err := request.Operator.Validate(); err != nil {
			return err
		}
		restoreID := strings.TrimSpace(request.RestoreID)
		if restoreID == "" || len(restoreID) > MaxRestoreIDBytes {
			return fmt.Errorf("%w: 恢复编号不能为空且不超过 %d 字节",
				ErrOptionsInvalid, MaxRestoreIDBytes)
		}
		for index := 0; index < len(restoreID); index++ {
			character := restoreID[index]
			allowed := (character >= 'a' && character <= 'z') ||
				(character >= '0' && character <= '9') || character == '-' || character == '_'
			if !allowed {
				return fmt.Errorf("%w: 恢复编号只允许小写字母、数字、- 与 _", ErrOptionsInvalid)
			}
		}
		state := c.State()
		if state.Mode != ModeMaintenance {
			return fmt.Errorf("%w：必须先进入维护状态", ErrNotMaintenance)
		}
		now := c.now().UTC()
		state.Pending = &PendingRestore{
			RestoreID:      restoreID,
			NextGeneration: state.Generation + 1,
			BackupSHA256:   strings.TrimSpace(request.BackupSHA256),
			OperatorID:     request.Operator.ID,
			StartedAt:      now,
		}
		state.OperatorID = request.Operator.ID
		state.Machine = request.Operator.Machine
		state.UpdatedAt = now
		if err := c.writeStateLocked(state); err != nil {
			return err
		}
		c.mu.Lock()
		c.state = state
		c.mu.Unlock()
		token = Token{RestoreID: restoreID, Generation: state.Generation,
			NextGeneration: state.Pending.NextGeneration, StartedAt: now}
		return nil
	})
	if err != nil {
		return Token{}, err
	}
	return token, nil
}

// CompleteRestore 把恢复代际推进到 pending.NextGeneration 并清除 pending；维护状态
// 仍保持，直到调用方显式退出。它必须在数据库侧后处理提交成功之后调用。
func (c *Controller) CompleteRestore(ctx context.Context, token Token) error {
	return c.withLock(ctx, func() error {
		state := c.State()
		if state.Pending == nil || state.Pending.RestoreID != token.RestoreID {
			return fmt.Errorf("%w：恢复尝试 %s 不在 pending 状态",
				ErrPendingRestore, token.RestoreID)
		}
		if state.Pending.NextGeneration != token.NextGeneration {
			return fmt.Errorf("%w：恢复尝试 %s 的代际已变化", ErrPendingRestore, token.RestoreID)
		}
		now := c.now().UTC()
		state.Generation = token.NextGeneration
		state.Pending = nil
		state.UpdatedAt = now
		if err := c.writeStateLocked(state); err != nil {
			return err
		}
		c.mu.Lock()
		c.state = state
		c.mu.Unlock()
		return nil
	})
}

// AbortRestore 清除未完成恢复尝试（不推进代际），维护状态保持。用于确认切换前失败
// 且不需要保留 pending 的场景；调用方仍必须显式退出维护状态。
func (c *Controller) AbortRestore(ctx context.Context, restoreID string) error {
	return c.withLock(ctx, func() error {
		state := c.State()
		if state.Pending == nil || state.Pending.RestoreID != restoreID {
			return nil
		}
		state.Pending = nil
		state.UpdatedAt = c.now().UTC()
		if err := c.writeStateLocked(state); err != nil {
			return err
		}
		c.mu.Lock()
		c.state = state
		c.mu.Unlock()
		return nil
	})
}

// ReconcileResult 是库外代际与数据库记录的核对结果。
type ReconcileResult struct {
	ExternalGeneration uint64
	DatabaseGeneration uint64
	// IncompletePending 表示存在未完成的恢复尝试（数据库仍是恢复前状态，可重新执行）。
	IncompletePending bool
	// Finalized 表示本次核对把“数据库已提交、库外未确认”的恢复收尾。
	Finalized bool
	// Mismatch 表示库外与库内代际不一致且不是可收尾的中断场景（疑似带外回滚）。
	Mismatch bool
	// Detail 是给操作者的直白说明（不含秘密）。
	Detail string
}

// Reconcile 核对数据库内恢复代际与库外权威代际：
//   - pending 存在且数据库代际 == pending.NextGeneration：数据库侧已提交但库外未确认，
//     本次核对推进库外代际并清除 pending（崩溃在两次落盘之间可恢复）；
//   - pending 存在且数据库代际 == 当前代际：中断在切换前/切换中，数据库仍是恢复前
//     状态，允许重新执行恢复；
//   - 其它不一致：Mismatch=true，调用方必须 fail-closed 或要求显式确认带外回滚。
func (c *Controller) Reconcile(ctx context.Context, databaseGeneration uint64) (ReconcileResult, error) {
	var result ReconcileResult
	err := c.withLock(ctx, func() error {
		state := c.State()
		result.ExternalGeneration = state.Generation
		result.DatabaseGeneration = databaseGeneration
		switch {
		case state.Pending != nil && databaseGeneration == state.Pending.NextGeneration:
			offset := state.Pending.RestoreID
			now := c.now().UTC()
			state.Generation = state.Pending.NextGeneration
			state.Pending = nil
			state.UpdatedAt = now
			if err := c.writeStateLocked(state); err != nil {
				return err
			}
			c.mu.Lock()
			c.state = state
			c.mu.Unlock()
			result.Finalized = true
			result.Detail = fmt.Sprintf("已确认恢复 %s 的数据库侧提交并推进库外代际到 %d",
				offset, state.Generation)
		case state.Pending != nil && databaseGeneration == state.Generation:
			result.IncompletePending = true
			result.Detail = fmt.Sprintf("恢复尝试 %s 尚未完成，数据库仍是恢复前状态，可重新执行",
				state.Pending.RestoreID)
		case state.Pending == nil && databaseGeneration == state.Generation:
			result.Detail = "库外代际与数据库记录一致"
		default:
			result.Mismatch = true
			current := uint64(0)
			if state.Pending != nil {
				current = state.Pending.NextGeneration
			}
			result.Detail = fmt.Sprintf("库外代际 %d、数据库记录 %d%s 不一致（疑似带外回滚/替换），"+
				"恢复前检查必须确认或重新执行恢复", result.ExternalGeneration,
				result.DatabaseGeneration,
				pendingSuffix(state.Pending != nil, current))
		}
		return nil
	})
	if err != nil {
		return ReconcileResult{}, err
	}
	return result, nil
}

// pendingSuffix 生成诊断文本片段。
func pendingSuffix(hasPending bool, next uint64) string {
	if !hasPending {
		return ""
	}
	return fmt.Sprintf("（pending 期望 %d）", next)
}

// LockRestore 取得跨进程恢复排他锁，供一次完整恢复流程独占使用。返回的释放函数
// 幂等；未释放时其它 Controller/进程的恢复请求返回 ErrRestoreLocked。
func (c *Controller) LockRestore(ctx context.Context) (func(), error) {
	if c == nil {
		return nil, ErrOptionsInvalid
	}
	if ctx == nil {
		ctx = context.Background()
	}
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()
	if c.sessionHeld {
		return nil, ErrRestoreLocked
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	lock, err := acquireLock(filepath.Join(filepath.Dir(c.statePath), LockFileName))
	if err != nil {
		if errors.Is(err, errLockBusy) {
			return nil, ErrRestoreLocked
		}
		return nil, fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	if err := lock.WriteMetadata(fmt.Sprintf("pid=%d time=%s\n", os.Getpid(),
		c.now().UTC().Format(time.RFC3339))); err != nil {
		lock.Release()
		return nil, fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	c.session = lock
	c.sessionHeld = true
	return func() {
		c.sessionMu.Lock()
		defer c.sessionMu.Unlock()
		if !c.sessionHeld {
			return
		}
		c.sessionHeld = false
		c.session.Release()
		c.session = nil
	}, nil
}

// Close 释放可能持有的恢复锁；不改变库外状态文件。重复调用安全。
func (c *Controller) Close() error {
	if c == nil {
		return nil
	}
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()
	if c.sessionHeld && c.session != nil {
		c.session.Release()
		c.session = nil
		c.sessionHeld = false
	}
	return nil
}

// withLock 串行化 Controller 状态操作，并在没有长恢复会话时短暂取得跨进程锁，
// 保证多个进程不会同时改写库外状态。
func (c *Controller) withLock(ctx context.Context, fn func() error) error {
	if c == nil {
		return ErrOptionsInvalid
	}
	if ctx == nil {
		ctx = context.Background()
	}
	c.mu.Lock()
	missing := c.missing
	c.mu.Unlock()
	if missing {
		return fmt.Errorf("%w: 库外恢复状态未初始化（需受控初始化）", ErrStateMissing)
	}
	c.sessionMu.Lock()
	held := c.sessionHeld
	c.sessionMu.Unlock()
	if held {
		return fn()
	}
	lock, err := acquireLock(filepath.Join(filepath.Dir(c.statePath), LockFileName))
	if err != nil {
		if errors.Is(err, errLockBusy) {
			return ErrRestoreLocked
		}
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	defer lock.Release()
	return fn()
}

// loadState 读取并用主密钥 HMAC 校验库外状态。文件缺失返回 missing=true（调用方
// 必须显式初始化，不得静默重建）；HMAC/结构校验失败返回 ErrStateInvalid。
func (c *Controller) loadState() (State, bool, error) {
	data, err := os.ReadFile(c.statePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return State{}, true, nil
		}
		return State{}, false, fmt.Errorf("%w: 无法读取库外状态文件", ErrStoreUnavailable)
	}
	if len(data) > MaxStateBytes {
		return State{}, false, fmt.Errorf("%w: 状态文件超过 %d 字节", ErrStateInvalid, MaxStateBytes)
	}
	var document stateDocument
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return State{}, false, fmt.Errorf("%w: 状态文件无法解析", ErrStateInvalid)
	}
	if err := c.verifyStateMAC(document); err != nil {
		return State{}, false, err
	}
	var state State
	strict := json.NewDecoder(strings.NewReader(string(document.Payload)))
	strict.DisallowUnknownFields()
	if err := strict.Decode(&state); err != nil {
		return State{}, false, fmt.Errorf("%w: 状态内容无法解析", ErrStateInvalid)
	}
	if err := validateState(state); err != nil {
		return State{}, false, err
	}
	if state.UpdatedAt.IsZero() {
		state.UpdatedAt = c.now().UTC()
	}
	return state, false, nil
}

// verifyStateMAC 用主密钥环按用途域复核状态 MAC；密钥环不可用或 MAC 不匹配都
// fail-closed（不提供无密钥降级路径）。
func (c *Controller) verifyStateMAC(document stateDocument) error {
	if strings.TrimSpace(document.KeyID) == "" || strings.TrimSpace(document.MAC) == "" {
		return fmt.Errorf("%w: 状态文件缺少完整性封装", ErrStateInvalid)
	}
	ring, err := secrets.LoadKeyring(context.Background(), c.keyring)
	if err != nil {
		return fmt.Errorf("%w: 无法加载状态完整性密钥", ErrKeyringUnavailable)
	}
	expected, err := ring.HMACDigest(document.KeyID, stateMACDomain, document.Payload)
	if err != nil {
		return fmt.Errorf("%w: 状态完整性密钥版本不存在", ErrStateInvalid)
	}
	actual, err := hex.DecodeString(document.MAC)
	if err != nil || !constantTimeEqual(expected, actual) {
		return fmt.Errorf("%w: 状态文件 HMAC 校验失败（被篡改或密钥不匹配）", ErrStateInvalid)
	}
	return nil
}

// constantTimeEqual 常量时间比较字节序列。
func constantTimeEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := 0; index < len(left); index++ {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}

// writeStateLocked 序列化并原子写入状态文件（调用方不需要外部锁）。
func (c *Controller) writeStateLocked(state State) error {
	return c.writeStateFile(state)
}

// writeStateFile 校验状态并原子替换库外状态文件。
func (c *Controller) writeStateFile(state State) error {
	state.Version = StateVersion
	if state.Mode == "" {
		state.Mode = ModeNormal
	}
	if err := validateState(state); err != nil {
		return err
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("%w: 无法序列化状态", ErrStoreUnavailable)
	}
	ring, err := secrets.LoadKeyring(context.Background(), c.keyring)
	if err != nil {
		return fmt.Errorf("%w: 无法加载状态完整性密钥", ErrKeyringUnavailable)
	}
	keyID := ring.CurrentKeyID()
	mac, err := ring.HMACDigest(keyID, stateMACDomain, payload)
	if err != nil {
		return fmt.Errorf("%w: 无法计算状态完整性 MAC", ErrKeyringUnavailable)
	}
	document, err := json.Marshal(stateDocument{Payload: payload, KeyID: keyID,
		MAC: hex.EncodeToString(mac)})
	if err != nil {
		return fmt.Errorf("%w: 无法序列化状态文档", ErrStoreUnavailable)
	}
	directory := filepath.Dir(c.statePath)
	temporary, err := os.CreateTemp(directory, ".restore-state-*.tmp")
	if err != nil {
		return fmt.Errorf("%w: 无法创建状态临时文件", ErrStoreUnavailable)
	}
	temporaryPath := temporary.Name()
	cleanup := func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}
	if err := temporary.Chmod(0o600); err != nil && !isWindows() {
		cleanup()
		return fmt.Errorf("%w: 无法设置状态文件权限", ErrStoreUnavailable)
	}
	if err := writeAll(temporary, document); err != nil {
		cleanup()
		return fmt.Errorf("%w: 无法写入状态文件", ErrStoreUnavailable)
	}
	if err := temporary.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("%w: 状态文件 fsync 失败", ErrStoreUnavailable)
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("%w: 状态文件关闭失败", ErrStoreUnavailable)
	}
	if err := os.Rename(temporaryPath, c.statePath); err != nil {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("%w: 状态文件替换失败", ErrStoreUnavailable)
	}
	syncDirectory(directory)
	return nil
}

// validateState 校验状态字段的取值、时间与 pending 关系。
func validateState(state State) error {
	if state.Version != StateVersion {
		return fmt.Errorf("%w: 状态版本 %d 不受支持", ErrStateInvalid, state.Version)
	}
	switch state.Mode {
	case ModeNormal, ModeMaintenance:
	default:
		return fmt.Errorf("%w: 状态模式未知", ErrStateInvalid)
	}
	if state.Pending != nil {
		pending := state.Pending
		if pending.RestoreID == "" || len(pending.RestoreID) > MaxRestoreIDBytes {
			return fmt.Errorf("%w: pending 恢复编号非法", ErrStateInvalid)
		}
		if pending.NextGeneration != state.Generation+1 {
			return fmt.Errorf("%w: pending 代际必须恰好比当前代际大 1", ErrStateInvalid)
		}
		if pending.OperatorID == "" || len(pending.OperatorID) > MaxOperatorIDBytes {
			return fmt.Errorf("%w: pending 操作者标识非法", ErrStateInvalid)
		}
		if pending.StartedAt.IsZero() {
			return fmt.Errorf("%w: pending 开始时间缺失", ErrStateInvalid)
		}
	}
	if len(state.OperatorID) > MaxOperatorIDBytes || len(state.Machine) > MaxMachineBytes {
		return fmt.Errorf("%w: 操作者标识过长", ErrStateInvalid)
	}
	if len([]rune(state.Reason)) > MaxReasonRunes {
		return fmt.Errorf("%w: 状态原因过长", ErrStateInvalid)
	}
	if state.JournalSeq < 0 {
		return fmt.Errorf("%w: 审计锚点序号非法", ErrStateInvalid)
	}
	if state.JournalSeq == 0 && state.JournalHash != "" {
		return fmt.Errorf("%w: 审计锚点哈希缺少序号", ErrStateInvalid)
	}
	if state.JournalSeq > 0 && (len(state.JournalHash) != 64 || !validHex(state.JournalHash)) {
		return fmt.Errorf("%w: 审计锚点哈希非法", ErrStateInvalid)
	}
	return nil
}

// cloneState 返回深拷贝，避免调用方修改内部 pending 指针。
func cloneState(state State) State {
	cloned := state
	if state.Pending != nil {
		pending := *state.Pending
		cloned.Pending = &pending
	}
	return cloned
}

// validReason 校验原因文本：去首尾空白后非空、字符数有界、无控制字符。
func validReason(reason string) (string, error) {
	trimmed := strings.TrimSpace(reason)
	if trimmed == "" {
		return "", fmt.Errorf("%w: 原因不能为空", ErrOptionsInvalid)
	}
	if len([]rune(trimmed)) > MaxReasonRunes {
		return "", fmt.Errorf("%w: 原因不能超过 %d 个字符", ErrOptionsInvalid, MaxReasonRunes)
	}
	if strings.ContainsFunc(trimmed, unicode.IsControl) {
		return "", fmt.Errorf("%w: 原因不能包含控制字符", ErrOptionsInvalid)
	}
	return trimmed, nil
}

// ensureControlledDir 创建或校验状态目录：必须是真实目录（非符号链接），非 Windows
// 要求不向组/其他用户开放写权限。
func ensureControlledDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: 无法检查状态目录", ErrStoreUnavailable)
		}
		if err := os.MkdirAll(path, 0o700); err != nil {
			return fmt.Errorf("%w: 无法创建状态目录", ErrStoreUnavailable)
		}
		info, err = os.Lstat(path)
		if err != nil {
			return fmt.Errorf("%w: 无法检查状态目录", ErrStoreUnavailable)
		}
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: 状态目录不能是符号链接", ErrOptionsInvalid)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: 状态路径不是目录", ErrOptionsInvalid)
	}
	if !isWindows() && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: 状态目录不能向组/其他用户开放权限", ErrOptionsInvalid)
	}
	return nil
}

// samePath 判断两个绝对路径是否指向同一路径文本（不解析符号链接，保守比较）。
func samePath(left, right string) bool {
	return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
}

// containsPath 判断 child 是否位于 parent 目录内。
func containsPath(child, parent string) bool {
	relative, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	if relative == "." {
		return true
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

// writeAll 把完整字节写入文件。
func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}
