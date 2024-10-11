package setupconsole

// 步骤 295：完整实例重新初始化的独立流程（WS4，危险操作）。
//
// 本文件只做“计划/路径校验/保留与清除清单/精确确认/可恢复执行日志”，不直接删除
// 任何文件、不打开数据库、不改变服务状态：
//   - 执行必须由注入的 Reinitializer 完成，且调用方已取得 281 维护排他锁、主服务
//     已停止；本文件不提供绕过锁的入口；
//   - 目标限制：实例目录必须存在且不是符号链接；各目标解析后不得逃出实例目录
//     （外部数据库/附件必须显式确认）；含 .git/go.mod 的代码仓库根、其他实例目录
//     与调用方保留路径一律拒绝；
//   - 清除清单是显式 allow-list（数据库及其 WAL 伴生文件、配置、附件、维护状态、
//     可选主密钥），不删除清单外对象、不递归删除链接外目标；
//   - 执行计划写入实例目录内的可恢复 JSONL 日志，部分失败可按步骤重入。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// reinitConfirmPrefix 是完整重新初始化的确认串前缀（后接实例 ID）。
	reinitConfirmPrefix = "REINITIALIZE-"
	// reinitJournalName 是实例目录内的重新初始化执行日志文件名。
	reinitJournalName = ".login-setup-reinit.jsonl"
	// reinitJournalMaxBytes 限制执行日志大小（保留最近记录）。
	reinitJournalMaxBytes int64 = 256 * 1024
)

// ReinitPaths 是完整重新初始化涉及的精确路径（全部来自配置/实例检测，不接受
// 请求参数里的任意路径）。
type ReinitPaths struct {
	InstanceDir    string `json:"instance_dir"`
	ConfigPath     string `json:"config_path"`
	DatabasePath   string `json:"database_path"`
	AttachmentsDir string `json:"attachments_dir,omitempty"`
	StateDir       string `json:"state_dir,omitempty"`
	MasterKeyFile  string `json:"master_key_file,omitempty"`
	LogDir         string `json:"log_dir,omitempty"`
}

// ReinitRequest 是生成完整重新初始化计划的输入。
type ReinitRequest struct {
	Paths ReinitPaths
	// InstanceID 是实例稳定标识（来自维护状态，不是用户自由输入）。
	InstanceID string
	// ConfirmText 必须逐字等于 "REINITIALIZE-<InstanceID>"。
	ConfirmText string
	// KeepMasterKey 保留主密钥材料（仅当明确只重建数据库/配置时使用）。
	KeepMasterKey bool
	// AcknowledgeExternalPaths 显式确认数据库/附件位于实例目录之外。
	AcknowledgeExternalPaths bool
	// AcknowledgeOldCredentials 显式确认“旧凭证/旧会话不会复活”。
	AcknowledgeOldCredentials bool
	// ReservedPaths 是绝对禁止触碰的路径（代码仓库根、其他实例目录、用户数据）。
	ReservedPaths []string
	// BackupAvailable 表示调用方已有可用备份能力；false 时计划给出明确原因。
	BackupAvailable bool
}

// ReinitItem 是清除/保留清单的一项。
type ReinitItem struct {
	Label    string `json:"label"`
	Path     string `json:"path"`
	Kind     string `json:"kind"` // file|dir|file-set
	Required bool   `json:"required"`
	Detail   string `json:"detail,omitempty"`
}

// ReinitPlan 是完整重新初始化的执行计划与确认要求。
type ReinitPlan struct {
	InstanceID string      `json:"instance_id"`
	Paths      ReinitPaths `json:"paths"`
	// ClearItems 是允许清除的显式清单（allow-list）。
	ClearItems []ReinitItem `json:"clear_items"`
	// RetainItems 是明确保留的内容（代码仓库、其他实例、备份、日志等）。
	RetainItems []ReinitItem `json:"retain_items"`
	// Steps 是可恢复执行步骤。
	Steps []string `json:"steps"`
	// JournalPath 是可恢复执行日志路径（实例目录内）。
	JournalPath string `json:"journal_path"`
	// RequiredConfirm 是必须逐字输入的确认串。
	RequiredConfirm string `json:"required_confirm"`
	// KeepMasterKey 表示保留主密钥材料（默认 false：更换/移除，防旧凭证复活）。
	KeepMasterKey bool `json:"keep_master_key"`
	// BackupRecommended/BackupNote 说明备份建议或无法备份的原因。
	BackupRecommended bool   `json:"backup_recommended"`
	BackupNote        string `json:"backup_note"`
	// CanExecute 为 false 时 Blocking 给出全部阻塞原因。
	CanExecute bool `json:"can_execute"`
	// RequiresMaintenanceLock 恒为 true：执行前必须取得 281 排他锁并停止主服务。
	RequiresMaintenanceLock bool     `json:"requires_maintenance_lock"`
	Blocking                []string `json:"blocking,omitempty"`
	Warnings                []string `json:"warnings,omitempty"`
}

// PlanFullReinit 生成完整重新初始化计划；不删除任何文件、不访问数据库。
func PlanFullReinit(request ReinitRequest) (ReinitPlan, error) {
	paths, err := normalizeReinitPaths(request.Paths)
	if err != nil {
		return ReinitPlan{}, err
	}
	instanceID := strings.TrimSpace(request.InstanceID)
	plan := ReinitPlan{
		InstanceID: instanceID, Paths: paths,
		RequiredConfirm:         reinitConfirmPrefix + instanceID,
		KeepMasterKey:           request.KeepMasterKey,
		JournalPath:             filepath.Join(paths.InstanceDir, reinitJournalName),
		RequiresMaintenanceLock: true,
		BackupRecommended:       true,
	}
	block := func(reason string) { plan.Blocking = append(plan.Blocking, reason) }
	if instanceID == "" || strings.ContainsAny(instanceID, " \t\r\n/\\") {
		block("实例标识缺失或包含非法字符：必须来自维护状态的稳定实例 ID")
	}
	if strings.TrimSpace(request.ConfirmText) != plan.RequiredConfirm {
		block("确认串必须逐字等于 " + plan.RequiredConfirm)
	}
	if err := validateReinitTargets(paths, request.ReservedPaths, request.AcknowledgeExternalPaths, &plan); err != nil {
		block(err.Error())
	}
	if !request.AcknowledgeOldCredentials {
		block("必须显式确认：清空后旧会话/旧找回授权/旧一次性凭证不会复活")
	}
	if !request.BackupAvailable {
		plan.BackupRecommended = false
		plan.BackupNote = "未检测到可用备份能力：请先完成一次完整备份后再重新初始化；" +
			"无法备份时本流程不会假装备份成功"
		plan.Warnings = append(plan.Warnings,
			"在无可用备份时继续完整重新初始化将不可恢复地丢失现有账户与业务数据")
	} else {
		plan.BackupNote = "执行前请先创建一份完整备份并记录产物路径/大小/SHA256；备份不随重新初始化删除"
	}

	plan.ClearItems = buildReinitClearItems(paths, request.KeepMasterKey)
	validateReinitClearItems(paths, plan.JournalPath, plan.ClearItems, &plan)
	plan.RetainItems = buildReinitRetainItems(paths, request.ReservedPaths)
	if request.KeepMasterKey {
		plan.Warnings = append(plan.Warnings,
			"保留主密钥：若旧数据库副本被带外恢复，旧密文仍可能被解密；彻底清空通常应轮换/移除主密钥")
	} else {
		plan.Warnings = append(plan.Warnings,
			"将移除/更换主密钥：旧加密材料（若仍有副本）将不可解密，这是防旧凭证复活的一部分")
	}
	plan.Steps = []string{
		"确认没有正在运行的 login-server 实例（共享维护锁，不杀无关进程）",
		"创建/确认完整备份产物并记录摘要（无备份能力时明确记录原因）",
		"取得维护排他锁并进入受控停止状态",
		"按清除清单逐项删除（仅实例内允许路径；符号链接/链接外目标拒绝）",
		"按需生成新的主密钥材料并重建数据库结构（复用 WS2 282 初始化）",
		"重建唯一 root（复用 WS2 283）并写入初始化进度",
		"重新检测实例状态，提示下一步（推荐配置/账户方案/服务启动）",
	}
	plan.CanExecute = len(plan.Blocking) == 0
	return plan, nil
}

// Reinitializer 是完整重新初始化的执行注入点（由持有维护锁的集成层实现）。
type Reinitializer interface {
	ExecuteFullReinit(ctx context.Context, plan ReinitPlan, journal *ReinitJournal) (ReinitResult, error)
}

// ReinitResult 是执行结果（脱敏）。
type ReinitResult struct {
	Completed     bool   `json:"completed"`
	InstanceID    string `json:"instance_id"`
	ClearedItems  int    `json:"cleared_items"`
	KeptMasterKey bool   `json:"kept_master_key"`
	NewRootUserID string `json:"new_root_user_id,omitempty"`
	// GeneratedRootPassword 只在本次内存传递并展示一次，禁止日志/审计/持久化。
	GeneratedRootPassword string   `json:"-"`
	NextSteps             []string `json:"next_steps,omitempty"`
}

// ExecuteFullReinitWith 校验计划/确认并调用注入执行器；不自行删除文件。
//
// maintenanceLockHeld 必须由调用方在真正取得 281 排他锁并停止主服务后传入 true；
// 本函数无法替调用方证明锁状态，因此要求显式参数并在日志中记录。
func ExecuteFullReinitWith(ctx context.Context, reinitializer Reinitializer, plan ReinitPlan, confirm string, maintenanceLockHeld bool) (ReinitResult, error) {
	if reinitializer == nil {
		return ReinitResult{}, errors.New("未注入重新初始化执行器（需要 WS2 初始化与 281 维护锁）")
	}
	if !maintenanceLockHeld {
		return ReinitResult{}, errors.New("必须已取得维护排他锁并停止主服务后才能执行完整重新初始化")
	}
	if !plan.CanExecute {
		return ReinitResult{}, fmt.Errorf("重新初始化计划存在阻塞项：%s", strings.Join(plan.Blocking, "；"))
	}
	if strings.TrimSpace(confirm) != plan.RequiredConfirm {
		return ReinitResult{}, fmt.Errorf("确认串不匹配：必须逐字输入 %q", plan.RequiredConfirm)
	}
	journal, err := OpenReinitJournal(plan.Paths.InstanceDir)
	if err != nil {
		return ReinitResult{}, err
	}
	return reinitializer.ExecuteFullReinit(ctx, plan, journal)
}

// ---- 路径校验 ----

func normalizeReinitPaths(paths ReinitPaths) (ReinitPaths, error) {
	requireAbs := func(label, value string) (string, error) {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			return "", fmt.Errorf("%s 未设置", label)
		}
		if !filepath.IsAbs(trimmed) {
			return "", fmt.Errorf("%s 必须是绝对路径", label)
		}
		return filepath.Clean(trimmed), nil
	}
	var err error
	normalized := ReinitPaths{}
	if normalized.InstanceDir, err = requireAbs("实例目录", paths.InstanceDir); err != nil {
		return ReinitPaths{}, err
	}
	if normalized.ConfigPath, err = requireAbs("配置文件", paths.ConfigPath); err != nil {
		return ReinitPaths{}, err
	}
	if normalized.DatabasePath, err = requireAbs("数据库文件", paths.DatabasePath); err != nil {
		return ReinitPaths{}, err
	}
	if strings.TrimSpace(paths.AttachmentsDir) != "" {
		if normalized.AttachmentsDir, err = requireAbs("附件目录", paths.AttachmentsDir); err != nil {
			return ReinitPaths{}, err
		}
	}
	if strings.TrimSpace(paths.StateDir) != "" {
		if normalized.StateDir, err = requireAbs("维护状态目录", paths.StateDir); err != nil {
			return ReinitPaths{}, err
		}
	}
	if strings.TrimSpace(paths.MasterKeyFile) != "" {
		if normalized.MasterKeyFile, err = requireAbs("主密钥文件", paths.MasterKeyFile); err != nil {
			return ReinitPaths{}, err
		}
	}
	if strings.TrimSpace(paths.LogDir) != "" {
		if normalized.LogDir, err = requireAbs("日志目录", paths.LogDir); err != nil {
			return ReinitPaths{}, err
		}
	}
	return normalized, nil
}

func validateReinitTargets(paths ReinitPaths, reserved []string, allowExternal bool, plan *ReinitPlan) error {
	info, err := os.Lstat(paths.InstanceDir)
	if err != nil {
		return fmt.Errorf("实例目录不可用：%w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("实例目录必须是真实目录（不能是符号链接）")
	}
	resolvedInstance, err := filepath.EvalSymlinks(paths.InstanceDir)
	if err != nil {
		return fmt.Errorf("解析实例目录失败：%w", err)
	}
	// 维护状态目录不得等于或包含实例目录：否则清除清单会删除实例根，连带抹掉
	// 配置、维护日志与重初始化执行日志（破坏性证据不能被自身清除）。
	if paths.StateDir != "" {
		stateClean := filepath.Clean(paths.StateDir)
		if samePathOrInside(paths.InstanceDir, stateClean) {
			plan.Blocking = append(plan.Blocking,
				"维护状态目录不能等于或包含实例目录："+stateClean)
		}
	}
	targets := []struct {
		label string
		path  string
	}{
		{"配置文件", paths.ConfigPath},
		{"数据库文件", paths.DatabasePath},
		{"附件目录", paths.AttachmentsDir},
		{"维护状态目录", paths.StateDir},
		{"主密钥文件", paths.MasterKeyFile},
		{"日志目录", paths.LogDir},
	}
	for _, target := range targets {
		if target.path == "" {
			continue
		}
		if err := rejectReservedPath(target.path, reserved); err != nil {
			return fmt.Errorf("%s：%w", target.label, err)
		}
		if err := rejectCodeRepository(target.path); err != nil {
			return fmt.Errorf("%s：%w", target.label, err)
		}
		resolved, resolveErr := resolveExistingTarget(target.path)
		if resolveErr != nil {
			return fmt.Errorf("%s：%w", target.label, resolveErr)
		}
		inside, outsideErr := pathWithinDirectory(resolved, resolvedInstance)
		if outsideErr != nil {
			return fmt.Errorf("%s：%w", target.label, outsideErr)
		}
		if !inside {
			if !allowExternal {
				return fmt.Errorf("%s 位于实例目录之外（%s）：必须显式确认外部路径", target.label, resolved)
			}
			plan.Warnings = append(plan.Warnings,
				"外部路径将被清除："+target.label+" "+resolved+"（已显式确认）")
		}
	}
	return nil
}

// validateReinitClearItems 断言清除清单绝不包含实例目录自身或承载维护证据的
// 日志路径（维护日志/重初始化执行日志）。违反时阻塞计划，执行器不会运行。
func validateReinitClearItems(paths ReinitPaths, journalPath string, items []ReinitItem, plan *ReinitPlan) {
	protected := []struct {
		label string
		path  string
	}{
		{label: "实例目录", path: paths.InstanceDir},
		{label: "重初始化执行日志", path: journalPath},
		{label: "维护日志", path: filepath.Join(filepath.Clean(paths.InstanceDir), ".login-setup-maintenance.jsonl")},
	}
	for _, item := range items {
		itemPath := filepath.Clean(item.Path)
		for _, guard := range protected {
			if guard.path == "" {
				continue
			}
			if samePathOrInside(filepath.Clean(guard.path), itemPath) {
				plan.Blocking = append(plan.Blocking,
					"清除项 "+item.Label+" 不能包含/等于"+guard.label+"："+itemPath)
			}
		}
	}
}

func rejectReservedPath(path string, reserved []string) error {
	cleanPath := filepath.Clean(path)
	for _, item := range reserved {
		if strings.TrimSpace(item) == "" {
			continue
		}
		reservedAbs, err := filepath.Abs(item)
		if err != nil {
			continue
		}
		reservedClean := filepath.Clean(reservedAbs)
		if samePathOrInside(cleanPath, reservedClean) {
			return fmt.Errorf("目标位于保留路径内：%s", reservedClean)
		}
	}
	return nil
}

// rejectCodeRepository 拒绝把代码仓库/模块根当作可清除目标。
func rejectCodeRepository(path string) error {
	cleanPath := filepath.Clean(path)
	for {
		for _, marker := range []string{".git", "go.mod"} {
			if _, err := os.Lstat(filepath.Join(cleanPath, marker)); err == nil {
				return fmt.Errorf("目标位于代码仓库/模块内（发现 %s）：禁止清除代码仓库", marker)
			}
		}
		parent := filepath.Dir(cleanPath)
		if parent == cleanPath {
			return nil
		}
		cleanPath = parent
	}
}

func resolveExistingTarget(path string) (string, error) {
	current := filepath.Clean(path)
	missing := []string{}
	for {
		if _, err := os.Lstat(current); err == nil {
			resolved, resolveErr := filepath.EvalSymlinks(current)
			if resolveErr != nil {
				return "", fmt.Errorf("解析符号链接失败：%w", resolveErr)
			}
			for index := len(missing) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, missing[index])
			}
			return resolved, nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return filepath.Clean(path), nil
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}

func pathWithinDirectory(path, directory string) (bool, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false, err
	}
	absDir, err := filepath.Abs(directory)
	if err != nil {
		return false, err
	}
	return samePathOrInside(absPath, absDir), nil
}

func samePathOrInside(path, directory string) bool {
	pathClean := strings.ToLower(filepath.Clean(path))
	dirClean := strings.ToLower(filepath.Clean(directory))
	if pathClean == dirClean {
		return true
	}
	return strings.HasPrefix(pathClean, dirClean+string(filepath.Separator))
}

func buildReinitClearItems(paths ReinitPaths, keepMasterKey bool) []ReinitItem {
	items := []ReinitItem{
		{Label: "数据库文件", Path: paths.DatabasePath, Kind: "file", Required: true,
			Detail: "含 -wal/-shm 伴生文件；重建后从空结构开始"},
		{Label: "配置文件", Path: paths.ConfigPath, Kind: "file", Required: true,
			Detail: "重新由初始化向导生成"},
	}
	if paths.AttachmentsDir != "" {
		items = append(items, ReinitItem{Label: "附件目录", Path: paths.AttachmentsDir,
			Kind: "dir", Detail: "头像等附件；目录内链接外目标不会被跟随"})
	}
	if paths.StateDir != "" {
		items = append(items, ReinitItem{Label: "维护状态/恢复代际目录", Path: paths.StateDir,
			Kind: "dir", Detail: "恢复代际与维护日志；清空后旧凭证不会因复制旧库复活"})
	}
	if paths.MasterKeyFile != "" && !keepMasterKey {
		items = append(items, ReinitItem{Label: "主密钥文件（将更换）", Path: paths.MasterKeyFile,
			Kind: "file", Detail: "更换后旧加密材料不可解密"})
	}
	return items
}

func buildReinitRetainItems(paths ReinitPaths, reserved []string) []ReinitItem {
	items := []ReinitItem{
		{Label: "代码仓库/程序目录", Path: "（仓库根，不在清除清单）", Kind: "dir",
			Detail: "重新初始化不删除代码、构建脚本或发布产物"},
		{Label: "执行日志目录（可选）", Path: paths.LogDir, Kind: "dir",
			Detail: "日志保留用于事故复盘，除非操作者另行处理"},
	}
	for _, item := range reserved {
		items = append(items, ReinitItem{Label: "保留路径", Path: filepath.Clean(item), Kind: "dir",
			Detail: "调用方显式保留（其他实例/用户数据）"})
	}
	return items
}

// ---- 可恢复执行日志 ----

// ReinitJournalEntry 是重新初始化执行日志的一行（不含秘密/配置内容）。
type ReinitJournalEntry struct {
	Sequence    int64     `json:"sequence"`
	OperationID string    `json:"operation_id"`
	Step        string    `json:"step"`
	Status      string    `json:"status"` // started|success|failed|cancelled
	ErrorCode   string    `json:"error_code,omitempty"`
	At          time.Time `json:"at"`
}

// ReinitJournal 是实例内可恢复执行日志。
type ReinitJournal struct {
	path      string
	operation string
	sequence  int64
}

// OpenReinitJournal 打开/创建实例目录内的执行日志（0600 追加）。
func OpenReinitJournal(instanceDir string) (*ReinitJournal, error) {
	trimmed := strings.TrimSpace(instanceDir)
	if trimmed == "" || !filepath.IsAbs(trimmed) {
		return nil, errors.New("实例目录必须是绝对路径")
	}
	path := filepath.Join(filepath.Clean(trimmed), reinitJournalName)
	operationID, err := newConfigPackageID()
	if err != nil {
		return nil, err
	}
	journal := &ReinitJournal{path: path, operation: "reinit/" + operationID}
	return journal, nil
}

// Path 返回执行日志路径。
func (j *ReinitJournal) Path() string {
	if j == nil {
		return ""
	}
	return j.path
}

// Record 追加一步执行状态（行级 JSON + Sync；超过上限时由调用方重建）。
func (j *ReinitJournal) Record(step, status, errorCode string) error {
	if j == nil {
		return errors.New("执行日志未初始化")
	}
	j.sequence++
	entry := ReinitJournalEntry{
		Sequence: j.sequence, OperationID: j.operation, Step: step,
		Status: status, ErrorCode: errorCode, At: time.Now().UTC(),
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(j.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("打开重新初始化执行日志失败：%w", err)
	}
	defer file.Close()
	if _, err := file.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("写入执行日志失败：%w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("同步执行日志失败：%w", err)
	}
	return nil
}

// ReadReinitJournal 读取执行日志（用于崩溃后恢复判断）；文件不存在返回空。
func ReadReinitJournal(instanceDir string) ([]ReinitJournalEntry, error) {
	path := filepath.Join(filepath.Clean(instanceDir), reinitJournalName)
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("读取执行日志失败：%w", err)
	}
	if int64(len(raw)) > reinitJournalMaxBytes {
		raw = raw[len(raw)-int(reinitJournalMaxBytes):]
	}
	entries := make([]ReinitJournalEntry, 0, 16)
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var entry ReinitJournalEntry
		if json.Unmarshal([]byte(line), &entry) != nil {
			continue // 崩溃时的半行记录忽略
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// ReinitResumeHint 汇总最近的未完成步骤（崩溃恢复提示）。
func ReinitResumeHint(entries []ReinitJournalEntry) string {
	lastByOperation := map[string]ReinitJournalEntry{}
	order := make([]string, 0, 4)
	for _, entry := range entries {
		if _, exists := lastByOperation[entry.OperationID]; !exists {
			order = append(order, entry.OperationID)
		}
		lastByOperation[entry.OperationID] = entry
	}
	if len(order) == 0 {
		return ""
	}
	last := lastByOperation[order[len(order)-1]]
	if last.Status == "success" {
		return "上次重新初始化已成功完成（operation " + last.OperationID + "）"
	}
	return fmt.Sprintf("检测到未完成的重新初始化（operation %s，步骤 %q，状态 %s）：请先核对实例状态再继续",
		last.OperationID, last.Step, last.Status)
}
