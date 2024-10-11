package setupconsole

// 步骤 292：备份检查、单项导出与受控恢复计划（WS4）。
//
// 本文件只做“只读检查/导出模型/恢复计划/确认要求”，不自行实现备份格式、恢复
// 事务或维护锁：
//   - 备份产物格式、结构检查、认证验证、单项导出全部复用 internal/backup 的
//     成熟实现（InspectFile/VerifyFile/ExtractEntry）；
//   - 受控恢复的实际执行（维护锁、预演、恢复代际、旧凭证失效、审计合并）复用
//     internal/restore + internal/maintenance，由后续 WS4 recover.go 在 WS1 的
//     281 锁落地后接入；本文件只产出可执行的计划与精确确认要求。
//
// 安全边界：
//   - 只读列表不跟随备份产物符号链接；跳过目录/特殊文件/超限文件并明确显示原因；
//   - 认证验证必须显式提供主密钥环（与备份文件分离保管），缺失时明确显示“未认证”；
//   - 导出沿用 backup.ExtractEntry 的受控暂存/敏感条目确认/操作记录；
//   - 恢复计划要求：结构/认证通过、维护锁（由调用方保证）、精确目标确认串、
//     带外代际替换显式确认；任何一项不满足都不可执行。

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/backup"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
)

const (
	// backupArtifactSuffix 是备份产物扩展名（与 internal/backup 一致）。
	backupArtifactSuffix = ".elnbak"
	// maxBackupArtifactEntries 限制列表扫描的目录项数，防止超大目录拖垮控制台。
	maxBackupArtifactEntries = 500
	// maxBackupArtifactBytes 限制可检查/导出的单份备份大小（默认 8 GiB）。
	maxBackupArtifactBytes int64 = 8 << 30
)

// BackupArtifact 是备份目录中的一份候选产物（轻量元数据；检查按需执行）。
type BackupArtifact struct {
	Path    string    `json:"path"`
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`
	// Problem 非空表示该目录项被跳过/不可用（符号链接、超限、读取失败等）。
	Problem string `json:"problem,omitempty"`
}

// BackupInspection 是一份备份的只读检查结果（结构检查 + 可选认证验证）。
type BackupInspection struct {
	Path     string    `json:"path"`
	FileSize int64     `json:"file_size"`
	ModTime  time.Time `json:"mod_time"`
	// Report 是 internal/backup 的结构/认证报告（不含秘密）。
	Report backup.VerifyReport `json:"report"`
	// Authenticated 表示是否已用主密钥环完成认证验证；false 时只有结构结论。
	Authenticated bool `json:"authenticated"`
	// Summaries 是给人看的范围/状态摘要（不包含内容数据或秘密）。
	DatabaseEngine  string   `json:"database_engine,omitempty"`
	SchemaVersion   string   `json:"schema_version,omitempty"`
	SchemaNumber    int      `json:"schema_version_number,omitempty"`
	ContentStatus   string   `json:"content_status,omitempty"`
	EntryKinds      []string `json:"entry_kinds,omitempty"`
	EntryCount      int      `json:"entry_count"`
	Warnings        []string `json:"warnings,omitempty"`
	Problem         string   `json:"problem,omitempty"`
	EncryptionState string   `json:"encryption_state"`
}

// ListBackupArtifacts 列出备份目录中的候选产物（只读；不打开/不认证）。
//
// 只接受目录内的普通文件（*.elnbak），不跟随符号链接；超出数量/大小上限的项以
// Problem 标注而不是静默忽略。目录不存在或不是目录返回错误。
func ListBackupArtifacts(dir string) ([]BackupArtifact, error) {
	cleanDir, err := controlledBackupDir(dir)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(cleanDir)
	if err != nil {
		return nil, fmt.Errorf("读取备份目录失败：%w", err)
	}
	artifacts := make([]BackupArtifact, 0, len(entries))
	scanned := 0
	for _, entry := range entries {
		if scanned >= maxBackupArtifactEntries {
			break
		}
		scanned++
		artifact := BackupArtifact{Name: entry.Name()}
		info, infoErr := entry.Info()
		if infoErr != nil {
			artifact.Problem = "无法读取目录项信息"
			artifacts = append(artifacts, artifact)
			continue
		}
		artifact.Path = filepath.Join(cleanDir, entry.Name())
		artifact.ModTime = info.ModTime()
		artifact.Size = info.Size()
		if entry.IsDir() {
			continue // 目录不是备份产物
		}
		if !strings.EqualFold(filepath.Ext(entry.Name()), backupArtifactSuffix) {
			continue // 只关心备份产物，其他文件不展示
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			artifact.Problem = "不是普通文件（可能是符号链接），已跳过"
			artifacts = append(artifacts, artifact)
			continue
		}
		if artifact.Size <= 0 || artifact.Size > maxBackupArtifactBytes {
			artifact.Problem = fmt.Sprintf("文件大小超出可检查范围（上限 %d 字节）", maxBackupArtifactBytes)
			artifacts = append(artifacts, artifact)
			continue
		}
		artifacts = append(artifacts, artifact)
	}
	sort.SliceStable(artifacts, func(i, j int) bool {
		if !artifacts[i].ModTime.Equal(artifacts[j].ModTime) {
			return artifacts[i].ModTime.After(artifacts[j].ModTime)
		}
		return artifacts[i].Name < artifacts[j].Name
	})
	return artifacts, nil
}

// InspectBackupArtifact 只读检查一份备份的结构/头部/密文摘要（不需要主密钥）。
//
// 结果只能发现截断/位翻转与展示元数据，不声称认证通过；认证验证用
// VerifyBackupArtifact。
func InspectBackupArtifact(ctx context.Context, path string) (BackupInspection, error) {
	cleanPath, info, err := controlledBackupFile(path)
	if err != nil {
		return BackupInspection{}, err
	}
	if info.Size() <= 0 || info.Size() > maxBackupArtifactBytes {
		return BackupInspection{}, fmt.Errorf("备份文件大小超出可检查范围（上限 %d 字节）", maxBackupArtifactBytes)
	}
	report, inspectErr := backup.InspectFile(ctx, cleanPath)
	inspection := BackupInspection{
		Path: cleanPath, FileSize: info.Size(), ModTime: info.ModTime(),
		Report: report, Authenticated: false,
	}
	inspection.EncryptionState = encryptionStateText(report)
	inspection.DatabaseEngine = report.Database.Engine
	inspection.SchemaVersion = report.Database.SchemaVersion
	inspection.SchemaNumber = report.Database.SchemaVersionNumber
	inspection.ContentStatus = ws4ContentSummary(report.Content)
	inspection.EntryCount = len(report.Entries)
	for _, entry := range report.Entries {
		inspection.EntryKinds = ws4AppendUnique(inspection.EntryKinds, entry.Kind)
	}
	if inspectErr != nil {
		inspection.Problem = "备份结构检查失败：" + ws4SafeErrorText(inspectErr)
		inspection.Warnings = append(inspection.Warnings, "结构检查失败时不要尝试恢复；请重新选择完整备份。")
		return inspection, nil
	}
	if !report.StructuralValid {
		inspection.Warnings = append(inspection.Warnings, "结构检查未通过：文件可能截断或被替换。")
	}
	if report.Encrypted && !report.Authenticated {
		inspection.Warnings = append(inspection.Warnings,
			"该备份已加密；未提供主密钥环前只能确认结构，不能确认内容来源与完整性。")
	}
	return inspection, nil
}

// VerifyBackupArtifact 用主密钥环认证验证一份备份，并返回只读检查结果。
//
// masterKeyFile 是受保护的主密钥环文件路径（与备份分开保管）；不读取命令行口令、
// 不把密钥材料写入日志或结果。
func VerifyBackupArtifact(ctx context.Context, path, masterKeyFile string) (BackupInspection, error) {
	cleanPath, info, err := controlledBackupFile(path)
	if err != nil {
		return BackupInspection{}, err
	}
	ring, err := loadBackupKeyring(ctx, masterKeyFile)
	if err != nil {
		return BackupInspection{}, err
	}
	report, verifyErr := backup.VerifyFile(ctx, cleanPath, ring)
	inspection := BackupInspection{
		Path: cleanPath, FileSize: info.Size(), ModTime: info.ModTime(),
		Report: report, Authenticated: report.Authenticated,
	}
	inspection.EncryptionState = encryptionStateText(report)
	inspection.DatabaseEngine = report.Database.Engine
	inspection.SchemaVersion = report.Database.SchemaVersion
	inspection.SchemaNumber = report.Database.SchemaVersionNumber
	inspection.ContentStatus = ws4ContentSummary(report.Content)
	inspection.EntryCount = len(report.Entries)
	for _, entry := range report.Entries {
		inspection.EntryKinds = ws4AppendUnique(inspection.EntryKinds, entry.Kind)
	}
	if verifyErr != nil {
		inspection.Problem = "备份认证验证失败：" + ws4SafeErrorText(verifyErr)
		inspection.Warnings = append(inspection.Warnings, "认证失败时禁止恢复；请确认主密钥环与备份来源。")
		return inspection, nil
	}
	if report.Encrypted && !report.Authenticated {
		inspection.Warnings = append(inspection.Warnings,
			"主密钥环不匹配或密文认证未通过：该备份不可用于恢复。")
	}
	if report.Content.Attachments.Status != backup.ContentIncluded &&
		report.Content.Attachments.Status != backup.ContentNoReferences &&
		report.Content.Attachments.Status != backup.ContentNotConfigured &&
		report.Content.Attachments.Status != backup.ContentExcluded {
		inspection.Warnings = append(inspection.Warnings,
			"备份附件状态不是已知稳定值，恢复前需确认内容范围。")
	}
	return inspection, nil
}

// BackupExportRequest 是单项导出请求（复用 backup.ExtractEntry 的受控约束）。
type BackupExportRequest struct {
	// Path 是备份文件路径。
	Path string
	// MasterKeyFile 是受保护主密钥环文件路径。
	MasterKeyFile string
	// EntryName 是清单条目名（如 attachments/avatars/xxx 或固定数据库条目）。
	EntryName string
	// OutputPath 是导出目标绝对路径；目标必须不存在，父目录必须已存在。
	OutputPath string
	// IncludeSensitive 表示导出原始数据库条目时的显式确认（附件/配置不需要）。
	IncludeSensitive bool
	// Operator 是本地受控操作者标识（进入本地导出操作记录）。
	Operator string
	// OperationLogPath 可选：本地导出操作记录路径；空则写入输出目录。
	OperationLogPath string
}

// BackupExportResult 是单项导出的脱敏结果。
type BackupExportResult struct {
	BackupID         string `json:"backup_id"`
	EntryName        string `json:"entry_name"`
	EntryKind        string `json:"entry_kind"`
	SizeBytes        int64  `json:"size_bytes"`
	SHA256           string `json:"sha256"`
	OutputFile       string `json:"output_file"`
	Sensitive        bool   `json:"sensitive_included"`
	OperationLogPath string `json:"operation_log"`
}

// ExportBackupEntry 从备份中受控导出单个条目（数据库条目需显式敏感确认）。
func ExportBackupEntry(ctx context.Context, request BackupExportRequest) (BackupExportResult, error) {
	backupPath, _, err := controlledBackupFile(request.Path)
	if err != nil {
		return BackupExportResult{}, err
	}
	if strings.TrimSpace(request.EntryName) == "" {
		return BackupExportResult{}, errors.New("必须指定要导出的备份条目名")
	}
	if strings.TrimSpace(request.OutputPath) == "" {
		return BackupExportResult{}, errors.New("必须指定导出目标路径")
	}
	ring, err := loadBackupKeyring(ctx, request.MasterKeyFile)
	if err != nil {
		return BackupExportResult{}, err
	}
	operator := strings.TrimSpace(request.Operator)
	if operator == "" {
		operator = "login-setup"
	}
	result, err := backup.ExtractEntry(ctx, backup.ExtractEntryOptions{
		Path: backupPath, Keyring: ring, EntryName: request.EntryName,
		OutputPath: request.OutputPath, IncludeSensitive: request.IncludeSensitive,
		Operator: operator, OperationLogPath: request.OperationLogPath,
	})
	if err != nil {
		return BackupExportResult{}, fmt.Errorf("导出备份条目失败：%w", err)
	}
	return BackupExportResult{
		BackupID: result.BackupID, EntryName: result.EntryName,
		EntryKind: result.EntryKind, SizeBytes: result.SizeBytes,
		SHA256: result.SHA256, OutputFile: result.OutputPath,
		Sensitive: result.Sensitive, OperationLogPath: result.OperationLog,
	}, nil
}

// RestorePlanRequest 是生成受控恢复计划的输入。
type RestorePlanRequest struct {
	// Inspection 已完成的只读检查（建议先经 VerifyBackupArtifact 认证）。
	Inspection BackupInspection
	// DatabasePath 是当前实例的 SQLite 数据库绝对路径（恢复目标）。
	DatabasePath string
	// StateDir 是库外维护/恢复状态目录（必须与数据库目录不同）。
	StateDir string
	// ConfirmText 必须精确等于备份 ID（或路径基线），防止误点。
	ConfirmText string
	// AcknowledgeOutOfBand 表示操作者已确认“库外代际与数据库记录不一致”的带外替换。
	AcknowledgeOutOfBand bool
}

// RestoreCheck 是恢复计划中的单项检查。
type RestoreCheck struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

// RestorePlan 是受控恢复的前置条件与精确确认要求。
//
// 本计划不执行恢复；实际执行必须由调用方在取得 281 维护锁、主服务停止后，用
// internal/restore 的 Rehearse/Execute 完成，并保留恢复代际与审计。
type RestorePlan struct {
	BackupPath   string `json:"backup_path"`
	BackupID     string `json:"backup_id"`
	DatabasePath string `json:"database_path"`
	StateDir     string `json:"state_dir"`
	CanExecute   bool   `json:"can_execute"`
	// RequiredConfirm 是操作者必须逐字输入的确认串。
	RequiredConfirm string `json:"required_confirm"`
	// RequiredSteps 是执行前置步骤（维护锁、服务停止、预演、回退备份等）。
	RequiredSteps []string         `json:"required_steps"`
	Checks        []RestoreCheck   `json:"checks"`
	Blocking      []string         `json:"blocking,omitempty"`
	Warnings      []string         `json:"warnings,omitempty"`
	Consequences  []string         `json:"consequences"`
	PreviewAt     time.Time        `json:"preview_at"`
	Inspection    BackupInspection `json:"-"`
}

// PlanControlledRestore 依据只读检查生成受控恢复计划；不写盘、不打开数据库。
//
// 计划只有在以下条件全部满足时才 CanExecute=true：备份结构通过、已认证（主密钥
// 正确）、目标数据库与状态目录为受控绝对路径且不同目录、确认串精确匹配、带外替换
// 已显式确认。实际执行仍需维护锁与主服务停止（见 recover.go）。
func PlanControlledRestore(request RestorePlanRequest) (RestorePlan, error) {
	inspection := request.Inspection
	plan := RestorePlan{
		BackupPath: inspection.Path, BackupID: inspection.Report.BackupID,
		DatabasePath:    strings.TrimSpace(request.DatabasePath),
		StateDir:        strings.TrimSpace(request.StateDir),
		RequiredConfirm: inspection.Report.BackupID,
		PreviewAt:       time.Now().UTC(), Inspection: inspection,
	}
	if plan.RequiredConfirm == "" {
		plan.RequiredConfirm = filepath.Base(inspection.Path)
	}
	checks := make([]RestoreCheck, 0, 8)
	block := func(name, detail string) {
		checks = append(checks, RestoreCheck{Name: name, Passed: false, Detail: detail})
		plan.Blocking = append(plan.Blocking, detail)
	}
	pass := func(name, detail string) {
		checks = append(checks, RestoreCheck{Name: name, Passed: true, Detail: detail})
	}

	if inspection.Problem != "" {
		block("备份结构检查", inspection.Problem)
	} else {
		pass("备份结构检查", "备份容器结构可读")
	}
	if !inspection.Report.StructuralValid {
		block("容器结构", "结构检查未通过（可能截断/位翻转）")
	} else {
		pass("容器结构", "结构检查通过")
	}
	if !inspection.Authenticated {
		block("内容认证", "未完成主密钥认证验证：禁止恢复（需用 VerifyBackupArtifact 验证）")
	} else {
		pass("内容认证", "主密钥认证通过")
	}
	if !inspection.Report.Content.Database || strings.TrimSpace(inspection.Report.Database.Engine) == "" {
		block("备份数据库条目", "备份中未发现可恢复的数据库条目")
	} else {
		pass("备份数据库条目", "数据库引擎："+inspection.Report.Database.Engine+
			" schema="+inspection.Report.Database.SchemaVersion)
	}
	if inspection.ContentStatus != "" && !strings.Contains(inspection.ContentStatus, "database=included") {
		plan.Warnings = append(plan.Warnings,
			"备份内容范围不完整（"+inspection.ContentStatus+"）：恢复可能缺失附件/配置。")
	}
	if plan.DatabasePath == "" || !filepath.IsAbs(plan.DatabasePath) {
		block("数据库目标", "必须给出当前实例数据库的绝对路径")
	} else {
		pass("数据库目标", plan.DatabasePath)
	}
	if plan.StateDir == "" || !filepath.IsAbs(plan.StateDir) {
		block("恢复状态目录", "必须给出库外恢复状态目录的绝对路径（与数据库目录不同）")
	} else if ws4SameDirectory(plan.StateDir, filepath.Dir(plan.DatabasePath)) {
		block("恢复状态目录", "恢复状态目录不能与数据库目录相同（回滚会覆盖恢复代际）")
	} else {
		pass("恢复状态目录", plan.StateDir)
	}
	if strings.TrimSpace(request.ConfirmText) != plan.RequiredConfirm {
		block("精确确认", "确认串必须逐字等于 "+plan.RequiredConfirm)
	} else {
		pass("精确确认", "确认串匹配")
	}
	if request.AcknowledgeOutOfBand {
		plan.Warnings = append(plan.Warnings,
			"已声明存在带外代际替换：仅在实际检测到代际不一致且确认来源可信时继续。")
	}

	plan.Checks = checks
	plan.CanExecute = len(plan.Blocking) == 0
	plan.RequiredSteps = []string{
		"取得维护排他锁并确认主服务已停止（不得杀无关进程）",
		"再次执行恢复预演（Rehearse），确认迁移前缀/容量/影响范围",
		"创建恢复前回退备份（受控输出目录内新文件）",
		"执行恢复并保留恢复代际、旧凭证失效与审计合并",
		"恢复后重新检测实例状态并提示需重启/重新登录",
	}
	plan.Consequences = []string{
		"当前数据库与附件会被备份内容替换；恢复前的数据需要回退备份才能找回",
		"现有会话、刷新令牌、找回授权与一次性凭证不会从备份中复活（恢复代际保护）",
		"恢复后的配置/密钥引用若与备份来源不同，将按维护流程提示重新核对",
	}
	return plan, nil
}

// RegisterWS4 注册 WS4 全部已实现控制台入口（500 备份检查、520 服务状态、
// 530 配置导入导出、540 保留数据恢复、550 完整重新初始化）。
//
// cmd/login-setup/main.go 已由 WS1 接线 RegisterWS2/RegisterWS3/RegisterWS4；
// WS4 不编辑 main。默认本地维护会话 opener 与入口同源，可用 WithWS4SessionOpener
// 覆盖；未实现能力不注册假按钮。
func RegisterWS4(app *App, options ...WS4Option) error {
	if app == nil {
		return errors.New("RegisterWS4: app 不能为空")
	}
	config := ws4Options{}
	for _, option := range options {
		if option == nil {
			continue
		}
		if err := option(&config); err != nil {
			return err
		}
	}
	if config.openSession == nil {
		config.openSession = ws4DefaultSessionOpener(app)
	}
	if err := app.RegisterMenu(MenuEntry{
		ID: "ws4-backup", Label: "备份检查与恢复", Order: 500,
	}); err != nil {
		return err
	}
	if err := app.RegisterScreen("ws4-backup", func() ScreenController {
		return NewBackupScreen(BackupScreenOptions{})
	}); err != nil {
		return err
	}
	if err := app.RegisterMenu(MenuEntry{
		ID: "ws4-service", Label: "服务状态与一键启动", Order: 520,
	}); err != nil {
		return err
	}
	if err := app.RegisterScreen("ws4-service", func() ScreenController {
		return NewServiceScreen()
	}); err != nil {
		return err
	}
	if err := RegisterWS4ConfigIOScreen(app); err != nil {
		return err
	}
	if err := RegisterWS4RecoverScreen(app, config.openSession); err != nil {
		return err
	}
	return RegisterWS4ReinitScreen(app)
}

// BackupScreenOptions 是备份检查画面的本地选项（不来自 HTTP/请求参数）。
type BackupScreenOptions struct {
	// BackupDir 是备份产物目录绝对路径；空则画面内可编辑。
	BackupDir string
	// MasterKeyFile 是可选的主密钥环文件路径；设置后按 'v' 认证验证。
	MasterKeyFile string
}

// BackupScreen 是步骤 292 的只读备份检查画面。
//
// 交互：↑/↓ 选择、r 刷新、d 编辑备份目录、m 编辑主密钥文件路径、v 认证验证选中项、
// Esc 返回。画面不做恢复/导出（需维护锁与后续实现），只显示检查结论与阻塞原因。
type BackupScreen struct {
	options   BackupScreenOptions
	dir       string
	keyFile   string
	editing   string // "", "dir", "key"
	buffer    string
	artifacts []BackupArtifact
	selected  int
	scroll    int
	inspect   *BackupInspection
	// entries 是当前检查结果的清单条目（按 "l" 载入；导出选择用）。
	entries        []backup.EntryReport
	entryIndex     int
	exportTarget   string
	pendingExport  bool
	pendingRestore bool
	message        string
	errText        string
	loading        bool
	y              int
}

// NewBackupScreen 创建备份检查画面。
func NewBackupScreen(options BackupScreenOptions) *BackupScreen {
	return &BackupScreen{options: options, dir: options.BackupDir, keyFile: options.MasterKeyFile}
}

// Title 实现 ScreenController。
func (s *BackupScreen) Title() string { return "备份检查与恢复（步骤 292）" }

// Render 实现 ScreenController：只写画布，不直接读写终端。
func (s *BackupScreen) Render(ctx context.Context, canvas *Canvas, session SessionView) {
	width := canvas.Width()
	if width < 40 {
		width = 40
	}
	canvas.Clear()
	line := func(text string) {
		canvas.Text(0, s.nextY(canvas), ws4ClipText(text, width))
	}
	s.resetY()
	line("备份目录：" + ws4ValueOr(s.dir, "（未设置，按 d 编辑）"))
	line("主密钥：" + ws4ValueOr(s.keyFile, "（未设置：仅结构检查，按 m 编辑）"))
	line(strings.Repeat("-", ws4MinInt(width, 72)))
	if s.loading {
		line("正在读取备份目录…")
		return
	}
	if s.errText != "" {
		line("错误：" + s.errText)
	}
	if len(s.artifacts) == 0 {
		line("目录中没有可检查的 *.elnbak 备份产物。")
	} else {
		line(fmt.Sprintf("共 %d 项（↑/↓ 选择；r 刷新；v 认证验证）", len(s.artifacts)))
		visible := canvas.Height() - s.currentY() - 12
		if visible < 3 {
			visible = 3
		}
		if s.selected < s.scroll {
			s.scroll = s.selected
		}
		if s.selected >= s.scroll+visible {
			s.scroll = s.selected - visible + 1
		}
		for index := s.scroll; index < len(s.artifacts) && index < s.scroll+visible; index++ {
			item := s.artifacts[index]
			marker := "  "
			if index == s.selected {
				marker = "> "
			}
			detail := fmt.Sprintf("%s%s  %s  %s", marker, ws4ClipText(item.Name, width-30),
				ws4HumanBytes(item.Size), item.ModTime.Local().Format("2006-01-02 15:04"))
			if item.Problem != "" {
				detail += "  [" + item.Problem + "]"
			}
			line(detail)
		}
	}
	if s.inspect != nil {
		canvas.HLine(s.nextY(canvas), '-', '-')
		s.renderInspection(canvas, width)
	}
	if len(s.entries) > 0 {
		line := func(text string) { canvas.Text(0, s.nextY(canvas), ws4ClipText(text, width)) }
		line("清单条目（↑/↓ 选择，e 导出）：")
		visible := len(s.entries)
		if visible > 8 {
			visible = 8
		}
		start := 0
		if s.entryIndex >= visible {
			start = s.entryIndex - visible + 1
		}
		for index := start; index < len(s.entries) && index < start+visible; index++ {
			marker := "  "
			if index == s.entryIndex {
				marker = "> "
			}
			line("  " + marker + s.entries[index].Name + " (" + s.entries[index].Kind + ")")
		}
	}
	if s.pendingExport || s.pendingRestore {
		line := func(text string) { canvas.Text(0, s.nextY(canvas), ws4ClipText(text, width)) }
		if s.pendingExport {
			line("再次按 e 确认导出选中条目")
		}
		if s.pendingRestore {
			line("再次按 s 确认受控恢复")
		}
	}
	if s.editing != "" {
		canvas.HLine(s.nextY(canvas), '-', '-')
		label := "输入备份目录（Enter 应用，Esc 取消）："
		if s.editing == "key" {
			label = "输入主密钥环文件路径（Enter 应用，Esc 取消）："
		}
		line(label)
		line("> " + ws4ClipText(s.buffer, width-2))
	}
	if s.message != "" {
		line(s.message)
	}
	line("Esc 返回；r 刷新；d 改备份目录；m 改主密钥；v 认证验证选中备份")
}

// HandleKey 实现 ScreenController。
func (s *BackupScreen) HandleKey(ctx context.Context, key Key, session SessionView) (bool, error) {
	if s.editing != "" {
		s.handleEditKey(key)
		return false, nil
	}
	switch key.Kind {
	case KeyEsc:
		return true, nil
	case KeyUp:
		if s.selected > 0 {
			s.selected--
			s.inspect = nil
			s.message = ""
		}
	case KeyDown:
		if s.selected+1 < len(s.artifacts) {
			s.selected++
			s.inspect = nil
			s.message = ""
		}
	case KeyRune:
		switch key.Rune {
		case 'r', 'R':
			s.refresh(ctx)
		case 'd', 'D':
			s.editing = "dir"
			s.buffer = s.dir
		case 'm', 'M':
			s.editing = "key"
			s.buffer = s.keyFile
		case 'v', 'V':
			s.clearPending()
			s.verifySelected(ctx)
		case 'l', 'L':
			s.clearPending()
			s.loadEntries()
		case 'e', 'E':
			if s.pendingExport {
				s.pendingExport = false
				s.exportSelected(ctx, session)
				break
			}
			s.prepareExport(session)
		case 's', 'S':
			if s.pendingRestore {
				s.pendingRestore = false
				s.restoreSelected(ctx, session)
				break
			}
			s.prepareRestore()
		}
	case KeyEnter:
		s.clearPending()
		s.inspectSelected(ctx)
	}
	return false, nil
}

func (s *BackupScreen) clearPending() {
	s.pendingExport = false
	s.pendingRestore = false
}

// loadEntries 从已完成的认证/结构检查中载入清单条目，供导出选择。
func (s *BackupScreen) loadEntries() {
	if s.inspect == nil {
		s.message = "请先按 Enter 检查选中备份"
		return
	}
	s.entries = append([]backup.EntryReport(nil), s.inspect.Report.Entries...)
	s.entryIndex = 0
	if len(s.entries) == 0 {
		s.message = "该备份未提供可见清单条目（未认证时只能看到结构结论）"
		return
	}
	s.message = "已载入清单条目：↑/↓ 选择，e 导出"
}

func (s *BackupScreen) selectedEntry() (backup.EntryReport, bool) {
	if s.entryIndex < 0 || s.entryIndex >= len(s.entries) {
		return backup.EntryReport{}, false
	}
	return s.entries[s.entryIndex], true
}

func (s *BackupScreen) prepareExport(session SessionView) {
	s.errText = ""
	if s.inspect == nil {
		s.errText = "请先检查并认证备份"
		return
	}
	if !s.inspect.Authenticated {
		s.errText = "导出需要先按 v 完成主密钥认证验证（未认证备份禁止解包）"
		return
	}
	if len(s.entries) == 0 {
		s.errText = "请先按 l 载入清单条目"
		return
	}
	entry, ok := s.selectedEntry()
	if !ok {
		s.errText = "未选择有效条目"
		return
	}
	instanceDir := ""
	if configPath := session.Detection.ConfigPath; configPath != "" {
		instanceDir = filepath.Dir(configPath)
	}
	if instanceDir == "" {
		s.errText = "未选择实例配置，无法确定受控导出目录"
		return
	}
	exportsDir := filepath.Join(instanceDir, "exports")
	if err := os.MkdirAll(exportsDir, 0o700); err != nil {
		s.errText = "创建受控导出目录失败：" + ws4SafeErrorText(err)
		return
	}
	baseName := strings.NewReplacer("/", "_", "\\\\", "_").Replace(entry.Name)
	s.exportTarget = filepath.Join(exportsDir,
		s.inspect.Report.BackupID+"-"+baseName)
	if _, err := ws4ExportTarget(instanceDir, s.exportTarget); err != nil {
		s.errText = ws4SafeErrorText(err)
		return
	}
	s.pendingExport = true
	extra := ""
	if entry.Kind == backup.EntryKindDatabase {
		extra = "；该条目是原始数据库条目，导出即包含敏感数据"
	}
	s.message = "将导出条目 " + entry.Name + " 到 " + s.exportTarget +
		extra + "；再次按 e 确认"
}

func (s *BackupScreen) exportSelected(ctx context.Context, session SessionView) {
	s.errText = ""
	entry, ok := s.selectedEntry()
	if !ok || s.exportTarget == "" {
		s.errText = "导出状态已失效，请重新选择"
		return
	}
	instanceDir, err := ws4InstanceDirForConfig(session.Detection.ConfigPath)
	if err != nil {
		s.errText = ws4SafeErrorText(err)
		return
	}
	target, err := ws4ExportTarget(instanceDir, s.exportTarget)
	if err != nil {
		s.errText = ws4SafeErrorText(err)
		return
	}
	maint, err := openWS4Maint(instanceDir)
	if err != nil {
		s.errText = ws4SafeErrorText(err)
		return
	}
	_, err = maint.runDestructive(ctx, session.Detection.DatabasePath, "backup.export",
		func() (string, error) {
			exported, exportErr := ExportBackupEntry(ctx, BackupExportRequest{
				Path: s.inspect.Path, MasterKeyFile: s.keyFile, EntryName: entry.Name,
				OutputPath: target, IncludeSensitive: entry.Kind == backup.EntryKindDatabase,
				Operator: "login-setup",
			})
			if exportErr != nil {
				return "backup", exportErr
			}
			_ = exported
			return "backup", nil
		})
	if err != nil {
		s.errText = ws4SafeErrorText(err)
		return
	}
	s.message = "条目已导出到 " + target + "（维护日志已记录；文件摘要见本地导出操作记录）"
	s.exportTarget = ""
}

func (s *BackupScreen) prepareRestore() {
	s.errText = ""
	if s.inspect == nil {
		s.errText = "请先选择并检查备份"
		return
	}
	if !s.inspect.Authenticated {
		s.errText = "恢复需要先按 v 完成主密钥认证验证"
		return
	}
	if s.inspect.Report.BackupID == "" {
		s.errText = "备份缺少编号，无法加载恢复源"
		return
	}
	s.pendingRestore = true
	s.message = "将执行受控恢复（维护锁+预演+恢复代际）；需再次按 s 确认"
}

func (s *BackupScreen) restoreSelected(ctx context.Context, session SessionView) {
	s.errText = ""
	instanceDir, err := ws4InstanceDirForConfig(session.Detection.ConfigPath)
	if err != nil {
		s.errText = ws4SafeErrorText(err)
		return
	}
	maint, err := openWS4Maint(instanceDir)
	if err != nil {
		s.errText = ws4SafeErrorText(err)
		return
	}
	var result app.BackupRestoreResult
	result, err = maint.runDestructiveRestore(ctx, session.Detection.DatabasePath,
		"backup.restore", func() (app.BackupRestoreResult, error) {
			return ExecuteControlledRestore(ctx, session.Detection.ConfigPath,
				session.Detection.DatabasePath, s.inspect.Report.BackupID,
				"login-setup local controlled restore", "RESTORE")
		})
	if err != nil {
		s.errText = ws4SafeErrorText(err) +
			"（恢复失败默认保持维护状态，不会自动对外放行；请检查库外状态后显式处置）"
		return
	}
	s.message = fmt.Sprintf("恢复完成：restore_id=%s generation=%d 撤销会话=%d 维护状态已退出=%t",
		result.RestoreID, result.Generation, result.RevokedSessions, result.MaintenanceExited)
}

func (s *BackupScreen) handleEditKey(key Key) {
	switch key.Kind {
	case KeyEsc:
		s.editing = ""
		s.buffer = ""
	case KeyEnter:
		value := strings.TrimSpace(s.buffer)
		if s.editing == "dir" {
			s.dir = value
		} else {
			s.keyFile = value
		}
		s.editing = ""
		s.buffer = ""
		s.inspect = nil
		s.message = "路径已更新，按 r 刷新"
	case KeyBackspace:
		if len(s.buffer) > 0 {
			runes := []rune(s.buffer)
			s.buffer = string(runes[:len(runes)-1])
		}
	case KeyRune:
		s.buffer += string(key.Rune)
	}
}

func (s *BackupScreen) refresh(ctx context.Context) {
	s.loading = true
	s.errText = ""
	s.inspect = nil
	s.artifacts = nil
	s.selected = 0
	s.scroll = 0
	defer func() { s.loading = false }()
	if strings.TrimSpace(s.dir) == "" {
		s.message = "请先按 d 设置备份目录"
		return
	}
	artifacts, err := ListBackupArtifacts(s.dir)
	if err != nil {
		s.errText = ws4SafeErrorText(err)
		return
	}
	s.artifacts = artifacts
	s.message = fmt.Sprintf("已刷新：%d 项", len(artifacts))
	_ = ctx
}

func (s *BackupScreen) selectedArtifact() (BackupArtifact, bool) {
	if s.selected < 0 || s.selected >= len(s.artifacts) {
		return BackupArtifact{}, false
	}
	item := s.artifacts[s.selected]
	if item.Problem != "" || item.Path == "" {
		return BackupArtifact{}, false
	}
	return item, true
}

func (s *BackupScreen) inspectSelected(ctx context.Context) {
	item, ok := s.selectedArtifact()
	if !ok {
		s.message = "选中项不可检查（见条目问题说明）"
		return
	}
	inspection, err := InspectBackupArtifact(ctx, item.Path)
	if err != nil {
		s.errText = ws4SafeErrorText(err)
		return
	}
	s.inspect = &inspection
	s.message = "结构检查完成；如需确认内容来源与完整性，按 v 做认证验证"
}

func (s *BackupScreen) verifySelected(ctx context.Context) {
	item, ok := s.selectedArtifact()
	if !ok {
		s.message = "选中项不可验证（见条目问题说明）"
		return
	}
	if strings.TrimSpace(s.keyFile) == "" {
		s.message = "未设置主密钥环路径：按 m 设置后才能认证验证"
		return
	}
	inspection, err := VerifyBackupArtifact(ctx, item.Path, s.keyFile)
	if err != nil {
		s.errText = ws4SafeErrorText(err)
		return
	}
	s.inspect = &inspection
	if inspection.Authenticated {
		s.message = "认证验证通过"
	} else {
		s.message = "认证验证未通过，禁止用于恢复"
	}
}

func (s *BackupScreen) renderInspection(canvas *Canvas, width int) {
	inspection := s.inspect
	line := func(text string) { canvas.Text(0, s.nextY(canvas), ws4ClipText(text, width)) }
	line("检查结果：" + filepath.Base(inspection.Path))
	line(fmt.Sprintf("备份 ID：%s  格式版本：%d  大小：%s",
		ws4ValueOr(inspection.Report.BackupID, "未知"), inspection.Report.FormatVersion,
		ws4HumanBytes(inspection.FileSize)))
	line(fmt.Sprintf("创建时间：%s  来源主机：%s  应用版本：%s",
		ws4FormatTimeOrEmpty(inspection.Report.CreatedAt), ws4ValueOr(inspection.Report.Host, "未知"),
		ws4ValueOr(inspection.Report.AppVersion, "未知")))
	line(fmt.Sprintf("加密：%s  认证：%s  结构：%s", inspection.EncryptionState,
		ws4BoolText(inspection.Authenticated, "通过", "未认证"),
		ws4BoolText(inspection.Report.StructuralValid, "通过", "未通过")))
	line(fmt.Sprintf("数据库：%s schema=%s 内容范围：%s 条目数：%d",
		ws4ValueOr(inspection.DatabaseEngine, "未知"), ws4ValueOr(inspection.SchemaVersion, "未知"),
		ws4ValueOr(inspection.ContentStatus, "未知"), inspection.EntryCount))
	if len(inspection.EntryKinds) > 0 {
		line("条目类型：" + strings.Join(inspection.EntryKinds, ", "))
	}
	if inspection.Problem != "" {
		line("问题：" + inspection.Problem)
	}
	for _, warning := range inspection.Warnings {
		line("提示：" + warning)
	}
	if inspection.Report.StructuralValid && inspection.Authenticated {
		line("该备份可用于受控恢复：恢复前仍需维护锁、预演与精确确认（见 292 流程）。")
	}
}

func (s *BackupScreen) currentY() int { return s.y }
func (s *BackupScreen) nextY(canvas *Canvas) int {
	y := s.y
	if y < canvas.Height() {
		s.y++
	}
	return y
}
func (s *BackupScreen) resetY() { s.y = 0 }

// ---- 内部辅助 ----

func controlledBackupDir(dir string) (string, error) {
	trimmed := strings.TrimSpace(dir)
	if trimmed == "" {
		return "", errors.New("未设置备份目录")
	}
	if !filepath.IsAbs(trimmed) {
		return "", fmt.Errorf("备份目录必须是绝对路径：%s", trimmed)
	}
	cleanDir := filepath.Clean(trimmed)
	info, err := os.Lstat(cleanDir)
	if err != nil {
		return "", fmt.Errorf("备份目录不可用：%w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("备份目录不能是符号链接")
	}
	if !info.IsDir() {
		return "", errors.New("备份目录不是目录")
	}
	return cleanDir, nil
}

func controlledBackupFile(path string) (string, os.FileInfo, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "", nil, errors.New("未指定备份文件")
	}
	if !filepath.IsAbs(trimmed) {
		return "", nil, fmt.Errorf("备份文件必须是绝对路径：%s", trimmed)
	}
	cleanPath := filepath.Clean(trimmed)
	if !strings.EqualFold(filepath.Ext(cleanPath), backupArtifactSuffix) {
		return "", nil, fmt.Errorf("不是备份产物（扩展名必须为 %s）", backupArtifactSuffix)
	}
	info, err := os.Lstat(cleanPath)
	if err != nil {
		return "", nil, fmt.Errorf("备份文件不可用：%w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", nil, errors.New("备份文件必须是普通文件（不能是符号链接/设备）")
	}
	return cleanPath, info, nil
}

func loadBackupKeyring(ctx context.Context, masterKeyFile string) (*secrets.Keyring, error) {
	trimmed := strings.TrimSpace(masterKeyFile)
	if trimmed == "" {
		return nil, errors.New("必须提供主密钥环文件路径才能认证验证/导出")
	}
	if !filepath.IsAbs(trimmed) {
		return nil, fmt.Errorf("主密钥环文件必须是绝对路径：%s", trimmed)
	}
	provider, err := secrets.NewFileProvider(filepath.Clean(trimmed))
	if err != nil {
		return nil, fmt.Errorf("打开主密钥环失败：%w", err)
	}
	ring, err := secrets.LoadKeyring(ctx, provider)
	if err != nil {
		return nil, fmt.Errorf("加载主密钥环失败：%w", err)
	}
	return ring, nil
}

func ws4ContentSummary(content backup.ContentMeta) string {
	parts := make([]string, 0, 4)
	if content.Database {
		parts = append(parts, "database=included")
	}
	statusText := func(label string, status backup.ContentStatus) {
		if status.Status == "" {
			return
		}
		part := label + "=" + status.Status
		if status.Count > 0 {
			part += fmt.Sprintf("(%d)", status.Count)
		}
		parts = append(parts, part)
	}
	statusText("attachments", content.Attachments)
	statusText("config", content.Config)
	statusText("keyring", content.Keyring)
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " ")
}

func encryptionStateText(report backup.VerifyReport) string {
	if report.Encrypted {
		return "加密"
	}
	return "未加密（不支持作为正式备份发布）"
}

func ws4AppendUnique(values []string, value string) []string {
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func ws4SameDirectory(left, right string) bool {
	leftAbs, leftErr := filepath.Abs(left)
	rightAbs, rightErr := filepath.Abs(right)
	if leftErr != nil || rightErr != nil {
		return false
	}
	return strings.EqualFold(filepath.Clean(leftAbs), filepath.Clean(rightAbs))
}

func ws4HumanBytes(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	value := float64(size)
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	for _, name := range units {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.1f %s", value, name)
		}
	}
	return fmt.Sprintf("%.1f PiB", value)
}

func ws4ClipText(text string, width int) string {
	if width <= 0 {
		return ""
	}
	runes := []rune(text)
	if len(runes) <= width {
		return text
	}
	if width <= 1 {
		return string(runes[:width])
	}
	return string(runes[:width-1]) + "…"
}

func ws4ValueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func ws4BoolText(value bool, yes, no string) string {
	if value {
		return yes
	}
	return no
}

func ws4FormatTimeOrEmpty(value time.Time) string {
	if value.IsZero() {
		return "未知"
	}
	return value.Local().Format("2006-01-02 15:04:05")
}

func ws4SafeErrorText(err error) string {
	if err == nil {
		return ""
	}
	text := err.Error()
	text = strings.ReplaceAll(text, "\r", " ")
	text = strings.ReplaceAll(text, "\n", " ")
	if len(text) > 240 {
		text = text[:240] + "…"
	}
	return text
}

func ws4MinInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}
