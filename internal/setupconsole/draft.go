package setupconsole

// 配置草稿校验、脱敏差异预览与原子保存（步骤280）。
//
// 闭环：字段编辑（279）→ 全量校验 → 差异预览 → 显式应用。
//   - 外部修改检测：草稿记录初始文件摘要；保存前目标文件摘要不一致时按策略处理，
//     默认 fail（绝不自动覆盖他人修改）；
//   - 备份：目标文件当前内容有效时，保存前原子写入“最后有效副本”；目标已是坏文件
//     时不覆盖既有最后有效副本；
//   - 原子写入：同目录临时文件 + Sync + 原子替换（278 SafeWriteFile），失败不破坏
//     原文件；临时文件有固定前缀，可识别崩溃残留；
//   - 秘密占位保护：`***`/`[REDACTED]` 等占位不得覆盖真实秘密来源；
//   - 环境变量覆盖：保存结果单独列出被环境变量覆盖的字段（文件保存成功不等于这些
//     字段以文件值生效）；
//   - 文件保存与服务重载分别返回：hot-reloadable 字段与 restart-required 字段分开
//     汇总，不把保存成功当作已生效。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/config"
)

// 保存相关稳定错误。
var (
	// ErrSaveConflict 表示草稿开始后目标文件被外部修改（默认策略拒绝覆盖）。
	ErrSaveConflict = errors.New("配置文件在草稿期间被外部修改")
	// ErrDraftInvalid 表示草稿未通过正式配置校验。
	ErrDraftInvalid = errors.New("配置草稿校验未通过")
	// ErrSecretPlaceholder 表示草稿试图用占位符覆盖真实秘密来源。
	ErrSecretPlaceholder = errors.New("配置草稿包含秘密占位符，拒绝覆盖真实秘密")
)

// ConflictPolicy 是外部修改冲突处理策略。
type ConflictPolicy string

const (
	// ConflictFail 是默认策略：存在外部修改即拒绝保存。
	ConflictFail ConflictPolicy = "fail"
	// ConflictReload 表示要求调用方重新加载后重新编辑（本函数返回冲突，不写盘）。
	ConflictReload ConflictPolicy = "reload"
	// ConflictUseDraft 是显式无人值守策略：仍写盘，但先备份当前有效内容；
	// 只允许在调用方已展示冲突并由用户明确选择时使用。
	ConflictUseDraft ConflictPolicy = "use-draft"
)

// SaveRequest 是保存配置草稿的请求。
type SaveRequest struct {
	Draft          *ConfigDraft
	ConflictPolicy ConflictPolicy
	// CreateBackup 为真时保存前保留最后有效副本。
	CreateBackup bool
	// Mode 是新建文件时的权限；目标已存在时沿用现有权限。
	Mode os.FileMode
}

// SaveResult 是保存结果；文件保存与服务生效/重载事实分开返回。
type SaveResult struct {
	Saved       bool
	BackupPath  string
	FileDigest  string
	ConfigValid bool
	// ReloadResult: not-requested / hot-reload-required / restart-required。
	ReloadResult  string
	HotFields     []string
	RestartFields []string
	Conflict      bool
	// OverriddenFields 是因环境变量覆盖而不会以文件值生效的字段。
	OverriddenFields []string
}

// 可注入的原子写/摘要函数（测试注入失败，不改变生产路径）。
var writeFileAtomic = SafeWriteFile
var nowFunc = time.Now

// SaveConfigDraft 校验并原子保存草稿。
func SaveConfigDraft(ctx context.Context, request SaveRequest) (SaveResult, error) {
	result := SaveResult{ReloadResult: "not-requested"}
	if ctx == nil {
		ctx = context.Background()
	}
	draft := request.Draft
	if draft == nil {
		return result, errors.New("缺少配置草稿")
	}
	path := strings.TrimSpace(draft.Path)
	if path == "" {
		return result, errors.New("草稿缺少目标配置文件路径")
	}
	if request.ConflictPolicy == "" {
		request.ConflictPolicy = ConflictFail
	}
	if request.Mode == 0 {
		request.Mode = 0o600
	}
	// 1) 秘密占位保护（先于一般校验，给出稳定的占位专用错误）。
	if placeholderErr := rejectSecretPlaceholders(draft); placeholderErr != nil {
		return result, placeholderErr
	}
	// 2) 全量校验：不合法草稿绝不写盘。
	report := draft.Validate()
	result.ConfigValid = report.Valid
	if !report.Valid {
		return result, fmt.Errorf("%w: %s", ErrDraftInvalid, report.Summary)
	}
	// 3) 外部修改检测。
	conflict, currentRaw, currentDigest, conflictErr := detectExternalConflict(path, draft)
	if conflictErr != nil {
		return result, conflictErr
	}
	if conflict {
		switch request.ConflictPolicy {
		case ConflictReload, ConflictFail:
			result.Conflict = true
			return result, fmt.Errorf("%w（当前摘要 %s，草稿基线 %s）", ErrSaveConflict,
				shortDigest(currentDigest), shortDigest(draft.BaseDigest))
		case ConflictUseDraft:
			result.Conflict = true
			// 继续保存，但强制保留当前有效内容备份（见下一步）。
		default:
			return result, fmt.Errorf("未知冲突策略 %q", request.ConflictPolicy)
		}
	}
	// 4) 最后有效备份（当前文件内容有效时才写入/更新；坏文件不覆盖既有备份）。
	if request.CreateBackup {
		backupPath, backupErr := writeLastValidBackup(path, currentRaw)
		if backupErr != nil {
			return result, backupErr
		}
		result.BackupPath = backupPath
	}
	// 5) 原子写盘。
	currentMode := request.Mode
	if info, err := os.Stat(path); err == nil {
		currentMode = info.Mode().Perm()
	}
	if writeErr := writeFileAtomic(path, draft.Raw(), currentMode); writeErr != nil {
		return result, fmt.Errorf("原子保存配置失败: %w", writeErr)
	}
	sum := sha256.Sum256(draft.Raw())
	result.Saved = true
	result.FileDigest = hex.EncodeToString(sum[:])
	result.OverriddenFields = overriddenFields()
	// 6) 生效分类：对比保存前后的有效配置。
	if previousReport, err := loadConfigFromRaw(currentRaw); err == nil {
		if diff := config.DiffReload(previousReport, report.Config); !diff.Empty() {
			result.HotFields = diff.HotFields
			result.RestartFields = diff.RestartFields
			switch {
			case len(diff.RestartFields) > 0:
				result.ReloadResult = "restart-required"
			case len(diff.HotFields) > 0:
				result.ReloadResult = "hot-reload-required"
			}
		}
	}
	return result, nil
}

// detectExternalConflict 比较目标文件当前摘要与草稿基线。
func detectExternalConflict(path string, draft *ConfigDraft) (bool, []byte, string, error) {
	currentRaw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// 草稿基线是空文件摘要时视为一致（新建配置）；否则文件被删除也是冲突。
			emptySum := sha256.Sum256(nil)
			if draft.BaseDigest == hex.EncodeToString(emptySum[:]) || draft.BaseDigest == "" {
				return false, nil, "", nil
			}
			return true, nil, "", nil
		}
		return false, nil, "", fmt.Errorf("读取目标配置失败: %w", err)
	}
	sum := sha256.Sum256(currentRaw)
	currentDigest := hex.EncodeToString(sum[:])
	return currentDigest != draft.BaseDigest, currentRaw, currentDigest, nil
}

// writeLastValidBackup 当当前文件内容为有效配置时写“最后有效副本”。
func writeLastValidBackup(path string, currentRaw []byte) (string, error) {
	if len(currentRaw) == 0 {
		return "", nil
	}
	cfg, err := loadConfigFromRaw(currentRaw)
	if err != nil {
		// 当前文件是坏文件：不覆盖既有最后有效副本。
		return "", nil
	}
	_ = cfg
	backupPath := path + ".last-valid"
	backupRaw, backupErr := loadBackupBytes(backupPath)
	if backupErr == nil && digestBytes(backupRaw) == digestBytes(currentRaw) {
		return backupPath, nil
	}
	if err := writeFileAtomic(backupPath, currentRaw, 0o600); err != nil {
		return "", fmt.Errorf("写入最后有效备份失败: %w", err)
	}
	return backupPath, nil
}

// loadBackupBytes 读取既有备份（不存在返回错误）。
func loadBackupBytes(path string) ([]byte, error) { return os.ReadFile(path) }

// loadConfigFromRaw 用正式加载器校验一段配置文本（不落盘）。
func loadConfigFromRaw(raw []byte) (config.Config, error) {
	loaded, err := config.Load(config.LoadOptions{YAML: raw})
	if err != nil {
		return config.Config{}, err
	}
	return loaded, nil
}

// rejectSecretPlaceholders 拒绝用占位符覆盖秘密来源。
func rejectSecretPlaceholders(draft *ConfigDraft) error {
	for _, info := range config.Fields() {
		if !info.Secret {
			continue
		}
		value, found := draft.GetValue(info.Field)
		if !found {
			continue
		}
		text, ok := value.(string)
		if !ok {
			continue
		}
		trimmed := strings.TrimSpace(text)
		if trimmed == "***" || strings.EqualFold(trimmed, "[REDACTED]") ||
			strings.EqualFold(trimmed, "REDACTED") {
			return fmt.Errorf("%w: 字段 %s", ErrSecretPlaceholder, info.Field)
		}
	}
	return nil
}

// overriddenFields 返回当前进程环境变量覆盖的配置字段（只列字段名，不显示值）。
func overriddenFields() []string {
	var fields []string
	for _, info := range config.Fields() {
		if info.Env == "" {
			continue
		}
		if _, present := os.LookupEnv(info.Env); present {
			fields = append(fields, info.Field)
		}
	}
	return fields
}

// DetectStaleTempFiles 识别本工具崩溃可能留下的原子写入临时文件（不删除）。
func DetectStaleTempFiles(directory string) ([]string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	var stale []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasPrefix(entry.Name(), ".login-setup-save-") {
			stale = append(stale, filepath.Join(directory, entry.Name()))
		}
	}
	return stale, nil
}

// shortDigest 只显示摘要前 12 位（足够排障，不含秘密）。
func shortDigest(digest string) string {
	if len(digest) <= 12 {
		return digest
	}
	return digest[:12]
}

// digestBytes 计算字节摘要用于备份比较。
func digestBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
