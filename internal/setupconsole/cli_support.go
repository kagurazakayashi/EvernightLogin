package setupconsole

// 步骤297：非交互命令复用 WS1–WS4 领域能力的薄适配（新增文件，不修改 WS1–WS4
// 已有业务文件）。
//
//   - NewConfigDraftFromRaw：在保留 BaseDigest/BaseRaw（外部修改冲突检测）的前提下，
//     用“已计算好的新配置原文”构造草稿，供导入/恢复命令通过 WS1 280 SaveConfigDraft
//     原子保存；
//   - DraftConfigSaver：把 WS1 ConfigSaver 契约桥接到 SaveConfigDraft，使
//     ApplyConfigImport / ApplyRuntimeConfigRecovery 不复制第二套保存事务；
//   - 所有函数不读标准输入、不打印秘密；秘密由命令层从受限文件/标准输入取得。

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
)

// NewConfigDraftFromRaw 构造“base 为当前文件、内容为 newRaw”的草稿。
//
// 与 NewConfigDraft 的区别：NewConfigDraft(path, raw) 把 raw 同时作为基准和内容；
// 本函数保留 baseRaw 作为 BaseDigest/BaseRaw，内容取自 newRaw（例如导入/恢复计划
// 生成的 Proposed），从而 SaveConfigDraft 仍能检测外部并发修改。
func NewConfigDraftFromRaw(path string, baseRaw, newRaw []byte) (*ConfigDraft, error) {
	draft, err := NewConfigDraft(path, baseRaw)
	if err != nil {
		return nil, err
	}
	tree := map[string]any{}
	if strings.TrimSpace(string(newRaw)) != "" {
		if err := yaml.Unmarshal(newRaw, &tree); err != nil {
			return nil, fmt.Errorf("新配置 YAML 解析失败: %w", err)
		}
		if tree == nil {
			tree = map[string]any{}
		}
	}
	draft.tree = deepCopyTree(tree)
	return draft, nil
}

// DraftConfigSaver 把导入/恢复命令的保存请求桥接到 WS1 280 SaveConfigDraft。
type DraftConfigSaver struct {
	// Operator 进入保存审计（不含秘密）。空值使用 "login-setup-cli"。
	Operator string
}

// SaveConfig 实现 ConfigSaver：保留基准摘要、按冲突策略原子保存并创建最后有效副本。
func (s DraftConfigSaver) SaveConfig(ctx context.Context, request ConfigSaveRequest) (ConfigSaveOutcome, error) {
	path := filepath.Clean(strings.TrimSpace(request.Path))
	if path == "" {
		return ConfigSaveOutcome{}, fmt.Errorf("保存路径为空")
	}
	draft, err := NewConfigDraftFromRaw(path, request.BaseRaw, request.NewRaw)
	if err != nil {
		return ConfigSaveOutcome{}, err
	}
	operator := strings.TrimSpace(s.Operator)
	if operator == "" {
		operator = "login-setup-cli"
	}
	_ = operator // 保存审计由命令层/上层负责；SaveConfigDraft 不接收操作者字段。
	result, err := SaveConfigDraft(ctx, SaveRequest{
		Draft:          draft,
		ConflictPolicy: ConflictPolicy(strings.TrimSpace(request.ConflictPolicy)),
		CreateBackup:   request.CreateBackup,
		Mode:           0o600,
	})
	if err != nil {
		return ConfigSaveOutcome{}, err
	}
	return ConfigSaveOutcome{
		Saved:        result.Saved,
		BackupPath:   result.BackupPath,
		FileDigest:   result.FileDigest,
		ConfigValid:  result.ConfigValid,
		ReloadResult: result.ReloadResult,
		Conflict:     result.Conflict,
	}, nil
}

// 编译期确认 DraftConfigSaver 实现 ConfigSaver。
var _ ConfigSaver = DraftConfigSaver{}

// SanitizeText 清洗外部文本中的控制字符（保留换行/制表）；用于非交互命令的
// 人类输出，避免 ANSI 控制序列操纵终端。JSON 由 encoding/json 转义，不经过这里。
func SanitizeText(text string) string { return sanitizeDisplay(text) }
