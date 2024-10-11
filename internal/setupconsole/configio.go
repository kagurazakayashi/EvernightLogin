package setupconsole

// 步骤 293：配置导入导出与敏感配置加密包（WS4）。
//
// 三类产物严格区分：
//   1. 默认“脱敏 YAML”：可直接阅读/审阅，秘密来源（env/file 引用的名称）被替换为
//      占位符；占位符在导入时永远不覆盖现有配置秘密；
//   2. 显式“加密敏感配置包”：完整配置原文用主密钥环加密（复用 internal/secrets
//      的 AES-256-GCM Sealer 信封与 key_id），解密密钥（主密钥环文件）不随包分发；
//   3. 完整实例备份：由步骤 292 的备份服务负责，不是本文件产物。
//
// 本文件不写数据库、不迁移数据、不切换数据库连接；导入只生成“待应用”的配置草稿
// 与差异预览，真正的原子保存/版本冲突由 WS1 280 的 SaveConfigDraft/SafeWriteFile
// 接口完成（通过 ConfigSaver 注入，避免自造第二套保存逻辑）。

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"

	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
)

const (
	// configExportMaxPlaintextBytes 限制单个配置原文/加密包明文字节数。
	configExportMaxPlaintextBytes = 1 << 20 // 1 MiB
	// configExportMaxPackageBytes 限制加密包文件总字节数。
	configExportMaxPackageBytes int64 = 2 << 20 // 2 MiB
	// configExportMaxYAMLDepth 限制导出/导入预览时接受的 YAML 嵌套深度。
	configExportMaxYAMLDepth = 64
	// configPackageMagic 是加密敏感配置包的魔数。
	configPackageMagic = "LNCFG1"
	// configPackageVersion 是当前加密包格式版本。
	configPackageVersion = 1
	// configPackageMaxChunks 限制分块数量（每块 ≤ secrets.MaxPlaintextBytes）。
	configPackageMaxChunks = 64
	// configPackagePurpose 是加密包密文的用途绑定（解密必须完全一致）。
	configPackagePurpose = "setup.config.export"
	// maskedPlaceholder 是脱敏导出使用的占位值。
	maskedPlaceholder = "REDACTED"
)

// MaskedField 描述脱敏导出中被替换的字段。
type MaskedField struct {
	Path   string `json:"path"`
	Source string `json:"source"` // "secret-source" | "secret-like-value"
	// SourceKind 保留原来源类型（env/file）但隐藏名称，便于人工确认“这里需要秘密”。
	SourceKind string `json:"source_kind,omitempty"`
}

// MaskedConfigExport 是脱敏 YAML 导出结果。
type MaskedConfigExport struct {
	OutputPath string        `json:"output_path"`
	SizeBytes  int64         `json:"size_bytes"`
	SHA256     string        `json:"sha256"`
	Masked     []MaskedField `json:"masked"`
	Bytes      []byte        `json:"-"`
}

// MaskConfigYAML 把配置 YAML 中的秘密来源与疑似秘密值替换为占位符。
//
// 只处理标量；不解析成强类型，因此坏配置也能“尽力脱敏导出”（调用方应仅对通过
// 校验的配置做正式导出）。返回的脱敏文本不可直接作为有效配置使用。
func MaskConfigYAML(raw []byte) ([]byte, []MaskedField, error) {
	if len(raw) > configExportMaxPlaintextBytes {
		return nil, nil, fmt.Errorf("配置超过脱敏导出上限（%d 字节）", configExportMaxPlaintextBytes)
	}
	var document yaml.Node
	if err := yaml.Unmarshal(raw, &document); err != nil {
		return nil, nil, fmt.Errorf("配置不是合法 YAML，无法脱敏导出：%w", err)
	}
	if len(document.Content) == 0 {
		return []byte{}, nil, nil
	}
	masked := make([]MaskedField, 0, 8)
	root := document.Content[0]
	if err := maskYAMLNode(root, "", &masked, 0); err != nil {
		return nil, nil, err
	}
	encoded, err := yaml.Marshal(&document)
	if err != nil {
		return nil, nil, fmt.Errorf("重新编码脱敏 YAML 失败：%w", err)
	}
	return encoded, masked, nil
}

// maskYAMLNode 递归脱敏：secretSources 子节点保留来源类型、抹掉名称；其他映射中
// 名称像秘密的标量（password/secret/token/private_key）替换为占位符。
func maskYAMLNode(node *yaml.Node, path string, masked *[]MaskedField, depth int) error {
	if node == nil {
		return nil
	}
	if depth > configExportMaxYAMLDepth {
		return errors.New("配置 YAML 嵌套过深，拒绝脱敏导出")
	}
	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			if err := maskYAMLNode(child, path, masked, depth+1); err != nil {
				return err
			}
		}
		return nil
	case yaml.MappingNode:
		for index := 0; index+1 < len(node.Content); index += 2 {
			keyNode := node.Content[index]
			valueNode := node.Content[index+1]
			key := keyNode.Value
			childPath := key
			if path != "" {
				childPath = path + "." + key
			}
			if path == "secrets" || strings.HasPrefix(path, "secrets.") {
				if valueNode.Kind == yaml.MappingNode {
					if err := maskSecretSource(valueNode, childPath, masked); err != nil {
						return err
					}
					continue
				}
				if valueNode.Kind == yaml.ScalarNode {
					valueNode.Value = maskedPlaceholder
					valueNode.Tag = "!!str"
					*masked = append(*masked, MaskedField{Path: childPath, Source: "secret-like-value"})
					continue
				}
			}
			if valueNode.Kind == yaml.ScalarNode && looksLikeSecretName(key) {
				valueNode.Value = maskedPlaceholder
				valueNode.Tag = "!!str"
				*masked = append(*masked, MaskedField{Path: childPath, Source: "secret-like-value"})
				continue
			}
			if err := maskYAMLNode(valueNode, childPath, masked, depth+1); err != nil {
				return err
			}
		}
		return nil
	case yaml.SequenceNode:
		for index, child := range node.Content {
			if err := maskYAMLNode(child, fmt.Sprintf("%s[%d]", path, index), masked, depth+1); err != nil {
				return err
			}
		}
		return nil
	default:
		return nil
	}
}

func maskSecretSource(node *yaml.Node, path string, masked *[]MaskedField) error {
	kind := ""
	for index := 0; index+1 < len(node.Content); index += 2 {
		key := node.Content[index]
		value := node.Content[index+1]
		if value.Kind != yaml.ScalarNode {
			continue
		}
		if kind == "" && (key.Value == "env" || key.Value == "file") {
			kind = key.Value
		}
		value.Value = maskedPlaceholder
		value.Tag = "!!str"
	}
	*masked = append(*masked, MaskedField{Path: path, Source: "secret-source", SourceKind: kind})
	return nil
}

func looksLikeSecretName(name string) bool {
	lower := strings.ToLower(name)
	if lower == "confirm" || lower == "reason" {
		return false
	}
	for _, fragment := range []string{"password", "passwd", "secret", "token", "private_key", "privatekey", "api_key", "apikey"} {
		if strings.Contains(lower, fragment) {
			return true
		}
	}
	return false
}

// ExportMaskedConfig 读取配置原文并导出脱敏 YAML 到新文件（不覆盖已有文件）。
func ExportMaskedConfig(options ConfigExportOptions) (MaskedConfigExport, error) {
	raw, path, err := readConfigSource(options.ConfigPath)
	if err != nil {
		return MaskedConfigExport{}, err
	}
	maskedYAML, maskedFields, err := MaskConfigYAML(raw)
	if err != nil {
		return MaskedConfigExport{}, err
	}
	outputPath, err := controlledNewFilePath(options.OutputPath, ".yaml")
	if err != nil {
		return MaskedConfigExport{}, err
	}
	if err := SafeWriteFile(outputPath, maskedYAML, 0o600); err != nil {
		return MaskedConfigExport{}, fmt.Errorf("写入脱敏配置失败：%w", err)
	}
	sum := sha256.Sum256(maskedYAML)
	result := MaskedConfigExport{
		OutputPath: outputPath, SizeBytes: int64(len(maskedYAML)),
		SHA256: hex.EncodeToString(sum[:]), Masked: maskedFields, Bytes: maskedYAML,
	}
	_ = path
	return result, nil
}

// ConfigExportOptions 是脱敏/加密导出的输入。
type ConfigExportOptions struct {
	// ConfigPath 是源配置文件绝对路径。
	ConfigPath string
	// OutputPath 是导出目标绝对路径（必须不存在）。
	OutputPath string
	// MasterKeyFile 是受保护主密钥环文件路径（加密包必需）。
	MasterKeyFile string
	// Operator 是本地受控操作者标识（写入包元数据，不写日志秘密）。
	Operator string
}

// ConfigPackageSummary 是加密敏感配置包的脱敏元数据。
type ConfigPackageSummary struct {
	Path          string    `json:"path"`
	FormatVersion int       `json:"format_version"`
	CreatedAt     time.Time `json:"created_at"`
	Operator      string    `json:"operator,omitempty"`
	ConfigSize    int64     `json:"config_size"`
	ConfigSHA256  string    `json:"config_sha256"`
	KeyID         string    `json:"key_id"`
	PackageSize   int64     `json:"package_size"`
	PackageSHA256 string    `json:"package_sha256"`
}

// ExportEncryptedConfigPackage 把完整配置原文用主密钥环加密为可还原敏感配置包。
//
// 包内不包含主密钥或解密口令：必须另行保管主密钥环文件。包元数据不含配置内容。
func ExportEncryptedConfigPackage(ctx context.Context, options ConfigExportOptions) (ConfigPackageSummary, error) {
	raw, _, err := readConfigSource(options.ConfigPath)
	if err != nil {
		return ConfigPackageSummary{}, err
	}
	if report := ValidateConfigText(raw); !report.Valid {
		return ConfigPackageSummary{}, fmt.Errorf("配置未通过校验，拒绝导出敏感包：%s", report.Summary)
	}
	ring, err := loadBackupKeyring(ctx, options.MasterKeyFile)
	if err != nil {
		return ConfigPackageSummary{}, err
	}
	sealer, err := secrets.NewSealer(ring, nil)
	if err != nil {
		return ConfigPackageSummary{}, fmt.Errorf("创建配置包加密器失败：%w", err)
	}
	packageID, err := newConfigPackageID()
	if err != nil {
		return ConfigPackageSummary{}, err
	}
	createdAt := time.Now().UTC()
	header := configPackageHeader{
		Magic: configPackageMagic, FormatVersion: configPackageVersion,
		CreatedAt: createdAt.Format(time.RFC3339), Operator: strings.TrimSpace(options.Operator),
		ChunkSize:  secrets.MaxPlaintextBytes,
		Chunks:     (len(raw) + secrets.MaxPlaintextBytes - 1) / secrets.MaxPlaintextBytes,
		ConfigSize: int64(len(raw)), ConfigSHA256: sha256Hex(raw),
		Cipher: "AES-256-GCM (secrets.Sealer envelope)", KeyID: sealer.CurrentKeyID(),
		PackageID: packageID,
	}
	if header.Chunks < 1 {
		header.Chunks = 1
	}
	if header.Chunks > configPackageMaxChunks {
		return ConfigPackageSummary{}, errors.New("配置过大，超过加密包分块上限")
	}
	headerRaw, err := json.Marshal(header)
	if err != nil {
		return ConfigPackageSummary{}, err
	}
	var buffer bytes.Buffer
	buffer.WriteString(configPackageMagic)
	buffer.WriteByte(byte(configPackageVersion))
	if err := binary.Write(&buffer, binary.BigEndian, uint32(len(headerRaw))); err != nil {
		return ConfigPackageSummary{}, err
	}
	buffer.Write(headerRaw)
	for index := 0; index < header.Chunks; index++ {
		start := index * secrets.MaxPlaintextBytes
		end := start + secrets.MaxPlaintextBytes
		if end > len(raw) {
			end = len(raw)
		}
		sealed, err := sealer.Seal(configPackageBinding(packageID, index), raw[start:end])
		if err != nil {
			return ConfigPackageSummary{}, fmt.Errorf("加密配置分块失败：%w", err)
		}
		if err := binary.Write(&buffer, binary.BigEndian, uint32(len(sealed))); err != nil {
			return ConfigPackageSummary{}, err
		}
		buffer.Write(sealed)
	}
	if int64(buffer.Len()) > configExportMaxPackageBytes {
		return ConfigPackageSummary{}, errors.New("加密配置包超过大小上限")
	}
	outputPath, err := controlledNewFilePath(options.OutputPath, ".lncfg")
	if err != nil {
		return ConfigPackageSummary{}, err
	}
	if err := SafeWriteFile(outputPath, buffer.Bytes(), 0o600); err != nil {
		return ConfigPackageSummary{}, fmt.Errorf("写入加密配置包失败：%w", err)
	}
	return ConfigPackageSummary{
		Path: outputPath, FormatVersion: configPackageVersion, CreatedAt: createdAt,
		Operator: header.Operator, ConfigSize: int64(len(raw)),
		ConfigSHA256: sha256Hex(raw), KeyID: header.KeyID,
		PackageSize: int64(buffer.Len()), PackageSHA256: sha256Hex(buffer.Bytes()),
	}, nil
}

// DecryptedConfigPackage 是解密后的配置包内容（仅内存，不落盘）。
type DecryptedConfigPackage struct {
	Summary ConfigPackageSummary
	// Raw 是完整配置原文（含秘密来源引用，但不是秘密本身）。
	Raw    []byte
	Report ConfigReport
}

// ReadEncryptedConfigPackage 解密并校验敏感配置包（不写盘、不改配置）。
func ReadEncryptedConfigPackage(ctx context.Context, packagePath, masterKeyFile string) (DecryptedConfigPackage, error) {
	rawPackage, info, err := controlledPackageFile(packagePath)
	if err != nil {
		return DecryptedConfigPackage{}, err
	}
	decrypted, err := decryptConfigPackage(ctx, rawPackage, masterKeyFile)
	if err != nil {
		return DecryptedConfigPackage{}, err
	}
	report := ValidateConfigText(decrypted.Raw)
	summary := decrypted.Summary
	summary.Path = filepath.Clean(packagePath)
	summary.PackageSize = info.Size()
	summary.PackageSHA256 = sha256Hex(rawPackage)
	return DecryptedConfigPackage{Summary: summary, Raw: decrypted.Raw, Report: report}, nil
}

// ConfigImportPreview 是导入前的差异与影响预览（不写盘）。
type ConfigImportPreview struct {
	SourcePath  string `json:"source_path"`
	CurrentPath string `json:"current_path"`
	// SourceKind 是 "masked-yaml" 或 "encrypted-package"。
	SourceKind string `json:"source_kind"`
	// Proposed 是合并/替换后的完整配置原文（仅内存）。
	Proposed []byte `json:"-"`
	// ProposedReport 是 Proposed 的校验结果。
	ProposedReport ConfigReport `json:"-"`
	// Diff 是行级差异（已脱敏；只用于人工确认）。
	Diff []ConfigDiffLine `json:"diff"`
	// ChangedPaths 是发生变化的配置字段路径（尽力而为）。
	ChangedPaths []string `json:"changed_paths"`
	// MaskedPlaceholders 是仍为占位符、不会覆盖现有秘密的字段。
	MaskedPlaceholders []MaskedField `json:"masked_placeholders,omitempty"`
	// SecretSourcesChanged 表示秘密来源引用发生变化的字段。
	SecretSourcesChanged []string `json:"secret_sources_changed,omitempty"`
	// DatabasePathChange 非空表示导入会切换数据库定位（仅连接变更，不迁移数据）。
	DatabasePathChange string `json:"database_path_change,omitempty"`
	// Warnings 是导入前必须人工确认的事项。
	Warnings []string `json:"warnings,omitempty"`
	// Blocking 非空表示不可应用。
	Blocking []string `json:"blocking,omitempty"`
	// RequiredConfirm 是应用前必须逐字输入的确认串。
	RequiredConfirm string `json:"required_confirm"`
	CanApply        bool   `json:"can_apply"`
}

// ConfigDiffLine 是脱敏行级差异（kind: same/add/remove）。
type ConfigDiffLine struct {
	Kind string `json:"kind"`
	Line int    `json:"line"`
	Text string `json:"text"`
}

// PreviewConfigImport 解析导入源（脱敏 YAML 或加密包），与当前配置比较并生成预览。
//
// masked YAML 导入时占位符保留当前秘密来源；加密包导入时使用包内完整原文。
// 两种来源都必须通过 ValidateConfigText 才能应用。
func PreviewConfigImport(ctx context.Context, request ConfigImportRequest) (ConfigImportPreview, error) {
	currentRaw, _, err := readConfigSource(request.CurrentConfigPath)
	if err != nil {
		return ConfigImportPreview{}, err
	}
	sourceRaw, sourceKind, masked, err := readConfigImportSource(ctx, request)
	if err != nil {
		return ConfigImportPreview{}, err
	}
	proposed := sourceRaw
	maskedPlaceholders := masked
	if sourceKind == "masked-yaml" {
		merged, remaining, err := MergeMaskedConfig(currentRaw, sourceRaw)
		if err != nil {
			return ConfigImportPreview{}, err
		}
		proposed = merged
		maskedPlaceholders = remaining
	}
	preview := ConfigImportPreview{
		SourcePath:  filepath.Clean(request.ImportPath),
		CurrentPath: filepath.Clean(request.CurrentConfigPath),
		SourceKind:  sourceKind, Proposed: proposed,
		ProposedReport:     ValidateConfigText(proposed),
		MaskedPlaceholders: maskedPlaceholders,
	}
	preview.Diff = maskedLineDiff(currentRaw, proposed)
	preview.ChangedPaths = changedConfigPaths(currentRaw, proposed)
	preview.RequiredConfirm = previewProposedConfirm(sourceKind)
	if !preview.ProposedReport.Valid {
		preview.Blocking = append(preview.Blocking,
			"导入后的配置未通过校验："+preview.ProposedReport.Summary)
	}
	if change := databasePathChange(currentRaw, proposed); change != "" {
		preview.DatabasePathChange = change
		preview.Warnings = append(preview.Warnings,
			"导入会切换数据库连接（仅修改连接，不迁移/删除原库）："+change)
	}
	if len(maskedPlaceholders) > 0 {
		preview.Warnings = append(preview.Warnings,
			fmt.Sprintf("仍有 %d 个脱敏占位字段：应用时保留现有秘密来源，不会覆盖为占位符。",
				len(maskedPlaceholders)))
	}
	preview.SecretSourcesChanged = changedSecretSources(currentRaw, proposed)
	if len(preview.SecretSourcesChanged) > 0 {
		preview.Warnings = append(preview.Warnings,
			"秘密来源引用将变化（需确认目标环境存在对应 env/file）："+
				strings.Join(preview.SecretSourcesChanged, ", "))
	}
	preview.CanApply = len(preview.Blocking) == 0
	return preview, nil
}

// ConfigImportRequest 是导入预览/应用请求。
type ConfigImportRequest struct {
	// ImportPath 是待导入文件绝对路径（.yaml 脱敏导出或 .lncfg 加密包）。
	ImportPath string
	// CurrentConfigPath 是当前实例配置绝对路径。
	CurrentConfigPath string
	// MasterKeyFile 是加密包必需的主密钥环文件路径。
	MasterKeyFile string
	// ConfirmText 必须等于预览要求的确认串。
	ConfirmText string
	// ConflictPolicy 透传给 280 保存接口（"fail"|"reload"|"use-draft"）。
	ConflictPolicy string
}

// ConfigSaver 是 WS1 280 配置保存接口的注入点（由集成适配器实现）。
//
// Apply 必须完成：BaseDigest 冲突检测、秘密占位不覆盖、原子替换、最后有效备份，
// 并返回保存与服务重载分别的结果。本文件不自行实现这些安全语义。
type ConfigSaver interface {
	SaveConfig(ctx context.Context, request ConfigSaveRequest) (ConfigSaveOutcome, error)
}

// ConfigSaveRequest 是交给 WS1 保存接口的请求。
type ConfigSaveRequest struct {
	Path           string
	BaseRaw        []byte
	NewRaw         []byte
	ConflictPolicy string
	CreateBackup   bool
	Operator       string
}

// ConfigSaveOutcome 是保存接口返回的脱敏结果。
type ConfigSaveOutcome struct {
	Saved        bool
	BackupPath   string
	FileDigest   string
	ConfigValid  bool
	ReloadResult string
	Conflict     bool
}

// ConfigImportApplyResult 是应用导入后的结果（保存与重载分别报告）。
type ConfigImportApplyResult struct {
	Preview ConfigImportPreview
	Outcome ConfigSaveOutcome
}

// ApplyConfigImport 通过注入的 WS1 保存接口应用导入；不直接写配置文件。
func ApplyConfigImport(ctx context.Context, saver ConfigSaver, request ConfigImportRequest) (ConfigImportApplyResult, error) {
	if saver == nil {
		return ConfigImportApplyResult{}, errors.New("未注入配置保存接口（WS1 280）")
	}
	preview, err := PreviewConfigImport(ctx, request)
	if err != nil {
		return ConfigImportApplyResult{}, err
	}
	if !preview.CanApply {
		return ConfigImportApplyResult{Preview: preview},
			fmt.Errorf("导入预览存在阻塞项：%s", strings.Join(preview.Blocking, "；"))
	}
	if strings.TrimSpace(request.ConfirmText) != preview.RequiredConfirm {
		return ConfigImportApplyResult{Preview: preview},
			fmt.Errorf("确认串不匹配：必须逐字输入 %q", preview.RequiredConfirm)
	}
	currentRaw, _, err := readConfigSource(request.CurrentConfigPath)
	if err != nil {
		return ConfigImportApplyResult{Preview: preview}, err
	}
	outcome, err := saver.SaveConfig(ctx, ConfigSaveRequest{
		Path: filepath.Clean(request.CurrentConfigPath), BaseRaw: currentRaw,
		NewRaw: preview.Proposed, ConflictPolicy: request.ConflictPolicy,
		CreateBackup: true,
	})
	if err != nil {
		return ConfigImportApplyResult{Preview: preview}, err
	}
	return ConfigImportApplyResult{Preview: preview, Outcome: outcome}, nil
}

// MergeMaskedConfig 把脱敏 YAML 合并到当前配置：占位符字段保留当前值/来源，
// 其余字段采用导入值。返回合并后的原文与仍需用户补全的占位字段。
func MergeMaskedConfig(currentRaw, maskedRaw []byte) ([]byte, []MaskedField, error) {
	if len(currentRaw) > configExportMaxPlaintextBytes || len(maskedRaw) > configExportMaxPlaintextBytes {
		return nil, nil, errors.New("配置超过导入合并大小上限")
	}
	var currentDoc, maskedDoc yaml.Node
	if err := yaml.Unmarshal(currentRaw, &currentDoc); err != nil {
		return nil, nil, fmt.Errorf("当前配置解析失败：%w", err)
	}
	if err := yaml.Unmarshal(maskedRaw, &maskedDoc); err != nil {
		return nil, nil, fmt.Errorf("导入的脱敏 YAML 解析失败：%w", err)
	}
	if len(currentDoc.Content) == 0 || len(maskedDoc.Content) == 0 {
		return nil, nil, errors.New("配置为空，无法合并")
	}
	remaining := make([]MaskedField, 0, 8)
	mergedRoot := mergeYAMLNode(currentDoc.Content[0], maskedDoc.Content[0], "", &remaining, 0)
	encoded, err := yaml.Marshal(mergedRoot)
	if err != nil {
		return nil, nil, fmt.Errorf("编码合并后配置失败：%w", err)
	}
	return encoded, remaining, nil
}

func mergeYAMLNode(current, incoming *yaml.Node, path string, remaining *[]MaskedField, depth int) *yaml.Node {
	if depth > configExportMaxYAMLDepth || current == nil || incoming == nil {
		return current
	}
	if incoming.Kind == yaml.ScalarNode {
		if incoming.Value == maskedPlaceholder || strings.Contains(incoming.Value, maskedPlaceholder) {
			if path != "" {
				*remaining = append(*remaining, MaskedField{Path: path, Source: "placeholder-preserved"})
			}
			return current
		}
		return incoming
	}
	if incoming.Kind == yaml.MappingNode && current.Kind == yaml.MappingNode {
		merged := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		incomingKeys := map[string]*yaml.Node{}
		for index := 0; index+1 < len(incoming.Content); index += 2 {
			incomingKeys[incoming.Content[index].Value] = incoming.Content[index+1]
		}
		for index := 0; index+1 < len(current.Content); index += 2 {
			key := current.Content[index]
			value := current.Content[index+1]
			childPath := key.Value
			if path != "" {
				childPath = path + "." + key.Value
			}
			if replacement, exists := incomingKeys[key.Value]; exists {
				merged.Content = append(merged.Content, key, mergeYAMLNode(value, replacement, childPath, remaining, depth+1))
				delete(incomingKeys, key.Value)
				continue
			}
			merged.Content = append(merged.Content, key, value)
		}
		// 追加当前配置没有的新字段（保持导入顺序）。
		for index := 0; index+1 < len(incoming.Content); index += 2 {
			key := incoming.Content[index]
			if _, exists := incomingKeys[key.Value]; !exists {
				continue
			}
			childPath := key.Value
			if path != "" {
				childPath = path + "." + key.Value
			}
			merged.Content = append(merged.Content, key, incoming.Content[index+1])
			delete(incomingKeys, key.Value)
			_ = childPath
		}
		return merged
	}
	return incoming
}

func readConfigSource(configPath string) ([]byte, string, error) {
	trimmed := strings.TrimSpace(configPath)
	if trimmed == "" {
		return nil, "", errors.New("未指定配置文件路径")
	}
	if !filepath.IsAbs(trimmed) {
		return nil, "", fmt.Errorf("配置文件必须是绝对路径：%s", trimmed)
	}
	cleanPath := filepath.Clean(trimmed)
	info, err := os.Lstat(cleanPath)
	if err != nil {
		return nil, "", fmt.Errorf("配置文件不可用：%w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, "", errors.New("配置文件必须是普通文件（不能是符号链接）")
	}
	if info.Size() > configExportMaxPlaintextBytes {
		return nil, "", fmt.Errorf("配置文件超过处理上限（%d 字节）", configExportMaxPlaintextBytes)
	}
	raw, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, "", fmt.Errorf("读取配置文件失败：%w", err)
	}
	return raw, cleanPath, nil
}

func controlledNewFilePath(path, suffix string) (string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "", errors.New("未指定导出目标路径")
	}
	if !filepath.IsAbs(trimmed) {
		return "", fmt.Errorf("导出目标必须是绝对路径：%s", trimmed)
	}
	cleanPath := filepath.Clean(trimmed)
	if suffix != "" && !strings.EqualFold(filepath.Ext(cleanPath), suffix) {
		return "", fmt.Errorf("导出目标扩展名必须为 %s", suffix)
	}
	if _, err := os.Lstat(cleanPath); err == nil {
		return "", errors.New("导出目标已存在；为避免覆盖，请使用新文件名")
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("检查导出目标失败：%w", err)
	}
	return cleanPath, nil
}

func controlledPackageFile(path string) ([]byte, os.FileInfo, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return nil, nil, errors.New("未指定配置包路径")
	}
	if !filepath.IsAbs(trimmed) {
		return nil, nil, fmt.Errorf("配置包必须是绝对路径：%s", trimmed)
	}
	cleanPath := filepath.Clean(trimmed)
	if !strings.EqualFold(filepath.Ext(cleanPath), ".lncfg") {
		return nil, nil, errors.New("不是敏感配置包（扩展名必须为 .lncfg）")
	}
	info, err := os.Lstat(cleanPath)
	if err != nil {
		return nil, nil, fmt.Errorf("配置包不可用：%w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, nil, errors.New("配置包必须是普通文件（不能是符号链接）")
	}
	if info.Size() > configExportMaxPackageBytes {
		return nil, nil, fmt.Errorf("配置包超过大小上限（%d 字节）", configExportMaxPackageBytes)
	}
	raw, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, nil, fmt.Errorf("读取配置包失败：%w", err)
	}
	return raw, info, nil
}

type configPackageHeader struct {
	Magic         string `json:"magic"`
	FormatVersion int    `json:"format_version"`
	CreatedAt     string `json:"created_at"`
	Operator      string `json:"operator,omitempty"`
	ChunkSize     int    `json:"chunk_size"`
	Chunks        int    `json:"chunks"`
	ConfigSize    int64  `json:"config_size"`
	ConfigSHA256  string `json:"config_sha256"`
	Cipher        string `json:"cipher"`
	KeyID         string `json:"key_id"`
	PackageID     string `json:"package_id"`
}

func decryptConfigPackage(ctx context.Context, rawPackage []byte, masterKeyFile string) (DecryptedConfigPackage, error) {
	if len(rawPackage) < len(configPackageMagic)+1+4 {
		return DecryptedConfigPackage{}, errors.New("配置包过短或已截断")
	}
	if string(rawPackage[:len(configPackageMagic)]) != configPackageMagic {
		return DecryptedConfigPackage{}, errors.New("不是本工具生成的敏感配置包（魔数不匹配）")
	}
	offset := len(configPackageMagic)
	version := int(rawPackage[offset])
	offset++
	if version != configPackageVersion {
		return DecryptedConfigPackage{}, fmt.Errorf("不支持的配置包版本 %d（当前支持 %d）", version, configPackageVersion)
	}
	headerLen := int(binary.BigEndian.Uint32(rawPackage[offset:]))
	offset += 4
	if headerLen <= 0 || headerLen > 64*1024 || offset+headerLen > len(rawPackage) {
		return DecryptedConfigPackage{}, errors.New("配置包头长度异常")
	}
	var header configPackageHeader
	if err := json.Unmarshal(rawPackage[offset:offset+headerLen], &header); err != nil {
		return DecryptedConfigPackage{}, fmt.Errorf("配置包头不是合法 JSON：%w", err)
	}
	offset += headerLen
	if header.Magic != configPackageMagic || header.FormatVersion != configPackageVersion {
		return DecryptedConfigPackage{}, errors.New("配置包头与文件版本不一致")
	}
	if header.Chunks < 1 || header.Chunks > configPackageMaxChunks {
		return DecryptedConfigPackage{}, errors.New("配置包分块数量异常")
	}
	if header.ChunkSize != secrets.MaxPlaintextBytes {
		return DecryptedConfigPackage{}, errors.New("配置包分块大小不是本工具支持的固定值")
	}
	ring, err := loadBackupKeyring(ctx, masterKeyFile)
	if err != nil {
		return DecryptedConfigPackage{}, err
	}
	sealer, err := secrets.NewSealer(ring, nil)
	if err != nil {
		return DecryptedConfigPackage{}, err
	}
	plain := make([]byte, 0, header.ConfigSize)
	for index := 0; index < header.Chunks; index++ {
		if offset+4 > len(rawPackage) {
			return DecryptedConfigPackage{}, errors.New("配置包分块头截断")
		}
		sealedLen := int(binary.BigEndian.Uint32(rawPackage[offset:]))
		offset += 4
		if sealedLen <= 0 || sealedLen > secrets.MaxSealedBytes || offset+sealedLen > len(rawPackage) {
			return DecryptedConfigPackage{}, errors.New("配置包分块长度异常")
		}
		chunk, openErr := sealer.Open(configPackageBinding(header.PackageID, index), rawPackage[offset:offset+sealedLen])
		if openErr != nil {
			return DecryptedConfigPackage{}, fmt.Errorf("配置包分块认证失败（主密钥环不匹配或包被篡改）：%w", openErr)
		}
		plain = append(plain, chunk...)
		offset += sealedLen
	}
	if offset != len(rawPackage) {
		return DecryptedConfigPackage{}, errors.New("配置包尾部存在多余数据")
	}
	if int64(len(plain)) != header.ConfigSize {
		return DecryptedConfigPackage{}, errors.New("配置包明文长度与包头记录不一致")
	}
	if sha256Hex(plain) != header.ConfigSHA256 {
		return DecryptedConfigPackage{}, errors.New("配置包明文摘要与包头记录不一致")
	}
	createdAt, _ := time.Parse(time.RFC3339, header.CreatedAt)
	summary := ConfigPackageSummary{
		FormatVersion: header.FormatVersion, CreatedAt: createdAt, Operator: header.Operator,
		ConfigSize: header.ConfigSize, ConfigSHA256: header.ConfigSHA256, KeyID: header.KeyID,
	}
	_ = ctx
	return DecryptedConfigPackage{Summary: summary, Raw: plain}, nil
}

func readConfigImportSource(ctx context.Context, request ConfigImportRequest) ([]byte, string, []MaskedField, error) {
	trimmed := strings.TrimSpace(request.ImportPath)
	if trimmed == "" {
		return nil, "", nil, errors.New("未指定导入文件")
	}
	if !filepath.IsAbs(trimmed) {
		return nil, "", nil, fmt.Errorf("导入文件必须是绝对路径：%s", trimmed)
	}
	switch strings.ToLower(filepath.Ext(trimmed)) {
	case ".lncfg":
		decrypted, err := ReadEncryptedConfigPackage(ctx, trimmed, request.MasterKeyFile)
		if err != nil {
			return nil, "", nil, err
		}
		return decrypted.Raw, "encrypted-package", nil, nil
	case ".yaml", ".yml":
		raw, _, err := readConfigSourceWithSuffix(trimmed)
		if err != nil {
			return nil, "", nil, err
		}
		return raw, "masked-yaml", nil, nil
	default:
		return nil, "", nil, errors.New("导入文件必须是 .yaml/.yml（脱敏导出）或 .lncfg（加密敏感包）")
	}
}

func readConfigSourceWithSuffix(path string) ([]byte, string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, "", fmt.Errorf("导入文件不可用：%w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, "", errors.New("导入文件必须是普通文件（不能是符号链接）")
	}
	if info.Size() > configExportMaxPlaintextBytes {
		return nil, "", fmt.Errorf("导入文件超过大小上限（%d 字节）", configExportMaxPlaintextBytes)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("读取导入文件失败：%w", err)
	}
	return raw, path, nil
}

func configPackageBinding(packageID string, index int) secrets.Binding {
	return secrets.Binding{
		Purpose:  configPackagePurpose,
		ObjectID: fmt.Sprintf("%s/chunk/%d", packageID, index),
		ScopeID:  secrets.ScopeSystem,
	}
}

func newConfigPackageID() (string, error) {
	random := make([]byte, 16)
	if _, err := readCryptoRandom(random); err != nil {
		return "", fmt.Errorf("生成配置包编号失败：%w", err)
	}
	return "cfg_" + hex.EncodeToString(random), nil
}

// 隔离 crypto/rand 依赖，便于测试替换（生产永远使用 crypto/rand）。
var readCryptoRandom = rand.Read

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func previewProposedConfirm(string) string { return "IMPORT-CONFIG" }

// changedConfigPaths 尽力列出发生变化的顶层/二级字段路径。
func changedConfigPaths(before, after []byte) []string {
	var beforeDoc, afterDoc yaml.Node
	if yaml.Unmarshal(before, &beforeDoc) != nil || yaml.Unmarshal(after, &afterDoc) != nil {
		return nil
	}
	beforeFlat := map[string]string{}
	afterFlat := map[string]string{}
	flattenYAML(&beforeDoc, "", beforeFlat, 0)
	flattenYAML(&afterDoc, "", afterFlat, 0)
	changed := make([]string, 0, 8)
	for path, value := range afterFlat {
		if old, exists := beforeFlat[path]; !exists || old != value {
			changed = append(changed, path)
		}
	}
	for path := range beforeFlat {
		if _, exists := afterFlat[path]; !exists {
			changed = append(changed, path+"（删除）")
		}
	}
	sortStrings(changed)
	if len(changed) > 64 {
		changed = changed[:64]
	}
	return changed
}

func flattenYAML(node *yaml.Node, path string, flat map[string]string, depth int) {
	if node == nil || depth > configExportMaxYAMLDepth {
		return
	}
	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			flattenYAML(child, path, flat, depth+1)
		}
	case yaml.MappingNode:
		for index := 0; index+1 < len(node.Content); index += 2 {
			key := node.Content[index].Value
			childPath := key
			if path != "" {
				childPath = path + "." + key
			}
			flattenYAML(node.Content[index+1], childPath, flat, depth+1)
		}
	case yaml.SequenceNode:
		for index, child := range node.Content {
			flattenYAML(child, fmt.Sprintf("%s[%d]", path, index), flat, depth+1)
		}
	case yaml.ScalarNode:
		if path != "" {
			flat[path] = node.Value
		}
	}
}

func changedSecretSources(before, after []byte) []string {
	beforeSources := map[string]string{}
	afterSources := map[string]string{}
	collectSecretSources(before, beforeSources)
	collectSecretSources(after, afterSources)
	changed := make([]string, 0, 4)
	for path, source := range afterSources {
		if beforeSources[path] != source {
			changed = append(changed, path+" -> "+source)
		}
	}
	for path := range beforeSources {
		if _, exists := afterSources[path]; !exists {
			changed = append(changed, path+"（移除）")
		}
	}
	sortStrings(changed)
	return changed
}

func collectSecretSources(raw []byte, out map[string]string) {
	var document yaml.Node
	if yaml.Unmarshal(raw, &document) != nil || len(document.Content) == 0 {
		return
	}
	root := document.Content[0]
	if root.Kind != yaml.MappingNode {
		return
	}
	for index := 0; index+1 < len(root.Content); index += 2 {
		if root.Content[index].Value != "secrets" {
			continue
		}
		secretsNode := root.Content[index+1]
		if secretsNode.Kind != yaml.MappingNode {
			return
		}
		for j := 0; j+1 < len(secretsNode.Content); j += 2 {
			name := secretsNode.Content[j].Value
			sourceNode := secretsNode.Content[j+1]
			if sourceNode.Kind != yaml.MappingNode {
				continue
			}
			for k := 0; k+1 < len(sourceNode.Content); k += 2 {
				kind := sourceNode.Content[k].Value
				if kind != "env" && kind != "file" {
					continue
				}
				out["secrets."+name] = kind + ":" + sourceNode.Content[k+1].Value
			}
		}
	}
}

func databasePathChange(before, after []byte) string {
	beforePath := configDatabasePath(before)
	afterPath := configDatabasePath(after)
	if beforePath == afterPath {
		return ""
	}
	return beforePath + " -> " + afterPath
}

func configDatabasePath(raw []byte) string {
	var document yaml.Node
	if yaml.Unmarshal(raw, &document) != nil || len(document.Content) == 0 {
		return ""
	}
	root := document.Content[0]
	if root.Kind != yaml.MappingNode {
		return ""
	}
	for index := 0; index+1 < len(root.Content); index += 2 {
		if root.Content[index].Value != "database" {
			continue
		}
		database := root.Content[index+1]
		if database.Kind != yaml.MappingNode {
			return ""
		}
		for j := 0; j+1 < len(database.Content); j += 2 {
			if database.Content[j].Value == "path" && database.Content[j+1].Kind == yaml.ScalarNode {
				return database.Content[j+1].Value
			}
		}
	}
	return ""
}

// maskedLineDiff 是脱敏行级差异（不暴露秘密；占位符已替换）。
func maskedLineDiff(before, after []byte) []ConfigDiffLine {
	beforeMasked, _, _ := MaskConfigYAML(before)
	afterMasked, _, _ := MaskConfigYAML(after)
	if beforeMasked == nil {
		beforeMasked = before
	}
	if afterMasked == nil {
		afterMasked = after
	}
	beforeLines := splitLines(string(beforeMasked))
	afterLines := splitLines(string(afterMasked))
	diffs := make([]ConfigDiffLine, 0, 16)
	maxLen := len(beforeLines)
	if len(afterLines) > maxLen {
		maxLen = len(afterLines)
	}
	limit := maxLen
	if limit > 400 {
		limit = 400
	}
	for index := 0; index < limit; index++ {
		var beforeLine, afterLine string
		if index < len(beforeLines) {
			beforeLine = beforeLines[index]
		}
		if index < len(afterLines) {
			afterLine = afterLines[index]
		}
		if beforeLine == afterLine {
			diffs = append(diffs, ConfigDiffLine{Kind: "same", Line: index + 1, Text: afterLine})
			continue
		}
		if beforeLine != "" {
			diffs = append(diffs, ConfigDiffLine{Kind: "remove", Line: index + 1, Text: beforeLine})
		}
		if afterLine != "" {
			diffs = append(diffs, ConfigDiffLine{Kind: "add", Line: index + 1, Text: afterLine})
		}
	}
	return diffs
}

func splitLines(text string) []string {
	normalized := strings.ReplaceAll(text, "\r\n", "\n")
	lines := strings.Split(normalized, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

// 确认占位符/脱敏导出中的 UTF-8 合法性（导出前防御性检查）。
func validUTF8Text(raw []byte) bool {
	return utf8.Valid(raw)
}
