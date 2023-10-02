// 本文件实现 `loginctl config` 命令：有效配置查看、单字段读取、校验、重载分类
// 差异比较，以及非秘密字段的安全写入与秘密来源引用写入。
//
// 写入语义：
//   - 只接受非秘密字段（秘密用 set-secret 写来源引用，永不写明文值）。
//   - 先解析/校验目标 YAML，再把合并后的有效配置交给既有 config.Load 校验；校验
//     失败不写文件，保证“预演/失败不写数据”。
//   - 默认原子写（同目录临时文件 + rename）并为原文件保留一份备份；不跟随符号
//     链接，不修改文件权限（新文件默认 0644）。
//   - `--dry-run` 只输出将要发生的变更，不创建临时文件、不写配置。
package managecli

import (
	loginconfig "github.com/kagurazakayashi/EvernightLogin/config"

	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// configFieldKind 是 CLI 可写入的字段值类别。
type configFieldKind string

const (
	configKindString configFieldKind = "string"
	configKindBool   configFieldKind = "bool"
	configKindInt    configFieldKind = "int"
	configKindList   configFieldKind = "list"
	// configKindObjectList 表示结构化对象列表（目前只有客户端证书身份映射），
	// CLI 不自动改写，要求人工编辑配置文件，避免丢失字段或产生错误结构。
	configKindObjectList configFieldKind = "object-list"
	// configKindSecret 表示秘密字段：只允许 set-secret 写来源引用。
	configKindSecret configFieldKind = "secret"
)

// configFieldKinds 是每个字段的 CLI 值类别。测试会断言它覆盖 Fields() 的全部字段，
// 新增字段必须同步，避免 CLI 静默漏写或写错类型。
var configFieldKinds = map[string]configFieldKind{
	"server.listen_addr":                      configKindString,
	"server.extra_listen_addrs":               configKindList,
	"server.public_base_url":                  configKindString,
	"server.path_prefix":                      configKindString,
	"server.allowed_hosts":                    configKindList,
	"server.trusted_proxies":                  configKindList,
	"server.tls_terminating_proxy":            configKindBool,
	"server.tls_cert_files":                   configKindList,
	"server.tls_key_files":                    configKindList,
	"server.tls_ca_file":                      configKindString,
	"server.tls_pfx_file":                     configKindString,
	"server.tls_expiry_warning_days":          configKindInt,
	"server.tls_client_auth":                  configKindString,
	"server.tls_client_ca_files":              configKindList,
	"server.tls_client_identities":            configKindObjectList,
	"server.shutdown_timeout_seconds":         configKindInt,
	"logging.level":                           configKindString,
	"logging.format":                          configKindString,
	"database.driver":                         configKindString,
	"database.path":                           configKindString,
	"database.wal":                            configKindBool,
	"database.busy_timeout_ms":                configKindInt,
	"registration.enabled":                    configKindBool,
	"registration.require_review":             configKindBool,
	"registration.require_email_verification": configKindBool,
	"registration.default_role_ids":           configKindList,
	"passkey.enabled":                         configKindBool,
	"passkey.rp_id":                           configKindString,
	"passkey.rp_display_name":                 configKindString,
	"passkey.allowed_origins":                 configKindList,
	"passkey.user_verification":               configKindString,
	"app_qr_login.enabled":                    configKindBool,
	"app_qr_login.allowed_client_ids":         configKindList,
	"app_qr_login.request_ttl_seconds":        configKindInt,
	"app_qr_login.claim_interval_seconds":     configKindInt,
	"protocol.device_code_enabled":            configKindBool,
	"secrets.master_key":                      configKindSecret,
	"secrets.tls_pfx_password":                configKindSecret,
	"mail.enabled":                            configKindBool,
	"mail.smtp.addr":                          configKindString,
	"mail.smtp.host":                          configKindString,
	"mail.smtp.tls_mode":                      configKindString,
	"mail.smtp.trusted_roots":                 configKindList,
	"mail.smtp.username":                      configKindString,
	"mail.smtp.password":                      configKindSecret,
	"mail.smtp.timeout_seconds":               configKindInt,
	"mail.smtp.allow_plaintext_local":         configKindBool,
	"mail.from.address":                       configKindString,
	"mail.from.name":                          configKindString,
	"mail.app_name":                           configKindString,
	"mail.delivery.max_attempts":              configKindInt,
	"mail.delivery.timeout_seconds":           configKindInt,
}

// configCommandUsage 是 config 组的帮助文本。
const configCommandUsage = `用法：
  loginctl config show [--config <file>] [--json]
  loginctl config get <field> [--config <file>] [--json]
  loginctl config validate [--config <file>] [--json]
  loginctl config diff --old <file> --new <file> [--json]
  loginctl config set <field> <value> --file <file> [--dry-run] [--json]
  loginctl config set-secret <field> --source env:NAME|file:PATH --file <file> [--dry-run] [--json]

说明：
  - show/diff 的输出已脱敏：秘密字段只显示 [REDACTED] 或 [UNSET]。
  - set 只接受非秘密字段；秘密值不得出现在命令行，set-secret 只写 env:/file: 来源引用。
  - 每个字段的重载分类：hot-reloadable 表示重新加载配置即可生效；restart-required
    表示必须重启进程；CLI 不会替你重启服务。`

// runConfig 分派 config 子命令。
func (r *runner) runConfig(args []string) int {
	r.usageText = configCommandUsage
	if len(args) == 0 {
		return r.helpText("config", configCommandUsage)
	}
	subcommand, rest := args[0], args[1:]
	r.command = "config " + subcommand
	switch subcommand {
	case "show":
		return r.runConfigShow(rest)
	case "get":
		return r.runConfigGet(rest)
	case "validate":
		return r.runConfigValidate(rest)
	case "diff":
		return r.runConfigDiff(rest)
	case "set":
		return r.runConfigSet(rest, false)
	case "set-secret":
		return r.runConfigSet(rest, true)
	case "help", "-h", "--help":
		return r.helpText("config", configCommandUsage)
	default:
		return r.usage("未知的 config 子命令 %q（可用：show/get/validate/diff/set/set-secret）", subcommand)
	}
}

// helpText 输出命令帮助并返回成功。
func (r *runner) helpText(name, text string) int {
	if name != "" {
		fmt.Fprintf(r.stdout, "loginctl %s\n\n", name)
	}
	fmt.Fprintln(r.stdout, text)
	return ExitOK
}

// configShowOutput 是 config show 的 JSON 投影。
type configShowOutput struct {
	Valid bool `json:"valid"`
	// SecretsResolved 表示秘密来源在当前进程可解析；false 时字段值可能来自 CLI
	// 展示占位，服务启动前必须补齐真实来源。
	SecretsResolved bool                `json:"secrets_resolved"`
	FieldCount      int                 `json:"field_count"`
	HotReloadable   []string            `json:"hot_reloadable"`
	RestartRequired []string            `json:"restart_required"`
	Fields          []configFieldOutput `json:"fields"`
}

// configFieldOutput 是单个字段的脱敏投影。
type configFieldOutput struct {
	Field  string `json:"field"`
	Value  string `json:"value"`
	Class  string `json:"class"`
	Secret bool   `json:"secret"`
}

// runConfigShow 输出有效配置与重载分类。
func (r *runner) runConfigShow(args []string) int {
	values, positional, err := parseFlags(args, []flagDef{
		{name: "config", value: true}, {name: "json"},
	})
	if err != nil {
		return r.flagError(err)
	}
	if len(positional) != 0 {
		return r.usage("config show 不接受位置参数")
	}
	r.json = boolFlag(values, "json")
	config, exit := r.loadEffectiveConfigTolerant(values)
	if exit != ExitOK {
		return exit
	}
	output := configFieldsOutput(config)
	output.SecretsResolved = r.secretsResolved(values)
	if r.json {
		return r.succeed(output)
	}
	fmt.Fprint(r.stdout, config.Diagnostic())
	fmt.Fprintf(r.stdout, "\n共 %d 项；可热更新 %d 项，需重启 %d 项。\n",
		output.FieldCount, len(output.HotReloadable), len(output.RestartRequired))
	if !output.SecretsResolved {
		fmt.Fprintln(r.stdout, "注意：存在无法解析的秘密来源；秘密字段显示值可能来自占位，服务启动前必须补齐来源。")
	}
	return ExitOK
}

// secretsResolved 用严格加载判断秘密来源是否全部可解析（不输出任何秘密）。
func (r *runner) secretsResolved(values map[string]string) bool {
	options := loginconfig.LoadOptions{LookupEnv: r.options.LookupEnv}
	if path := stringFlag(values, "config"); path != "" {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return false
		}
		options.YAMLFile = absolute
	}
	_, err := loginconfig.Load(options)
	return err == nil
}

// configFieldsOutput 把有效配置投影为结构化输出。
func configFieldsOutput(config loginconfig.Config) configShowOutput {
	values := config.FieldValues()
	output := configShowOutput{Valid: true, FieldCount: len(values)}
	for _, item := range values {
		output.Fields = append(output.Fields, configFieldOutput{Field: item.Field,
			Value: item.Value, Class: string(item.Class), Secret: item.Secret})
		if item.Class == loginconfig.ReloadHotReloadable {
			output.HotReloadable = append(output.HotReloadable, item.Field)
		} else {
			output.RestartRequired = append(output.RestartRequired, item.Field)
		}
	}
	return output
}

// fieldOutput 是 config get 的输出。
type fieldOutput struct {
	Field  string `json:"field"`
	Value  string `json:"value"`
	Class  string `json:"class"`
	Secret bool   `json:"secret"`
}

// runConfigGet 输出单个字段的脱敏有效值与重载分类。
func (r *runner) runConfigGet(args []string) int {
	values, positional, err := parseFlags(args, []flagDef{
		{name: "config", value: true}, {name: "json"},
	})
	if err != nil {
		return r.flagError(err)
	}
	if len(positional) != 1 {
		return r.usage("用法：loginctl config get <field> [--config <file>] [--json]")
	}
	r.json = boolFlag(values, "json")
	field := strings.TrimSpace(positional[0])
	info, ok := loginconfig.LookupField(field)
	if !ok {
		return r.fail("CONFIG_FIELD_UNKNOWN", ExitUsage,
			fmt.Sprintf("未知配置字段 %q（可用 loginctl config show 查看）", field), nil)
	}
	config, exit := r.loadEffectiveConfigTolerant(values)
	if exit != ExitOK {
		return exit
	}
	output := fieldOutput{Field: info.Field, Value: configValueString(config, info.Field),
		Class: string(info.Class), Secret: info.Secret}
	return r.succeedWithText(output, "%s = %s（%s）\n", output.Field, output.Value, output.Class)
}

// configValueString 从 FieldValues 中取出指定字段的脱敏值。
func configValueString(config loginconfig.Config, field string) string {
	for _, item := range config.FieldValues() {
		if item.Field == field {
			return item.Value
		}
	}
	return ""
}

// runConfigValidate 校验配置；成功输出字段数与重载分类摘要。
func (r *runner) runConfigValidate(args []string) int {
	values, positional, err := parseFlags(args, []flagDef{
		{name: "config", value: true}, {name: "json"},
	})
	if err != nil {
		return r.flagError(err)
	}
	if len(positional) != 0 {
		return r.usage("config validate 不接受位置参数")
	}
	r.json = boolFlag(values, "json")
	config, exit := r.loadEffectiveConfig(values)
	if exit != ExitOK {
		return exit
	}
	output := configFieldsOutput(config)
	return r.succeedWithText(map[string]any{"valid": true,
		"field_count": output.FieldCount},
		"配置有效：共 %d 项字段（可热更新 %d，需重启 %d）。\n",
		output.FieldCount, len(output.HotReloadable), len(output.RestartRequired))
}

// configDiffOutput 是 config diff 的 JSON 投影。
type configDiffOutput struct {
	Changed         bool     `json:"changed"`
	HotReloadable   []string `json:"hot_reloadable,omitempty"`
	RestartRequired []string `json:"restart_required,omitempty"`
	// SecretsNotComparable 表示存在两侧都已设置的秘密字段：脱敏诊断无法判断秘密
	// 取值是否变化，只能比较“已设置/未设置”。
	SecretsNotComparable bool `json:"secrets_not_comparable"`
}

// runConfigDiff 比较两份配置文件的脱敏有效值，并按重载分类拆分差异。
func (r *runner) runConfigDiff(args []string) int {
	values, positional, err := parseFlags(args, []flagDef{
		{name: "old", value: true}, {name: "new", value: true}, {name: "json"},
	})
	if err != nil {
		return r.flagError(err)
	}
	if len(positional) != 0 {
		return r.usage("config diff 不接受位置参数")
	}
	r.json = boolFlag(values, "json")
	oldFile, newFile := stringFlag(values, "old"), stringFlag(values, "new")
	if oldFile == "" || newFile == "" {
		return r.usage("用法：loginctl config diff --old <file> --new <file> [--json]")
	}
	oldConfig, exit := r.loadEffectiveConfigTolerant(map[string]string{"config": oldFile})
	if exit != ExitOK {
		return exit
	}
	newConfig, exit := r.loadEffectiveConfigTolerant(map[string]string{"config": newFile})
	if exit != ExitOK {
		return exit
	}
	previous := make(map[string]configFieldOutput)
	for _, item := range configFieldsOutput(oldConfig).Fields {
		previous[item.Field] = item
	}
	output := configDiffOutput{}
	for _, item := range configFieldsOutput(newConfig).Fields {
		old, ok := previous[item.Field]
		if !ok || old.Value == item.Value {
			continue
		}
		if item.Secret {
			// 两侧都设置时值已脱敏为 [REDACTED]，差异不可判断；标记而不是误报。
			if old.Value == "[REDACTED]" && item.Value == "[REDACTED]" {
				output.SecretsNotComparable = true
				continue
			}
		}
		if item.Class == string(loginconfig.ReloadHotReloadable) {
			output.HotReloadable = append(output.HotReloadable, item.Field)
		} else {
			output.RestartRequired = append(output.RestartRequired, item.Field)
		}
	}
	output.Changed = len(output.HotReloadable) > 0 || len(output.RestartRequired) > 0
	sort.Strings(output.HotReloadable)
	sort.Strings(output.RestartRequired)
	if r.json {
		return r.succeed(output)
	}
	if !output.Changed {
		fmt.Fprintln(r.stdout, "两份配置的脱敏有效值没有差异。")
	} else {
		for _, field := range output.HotReloadable {
			fmt.Fprintf(r.stdout, "可热更新：%s\n", field)
		}
		for _, field := range output.RestartRequired {
			fmt.Fprintf(r.stdout, "需重启：%s\n", field)
		}
	}
	if output.SecretsNotComparable {
		fmt.Fprintln(r.stdout, "注意：两侧秘密字段均已设置；脱敏输出无法判断秘密值是否变化。")
	}
	return ExitOK
}

// configWriteOutput 是 config set/set-secret 的结果投影。
type configWriteOutput struct {
	Field        string `json:"field"`
	OldValue     string `json:"old_value"`
	NewValue     string `json:"new_value"`
	Class        string `json:"class"`
	Written      bool   `json:"written"`
	DryRun       bool   `json:"dry_run"`
	Backup       string `json:"backup,omitempty"`
	File         string `json:"file"`
	NeedsRestart bool   `json:"needs_restart"`
}

// runConfigSet 实现 config set 与 config set-secret。secretOnly 为 true 时只允许
// 秘密字段并写入来源引用；否则拒绝秘密字段。
func (r *runner) runConfigSet(args []string, secretOnly bool) int {
	defs := []flagDef{{name: "file", value: true}, {name: "json"},
		{name: "dry-run"}}
	if secretOnly {
		defs = append(defs, flagDef{name: "source", value: true})
	}
	values, positional, err := parseFlags(args, defs)
	if err != nil {
		return r.flagError(err)
	}
	r.json = boolFlag(values, "json")
	dryRun := boolFlag(values, "dry-run")
	if secretOnly && len(positional) != 1 {
		return r.usage("用法：loginctl config set-secret <field> --source env:NAME|file:PATH " +
			"--file <file> [--dry-run] [--json]")
	}
	if !secretOnly && len(positional) != 2 {
		return r.usage("用法：loginctl config set <field> <value> --file <file> [--dry-run] [--json]")
	}
	file := stringFlag(values, "file")
	if file == "" {
		return r.usage("必须用 --file 指定要写入的 YAML 配置文件")
	}
	field := strings.TrimSpace(positional[0])
	rawValue := ""
	if !secretOnly {
		rawValue = positional[1]
	}
	info, ok := loginconfig.LookupField(field)
	if !ok {
		return r.fail("CONFIG_FIELD_UNKNOWN", ExitUsage,
			fmt.Sprintf("未知配置字段 %q", field), nil)
	}
	kind, knownKind := configFieldKinds[field]
	if !knownKind {
		return r.fail("CONFIG_FIELD_UNSUPPORTED", ExitError,
			fmt.Sprintf("字段 %s 未登记 CLI 写入类型（请人工编辑配置文件）", field), nil)
	}
	absoluteFile, exit := r.configWritableFile(file)
	if exit != ExitOK {
		return exit
	}
	var valueNode *yaml.Node
	var renderedValue string
	if secretOnly {
		if kind != configKindSecret {
			return r.fail("CONFIG_FIELD_NOT_SECRET", ExitUsage,
				fmt.Sprintf("字段 %s 不是秘密字段；普通值请用 config set", field), nil)
		}
		sourceSpec := stringFlag(values, "source")
		if sourceSpec == "" {
			return r.usage("config set-secret 必须用 --source 指定 env:NAME 或 file:绝对路径")
		}
		source, err := loginconfig.ParseSecretSource(sourceSpec)
		if err != nil {
			return r.fail("CONFIG_SECRET_SOURCE_INVALID", ExitUsage, err.Error(), nil)
		}
		if source.Kind == loginconfig.SecretSourceFile && !filepath.IsAbs(source.Name) {
			return r.fail("CONFIG_SECRET_SOURCE_INVALID", ExitUsage,
				"秘密文件来源必须使用绝对路径", nil)
		}
		valueNode = secretSourceNode(string(source.Kind), source.Name)
		renderedValue = "[" + string(source.Kind) + ":" + source.Name + "]"
	} else {
		if kind == configKindSecret {
			return r.fail("CONFIG_FIELD_SECRET", ExitUsage,
				"秘密字段不得以明文值写入配置；请使用 config set-secret --source env:NAME|file:PATH", nil)
		}
		if kind == configKindObjectList {
			return r.fail("CONFIG_FIELD_UNSUPPORTED", ExitUsage,
				fmt.Sprintf("字段 %s 是结构化对象列表；请人工编辑配置文件并用 config validate 校验", field), nil)
		}
		node, rendered, err := buildValueNode(kind, rawValue)
		if err != nil {
			return r.fail("CONFIG_VALUE_INVALID", ExitUsage, err.Error(), nil)
		}
		valueNode = node
		renderedValue = rendered
	}
	document, err := loadYAMLDocument(absoluteFile)
	if err != nil {
		return r.fail("CONFIG_FILE_INVALID", ExitError, err.Error(), nil)
	}
	if err := setYAMLField(document, field, valueNode); err != nil {
		return r.fail("CONFIG_FILE_INVALID", ExitError, err.Error(), nil)
	}
	encoded, err := marshalYAML(document)
	if err != nil {
		return r.fail("CONFIG_FILE_INVALID", ExitError, "YAML 序列化失败", nil)
	}
	// 用既有加载器校验写入后的完整配置；失败则不落盘，保证失败不留下半更新文件。
	// 校验时对配置中引用的 env: 秘密来源使用占位值：写入来源引用本身不需要该
	// 环境变量已设置，否则 set-secret 会因“当前进程未设置该变量”而无法写引用。
	if _, err := loginconfig.Load(loginconfig.LoadOptions{YAML: encoded,
		LookupEnv: lookupWithSecretPlaceholder(document, r.options.LookupEnv)}); err != nil {
		details := configErrorDetails(err)
		return r.fail("CONFIG_INVALID", ExitError, "写入后的配置未通过校验，未写入："+err.Error(), details)
	}
	oldValue := ""
	if existing, loadErr := r.loadEffectiveConfigTolerant(map[string]string{
		"config": absoluteFile}); loadErr == ExitOK {
		oldValue = configValueString(existing, field)
	}
	output := configWriteOutput{Field: field, OldValue: oldValue, NewValue: renderedValue,
		Class: string(info.Class), DryRun: dryRun, File: absoluteFile,
		NeedsRestart: info.Class == loginconfig.ReloadRestartRequired}
	if !dryRun {
		backup, writeErr := writeConfigAtomic(absoluteFile, encoded)
		if writeErr != nil {
			return r.fail("CONFIG_WRITE_FAILED", ExitError, writeErr.Error(), nil)
		}
		output.Written = true
		output.Backup = backup
	}
	if r.json {
		return r.succeed(output)
	}
	if dryRun {
		fmt.Fprintf(r.stdout, "预演（未写入）：%s: %s -> %s\n", field, oldValue, renderedValue)
	} else {
		fmt.Fprintf(r.stdout, "已写入：%s: %s -> %s（文件 %s）\n", field,
			oldValue, renderedValue, absoluteFile)
		if output.Backup != "" {
			fmt.Fprintf(r.stdout, "原文件备份：%s\n", output.Backup)
		}
	}
	if output.NeedsRestart {
		fmt.Fprintln(r.stdout, "该字段标记为 restart-required：需要重启进程后生效（CLI 不会重启服务）。")
	} else {
		fmt.Fprintln(r.stdout, "该字段标记为 hot-reloadable：重新加载配置后生效（CLI 不会自动重载）。")
	}
	return ExitOK
}

// marshalYAML 以 2 空格缩进编码配置，保持与常见手写 YAML 一致的排版。
func marshalYAML(document *yaml.Node) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := yaml.NewEncoder(&buffer)
	encoder.SetIndent(2)
	if err := encoder.Encode(document); err != nil {
		_ = encoder.Close()
		return nil, err
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// configWritableFile 校验目标配置路径：绝对化、父目录存在、目标不是符号链接。
func (r *runner) configWritableFile(file string) (string, int) {
	absolute, err := filepath.Abs(file)
	if err != nil {
		return "", r.usage("--file 路径无效")
	}
	info, err := os.Lstat(absolute)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return "", r.fail("CONFIG_FILE_INVALID", ExitUsage,
				"配置文件不能是符号链接（避免写入跟随到意外位置）", nil)
		}
		if !info.Mode().IsRegular() {
			return "", r.fail("CONFIG_FILE_INVALID", ExitUsage,
				"配置文件必须是普通文件", nil)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", r.fail("CONFIG_FILE_INVALID", ExitError, "无法检查配置文件", nil)
	}
	parent := filepath.Dir(absolute)
	parentInfo, err := os.Stat(parent)
	if err != nil || !parentInfo.IsDir() {
		return "", r.fail("CONFIG_FILE_INVALID", ExitUsage, "配置文件所在目录不存在", nil)
	}
	return absolute, ExitOK
}

// buildValueNode 把命令行文本转换为 YAML 值节点，并返回用于展示的规范化文本。
func buildValueNode(kind configFieldKind, raw string) (*yaml.Node, string, error) {
	switch kind {
	case configKindString:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: raw}, raw, nil
	case configKindBool:
		normalized := strings.ToLower(strings.TrimSpace(raw))
		if normalized != "true" && normalized != "false" {
			return nil, "", fmt.Errorf("值必须是 true 或 false")
		}
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: normalized}, normalized, nil
	case configKindInt:
		trimmed := strings.TrimSpace(raw)
		if _, err := strconv.Atoi(trimmed); err != nil {
			return nil, "", fmt.Errorf("值必须是整数")
		}
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: trimmed}, trimmed, nil
	case configKindList:
		items, err := parseListValue(raw)
		if err != nil {
			return nil, "", err
		}
		node := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for _, item := range items {
			node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode,
				Tag: "!!str", Value: item})
		}
		return node, "[" + strings.Join(items, ", ") + "]", nil
	default:
		return nil, "", fmt.Errorf("不支持的字段类型")
	}
}

// parseListValue 解析列表值：JSON 字符串数组，或逗号分隔文本（自动去空白、拒绝空项）。
func parseListValue(raw string) ([]string, error) {
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "[") {
		var items []string
		if err := yaml.Unmarshal([]byte(trimmed), &items); err != nil {
			return nil, fmt.Errorf("列表值必须是 JSON 字符串数组或逗号分隔文本")
		}
		for _, item := range items {
			if strings.TrimSpace(item) == "" {
				return nil, fmt.Errorf("列表值不能包含空项")
			}
		}
		return items, nil
	}
	if trimmed == "" {
		return nil, nil
	}
	parts := strings.Split(trimmed, ",")
	items := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item == "" {
			return nil, fmt.Errorf("列表值不能包含空项")
		}
		items = append(items, item)
	}
	return items, nil
}

// secretSourceNode 构造 YAML 秘密来源映射 {env: NAME} 或 {file: ABS}。
func secretSourceNode(kind, name string) *yaml.Node {
	return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: kind},
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: name},
	}}
}

// loadYAMLDocument 读取 YAML 文件为可编辑节点树；文件不存在或为空时返回空映射。
func loadYAMLDocument(path string) (*yaml.Node, error) {
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("无法读取配置文件：%v", err)
	}
	if len(data) == 0 {
		document := &yaml.Node{Kind: yaml.DocumentNode}
		document.Content = []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}
		return document, nil
	}
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("配置文件不是合法 YAML：%v", err)
	}
	if document.Kind == 0 {
		document = yaml.Node{Kind: yaml.DocumentNode}
	}
	if len(document.Content) == 0 {
		document.Content = []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}
	}
	if document.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("配置文件的顶层必须是映射（键值对）")
	}
	return &document, nil
}

// setYAMLField 在文档节点树中设置点分字段（当前所有字段都是“段.键”两段）。
func setYAMLField(document *yaml.Node, field string, value *yaml.Node) error {
	section, key, ok := strings.Cut(field, ".")
	if !ok || section == "" || key == "" {
		return fmt.Errorf("字段路径必须是 section.key 形式")
	}
	root := document.Content[0]
	sectionNode := mappingChild(root, section)
	if sectionNode == nil {
		sectionNode = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		root.Content = append(root.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: section}, sectionNode)
	} else if sectionNode.Kind != yaml.MappingNode {
		return fmt.Errorf("配置段 %s 不是映射，拒绝改写", section)
	}
	existing := mappingChild(sectionNode, key)
	if existing == nil {
		sectionNode.Content = append(sectionNode.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, value)
		return nil
	}
	// 用新节点替换旧值节点；键节点与注释保持不变。
	for index := 0; index+1 < len(sectionNode.Content); index += 2 {
		if sectionNode.Content[index].Value == key {
			sectionNode.Content[index+1] = value
			return nil
		}
	}
	return fmt.Errorf("无法定位字段 %s", field)
}

// mappingChild 返回映射中指定键的值节点；不存在返回 nil。
func mappingChild(mapping *yaml.Node, key string) *yaml.Node {
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == key {
			return mapping.Content[index+1]
		}
	}
	return nil
}

// lookupWithSecretPlaceholder 包装环境变量读取：对 YAML 中 env: 秘密来源引用的
// 变量名，若当前环境未设置则返回占位值，使“写入来源引用”不依赖变量已设置；
// 其他变量名保持原样，避免伪造普通配置环境覆盖。
func lookupWithSecretPlaceholder(document *yaml.Node,
	base func(string) (string, bool)) func(string) (string, bool) {
	names := secretEnvNames(document)
	return func(name string) (string, bool) {
		value, ok := readEnv(base, name)
		if ok && value != "" {
			return value, true
		}
		if _, isSecretSource := names[name]; isSecretSource {
			return "managecli-validation-placeholder-secret", true
		}
		return value, ok
	}
}

// readEnv 使用注入的读取函数或系统环境。
func readEnv(base func(string) (string, bool), name string) (string, bool) {
	if base != nil {
		return base(name)
	}
	return os.LookupEnv(name)
}

// secretEnvNames 收集 YAML secrets 段中 env: 来源引用的变量名。
func secretEnvNames(document *yaml.Node) map[string]struct{} {
	names := make(map[string]struct{})
	if document == nil || len(document.Content) == 0 {
		return names
	}
	secretsNode := mappingChild(document.Content[0], "secrets")
	if secretsNode == nil || secretsNode.Kind != yaml.MappingNode {
		return names
	}
	for index := 0; index+1 < len(secretsNode.Content); index += 2 {
		source := secretsNode.Content[index+1]
		if source.Kind != yaml.MappingNode {
			continue
		}
		if envNode := mappingChild(source, "env"); envNode != nil && envNode.Value != "" {
			names[envNode.Value] = struct{}{}
		}
	}
	return names
}

// writeConfigAtomic 原子写入配置，并为原文件生成不覆盖已有备份的副本。
// 返回备份路径（原文件不存在时为空）。写入失败时不留下目标路径的半更新内容。
func writeConfigAtomic(path string, data []byte) (string, error) {
	backup := ""
	if info, err := os.Stat(path); err == nil {
		original, readErr := os.ReadFile(path)
		if readErr != nil {
			return "", fmt.Errorf("无法读取原配置文件用于备份")
		}
		backup = path + ".bak"
		if _, statErr := os.Stat(backup); statErr == nil {
			backup = fmt.Sprintf("%s.bak-%d", path, timeStampNow().Unix())
		}
		if err := writeFileAtomic(backup, original, info.Mode().Perm()); err != nil {
			return "", fmt.Errorf("无法创建配置备份：%v", err)
		}
	}
	if err := writeFileAtomic(path, data, 0o644); err != nil {
		return "", fmt.Errorf("无法写入配置文件：%v", err)
	}
	return backup, nil
}

// writeFileAtomic 在目标同目录写临时文件并 rename，避免半更新文件。
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".loginctl-config-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	cleanup := func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryName)
	}
	if err := temporary.Chmod(mode); err != nil {
		cleanup()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := temporary.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryName)
		return err
	}
	if err := os.Rename(temporaryName, path); err != nil {
		_ = os.Remove(temporaryName)
		return err
	}
	return nil
}

// timeStampNow 返回当前时间，便于测试替换（备份名后缀只用于避免覆盖）。
func timeStampNow() time.Time { return time.Now() }

// flagError 由 managecli.go 中的通用实现提供；这里只保留 config 组帮助文本的绑定。

// configErrorDetails 把配置错误转换为脱敏结构化详情（供 set 校验失败输出）。
func configErrorDetails(err error) []configErrorDetail {
	var configErrors loginconfig.ConfigErrors
	if !errors.As(err, &configErrors) {
		return nil
	}
	details := make([]configErrorDetail, 0, len(configErrors))
	for _, item := range configErrors {
		details = append(details, configErrorDetail{Kind: item.Kind.String(),
			Source: item.Source, Field: item.Field, Line: item.Line, Detail: item.Detail})
	}
	return details
}
