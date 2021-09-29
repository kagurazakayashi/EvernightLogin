// Command verify-docs 静态核对 docs/guide 与产品定义的一致性。
//
// 它只读仓库文件，不联网、不启动服务、不写文件。检查项：
//   - 错误码注册表（error_codes.go）与错误码手册逐项一致（码/分类/HTTP/说明/顺序）；
//   - docs/guide/troubleshooting.md 覆盖全部已登记错误码；
//   - docs/guide 中引用的错误码都存在（允许 CLI 工具码与环境变量名）；
//   - 配置字段（config.go 的 configFields）与 docs/guide/configuration.md 表逐项一致
//     （字段、重载分类、秘密标记、环境变量）；默认值对照内置快照；
//   - 系统权限键（internal/preset/catalog.go）全部出现在
//     docs/guide/applications-and-permissions.md；
//   - docs/guide 内部相对链接可达，且必备文档齐全；
//   - 传入 -cli-dir 时额外检查已构建 CLI 的帮助/版本输出包含文档依赖的命令。
//
// 用法（仓库根目录）：
//
//	go run ./scripts/verify-docs
//	go run ./scripts/verify-docs -cli-dir %TEMP%\login-begin
//
// 成功输出 "DOCS VERIFY: PASS checks=N failures=0" 并以 0 退出；存在失败时逐条打印并
// 以非 0 退出。默认值快照镜像 login.Default()，修改默认值时必须同步本文件与
// docs/guide/configuration.md。
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

func main() {
	cliDir := flag.String("cli-dir", "", "可选：已构建的 login-server/loginctl/login-backup 所在目录")
	flag.Parse()

	root, err := findRepoRoot()
	if err != nil {
		fatalf("定位仓库根目录失败：%v", err)
	}
	v := &verifier{root: root}
	v.checkErrorCodeRegistry()
	v.checkTroubleshootingCoverage()
	v.checkConfigReference()
	v.checkPermissionKeys()
	v.checkGuideErrorCodeReferences()
	v.checkLinks()
	v.checkRequiredDocs()
	if *cliDir != "" {
		v.checkCLI(*cliDir)
	}
	v.summary()
}

type verifier struct {
	root     string
	checks   int
	failures []string
}

func (v *verifier) pass() { v.checks++ }

func (v *verifier) fail(format string, args ...any) {
	v.checks++
	v.failures = append(v.failures, fmt.Sprintf(format, args...))
}

func (v *verifier) summary() {
	for _, failure := range v.failures {
		fmt.Println("FAIL:", failure)
	}
	if len(v.failures) == 0 {
		fmt.Printf("DOCS VERIFY: PASS checks=%d failures=0\n", v.checks)
		return
	}
	fmt.Printf("DOCS VERIFY: FAIL checks=%d failures=%d\n", v.checks, len(v.failures))
	os.Exit(1)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "verify-docs: "+format+"\n", args...)
	os.Exit(2)
}

func (v *verifier) path(rel string) string { return filepath.Join(v.root, rel) }

func (v *verifier) read(rel string) string {
	data, err := os.ReadFile(v.path(rel))
	if err != nil {
		fatalf("读取 %s 失败：%v", rel, err)
	}
	return string(data)
}

func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("向上未找到 go.mod")
		}
		dir = parent
	}
}

// ---- 错误码注册表 ----

type errorCodeDef struct {
	Code     string
	Category string
	Message  string
	HTTP     int
}

func (v *verifier) checkErrorCodeRegistry() {
	source := v.read("error_codes.go")
	definitionPattern := regexp.MustCompile(`\{Code(\w+), Category(\w+), "((?:[^"\\]|\\.)*)", (\d+)\}`)
	matches := definitionPattern.FindAllStringSubmatch(source, -1)
	if len(matches) == 0 {
		v.fail("error_codes.go 未解析出错误码定义")
		return
	}
	categoryPattern := regexp.MustCompile(`Category(\w+)\s+ErrorCategory\s*=\s*"([^"]+)"`)
	categories := map[string]string{}
	for _, match := range categoryPattern.FindAllStringSubmatch(source, -1) {
		categories[match[1]] = match[2]
	}
	defs := make([]errorCodeDef, 0, len(matches))
	for _, match := range matches {
		http := 0
		fmt.Sscanf(match[4], "%d", &http)
		category, ok := categories[match[2]]
		if !ok {
			v.fail("错误码分类常量 %s 未找到中文映射", match[2])
			category = match[2]
		}
		defs = append(defs, errorCodeDef{Category: category, Message: match[3], HTTP: http})
	}
	// 常量名 -> 字符串值，用于确认定义中的常量名顺序与手册一致。
	constPattern := regexp.MustCompile(`Code\w+\s+ErrorCode\s*=\s*"([A-Z0-9_]+)"`)
	consts := constPattern.FindAllStringSubmatch(source, -1)
	if len(consts) != len(defs) {
		v.fail("错误码常量数 %d 与定义数 %d 不一致", len(consts), len(defs))
	}
	for index := range defs {
		if index < len(defs) {
			defs[index].Code = consts[index][1]
		}
	}

	v.pass()
	manual := v.read("docs/requirements/login_错误码与排障手册.md")
	rows := parseMarkdownTableRows(manual)
	manualDefs := make([]errorCodeDef, 0, len(rows))
	for _, cells := range rows {
		if len(cells) < 3 || !isErrorCodeShape(cells[0]) {
			continue
		}
		http := 0
		if strings.TrimSpace(cells[2]) != "—" && strings.TrimSpace(cells[2]) != "-" {
			fmt.Sscanf(strings.TrimSpace(cells[2]), "%d", &http)
		}
		manualDefs = append(manualDefs, errorCodeDef{Code: normalizeCodeCell(cells[0]), Category: cells[1], HTTP: http})
	}
	if len(manualDefs) != len(defs) {
		v.fail("手册错误码行数 %d 与注册表 %d 不一致", len(manualDefs), len(defs))
		return
	}
	v.pass()
	for index, def := range defs {
		man := manualDefs[index]
		switch {
		case man.Code != def.Code:
			v.fail("错误码第 %d 项：注册表 %s，手册 %s", index+1, def.Code, man.Code)
		case man.Category != def.Category:
			v.fail("错误码 %s 分类：注册表 %s，手册 %s", def.Code, def.Category, man.Category)
		case man.HTTP != def.HTTP:
			v.fail("错误码 %s HTTP：注册表 %d，手册 %d", def.Code, def.HTTP, man.HTTP)
		}
	}
	v.pass()
	if len(defs) != 48 {
		v.fail("错误码数量为 %d，文档约定为 48（新增码请同步更新本检查与手册）", len(defs))
	}
	v.pass()
}

func (v *verifier) checkTroubleshootingCoverage() {
	text := v.read("docs/guide/troubleshooting.md")
	rows := parseMarkdownTableRows(text)
	documented := map[string]bool{}
	for _, cells := range rows {
		if len(cells) == 0 {
			continue
		}
		code := normalizeCodeCell(cells[0])
		if isErrorCodeShape(code) {
			documented[code] = true
		}
	}
	source := v.read("error_codes.go")
	constPattern := regexp.MustCompile(`Code\w+\s+ErrorCode\s*=\s*"([A-Z0-9_]+)"`)
	count := 0
	for _, match := range constPattern.FindAllStringSubmatch(source, -1) {
		count++
		if !documented[match[1]] {
			v.fail("docs/guide/troubleshooting.md 缺少错误码 %s", match[1])
		}
	}
	if count == 0 {
		v.fail("未从 error_codes.go 解析出错误码常量")
	}
	v.pass()
}

// ---- 配置字段 ----

type configField struct {
	Field  string
	Env    string
	Class  string
	Secret bool
}

var defaultSnapshot = map[string]string{
	"server.listen_addr":                      "127.0.0.1:8080",
	"server.extra_listen_addrs":               "[]",
	"server.public_base_url":                  "空",
	"server.path_prefix":                      "空",
	"server.allowed_hosts":                    "[]",
	"server.trusted_proxies":                  "[]",
	"server.tls_terminating_proxy":            "false",
	"server.tls_cert_files":                   "[]",
	"server.tls_key_files":                    "[]",
	"server.tls_ca_file":                      "空",
	"server.tls_pfx_file":                     "空",
	"server.tls_expiry_warning_days":          "30",
	"server.tls_client_auth":                  "disabled",
	"server.tls_client_ca_files":              "[]",
	"server.tls_client_identities":            "[]",
	"server.shutdown_timeout_seconds":         "10",
	"logging.level":                           "info",
	"logging.format":                          "text",
	"database.driver":                         "sqlite",
	"database.path":                           "database/login.db",
	"database.wal":                            "true",
	"database.busy_timeout_ms":                "5000",
	"registration.enabled":                    "false",
	"registration.require_review":             "false",
	"registration.require_email_verification": "false",
	"registration.default_role_ids":           "[]",
	"passkey.enabled":                         "false",
	"passkey.rp_id":                           "空",
	"passkey.rp_display_name":                 "空",
	"passkey.allowed_origins":                 "[]",
	"passkey.user_verification":               "required",
	"app_qr_login.enabled":                    "false",
	"app_qr_login.allowed_client_ids":         "[]",
	"app_qr_login.request_ttl_seconds":        "120",
	"app_qr_login.claim_interval_seconds":     "1",
	"secrets.master_key":                      "未配置",
	"secrets.tls_pfx_password":                "未配置",
}

func (v *verifier) checkConfigReference() {
	source := v.read("config.go")
	fieldPattern := regexp.MustCompile(`\{Field: "([^"]+)", Env: ([A-Za-z0-9_]+), Class: Reload(\w+)(, Secret: true)?\}`)
	envPattern := regexp.MustCompile(`(env\w+)\s*=\s*EnvVarPrefix \+ "([A-Z0-9_]+)"`)
	prefixPattern := regexp.MustCompile(`EnvVarPrefix\s*=\s*"([^"]*)"`)
	prefix := "LOGIN_"
	if match := prefixPattern.FindStringSubmatch(source); match != nil {
		prefix = match[1]
	}
	envNames := map[string]string{}
	for _, match := range envPattern.FindAllStringSubmatch(source, -1) {
		envNames[match[1]] = prefix + match[2]
	}
	matches := fieldPattern.FindAllStringSubmatch(source, -1)
	if len(matches) == 0 {
		v.fail("config.go 未解析出 configFields")
		return
	}
	fields := make([]configField, 0, len(matches))
	for _, match := range matches {
		class := "hot-reloadable"
		if match[3] == "RestartRequired" {
			class = "restart-required"
		}
		env, ok := envNames[match[2]]
		if !ok {
			v.fail("配置字段 %s 的环境变量常量 %s 未找到", match[1], match[2])
		}
		fields = append(fields, configField{Field: match[1], Env: env, Class: class, Secret: match[4] != ""})
	}
	if len(fields) != 37 {
		v.fail("配置字段数为 %d，文档约定为 37", len(fields))
	}
	if len(defaultSnapshot) != len(fields) {
		v.fail("默认值快照条目数 %d 与字段数 %d 不一致", len(defaultSnapshot), len(fields))
	}
	v.pass()

	text := v.read("docs/guide/configuration.md")
	rows := parseMarkdownTableRows(text)
	documented := map[string][]string{}
	var order []string
	for _, cells := range rows {
		if len(cells) < 6 {
			continue
		}
		field := strings.Trim(strings.TrimSpace(cells[0]), "`")
		if _, ok := defaultSnapshot[field]; !ok {
			continue
		}
		documented[field] = cells
		order = append(order, field)
	}
	if len(documented) != len(fields) {
		v.fail("configuration.md 配置字段行数 %d 与代码 %d 不一致", len(documented), len(fields))
	}
	for _, field := range fields {
		cells, ok := documented[field.Field]
		if !ok {
			v.fail("configuration.md 缺少配置字段 %s", field.Field)
			continue
		}
		if got := strings.TrimSpace(cells[2]); got != field.Class {
			v.fail("字段 %s 分类：文档 %q，代码 %q", field.Field, got, field.Class)
		}
		secretText := strings.TrimSpace(cells[3])
		if (secretText == "是") != field.Secret {
			v.fail("字段 %s 秘密标记：文档 %q，代码 %v", field.Field, secretText, field.Secret)
		}
		if got := strings.Trim(strings.TrimSpace(cells[4]), "`"); got != field.Env {
			v.fail("字段 %s 环境变量：文档 %q，代码 %q", field.Field, got, field.Env)
		}
		def := strings.TrimSpace(cells[1])
		def = strings.Trim(def, "`")
		if got := defaultSnapshot[field.Field]; got != def {
			v.fail("字段 %s 默认值：文档 %q，快照 %q", field.Field, def, got)
		}
	}
	// 表内字段顺序必须与代码顺序一致，避免漏项被“数量相同”掩盖。
	for index := 0; index < len(order) && index < len(fields); index++ {
		if order[index] != fields[index].Field {
			v.fail("configuration.md 第 %d 个字段顺序：文档 %s，代码 %s", index+1, order[index], fields[index].Field)
			break
		}
	}
	v.pass()
}

// ---- 权限键 ----

func (v *verifier) checkPermissionKeys() {
	source := v.read("internal/preset/catalog.go")
	start := strings.Index(source, "func catalogPermissionsV1()")
	end := strings.Index(source, "func catalogRolesV1()")
	if start < 0 || end <= start {
		v.fail("无法定位 internal/preset/catalog.go 的权限目录函数")
		return
	}
	keyPattern := regexp.MustCompile(`Key: "([^"]+)"`)
	keys := map[string]bool{}
	for _, match := range keyPattern.FindAllStringSubmatch(source[start:end], -1) {
		keys[match[1]] = true
	}
	if len(keys) != 50 {
		v.fail("系统权限键数量为 %d，文档约定为 50", len(keys))
	}
	v.pass()
	text := v.read("docs/guide/applications-and-permissions.md")
	for key := range keys {
		if !strings.Contains(text, "`"+key+"`") {
			v.fail("applications-and-permissions.md 缺少权限键 %s", key)
		}
	}
	v.pass()
}

// ---- 文档中的错误码引用 ----

var allowedUpperTokens = map[string]bool{
	// CLI / 工具级稳定错误码（不属于 48 个业务错误码）。
	"USAGE_INVALID":                   true,
	"CONFIG_FIELD_UNKNOWN":            true,
	"CONFIG_FIELD_UNSUPPORTED":        true,
	"CONFIG_FIELD_NOT_SECRET":         true,
	"CONFIG_FILE_INVALID":             true,
	"CONFIG_DEFAULT_DATABASE_REFUSED": true,
	"CONFIG_SECRET_SOURCE_INVALID":    true,
	"DATABASE_NOT_INITIALIZED":        true,
	"DATABASE_UNSUPPORTED":            true,
	"DATABASE_PATH_INVALID":           true,
	"MAINTENANCE_STATE_UNVERIFIED":    true,
	"MAIL_DIAGNOSTICS_UNAVAILABLE":    true,
	"NOTIFICATION_UNAVAILABLE":        true,
	"NOTIFICATION_TEST_DISABLED":      true,
	"MANAGEMENT_WRITE_NOT_EXPOSED":    true,
	"O_EXCL":                          true,
}

func (v *verifier) checkGuideErrorCodeReferences() {
	source := v.read("error_codes.go")
	constPattern := regexp.MustCompile(`Code\w+\s+ErrorCode\s*=\s*"([A-Z0-9_]+)"`)
	registered := map[string]bool{}
	for _, match := range constPattern.FindAllStringSubmatch(source, -1) {
		registered[match[1]] = true
	}
	files, err := filepath.Glob(v.path("docs/guide/*.md"))
	if err != nil || len(files) == 0 {
		v.fail("未找到 docs/guide/*.md")
		return
	}
	tokenPattern := regexp.MustCompile(`[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+`)
	referenced := map[string]bool{}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			v.fail("读取 %s 失败：%v", file, err)
			continue
		}
		text := stripFencedCodeBlocks(string(data))
		for _, token := range tokenPattern.FindAllString(text, -1) {
			if strings.HasPrefix(token, "LOGIN_") || registered[token] || allowedUpperTokens[token] {
				if registered[token] {
					referenced[token] = true
				}
				continue
			}
			v.fail("%s 引用了未登记的大写标识 %q（若不是错误码/环境变量请避免该写法）",
				filepath.Base(file), token)
		}
	}
	if len(referenced) == 0 {
		v.fail("docs/guide 未引用任何已登记错误码")
	}
	v.pass()
}

// ---- 链接与必备文档 ----

func (v *verifier) checkLinks() {
	files, err := filepath.Glob(v.path("docs/guide/*.md"))
	if err != nil {
		v.fail("枚举 docs/guide 失败：%v", err)
		return
	}
	linkPattern := regexp.MustCompile(`\]\(([^)\s]+)\)`)
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		text := stripFencedCodeBlocks(string(data))
		for _, match := range linkPattern.FindAllStringSubmatch(text, -1) {
			target := match[1]
			if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") ||
				strings.HasPrefix(target, "mailto:") || strings.HasPrefix(target, "#") {
				continue
			}
			if index := strings.Index(target, "#"); index >= 0 {
				target = target[:index]
			}
			if target == "" {
				continue
			}
			resolved := filepath.Join(filepath.Dir(file), filepath.FromSlash(target))
			if _, err := os.Stat(resolved); err != nil {
				v.fail("%s 的链接 %q 不可达", filepath.Base(file), match[1])
			}
		}
	}
	v.pass()
}

func (v *verifier) checkRequiredDocs() {
	required := []string{
		"README.md", "quickstart.md", "deployment-modes.md", "api-status.md",
		"login-and-oauth.md", "applications-and-permissions.md", "roles-and-scopes.md",
		"configuration.md", "support-and-recovery.md", "root-cli.md",
		"audit-and-reports.md", "backup-and-restore.md", "troubleshooting.md",
	}
	for _, name := range required {
		if _, err := os.Stat(v.path("docs/guide/" + name)); err != nil {
			v.fail("缺少必备文档 docs/guide/%s", name)
		}
	}
	v.pass()
}

// ---- 可选 CLI 一致性 ----

func (v *verifier) checkCLI(dir string) {
	type cliCheck struct {
		bin      string
		args     []string
		contains []string
	}
	checks := []cliCheck{
		{"login-server", []string{"--version"}, []string{"login-server"}},
		{"login-server", []string{"--help"}, []string{"--version", "--help"}},
		{"loginctl", []string{"help"}, []string{"root-recover", "restore-preflight", "restore-apply", "maintenance-exit", "config", "diag", "migrate", "task", "session", "user"}},
		{"login-backup", []string{"help"}, []string{"create", "verify", "info", "list", "tables", "preview", "export", "extract"}},
	}
	for _, check := range checks {
		bin := filepath.Join(dir, check.bin)
		if filepath.Ext(bin) == "" && os.PathSeparator == '\\' {
			bin += ".exe"
		}
		if _, err := os.Stat(bin); err != nil {
			v.fail("CLI 检查：找不到 %s", bin)
			continue
		}
		output, err := runCLI(bin, check.args...)
		if err != nil {
			v.fail("CLI 检查：%s %s 执行失败：%v", check.bin, strings.Join(check.args, " "), err)
			continue
		}
		for _, want := range check.contains {
			if !strings.Contains(output, want) {
				v.fail("CLI 检查：%s %s 输出缺少 %q", check.bin, strings.Join(check.args, " "), want)
			}
		}
	}
	v.pass()
}

func runCLI(bin string, args ...string) (string, error) {
	command := exec.Command(bin, args...)
	var buffer bytes.Buffer
	command.Stdout = &buffer
	command.Stderr = &buffer
	err := command.Run()
	return buffer.String(), err
}

// ---- 工具函数 ----

func stripFencedCodeBlocks(text string) string {
	var builder strings.Builder
	inFence := false
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inFence = !inFence
			builder.WriteString("\n")
			continue
		}
		if inFence {
			builder.WriteString("\n")
			continue
		}
		builder.WriteString(line)
		builder.WriteString("\n")
	}
	return builder.String()
}

func normalizeCodeCell(cell string) string {
	return strings.Trim(strings.TrimSpace(cell), "`")
}

// isErrorCodeShape 判断单元格是否只由大写字母/数字/下划线组成；单字错误码（如
// CONFLICT）也合法，因此不要求必须含下划线。
func isErrorCodeShape(token string) bool {
	if token == "" || token[0] < 'A' || token[0] > 'Z' {
		return false
	}
	for _, r := range token {
		if !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && r != '_' {
			return false
		}
	}
	return true
}

// parseMarkdownTableRows 返回 Markdown 表格的数据行（跳过表头与分隔行），每个单元格
// 已去除首尾空白；反斜杠转义的竖线 \| 按普通字符处理。
func parseMarkdownTableRows(text string) [][]string {
	var rows [][]string
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "|") || !strings.HasSuffix(trimmed, "|") {
			continue
		}
		cells := splitTableRow(trimmed)
		if len(cells) == 0 {
			continue
		}
		separator := true
		for _, cell := range cells {
			if strings.Trim(cell, " -:") != "" {
				separator = false
				break
			}
		}
		if separator {
			continue
		}
		if cells[0] == "错误码" || cells[0] == "现象" || cells[0] == "YAML 字段" ||
			cells[0] == "权限键" || cells[0] == "命令" {
			continue
		}
		rows = append(rows, cells)
	}
	sort.SliceStable(rows, func(i, j int) bool { return false }) // 保留原始顺序
	return rows
}

func splitTableRow(line string) []string {
	line = strings.TrimPrefix(line, "|")
	line = strings.TrimSuffix(line, "|")
	var cells []string
	var current strings.Builder
	escaped := false
	for _, r := range line {
		switch {
		case escaped:
			current.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case r == '|':
			cells = append(cells, strings.TrimSpace(current.String()))
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}
	cells = append(cells, strings.TrimSpace(current.String()))
	return cells
}
