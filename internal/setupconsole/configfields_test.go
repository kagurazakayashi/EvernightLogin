package setupconsole

// 步骤279：全配置字段编辑模型的定向测试（注册表驱动、默认/文件/有效值、覆盖提示、
// 秘密字段状态、列表/映射/嵌套编辑、清空/零值区分、差异与草稿不写盘）。

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestConfigDraftEditAndValidate 覆盖标量/布尔/数字/列表/映射/嵌套编辑与清空。
func TestConfigDraftEditAndValidate(t *testing.T) {
	draft, err := NewConfigDraft("login.yaml",
		[]byte("database:\n  driver: sqlite\n  path: database/login.db\nlogging:\n  level: info\n"))
	if err != nil {
		t.Fatalf("构造草稿: %v", err)
	}
	// 标量替换。
	if err := draft.SetValue("database.path", "data/prod/login.db"); err != nil {
		t.Fatalf("设置字符串: %v", err)
	}
	if value, found := draft.GetValue("database.path"); !found || value != "data/prod/login.db" {
		t.Fatalf("字符串读取异常: %v %v", value, found)
	}
	if !draft.IsModified("database.path") {
		t.Fatal("修改后的字段未标记 modified")
	}
	if draft.IsModified("database.driver") {
		t.Fatal("未修改字段误标 modified")
	}
	// 布尔/数字/列表/映射。
	if err := draft.SetValue("database.wal", false); err != nil {
		t.Fatalf("设置布尔: %v", err)
	}
	if err := draft.SetValue("server.shutdown_timeout_seconds", 42); err != nil {
		t.Fatalf("设置数字: %v", err)
	}
	if err := draft.SetValue("server.allowed_hosts", []any{"a.example", "b.example"}); err != nil {
		t.Fatalf("设置列表: %v", err)
	}
	report := draft.Validate()
	if !report.Valid {
		t.Fatalf("合法草稿应校验通过: %s %+v", report.Summary, report.Issues)
	}
	// 清空文件值 → 回退默认（不再算修改）。
	draft.Unset("database.path")
	if _, found := draft.GetValue("database.path"); found {
		t.Fatal("Unset 后文件值仍存在")
	}
	if !draft.IsModified("database.path") {
		t.Fatal("清空已有的文件值应算修改（相对初始文件）")
	}
	// 未设置过的字段 Unset 后仍不算修改。
	if draft.IsModified("server.tls_ca_file") {
		t.Fatal("未设置字段不应算修改")
	}
	draft.Unset("server.tls_ca_file")
	if draft.IsModified("server.tls_ca_file") {
		t.Fatal("未设置字段 Unset 后不应算修改")
	}
	// 空字符串与未设置的区分。
	if err := draft.SetValue("server.public_base_url", ""); err != nil {
		t.Fatalf("设置空字符串: %v", err)
	}
	if value, found := draft.GetValue("server.public_base_url"); !found || value != "" {
		t.Fatalf("空字符串未保留: %v %v", value, found)
	}
}

// TestBuildFieldViews 覆盖默认/文件/有效值、覆盖提示、秘密脱敏与错误字段映射。
func TestBuildFieldViews(t *testing.T) {
	t.Setenv("LOGIN_DATABASE_PATH", "/tmp/env-override.db")
	draft, err := NewConfigDraft("login.yaml", []byte("database:\n  path: file/path.db\n"))
	if err != nil {
		t.Fatalf("构造草稿: %v", err)
	}
	views := BuildFieldViews(draft)
	if len(views) < 50 {
		t.Fatalf("字段视图数量 = %d，应覆盖注册表全部字段", len(views))
	}
	byPath := make(map[string]FieldView, len(views))
	for _, view := range views {
		byPath[view.Path] = view
	}
	databasePath := byPath["database.path"]
	if databasePath.File != `"file/path.db"` || !databasePath.HasFile {
		t.Fatalf("文件值展示异常: %+v", databasePath)
	}
	if databasePath.Override == "" || !strings.Contains(databasePath.Override, "LOGIN_DATABASE_PATH") {
		t.Fatalf("环境变量覆盖提示缺失: %+v", databasePath)
	}
	if databasePath.ClassLabel != "重启进程后生效" {
		t.Fatalf("重载分类展示异常: %+v", databasePath)
	}
	secret := byPath["secrets.master_key"]
	if !secret.Secret {
		t.Fatal("主密钥字段应标记为秘密")
	}
	if strings.Contains(strings.ToLower(secret.File+secret.Effective), "env:") ||
		strings.Contains(strings.ToLower(secret.File+secret.Effective), "file:") {
		t.Fatalf("秘密字段泄露来源引用: %+v", secret)
	}
	// 非法草稿：受影响字段带错误说明，有效值标未知。
	badDraft, err := NewConfigDraft("login.yaml", []byte("database:\n  busy_timeout_ms: 0\n"))
	if err != nil {
		t.Fatalf("构造坏草稿: %v", err)
	}
	badViews := BuildFieldViews(badDraft)
	foundError := false
	for _, view := range badViews {
		if view.Error != "" {
			foundError = true
		}
	}
	if !foundError {
		t.Fatal("坏草稿应把错误映射到字段视图")
	}
}

// TestParseFieldInputTypes 覆盖输入解析的标量/列表/映射/字符串回退。
func TestParseFieldInputTypes(t *testing.T) {
	cases := []struct {
		input string
		check func(any) bool
	}{
		{"true", func(value any) bool { b, ok := value.(bool); return ok && b }},
		{"42", func(value any) bool { i, ok := value.(int); return ok && i == 42 }},
		{`"hello"`, func(value any) bool { s, ok := value.(string); return ok && s == "hello" }},
		{"[a, b]", func(value any) bool {
			list, ok := value.([]any)
			return ok && len(list) == 2 && list[0] == "a"
		}},
		{"{k: v}", func(value any) bool {
			mapping, ok := value.(map[string]any)
			return ok && mapping["k"] == "v"
		}},
		{"host:port", func(value any) bool { s, ok := value.(string); return ok && s == "host:port" }},
	}
	for _, testCase := range cases {
		value, err := ParseFieldInput(testCase.input)
		if err != nil {
			t.Fatalf("解析 %q: %v", testCase.input, err)
		}
		if !testCase.check(value) {
			t.Fatalf("解析 %q 得到 %#v", testCase.input, value)
		}
	}
}

// TestConfigDraftDiff 覆盖行级差异与未知字段保留。
func TestConfigDraftDiff(t *testing.T) {
	draft, err := NewConfigDraft("login.yaml",
		[]byte("server:\n  custom_unknown_field: keep-me\n"))
	if err != nil {
		t.Fatalf("构造草稿: %v", err)
	}
	if err := draft.SetValue("logging.level", "debug"); err != nil {
		t.Fatalf("设置字段: %v", err)
	}
	if !strings.Contains(string(draft.Raw()), "custom_unknown_field") {
		t.Fatal("草稿序列化丢失未知字段")
	}
	diff := draft.Diff()
	adds, removes := 0, 0
	for _, line := range diff {
		switch line.Kind {
		case "add":
			adds++
		case "remove":
			removes++
		}
	}
	if adds == 0 || removes == 0 {
		t.Fatalf("差异行数异常: add=%d remove=%d", adds, removes)
	}
}

// TestAppFieldsScreenDraftNotWritten 覆盖全屏字段编辑不写盘与筛选/编辑流程。
func TestAppFieldsScreenDraftNotWritten(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "login.yaml")
	original := "database:\n  path: database/login.db\nlogging:\n  level: info\n"
	if err := os.WriteFile(configPath, []byte(original), 0o600); err != nil {
		t.Fatalf("写入配置: %v", err)
	}
	terminal := newFakeTerminal(
		downKey(), downKey(), enterKey(), // 全配置字段编辑（index 2）
		runeKey('/'), runeKey('d'), runeKey('a'), runeKey('t'), runeKey('a'),
		runeKey('b'), runeKey('a'), runeKey('s'), runeKey('e'), enterKey(), // 搜索 database
		enterKey(), // 编辑当前字段（database.driver 或 database.path）
		runeKey('x'),
		enterKey(),                                                        // 应用草稿
		escKey(),                                                          // 返回配置诊断/主菜单路径
		escKey(),                                                          // 回到主菜单（配置画面 Esc）
		downKey(), downKey(), downKey(), downKey(), downKey(), enterKey(), // 退出
	)
	app := NewApp(terminal, configPath, func(ctx context.Context,
		options DetectOptions) Detection {
		return Detection{Kind: StateReady, ConfigPath: options.ConfigPath, Summary: "就绪"}
	})
	if err := app.Run(context.Background()); err != nil {
		t.Fatalf("运行控制台: %v", err)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("读取原配置: %v", err)
	}
	if string(data) != original {
		t.Fatal("字段编辑草稿被自动写盘（禁止）")
	}
	joined := strings.Join(terminal.frames, "\n")
	for _, want := range []string{"全配置字段编辑", "配置文件：", "校验"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("字段编辑画面缺少内容 %q", want)
		}
	}
}
