package apidoc

import (
	"os"
	"path/filepath"
	"testing"
)

// writeFixture 在临时目录写入文件并自动创建父目录。
func writeFixture(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("创建测试目录失败：%v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("写测试文件失败：%v", err)
	}
}

// TestScanPages 校验 UIRoute 字面量扫描（含访问级别与排序、_test.go 排除）。
func TestScanPages(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "pages.go", `package login

var builtinRoutes = []UIRoute{
	{Name: "auth.login", Method: "GET", Path: "/login", Access: UIAccessPublic},
	{Name: "account.profile", Method: "GET", Path: "/account/profile", Access: UIAccessUser},
}
`)
	writeFixture(t, root, "pages_test.go", `package login

var ignored = []UIRoute{{Name: "test.only", Path: "/test"}}
`)
	pages, err := scanPages(root)
	if err != nil {
		t.Fatalf("scanPages 失败：%v", err)
	}
	if len(pages) != 2 {
		t.Fatalf("页面数 = %d，期望 2：%+v", len(pages), pages)
	}
	if pages[0].Name != "account.profile" || pages[0].Access != "UIAccessUser" {
		t.Errorf("页面扫描结果不符合预期：%+v", pages[0])
	}
	if pages[1].Name != "auth.login" || pages[1].Method != "GET" {
		t.Errorf("页面扫描结果不符合预期：%+v", pages[1])
	}
}

// TestScanAdminRoutes 校验 add(...) 与 DomainRoute 字面量两种注册。
func TestScanAdminRoutes(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "internal/adminapi/handler.go", `package adminapi

type route struct{}

func (s *Server) buildRoutes() []route {
	add(http.MethodGet, "users", nil)
	add(http.MethodPost, "users", nil)
	return nil
}
`)
	writeFixture(t, root, "internal/serverapp/routes.go", `package serverapp

var domainRoutes = []DomainRoute{
	DomainRoute{Method: "GET", Pattern: "sessions"},
}
`)
	routes, err := scanAdminRoutes(root)
	if err != nil {
		t.Fatalf("scanAdminRoutes 失败：%v", err)
	}
	if len(routes) != 3 {
		t.Fatalf("管理路由数 = %d，期望 3：%+v", len(routes), routes)
	}
	if routes[0].Method != "GET" || routes[0].Pattern != "sessions" {
		t.Errorf("路由排序不符合预期：%+v", routes[0])
	}
}

// TestScanProtocol 校验协议路径常量与包注释端点表。
func TestScanProtocol(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "internal/protocolapi/protocolapi.go", `package protocolapi

const (
	// PathAuthorize 是授权端点。
	PathAuthorize = "/oauth/authorize"
	PathToken     = "/oauth/token"
)

// 协议端点：
//
//	GET /oauth/authorize
//	POST /oauth/token
`)
	paths, endpoints, err := scanProtocol(root)
	if err != nil {
		t.Fatalf("scanProtocol 失败：%v", err)
	}
	if len(paths) != 2 || paths[0].Name != "PathAuthorize" || paths[0].Path != "/oauth/authorize" {
		t.Fatalf("协议路径扫描不符合预期：%+v", paths)
	}
	if len(endpoints) != 2 || endpoints[0].Method != "GET" {
		t.Fatalf("协议端点扫描不符合预期：%+v", endpoints)
	}
}

// TestScanGoAPI 校验 app/根包公开符号与接口方法签名提取。
func TestScanGoAPI(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "go.mod", "module example.com/test\n")
	writeFixture(t, root, "app/app.go", `package app

type Runtime struct{}

// Open 构造运行时。
func Open() *Runtime { return &Runtime{} }

// Start 启动后台任务。
func (r *Runtime) Start() error { return nil }

// UserService 是用户领域公开接口。
type UserService interface {
	// Get 查询用户。
	Get(id string) (string, error)
}

// User 是公开用户资料。
type User struct {
	ID   string
	Name string
}
`)
	writeFixture(t, root, "root.go", `package login

// Version 是版本信息。
type Version struct{ Value string }

// CurrentVersion 返回版本。
func CurrentVersion() Version { return Version{} }

const DefaultPort = 8080
`)
	api, err := scanGoAPI(root)
	if err != nil {
		t.Fatalf("scanGoAPI 失败：%v", err)
	}
	if len(api.RuntimeMethods) != 1 || api.RuntimeMethods[0].Name != "Start" {
		t.Errorf("Runtime 方法扫描不符合预期：%+v", api.RuntimeMethods)
	}
	if len(api.Interfaces) != 1 || api.Interfaces[0].Name != "UserService" {
		t.Fatalf("接口扫描不符合预期：%+v", api.Interfaces)
	}
	if got := api.Interfaces[0].Methods[0].Signature; got != "(id string) (string, error)" {
		t.Errorf("接口方法签名 = %q", got)
	}
	if len(api.AppTypes) != 3 {
		t.Errorf("app 公开类型数 = %d，期望 3（含接口）", len(api.AppTypes))
	}
	if api.RootTypeCount != 1 || api.RootFuncCount != 1 {
		t.Errorf("根包公开面 = %d 类型/%d 函数，期望 1/1", api.RootTypeCount, api.RootFuncCount)
	}
}

// TestScanCLI 校验 cobra 与 flag.NewFlagSet 两种命令/flag 提取。
func TestScanCLI(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "cmd/login-server/main.go", `package main

import "github.com/spf13/cobra"

func newServeCommand() *cobra.Command {
	command := &cobra.Command{Use: "serve", Short: "启动服务"}
	flags := command.Flags()
	flags.StringVar(nil, "config", "", "配置文件路径")
	flags.BoolVar(nil, "enable-protocol", false, "启用协议端点")
	return command
}

func newInitCommand() *cobra.Command {
	command := &cobra.Command{Use: "init"}
	flags := command.Flags()
	flags.StringVar(nil, "operator", "", "操作者")
	return command
}
`)
	writeFixture(t, root, "cmd/login-backup/cli.go", "package main\n\nimport \"flag\"\n\nconst programName = \"login-backup\"\n\nfunc runCreate() int {\n\tflags := flag.NewFlagSet(programName+\" create\", flag.ContinueOnError)\n\tflags.String(\"output\", \"\", \"输出目录\")\n\treturn 0\n}\n")
	writeFixture(t, root, "internal/managecli/managecli.go", `package managecli

func Run(args []string) int {
	switch args[0] {
	case "config", "diag":
		return 0
	}
	return 1
}
`)
	writeFixture(t, root, "cmd/loginctl/loginctl.go", `package main

func main() {
	switch args[0] {
	case "root-recover":
	case "config", "diag":
	}
}
`)
	binaries, err := scanCLI(root)
	if err != nil {
		t.Fatalf("scanCLI 失败：%v", err)
	}
	byName := map[string]CLIBinary{}
	for _, binary := range binaries {
		byName[binary.Name] = binary
	}
	server, ok := byName["login-server"]
	if !ok || len(server.Subcommands) != 2 {
		t.Fatalf("login-server 子命令扫描不符合预期：%+v", byName)
	}
	for _, command := range server.Subcommands {
		if command.Name == "serve" && len(command.Flags) != 2 {
			t.Errorf("serve flag 数 = %d，期望 2", len(command.Flags))
		}
	}
	backup, ok := byName["login-backup"]
	if !ok || len(backup.Subcommands) != 1 || backup.Subcommands[0].Name != "create" {
		t.Fatalf("login-backup 子命令扫描不符合预期：%+v", byName)
	}
	if len(backup.Subcommands[0].Flags) != 1 || backup.Subcommands[0].Flags[0].Name != "output" {
		t.Errorf("login-backup flag 扫描不符合预期：%+v", backup.Subcommands[0].Flags)
	}
	loginctl, ok := byName["loginctl"]
	if !ok {
		t.Fatalf("缺少 loginctl：%+v", byName)
	}
	names := map[string]bool{}
	for _, command := range loginctl.Subcommands {
		names[command.Name] = true
	}
	for _, want := range []string{"root-recover", "config", "diag"} {
		if !names[want] {
			t.Errorf("loginctl 缺少子命令 %s：%+v", want, names)
		}
	}
}

// TestLoadSnippets 校验示例提取（包含文档注释、按函数名排序）。
func TestLoadSnippets(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "examples/reference-snippets/snippets.go", `package referenceexamples

// ExampleB 演示 B。
func ExampleB() {}

// ExampleA 演示 A。
func ExampleA() { _ = 1 }
`)
	snippets, err := loadSnippets(root)
	if err != nil {
		t.Fatalf("loadSnippets 失败：%v", err)
	}
	if len(snippets) != 2 {
		t.Fatalf("示例数 = %d，期望 2", len(snippets))
	}
	if snippets[0].Symbol != "ExampleA" || !containsSubstring(snippets[0].Code, "// ExampleA 演示 A。") {
		t.Errorf("示例提取未包含文档注释：%+v", snippets[0])
	}
}

// containsSubstring 是测试用的子串判断。
func containsSubstring(text, want string) bool {
	return len(want) == 0 || (len(text) >= len(want) && indexOf(text, want) >= 0)
}

// indexOf 返回子串位置（-1 表示不存在）。
func indexOf(text, want string) int {
	for index := 0; index+len(want) <= len(text); index++ {
		if text[index:index+len(want)] == want {
			return index
		}
	}
	return -1
}
