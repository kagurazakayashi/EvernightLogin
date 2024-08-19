package apidoc

// 本文件定义生成库的中间模型与 4 个机器 JSON 的对外结构。所有切片在生成前按
// 稳定顺序排序，JSON 使用固定字段顺序（结构体字段声明顺序），保证 -write 幂等。

// ErrorEntry 是一个公开错误码条目；数据来自 errs 包注册表与公开说明补充。
type ErrorEntry struct {
	Code           string `json:"code"`
	Category       string `json:"category"`
	HTTPStatus     int    `json:"http_status"`
	DefaultMessage string `json:"default_message"`
	Cause          string `json:"cause,omitempty"`
	Advice         string `json:"advice,omitempty"`
	Retry          string `json:"retry,omitempty"`
}

// PermissionEntry 是一个内置权限键的公开说明（来自 internal/preset 目录）。
type PermissionEntry struct {
	Key            string   `json:"key"`
	Name           string   `json:"name"`
	Summary        string   `json:"summary"`
	Scope          string   `json:"scope"`
	Limits         string   `json:"limits"`
	RequiresReauth bool     `json:"requires_reauth"`
	RootOnly       bool     `json:"root_only"`
	DefaultRoles   []string `json:"default_roles,omitempty"`
	Implemented    bool     `json:"implemented"`
	Capabilities   []string `json:"capabilities,omitempty"`
}

// RoleEntry 是一个预设角色模板（系统角色或每应用生成的角色模板）。
type RoleEntry struct {
	Key                string   `json:"key"`
	Name               string   `json:"name"`
	Summary            string   `json:"summary"`
	Limits             string   `json:"limits"`
	Builtin            bool     `json:"builtin"`
	Core               bool     `json:"core,omitempty"`
	DefaultPermissions []string `json:"default_permissions,omitempty"`
	DefaultGroupKey    string   `json:"default_group_key,omitempty"`
	ApplicationScope   bool     `json:"application_scope"`
	Capabilities       []string `json:"capabilities,omitempty"`
}

// GroupEntry 是一个预设用户组模板（系统组或每应用生成的组模板）。
type GroupEntry struct {
	Key              string `json:"key"`
	Name             string `json:"name"`
	Description      string `json:"description"`
	ApplicationScope bool   `json:"application_scope"`
}

// ConfigFieldEntry 是一个配置字段的机器元数据；语义说明以
// docs/guide/configuration.md 为唯一权威，本文件只提供字段/环境变量/生效分类。
type ConfigFieldEntry struct {
	Field  string `json:"field"`
	Env    string `json:"env"`
	Class  string `json:"reload_class"`
	Secret bool   `json:"secret"`
}

// AdminRoute 是一条管理 JSON API 路由（pattern 相对于管理 API 前缀）。
type AdminRoute struct {
	Method       string   `json:"method"`
	Pattern      string   `json:"pattern"`
	Source       string   `json:"source"`
	Capabilities []string `json:"capabilities,omitempty"`
}

// ProtocolPath 是协议包导出的端点点位常量（常量名 + 路径）。
type ProtocolPath struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// ProtocolEndpoint 是协议包文档表中声明的 HTTP 端点（方法 + 路径）。
type ProtocolEndpoint struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

// PageRoute 是一个内置页面命名路由（UIRoute 冻结契约）。
type PageRoute struct {
	Name         string   `json:"name"`
	Method       string   `json:"method"`
	Path         string   `json:"path"`
	Access       string   `json:"access,omitempty"`
	Source       string   `json:"source"`
	Capabilities []string `json:"capabilities,omitempty"`
}

// ExitCode 是一个 CLI 进程退出码常量。
type ExitCode struct {
	Name  string `json:"name"`
	Value int    `json:"value"`
	Doc   string `json:"doc,omitempty"`
}

// CLIFlag 是一个 CLI flag 的公开名称与类型；default/usage 取源码字面量（可空）。
type CLIFlag struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Default string `json:"default,omitempty"`
	Usage   string `json:"usage,omitempty"`
}

// CLISubcommand 是一个 CLI 子命令（可含 flag 与源码位置）。
type CLISubcommand struct {
	Name   string    `json:"name"`
	Source string    `json:"source"`
	Flags  []CLIFlag `json:"flags,omitempty"`
}

// CLIBinary 是一个命令行程序及其命令树与稳定退出码。
type CLIBinary struct {
	Name        string          `json:"name"`
	Source      string          `json:"source"`
	Subcommands []CLISubcommand `json:"subcommands"`
	ExitCodes   []ExitCode      `json:"exit_codes,omitempty"`
}

// GoFunc 是公开 Go 函数/方法（签名 + 文档首句）。
type GoFunc struct {
	Name      string `json:"name"`
	Signature string `json:"signature"`
	Doc       string `json:"doc,omitempty"`
	Source    string `json:"source"`
}

// GoMethod 是公开类型上的方法或接口方法。
type GoMethod struct {
	Name      string `json:"name"`
	Signature string `json:"signature"`
	Doc       string `json:"doc,omitempty"`
}

// GoValue 是 app 包公开变量或常量（能力声明会引用哨兵错误等公开值）。
type GoValue struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Doc    string `json:"doc,omitempty"`
	Source string `json:"source"`
}

// GoInterface 是 app 包公开服务接口。
type GoInterface struct {
	Name    string     `json:"name"`
	Doc     string     `json:"doc,omitempty"`
	Source  string     `json:"source"`
	Methods []GoMethod `json:"methods"`
}

// GoType 是公开 Go 类型（非接口）的名称、类别、文档与源码位置。
type GoType struct {
	Name    string   `json:"name"`
	Kind    string   `json:"kind"`
	Doc     string   `json:"doc,omitempty"`
	Source  string   `json:"source"`
	Members []string `json:"members,omitempty"`
}

// RootFileSummary 汇总根包一个源文件导出的类型/函数数量与名称。
type RootFileSummary struct {
	File   string   `json:"file"`
	Types  []string `json:"types,omitempty"`
	Funcs  []string `json:"funcs,omitempty"`
	Consts []string `json:"consts,omitempty"`
	Vars   []string `json:"vars,omitempty"`
}

// GoAPI 是公开 Go API 盘点结果（Phase A 先给框架与稳定领域，Phase B 补全）。
type GoAPI struct {
	RuntimeMethods      []GoFunc          `json:"runtime_methods"`
	RuntimeTypes        []GoType          `json:"runtime_types"`
	AppFuncs            []GoFunc          `json:"app_funcs"`
	AppVars             []GoValue         `json:"app_vars"`
	ExportedMethodCount int               `json:"exported_method_count"`
	Interfaces          []GoInterface     `json:"interfaces"`
	AppTypes            []GoType          `json:"app_types"`
	RootFuncs           []GoFunc          `json:"root_funcs"`
	RootFiles           []RootFileSummary `json:"root_files"`
	RootTypeCount       int               `json:"root_type_count"`
	RootFuncCount       int               `json:"root_func_count"`
}

// CapabilityRef 是 catalog.json 中一条能力的参考索引（不复制状态；状态见能力矩阵）。
type CapabilityRef struct {
	ID                       string   `json:"id"`
	Title                    string   `json:"title"`
	Domain                   string   `json:"domain"`
	Notes                    string   `json:"notes,omitempty"`
	Expect                   string   `json:"expect,omitempty"`
	AppAPI                   []string `json:"app_api,omitempty"`
	RootAPI                  []string `json:"root_api,omitempty"`
	AdminRoutes              []string `json:"admin_routes,omitempty"`
	ProtocolPaths            []string `json:"protocol_paths,omitempty"`
	CLI                      []string `json:"cli,omitempty"`
	Pages                    []string `json:"pages,omitempty"`
	Permissions              []string `json:"permissions,omitempty"`
	UnimplementedPermissions []string `json:"unimplemented_permissions,omitempty"`
	PaginationMode           string   `json:"pagination_mode,omitempty"`
}

// PendingSection 是 Phase A 尚未展开为方法级参考的 Go API 领域（Phase B 补齐）。
type PendingSection struct {
	ID      string `json:"id"`
	Reason  string `json:"reason"`
	Symbols int    `json:"symbols"`
}

// CrossCheck 是只读交叉核对结果（不重新生成能力矩阵）。
type CrossCheck struct {
	MatrixCapabilities      int      `json:"matrix_capabilities"`
	MatrixAdminRoutes       int      `json:"matrix_admin_routes"`
	MatrixPages             int      `json:"matrix_pages"`
	MatrixProtocol          int      `json:"matrix_protocol_paths"`
	MatrixProtocolEndpoints int      `json:"matrix_protocol_endpoints"`
	MatrixCLI               int      `json:"matrix_cli"`
	MatrixPermissions       int      `json:"matrix_permissions"`
	MatrixRootTypes         int      `json:"matrix_root_types"`
	MatrixAppFuncs          int      `json:"matrix_app_funcs"`
	Mismatches              []string `json:"mismatches,omitempty"`
}

// Model 是一次完整盘点结果；Generate 只读源码与注册表，不修改任何文件。
type Model struct {
	Root              string
	Errors            []ErrorEntry
	Permissions       []PermissionEntry
	Roles             []RoleEntry
	ApplicationRoles  []RoleEntry
	Groups            []GroupEntry
	ApplicationGroups []GroupEntry
	CatalogVersion    string
	ConfigFields      []ConfigFieldEntry
	Capabilities      []CapabilityRef
	AdminRoutes       []AdminRoute
	ProtocolPaths     []ProtocolPath
	ProtocolEndpoints []ProtocolEndpoint
	Pages             []PageRoute
	CLIBinaries       []CLIBinary
	GoAPI             *GoAPI
	Snippets          []Snippet
	CrossCheck        CrossCheck
	Warnings          []string
	ClaimIssues       []string
	PendingSections   []PendingSection
}

// Markdown 生成的文件名（相对 docs/reference）。
const (
	fileIndex         = "README.md"
	fileErrors        = "errors.md"
	filePermissions   = "permissions.md"
	fileConfiguration = "configuration.md"
	fileHTTPAPI       = "http-api.md"
	fileCLI           = "cli.md"
	fileGoAPI         = "go-api.md"
	fileCapability    = "capability-map.md"
	fileAIIndex       = "ai-index.md"
	fileChangeLog     = "change-log.md"
	// JSON 文件名。
	fileErrorsJSON      = "error-codes.json"
	filePermissionsJSON = "permission-keys.json"
	fileHTTPRoutesJSON  = "http-routes.json"
	fileCLIJSON         = "cli-commands.json"
)

// markdownFiles 返回全部生成 Markdown 文件的相对路径（顺序稳定）。
func markdownFiles() []string {
	return []string{
		fileIndex, fileErrors, filePermissions, fileConfiguration,
		fileHTTPAPI, fileCLI, fileGoAPI, fileCapability, fileAIIndex, fileChangeLog,
	}
}

// jsonFiles 返回全部生成 JSON 文件的相对路径（顺序稳定）。
func jsonFiles() []string {
	return []string{
		fileErrorsJSON, filePermissionsJSON, fileHTTPRoutesJSON, fileCLIJSON,
	}
}
