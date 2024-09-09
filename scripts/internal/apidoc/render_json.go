package apidoc

import "encoding/json"

// 本文件生成 4 个机器可读 JSON。结构体字段顺序即 JSON 字段顺序，切片已排序，
// 不含时间戳/绝对路径/本机信息，因此 -write 幂等、-check 可逐字节比较。

// errorCodesJSON 是 error-codes.json 的顶层结构。
type errorCodesJSON struct {
	Schema      string       `json:"schema"`
	GeneratedBy string       `json:"generated_by"`
	Count       int          `json:"count"`
	Codes       []ErrorEntry `json:"codes"`
}

// permissionCounts 是权限目录各类条目数量。
type permissionCounts struct {
	Permissions       int `json:"permissions"`
	SystemRoles       int `json:"system_roles"`
	SystemGroups      int `json:"system_groups"`
	ApplicationRoles  int `json:"application_roles"`
	ApplicationGroups int `json:"application_groups"`
}

// permissionKeysJSON 是 permission-keys.json 的顶层结构。
type permissionKeysJSON struct {
	Schema            string            `json:"schema"`
	GeneratedBy       string            `json:"generated_by"`
	CatalogVersion    string            `json:"catalog_version"`
	Counts            permissionCounts  `json:"counts"`
	Permissions       []PermissionEntry `json:"permissions"`
	Roles             []RoleEntry       `json:"roles"`
	Groups            []GroupEntry      `json:"groups"`
	ApplicationRoles  []RoleEntry       `json:"application_roles"`
	ApplicationGroups []GroupEntry      `json:"application_groups"`
}

// routeCounts 是 HTTP 路由数量汇总。
type routeCounts struct {
	AdminRoutes       int `json:"admin_routes"`
	ProtocolPaths     int `json:"protocol_paths"`
	ProtocolEndpoints int `json:"protocol_endpoints"`
	Pages             int `json:"pages"`
}

// httpRoutesJSON 是 http-routes.json 的顶层结构。
type httpRoutesJSON struct {
	Schema            string             `json:"schema"`
	GeneratedBy       string             `json:"generated_by"`
	Counts            routeCounts        `json:"counts"`
	AdminRoutes       []AdminRoute       `json:"admin_routes"`
	ProtocolPaths     []ProtocolPath     `json:"protocol_paths"`
	ProtocolEndpoints []ProtocolEndpoint `json:"protocol_endpoints"`
	Pages             []PageRoute        `json:"pages"`
}

// httpOpenAPIJSON 是 http-openapi.json 的顶层结构：内嵌确定性 OpenAPI 3 文档，
// 另给文档生成数量与契约核对结果，便于机器消费。
type httpOpenAPIJSON struct {
	Schema         string          `json:"schema"`
	GeneratedBy    string          `json:"generated_by"`
	OperationCount int             `json:"operation_count"`
	Documented     int             `json:"documented"`
	Unregistered   int             `json:"unregistered"`
	OpenAPI        json.RawMessage `json:"openapi"`
}

// cliCounts 是 CLI 数量汇总。
type cliCounts struct {
	Binaries    int `json:"binaries"`
	Subcommands int `json:"subcommands"`
	Flags       int `json:"flags"`
}

// cliCommandsJSON 是 cli-commands.json 的顶层结构。
type cliCommandsJSON struct {
	Schema      string      `json:"schema"`
	GeneratedBy string      `json:"generated_by"`
	Counts      cliCounts   `json:"counts"`
	Binaries    []CLIBinary `json:"binaries"`
}

// jsonFiles 渲染全部机器 JSON（文件名到内容）。
func (m *Model) jsonFiles() map[string][]byte {
	files := map[string][]byte{}

	errorCodes := errorCodesJSON{
		Schema: schemaVersion + "/error-codes", GeneratedBy: "scripts/reference",
		Count: len(m.Errors), Codes: m.Errors,
	}
	files[fileErrorsJSON] = marshalJSON(errorCodes)

	permissions := permissionKeysJSON{
		Schema: schemaVersion + "/permission-keys", GeneratedBy: "scripts/reference",
		CatalogVersion: m.CatalogVersion,
		Counts: permissionCounts{
			Permissions: len(m.Permissions), SystemRoles: len(m.Roles),
			SystemGroups: len(m.Groups), ApplicationRoles: len(m.ApplicationRoles),
			ApplicationGroups: len(m.ApplicationGroups),
		},
		Permissions: m.Permissions, Roles: m.Roles, Groups: m.Groups,
		ApplicationRoles: m.ApplicationRoles, ApplicationGroups: m.ApplicationGroups,
	}
	files[filePermissionsJSON] = marshalJSON(permissions)

	routes := httpRoutesJSON{
		Schema: schemaVersion + "/http-routes", GeneratedBy: "scripts/reference",
		Counts: routeCounts{
			AdminRoutes: len(m.AdminRoutes), ProtocolPaths: len(m.ProtocolPaths),
			ProtocolEndpoints: len(m.ProtocolEndpoints), Pages: len(m.Pages),
		},
		AdminRoutes: m.AdminRoutes, ProtocolPaths: m.ProtocolPaths,
		ProtocolEndpoints: m.ProtocolEndpoints, Pages: m.Pages,
	}
	files[fileHTTPRoutesJSON] = marshalJSON(routes)

	pageOpenAPI := httpOpenAPIJSON{
		Schema: schemaVersion + "/http-openapi", GeneratedBy: "scripts/reference",
	}
	if m.PageOpenAPI != nil {
		pageOpenAPI.OperationCount = len(m.PageOpenAPI.Operations)
		pageOpenAPI.Documented = m.PageOpenAPI.Documented
		pageOpenAPI.Unregistered = m.PageOpenAPI.Unregistered
		pageOpenAPI.OpenAPI = json.RawMessage(m.PageOpenAPI.JSON)
	}
	if pageOpenAPI.OpenAPI == nil {
		pageOpenAPI.OpenAPI = json.RawMessage(`{"openapi":"3.0.3","paths":{}}`)
	}
	files[fileHTTPOpenAPIJSON] = marshalJSON(pageOpenAPI)

	cli := cliCommandsJSON{
		Schema: schemaVersion + "/cli-commands", GeneratedBy: "scripts/reference",
		Counts: cliCounts{
			Binaries: len(m.CLIBinaries), Subcommands: countCLISubcommands(m.CLIBinaries),
			Flags: countCLIFlags(m.CLIBinaries),
		},
		Binaries: m.CLIBinaries,
	}
	files[fileCLIJSON] = marshalJSON(cli)
	return files
}

// marshalJSON 输出两空格缩进、LF、末尾换行的确定性 JSON。
func marshalJSON(value any) []byte {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		// 生成物全部由本包可控结构组成，序列化失败属于内部错误，用 panic 明确暴露。
		panic("apidoc: JSON 序列化失败: " + err.Error())
	}
	return append(data, '\n')
}
