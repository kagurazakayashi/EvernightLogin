// 本文件实现步骤 220 的分页契约自动审计：
//   - 从 app 公开结构识别“可增长列表”的请求边界字段与结果继续字段；
//   - 校验能力声明中的分页证据是否“请求边界 + 结果继续”成对，fixed/none 例外
//     必须有明确理由；
//   - 扫描 app/session/authz/CLI/page 的分页默认值、上限与页面参数是否一致。
//
// 审计只使用源码静态事实（AST/字面量），不执行程序、不访问网络；结果写入
// capability-matrix 的 pagination_audit 字段，并参与 -strict 门禁。
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	paginationModeOffset = "offset"
	paginationModeCursor = "cursor"
	paginationModeFixed  = "fixed"
	paginationModeNone   = "none"

	// continuationGap 表示该列表当前只有单页上限、没有 HasMore/游标/总数继续
	// 语义；必须在 catalog 中写明 reason，并在能力报告的已知限制中暴露。
	continuationGap     = "gap"
	continuationHasMore = "has_more"
	continuationCursor  = "cursor"
	continuationTotal   = "total"
)

// paginationContract 是各入口分页参数的实际解析值（0 表示未解析到）。
type paginationContract struct {
	AppDefaultLimit     int      `json:"app_default_limit"`
	AppMaxLimit         int      `json:"app_max_limit"`
	AppMaxOffset        int      `json:"app_max_offset"`
	SessionDefaultLimit int      `json:"session_default_limit"`
	SessionMaxLimit     int      `json:"session_max_limit"`
	AuthzDefaultLimit   int      `json:"authz_default_limit"`
	AuthzMaxLimit       int      `json:"authz_max_limit"`
	CLIDefaultLimit     int      `json:"cli_default_limit"`
	CLIMaxLimit         int      `json:"cli_max_limit"`
	CLIOffsetCap        int      `json:"cli_offset_cap"`
	PageOffsetCap       int      `json:"page_offset_cap"`
	PageFixedLimit      int      `json:"page_fixed_limit"`
	Mismatches          []string `json:"mismatches,omitempty"`
}

// growableList 是一个盘点到的可增长列表请求/结果类型及其分页边界。
type growableList struct {
	Name               string   `json:"name"`
	Kind               string   `json:"kind"`
	Bounded            bool     `json:"bounded"`
	PageField          string   `json:"page_field,omitempty"`
	ContinuationFields []string `json:"continuation_fields,omitempty"`
	Capability         string   `json:"capability,omitempty"`
	ClaimMode          string   `json:"claim_mode,omitempty"`
}

// paginationAudit 是能力清单中的分页审计结果。
type paginationAudit struct {
	GrowableLists      []growableList     `json:"growable_lists"`
	BoundedLists       int                `json:"bounded_lists"`
	Exceptions         []string           `json:"exceptions,omitempty"`
	UncoveredLists     []string           `json:"uncovered_lists,omitempty"`
	Contract           paginationContract `json:"contract"`
	ContractMismatches []string           `json:"contract_mismatches,omitempty"`
}

// buildPaginationAudit 组装分页审计：候选列表分类、能力声明核对、跨层参数一致性。
func buildPaginationAudit(root string, catalog *catalogFile, inv *inventory) paginationAudit {
	audit := paginationAudit{Contract: scanPaginationContract(root)}
	audit.ContractMismatches = contractMismatches(audit.Contract)
	lists := classifyGrowableLists(catalog, inv)
	audit.GrowableLists = lists
	for _, list := range lists {
		if list.Bounded {
			audit.BoundedLists++
		}
		switch {
		case list.Capability == "":
			audit.UncoveredLists = append(audit.UncoveredLists,
				list.Name+"（未登记到任何能力声明）")
		case list.ClaimMode == paginationModeFixed || list.ClaimMode == paginationModeNone:
			audit.Exceptions = append(audit.Exceptions,
				list.Name+" -> "+list.Capability+"（"+list.ClaimMode+"：由能力声明理由承担）")
		case !list.Bounded:
			audit.UncoveredLists = append(audit.UncoveredLists,
				list.Name+"（能力 "+list.Capability+" 声明 "+list.ClaimMode+" 但缺少分页边界字段）")
		}
	}
	return audit
}

// classifyGrowableLists 从 app 公开结构识别列表请求/结果类型，并关联能力声明的
// 分页模式；用于发现“声明了能力但没有分页边界/例外”的遗漏。
func classifyGrowableLists(catalog *catalogFile, inv *inventory) []growableList {
	capabilityByType := map[string]string{}
	claimByCapability := map[string]*paginationClaim{}
	for _, capability := range catalog.Capabilities {
		claimByCapability[capability.ID] = capability.Pagination
		for _, ref := range capability.AppAPI {
			parts := strings.SplitN(ref, ".", 2)
			if len(parts) == 0 || parts[0] == "" {
				continue
			}
			if _, exists := capabilityByType[parts[0]]; !exists {
				capabilityByType[parts[0]] = capability.ID
			}
		}
	}
	names := make([]string, 0, len(inv.AppTypes))
	for name := range inv.AppTypes {
		names = append(names, name)
	}
	sort.Strings(names)
	lists := make([]growableList, 0, 16)
	for _, name := range names {
		if name == "AdminPage" || name == "AdminPageInfo" {
			continue
		}
		symbol := inv.AppTypes[name]
		if symbol == nil || symbol.Kind != "struct" {
			continue
		}
		kind, bounded, pageField, continuation := classifyAppListSymbol(name, symbol)
		if kind == "" {
			continue
		}
		list := growableList{Name: name, Kind: kind, Bounded: bounded,
			PageField: pageField, ContinuationFields: continuation}
		if capabilityID, ok := capabilityByType[name]; ok {
			list.Capability = capabilityID
			if claim := claimByCapability[capabilityID]; claim != nil {
				list.ClaimMode = claim.Mode
			}
		}
		lists = append(lists, list)
	}
	return lists
}

// classifyAppListSymbol 判断公开结构是否为列表请求/结果，并计算其分页边界；
// 返回空 kind 表示不是可增长列表类型。
func classifyAppListSymbol(name string, symbol *appSymbol) (kind string, bounded bool,
	pageField string, continuation []string) {
	hasSlice := false
	hasPageRequest := false
	hasLimit, hasOffset := false, false
	for field, fieldType := range symbol.FieldTypes {
		if strings.HasPrefix(fieldType, "[]") {
			hasSlice = true
		}
		if field == "Page" && strings.HasSuffix(fieldType, "AdminPage") {
			hasPageRequest = true
			pageField = "Page"
		}
		if field == "Limit" {
			hasLimit = true
		}
		if field == "Offset" {
			hasOffset = true
		}
		if isContinuationField(field, fieldType) {
			continuation = append(continuation, field)
		}
	}
	sort.Strings(continuation)
	isRequest := hasPageRequest || (hasLimit && hasOffset) ||
		strings.HasSuffix(name, "ListRequest")
	isResult := hasSlice && (strings.HasSuffix(name, "List") || len(continuation) > 0)
	if !isRequest && !isResult {
		// 名称以 List/Page 结尾但盘点不到切片时不强行当列表（可能是枚举视图）。
		return "", false, "", nil
	}
	if isResult && !isRequest {
		return "result", len(continuation) > 0, pageField, continuation
	}
	if isRequest && !isResult {
		return "request", hasPageRequest || (hasLimit && hasOffset), pageField, nil
	}
	// 同时满足请求与结果特征时按名称判定。
	if strings.HasSuffix(name, "ListRequest") {
		return "request", hasPageRequest || (hasLimit && hasOffset), pageField, nil
	}
	return "result", len(continuation) > 0, pageField, continuation
}

// isContinuationField 判断字段是否为结果继续语义（HasMore/Next*/PageInfo/Total/
// Returned/Cursor）。字段名是公开契约的一部分，不猜测内部实现。
func isContinuationField(field, fieldType string) bool {
	lower := strings.ToLower(field)
	if strings.Contains(lower, "hasmore") || strings.HasPrefix(lower, "next") ||
		lower == "total" || lower == "returned" || lower == "cursor" ||
		strings.Contains(lower, "nextcursor") || lower == "truncated" {
		return true
	}
	return strings.HasSuffix(fieldType, "AdminPageInfo") || strings.HasSuffix(fieldType, "PageInfo")
}

// isRequestBoundField 判断字段是否为请求分页边界（Page/Limit/Offset/Cursor）。
func isRequestBoundField(field, fieldType string) bool {
	lower := strings.ToLower(field)
	if lower == "page" && (fieldType == "AdminPage" || strings.HasSuffix(fieldType, "AdminPage")) {
		return true
	}
	return lower == "limit" || lower == "offset" || lower == "cursor"
}

// paginationEvidenceProblem 校验一条分页声明的证据是否成对：offset/cursor 必须有
// 请求边界证据和结果继续证据；允许 continuation=gap + reason 作为明确例外；fixed/
// none 必须有 reason。返回空字符串表示通过。
func paginationEvidenceProblem(inv *inventory, claim *paginationClaim) string {
	if claim == nil {
		return ""
	}
	if claim.Mode == paginationModeFixed || claim.Mode == paginationModeNone {
		if strings.TrimSpace(claim.Reason) == "" {
			return "固定/不分页能力必须写明理由"
		}
		return ""
	}
	if claim.Mode != paginationModeOffset && claim.Mode != paginationModeCursor {
		return "未知分页模式: " + claim.Mode
	}
	if len(claim.Evidence) == 0 {
		return "分页模式 " + claim.Mode + " 缺少字段证据"
	}
	hasRequest, hasContinuation := false, false
	for _, ref := range claim.Evidence {
		if strings.Contains(ref, ":") {
			// 内部 token 的存在性由 validateCapability 的 checkTokenEvidence 校验；
			// 这里只按 token 文本分类请求边界/结果继续语义。
			token := ref[strings.Index(ref, ":")+1:]
			if isRequestBoundText(token) {
				hasRequest = true
			}
			if isContinuationText(token) {
				hasContinuation = true
			}
			continue
		}
		parts := strings.SplitN(ref, ".", 2)
		if len(parts) != 2 {
			return "分页证据语法无效: " + ref
		}
		symbol, ok := inv.AppTypes[parts[0]]
		if !ok {
			return "分页证据不存在: " + ref
		}
		fieldType, ok := symbol.FieldTypes[parts[1]]
		if !ok {
			return "分页证据不存在: " + ref
		}
		if isRequestBoundField(parts[1], fieldType) {
			hasRequest = true
		}
		if isContinuationField(parts[1], fieldType) {
			hasContinuation = true
		}
	}
	if !hasRequest {
		return "缺少请求分页边界证据（Limit/Offset/Page/Cursor）"
	}
	switch claim.Continuation {
	case "":
		if !hasContinuation {
			return "缺少结果继续证据（HasMore/NextOffset/NextCursor/Total）"
		}
	case continuationGap:
		if strings.TrimSpace(claim.Reason) == "" {
			return "continuation=gap 必须写明理由（当前列表只有单页上限的明确例外）"
		}
	case continuationHasMore:
		if !hasContinuation {
			return "声明 continuation=has_more 但缺少 HasMore/Next 证据"
		}
	case continuationCursor:
		if !hasContinuation {
			return "声明 continuation=cursor 但缺少 Cursor/Next 证据"
		}
	case continuationTotal:
		if !hasContinuation {
			return "声明 continuation=total 但缺少 Total/Returned 证据"
		}
	default:
		return "未知 continuation: " + claim.Continuation
	}
	return ""
}

// isRequestBoundText 对内部 token（如 Limit/HasMore）做请求边界分类。
func isRequestBoundText(token string) bool {
	lower := strings.ToLower(token)
	return strings.Contains(lower, "limit") || strings.Contains(lower, "offset") ||
		strings.Contains(lower, "page") || strings.Contains(lower, "cursor")
}

// isContinuationText 对内部 token 做结果继续分类。
func isContinuationText(token string) bool {
	lower := strings.ToLower(token)
	return strings.Contains(lower, "hasmore") || strings.Contains(lower, "has_more") ||
		strings.Contains(lower, "next") || strings.Contains(lower, "total") ||
		strings.Contains(lower, "returned") || strings.Contains(lower, "cursor") ||
		strings.Contains(lower, "page")
}

// scanPaginationContract 从源码解析各入口的分页默认值/上限/页面参数。
func scanPaginationContract(root string) paginationContract {
	contract := paginationContract{}
	appConsts := intConstsInFile(root, "app/pagination.go")
	contract.AppDefaultLimit = appConsts["AdminDefaultPageLimit"]
	contract.AppMaxLimit = appConsts["AdminMaxPageLimit"]
	contract.AppMaxOffset = appConsts["AdminMaxPageOffset"]

	sessionConsts := intConstsInFile(root, "internal/session/session.go")
	contract.SessionDefaultLimit = sessionConsts["DefaultListPageSize"]
	contract.SessionMaxLimit = sessionConsts["MaxListPageSize"]

	authzConsts := intConstsInFile(root, "internal/authz/authz.go")
	contract.AuthzDefaultLimit = authzConsts["DefaultListLimit"]
	contract.AuthzMaxLimit = authzConsts["MaxListLimit"]

	cliConsts := intConstsInFile(root, "internal/managecli/domain_cmd.go")
	contract.CLIDefaultLimit = cliConsts["domainListDefaultLimit"]
	contract.CLIMaxLimit = cliConsts["domainListMaxLimit"]
	cliLiterals := intLiteralsInFile(root, "internal/managecli/domain_cmd.go")
	if cliLiterals[1000000] {
		contract.CLIOffsetCap = 1000000
	}

	pageLiterals := intLiteralsInFile(root, "ui_pages_admin.go")
	if pageLiterals[1000000] {
		contract.PageOffsetCap = 1000000
	}
	if pageLiterals[20] {
		contract.PageFixedLimit = 20
	}
	return contract
}

// contractMismatches 比较各层契约；app 包是公开 Go 契约的权威值，其余入口必须与
// 之一致（页面固定页大小不得为 0/超过最大值）。
func contractMismatches(contract paginationContract) []string {
	var mismatches []string
	add := func(format string, args ...any) {
		mismatches = append(mismatches, fmt.Sprintf(format, args...))
	}
	if contract.AppDefaultLimit <= 0 || contract.AppMaxLimit <= 0 || contract.AppMaxOffset <= 0 {
		add("无法解析 app 分页契约常量（默认/最大/offset 上限）")
		return mismatches
	}
	if contract.AppDefaultLimit > contract.AppMaxLimit {
		add("app 默认页大小 %d 超过最大页大小 %d",
			contract.AppDefaultLimit, contract.AppMaxLimit)
	}
	if contract.SessionDefaultLimit != contract.AppDefaultLimit {
		add("session 默认页大小 %d 与 app 契约 %d 不一致",
			contract.SessionDefaultLimit, contract.AppDefaultLimit)
	}
	if contract.SessionMaxLimit != contract.AppMaxLimit {
		add("session 最大页大小 %d 与 app 契约 %d 不一致",
			contract.SessionMaxLimit, contract.AppMaxLimit)
	}
	if contract.AuthzDefaultLimit != contract.AppDefaultLimit {
		add("authz 默认列表上限 %d 与 app 契约 %d 不一致",
			contract.AuthzDefaultLimit, contract.AppDefaultLimit)
	}
	if contract.AuthzMaxLimit != contract.AppMaxLimit {
		add("authz 最大列表上限 %d 与 app 契约 %d 不一致",
			contract.AuthzMaxLimit, contract.AppMaxLimit)
	}
	if contract.CLIDefaultLimit != contract.AppDefaultLimit {
		add("CLI 默认页大小 %d 与 app 契约 %d 不一致",
			contract.CLIDefaultLimit, contract.AppDefaultLimit)
	}
	if contract.CLIMaxLimit != contract.AppMaxLimit {
		add("CLI 最大页大小 %d 与 app 契约 %d 不一致",
			contract.CLIMaxLimit, contract.AppMaxLimit)
	}
	if contract.CLIOffsetCap != contract.AppMaxOffset {
		add("CLI offset 上限 %d 与 app 契约 %d 不一致",
			contract.CLIOffsetCap, contract.AppMaxOffset)
	}
	if contract.PageOffsetCap != contract.AppMaxOffset {
		add("页面 offset 上限 %d 与 app 契约 %d 不一致",
			contract.PageOffsetCap, contract.AppMaxOffset)
	}
	if contract.PageFixedLimit != contract.AppDefaultLimit {
		add("页面固定页大小 %d 与 app 默认 %d 不一致（页面若固定分页应显式登记例外）",
			contract.PageFixedLimit, contract.AppDefaultLimit)
	}
	if contract.PageFixedLimit > contract.AppMaxLimit {
		add("页面固定页大小 %d 超过 app 最大页大小 %d",
			contract.PageFixedLimit, contract.AppMaxLimit)
	}
	return mismatches
}

// intConstsInFile 解析 Go 文件中的整数 const 声明（支持引用同文件已声明常量）。
func intConstsInFile(root, rel string) map[string]int {
	values := map[string]int{}
	file := parseRootFile(root, rel)
	if file == nil {
		return values
	}
	for _, decl := range file.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.CONST {
			continue
		}
		for _, spec := range genDecl.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for index, name := range valueSpec.Names {
				if index >= len(valueSpec.Values) {
					continue
				}
				if value, ok := intExprValue(values, valueSpec.Values[index]); ok {
					values[name.Name] = value
				}
			}
		}
	}
	return values
}

// intExprValue 求值整数常量表达式：基本字面量与同文件常量标识符（含简单加法/
// 减法），足以覆盖当前契约常量；不猜测未知表达式。
func intExprValue(consts map[string]int, expr ast.Expr) (int, bool) {
	switch typed := expr.(type) {
	case *ast.BasicLit:
		return parseIntLiteral(typed.Value)
	case *ast.Ident:
		value, ok := consts[typed.Name]
		return value, ok
	case *ast.BinaryExpr:
		left, leftOK := intExprValue(consts, typed.X)
		right, rightOK := intExprValue(consts, typed.Y)
		if !leftOK || !rightOK {
			return 0, false
		}
		switch typed.Op {
		case token.ADD:
			return left + right, true
		case token.SUB:
			return left - right, true
		case token.MUL:
			return left * right, true
		}
	}
	return 0, false
}

// parseIntLiteral 解析 Go 整数字面量（允许下划线分隔）。
func parseIntLiteral(literal string) (int, bool) {
	cleaned := strings.ReplaceAll(literal, "_", "")
	value, err := strconv.ParseInt(cleaned, 0, 64)
	if err != nil || value < 0 || value > 1<<31-1 {
		return 0, false
	}
	return int(value), true
}

// intLiteralsInFile 收集 Go 文件中的整数字面量集合（用于页面/CLI 中直接写的
// 上限与固定页大小；只盘点字面量，不推断业务含义）。
func intLiteralsInFile(root, rel string) map[int]bool {
	literals := map[int]bool{}
	file := parseRootFile(root, rel)
	if file == nil {
		return literals
	}
	ast.Inspect(file, func(node ast.Node) bool {
		basic, ok := node.(*ast.BasicLit)
		if !ok || basic.Kind != token.INT {
			return true
		}
		if value, ok := parseIntLiteral(basic.Value); ok {
			literals[value] = true
		}
		return true
	})
	return literals
}

// parseRootFile 只读解析仓库内一个 Go 文件；失败返回 nil（审计记录为无法解析，
// 不 panic、不中断能力清单生成）。
func parseRootFile(root, rel string) *ast.File {
	path := filepath.Join(root, filepath.FromSlash(rel))
	file, err := parser.ParseFile(token.NewFileSet(), path, nil,
		parser.SkipObjectResolution|parser.ParseComments)
	if err != nil {
		return nil
	}
	return file
}
