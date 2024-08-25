package apidoc

import (
	"fmt"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// 本文件扫描 CLI 命令树：三种程序使用两种注册风格——
//   - login-server 使用 spf13/cobra：&cobra.Command{Use: ...} + flags.XxxVar 注册；
//   - loginctl / login-backup 使用标准库 flag.NewFlagSet("程序 子命令") + flags.XxxVar；
//   - loginctl 的管理命令组在 internal/managecli 中按 args[0] 分派。
//
// Phase A 提取顶层命令、可用 flag 与稳定退出码；嵌套子命令的动作级说明留给
// docs/guide/root-cli.md（Phase B 可继续细化，不阻塞机器 JSON）。

// cliFlagMethods 是 flag/FlagSet 与 cobra FlagSet 共有的 flag 注册方法（去掉 Var 后缀）。
var cliFlagMethods = map[string]string{
	"String": "string", "Bool": "bool", "Int": "int", "Int64": "int64",
	"Uint": "uint", "Uint64": "uint64", "Float64": "float64", "Duration": "duration",
}

// exitCodeNamePattern 匹配 CLI 退出码常量名。
var exitCodeNamePattern = regexp.MustCompile(`^Exit[A-Z][A-Za-z0-9]*$`)

// quotedLiteralPattern 从表达式文本中提取字符串字面量片段。
var quotedLiteralPattern = regexp.MustCompile(`"([^"]*)"`)

// cliDraft 是扫描过程中的命令草稿。
type cliDraft struct {
	Name   string
	Flags  []CLIFlag
	Source string
}

// scanCLI 扫描三个命令行程序的命令树、flag 与退出码。
func scanCLI(root string) ([]CLIBinary, error) {
	cmdRoot := filepath.Join(root, filepath.FromSlash(cmdRootDir))
	entries, err := os.ReadDir(cmdRoot)
	if err != nil {
		return nil, fmt.Errorf("读取 cmd 目录失败：%w", err)
	}
	var binaries []CLIBinary
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		program := entry.Name()
		dir := filepath.Join(cmdRoot, program)
		flagsets, err := scanFlagSets(root, dir)
		if err != nil {
			return nil, err
		}
		switches, err := scanSwitchCommands(root, dir, program)
		if err != nil {
			return nil, err
		}
		var cobraCommands []CLISubcommand
		if program == "login-server" {
			cobraCommands, err = scanCobraCommands(root, dir)
			if err != nil {
				return nil, err
			}
		}
		exitCodes, err := scanExitCodes(root, dir)
		if err != nil {
			return nil, err
		}
		commands := map[string]CLISubcommand{}
		add := func(name, source string, flags []CLIFlag) {
			name = strings.TrimSpace(name)
			if name == "" || strings.HasPrefix(name, "-") || name == program ||
				name == "help" || name == "version" {
				return
			}
			existing, ok := commands[name]
			if ok {
				if existing.Source == "" && source != "" {
					existing.Source = source
				}
				if len(existing.Flags) == 0 && len(flags) > 0 {
					existing.Flags = flags
				}
				commands[name] = existing
				return
			}
			commands[name] = CLISubcommand{Name: name, Source: source, Flags: flags}
		}
		for name, draft := range flagsets {
			add(name, draft.Source, draft.Flags)
		}
		for _, draft := range switches {
			add(draft.Name, draft.Source, nil)
		}
		for _, command := range cobraCommands {
			add(command.Name, command.Source, command.Flags)
		}
		if program == "loginctl" {
			if err := addManageCLICommands(root, &commands, add); err != nil {
				return nil, err
			}
		}
		sorted := make([]CLISubcommand, 0, len(commands))
		for _, command := range commands {
			sort.Slice(command.Flags, func(i, j int) bool { return command.Flags[i].Name < command.Flags[j].Name })
			sorted = append(sorted, command)
		}
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
		if len(sorted) == 0 {
			return nil, fmt.Errorf("程序 %s 未扫描到任何子命令", program)
		}
		binaries = append(binaries, CLIBinary{
			Name: program, Source: filepath.ToSlash(filepath.Join("cmd", program)),
			Subcommands: sorted, ExitCodes: exitCodes,
		})
	}
	sort.Slice(binaries, func(i, j int) bool {
		order := map[string]int{"login-server": 0, "loginctl": 1, "login-backup": 2}
		left, leftOK := order[binaries[i].Name]
		right, rightOK := order[binaries[j].Name]
		if leftOK && rightOK {
			return left < right
		}
		return binaries[i].Name < binaries[j].Name
	})
	return binaries, nil
}

// scanCobraCommands 扫描 login-server 的 cobra 命令树（Use 字面量 + Flags().XxxVar）。
func scanCobraCommands(root, dir string) ([]CLISubcommand, error) {
	files, err := listGoFiles(dir)
	if err != nil {
		return nil, err
	}
	var commands []CLISubcommand
	seen := map[string]bool{}
	for _, path := range files {
		file, fset, err := parseAt(path)
		if err != nil {
			return nil, err
		}
		rel := relPath(root, path)
		for _, decl := range file.Decls {
			funcDecl, ok := decl.(*ast.FuncDecl)
			if !ok || funcDecl.Body == nil {
				continue
			}
			use := ""
			var flagReceiver string
			ast.Inspect(funcDecl.Body, func(node ast.Node) bool {
				switch typed := node.(type) {
				case *ast.CompositeLit:
					if compositeTypeName(typed) != "Command" {
						return true
					}
					if use == "" {
						use = stringLit(compositeKeyValue(typed, "Use"))
					}
				case *ast.AssignStmt:
					if len(typed.Lhs) == 1 && len(typed.Rhs) == 1 {
						lhs, lhsOK := typed.Lhs[0].(*ast.Ident)
						call, callOK := typed.Rhs[0].(*ast.CallExpr)
						if lhsOK && callOK {
							if selector, ok := call.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "Flags" {
								flagReceiver = lhs.Name
							}
						}
					}
				}
				return true
			})
			if use == "" || flagReceiver == "" {
				continue
			}
			name := strings.Fields(use)[0]
			if seen[name] {
				continue
			}
			seen[name] = true
			flags := collectFlagCalls(file, fset, funcDecl.Body, flagReceiver)
			commands = append(commands, CLISubcommand{Name: name, Source: rel, Flags: flags})
		}
	}
	sort.Slice(commands, func(i, j int) bool { return commands[i].Name < commands[j].Name })
	return commands, nil
}

// collectFlagCalls 收集函数体内 flags.<Method>[Var](...) 注册的 flag。
func collectFlagCalls(file *ast.File, fset *token.FileSet, body *ast.BlockStmt, receiver string) []CLIFlag {
	flags := map[string]CLIFlag{}
	ast.Inspect(body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		receiverIdent, ok := selector.X.(*ast.Ident)
		if !ok || receiverIdent.Name != receiver {
			return true
		}
		flag, ok := flagFromCall(fset, call, selector.Sel.Name)
		if !ok {
			return true
		}
		flags[flag.Name] = flag
		return true
	})
	// flags.Lookup("name").NoOptDefVal = "value"：把“可省略值”语义附加到用法说明。
	ast.Inspect(body, func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		selector, ok := assign.Lhs[0].(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "NoOptDefVal" {
			return true
		}
		lookupCall, ok := selector.X.(*ast.CallExpr)
		if !ok {
			return true
		}
		lookupSelector, ok := lookupCall.Fun.(*ast.SelectorExpr)
		if !ok || lookupSelector.Sel.Name != "Lookup" || len(lookupCall.Args) != 1 {
			return true
		}
		name := stringLit(lookupCall.Args[0])
		value := stringLit(assign.Rhs[0])
		if name == "" || value == "" {
			return true
		}
		if flag, exists := flags[name]; exists {
			flag.Usage = strings.TrimSpace(flag.Usage + "（省略值等同于 " + value + "）")
			flags[name] = flag
		}
		return true
	})
	result := make([]CLIFlag, 0, len(flags))
	for _, flag := range flags {
		result = append(result, flag)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

// flagFromCall 从一次 flag 注册调用提取名称/类型/默认值/用法。
func flagFromCall(fset *token.FileSet, call *ast.CallExpr, method string) (CLIFlag, bool) {
	base := strings.TrimSuffix(method, "Var")
	flagType, ok := cliFlagMethods[base]
	if !ok {
		return CLIFlag{}, false
	}
	args := call.Args
	if strings.HasSuffix(method, "Var") {
		args = args[1:]
	}
	if len(args) < 1 {
		return CLIFlag{}, false
	}
	name := stringLit(args[0])
	if name == "" {
		return CLIFlag{}, false
	}
	flag := CLIFlag{Name: name, Type: flagType}
	if len(args) >= 2 {
		flag.Default = flagDefaultText(fset, args[1])
	}
	if len(args) >= 3 {
		flag.Usage = singleLine(stringLit(args[2]))
	}
	return flag, true
}

// flagDefaultText 把默认值表达式转成可读文本（字符串字面量去引号，其余保留源码形式）。
func flagDefaultText(fset *token.FileSet, expr ast.Expr) string {
	if literal, ok := expr.(*ast.BasicLit); ok && literal.Kind == token.STRING {
		if unquoted, err := strconv.Unquote(literal.Value); err == nil {
			return unquoted
		}
	}
	return exprString(fset, expr)
}

// scanFlagSets 扫描标准库 flag.NewFlagSet("程序 子命令") 风格命令及 flag。
func scanFlagSets(root, dir string) (map[string]cliDraft, error) {
	files, err := listGoFiles(dir)
	if err != nil {
		return nil, err
	}
	constants := map[string]string{}
	for _, path := range files {
		file, _, err := parseAt(path)
		if err != nil {
			return nil, err
		}
		collectStringConsts(file, constants)
	}
	result := map[string]cliDraft{}
	for _, path := range files {
		file, fset, err := parseAt(path)
		if err != nil {
			return nil, err
		}
		rel := relPath(root, path)
		for _, decl := range file.Decls {
			funcDecl, ok := decl.(*ast.FuncDecl)
			if !ok || funcDecl.Body == nil {
				continue
			}
			receiver, command := "", ""
			ast.Inspect(funcDecl.Body, func(node ast.Node) bool {
				assign, ok := node.(*ast.AssignStmt)
				if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
					return true
				}
				lhs, lhsOK := assign.Lhs[0].(*ast.Ident)
				call, callOK := assign.Rhs[0].(*ast.CallExpr)
				if !lhsOK || !callOK {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || selector.Sel.Name != "NewFlagSet" || len(call.Args) == 0 {
					return true
				}
				if packageIdent, ok := selector.X.(*ast.Ident); !ok || packageIdent.Name != "flag" {
					return true
				}
				receiver = lhs.Name
				command = parseFlagSetCommand(fset, call.Args[0], constants)
				return true
			})
			if receiver == "" || command == "" {
				continue
			}
			flags := collectFlagCalls(file, fset, funcDecl.Body, receiver)
			if existing, ok := result[command]; ok {
				if len(existing.Flags) == 0 {
					existing.Flags = flags
					existing.Source = rel
					result[command] = existing
				}
				continue
			}
			result[command] = cliDraft{Name: command, Source: rel, Flags: flags}
		}
	}
	return result, nil
}

// parseFlagSetCommand 从 flag.NewFlagSet 的名称表达式解析子命令名。
// 支持 "loginctl root-recover" 字面量与 programName + " create" 形式。
func parseFlagSetCommand(fset *token.FileSet, expr ast.Expr, constants map[string]string) string {
	if literal := stringLit(expr); literal != "" {
		fields := strings.Fields(literal)
		if len(fields) >= 2 {
			return fields[len(fields)-1]
		}
		return literal
	}
	text := exprString(fset, expr)
	parts := quotedLiteralPattern.FindAllStringSubmatch(text, -1)
	if len(parts) == 0 {
		return ""
	}
	last := strings.TrimSpace(parts[len(parts)-1][1])
	if fields := strings.Fields(last); len(fields) > 1 {
		return fields[len(fields)-1]
	}
	return last
}

// collectStringConsts 收集包内字符串常量（用于解析 programName 之类的名称拼接）。
func collectStringConsts(file *ast.File, constants map[string]string) {
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
				if value := stringLit(valueSpec.Values[index]); value != "" {
					constants[name.Name] = value
				}
			}
		}
	}
}

// scanSwitchCommands 扫描 switch args[0] 分派的顶层命令。
func scanSwitchCommands(root, dir, program string) ([]cliDraft, error) {
	files, err := listGoFiles(dir)
	if err != nil {
		return nil, err
	}
	var drafts []cliDraft
	seen := map[string]bool{}
	for _, path := range files {
		file, fset, err := parseAt(path)
		if err != nil {
			return nil, err
		}
		rel := relPath(root, path)
		ast.Inspect(file, func(node ast.Node) bool {
			switchStmt, ok := node.(*ast.SwitchStmt)
			if !ok || exprString(fset, switchStmt.Tag) != "args[0]" {
				return true
			}
			for _, stmt := range switchStmt.Body.List {
				clause, ok := stmt.(*ast.CaseClause)
				if !ok {
					continue
				}
				for _, expr := range clause.List {
					name := stringLit(expr)
					if name == "" || seen[name] || name == program ||
						name == "help" || name == "version" {
						continue
					}
					seen[name] = true
					drafts = append(drafts, cliDraft{Name: name, Source: rel})
				}
			}
			return true
		})
	}
	sort.Slice(drafts, func(i, j int) bool { return drafts[i].Name < drafts[j].Name })
	return drafts, nil
}

// addManageCLICommands 把 internal/managecli 中按 args[0] 分派的命令组补到 loginctl。
func addManageCLICommands(root string, commands *map[string]CLISubcommand, add func(name, source string, flags []CLIFlag)) error {
	dir := filepath.Join(root, filepath.FromSlash(manageCLIDir))
	files, err := listGoFiles(dir)
	if err != nil {
		return err
	}
	for _, path := range files {
		file, fset, err := parseAt(path)
		if err != nil {
			return err
		}
		rel := relPath(root, path)
		ast.Inspect(file, func(node ast.Node) bool {
			switchStmt, ok := node.(*ast.SwitchStmt)
			if !ok || exprString(fset, switchStmt.Tag) != "args[0]" {
				return true
			}
			for _, stmt := range switchStmt.Body.List {
				clause, ok := stmt.(*ast.CaseClause)
				if !ok {
					continue
				}
				for _, expr := range clause.List {
					if name := stringLit(expr); name != "" {
						add(name, rel, nil)
					}
				}
			}
			return true
		})
	}
	return nil
}

// scanExitCodes 扫描 cmd/<program> 的稳定退出码常量（ExitXxx = N）。
func scanExitCodes(root, dir string) ([]ExitCode, error) {
	files, err := listGoFiles(dir)
	if err != nil {
		return nil, err
	}
	seen := map[string]ExitCode{}
	for _, path := range files {
		file, _, err := parseAt(path)
		if err != nil {
			return nil, err
		}
		for _, decl := range file.Decls {
			genDecl, ok := decl.(*ast.GenDecl)
			if !ok || genDecl.Tok != token.CONST {
				continue
			}
			docs := docText(genDecl.Doc)
			for _, spec := range genDecl.Specs {
				valueSpec, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for index, name := range valueSpec.Names {
					if !exitCodeNamePattern.MatchString(name.Name) || index >= len(valueSpec.Values) {
						continue
					}
					literal, ok := valueSpec.Values[index].(*ast.BasicLit)
					if !ok || literal.Kind != token.INT {
						continue
					}
					value, convErr := strconv.Atoi(literal.Value)
					if convErr != nil {
						continue
					}
					doc := docs
					if valueSpec.Doc != nil {
						doc = docText(valueSpec.Doc)
					} else if valueSpec.Comment != nil {
						doc = docText(valueSpec.Comment)
					}
					if _, exists := seen[name.Name]; !exists {
						seen[name.Name] = ExitCode{Name: name.Name, Value: value, Doc: firstSentence(doc)}
					}
				}
			}
		}
	}
	codes := make([]ExitCode, 0, len(seen))
	for _, code := range seen {
		codes = append(codes, code)
	}
	sort.Slice(codes, func(i, j int) bool {
		if codes[i].Value != codes[j].Value {
			return codes[i].Value < codes[j].Value
		}
		return codes[i].Name < codes[j].Name
	})
	return codes, nil
}

// relPath 返回相对仓库根的斜杠路径。
func relPath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}
