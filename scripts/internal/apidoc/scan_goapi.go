package apidoc

import (
	"fmt"
	"go/ast"
	"go/token"
	"path/filepath"
	"sort"
)

// 本文件扫描公开 Go API：
//   - app 包（递归，步骤 215 可能把类型拆到子目录）：Runtime 的公开方法、公开函数、
//     服务接口（方法 + 签名 + 文档首句）与公开类型（成员名用于能力声明解析）；
//   - 根包（仅根目录 .go）：公开函数详情，以及按源文件分组的类型/函数/常量/变量清单。
//
// Phase A 输出“框架 + 稳定领域”的参考；每个内部服务领域的方法级说明（调用身份、
// 资源范围、分页、幂等、错误、最小例）留给 Phase B，避免在 214/215 重构前固化。

// scanGoAPI 盘点公开 Go API。
func scanGoAPI(root string) (*GoAPI, error) {
	api := &GoAPI{}
	appDir := filepath.Join(root, filepath.FromSlash(goAPIDirs[0]))
	var appFiles []string
	err := walkGoFiles(appDir, func(path string) error {
		appFiles = append(appFiles, path)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("扫描 app 包失败：%w", err)
	}
	sort.Strings(appFiles)
	for _, path := range appFiles {
		file, fset, err := parseAt(path)
		if err != nil {
			return nil, err
		}
		rel := relPath(root, path)
		for _, decl := range file.Decls {
			switch typed := decl.(type) {
			case *ast.GenDecl:
				if typed.Tok == token.VAR || typed.Tok == token.CONST {
					kind := "var"
					if typed.Tok == token.CONST {
						kind = "const"
					}
					for _, spec := range typed.Specs {
						valueSpec, ok := spec.(*ast.ValueSpec)
						if !ok {
							continue
						}
						doc := docText(valueSpec.Doc)
						if doc == "" {
							doc = docText(typed.Doc)
						}
						for _, name := range valueSpec.Names {
							if !name.IsExported() {
								continue
							}
							api.AppVars = append(api.AppVars, GoValue{
								Name: name.Name, Kind: kind,
								Doc: firstSentence(doc), Source: rel,
							})
						}
					}
					continue
				}
				if typed.Tok != token.TYPE {
					continue
				}
				for _, spec := range typed.Specs {
					typeSpec, ok := spec.(*ast.TypeSpec)
					if !ok || !typeSpec.Name.IsExported() {
						continue
					}
					doc := docText(typeSpec.Doc)
					if doc == "" {
						doc = docText(typed.Doc)
					}
					kind := "alias"
					var members []string
					switch underlying := typeSpec.Type.(type) {
					case *ast.StructType:
						kind = "struct"
						for _, field := range underlying.Fields.List {
							for _, name := range field.Names {
								if name.IsExported() {
									members = append(members, name.Name)
								}
							}
						}
					case *ast.InterfaceType:
						kind = "interface"
						var methods []GoMethod
						for _, field := range underlying.Methods.List {
							for _, name := range field.Names {
								if !name.IsExported() {
									continue
								}
								fn, ok := field.Type.(*ast.FuncType)
								if !ok {
									continue
								}
								methods = append(methods, GoMethod{
									Name: name.Name, Signature: signatureText(fset, fn),
									Doc: firstSentence(docText(field.Doc)),
								})
								members = append(members, name.Name)
							}
						}
						sort.Slice(methods, func(i, j int) bool { return methods[i].Name < methods[j].Name })
						api.Interfaces = append(api.Interfaces, GoInterface{
							Name: typeSpec.Name.Name, Doc: firstSentence(doc),
							Source: rel, Methods: methods,
						})
					}
					sort.Strings(members)
					api.AppTypes = append(api.AppTypes, GoType{
						Name: typeSpec.Name.Name, Kind: kind,
						Doc: firstSentence(doc), Source: rel, Members: members,
					})
				}
			case *ast.FuncDecl:
				if typed.Name == nil || !typed.Name.IsExported() {
					continue
				}
				doc := firstSentence(docText(typed.Doc))
				if typed.Recv != nil {
					// 能力矩阵的 app_funcs 口径包含导出方法，这里单独计数用于交叉核对。
					api.ExportedMethodCount++
				}
				if typed.Recv == nil {
					api.AppFuncs = append(api.AppFuncs, GoFunc{
						Name:      typed.Name.Name,
						Signature: signatureText(fset, typed.Type),
						Doc:       doc, Source: rel,
					})
					continue
				}
				if receiverTypeName(typed.Recv) != "Runtime" {
					continue
				}
				api.RuntimeMethods = append(api.RuntimeMethods, GoFunc{
					Name:      typed.Name.Name,
					Signature: signatureText(fset, typed.Type),
					Doc:       doc, Source: rel,
				})
			}
		}
	}
	sort.Slice(api.AppTypes, func(i, j int) bool {
		if api.AppTypes[i].Name != api.AppTypes[j].Name {
			return api.AppTypes[i].Name < api.AppTypes[j].Name
		}
		return api.AppTypes[i].Source < api.AppTypes[j].Source
	})
	sort.Slice(api.Interfaces, func(i, j int) bool { return api.Interfaces[i].Name < api.Interfaces[j].Name })
	sort.Slice(api.AppFuncs, func(i, j int) bool { return api.AppFuncs[i].Name < api.AppFuncs[j].Name })
	sort.Slice(api.AppVars, func(i, j int) bool {
		if api.AppVars[i].Name != api.AppVars[j].Name {
			return api.AppVars[i].Name < api.AppVars[j].Name
		}
		return api.AppVars[i].Source < api.AppVars[j].Source
	})
	sort.Slice(api.RuntimeMethods, func(i, j int) bool { return api.RuntimeMethods[i].Name < api.RuntimeMethods[j].Name })
	if len(api.RuntimeMethods) == 0 || len(api.Interfaces) == 0 {
		return nil, fmt.Errorf("app 包公开 API 扫描结果为空（Runtime 方法=%d、接口=%d），检查 app/ 目录结构是否变化",
			len(api.RuntimeMethods), len(api.Interfaces))
	}

	rootFiles, err := listGoFiles(root)
	if err != nil {
		return nil, fmt.Errorf("扫描根包失败：%w", err)
	}
	for _, path := range rootFiles {
		file, fset, err := parseAt(path)
		if err != nil {
			return nil, err
		}
		summary := RootFileSummary{File: filepath.Base(path)}
		var rootFuncs []GoFunc
		for _, decl := range file.Decls {
			switch typed := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range typed.Specs {
					switch specTyped := spec.(type) {
					case *ast.TypeSpec:
						if specTyped.Name.IsExported() {
							summary.Types = append(summary.Types, specTyped.Name.Name)
						}
					case *ast.ValueSpec:
						for _, name := range specTyped.Names {
							if !name.IsExported() {
								continue
							}
							if typed.Tok == token.CONST {
								summary.Consts = append(summary.Consts, name.Name)
							} else {
								summary.Vars = append(summary.Vars, name.Name)
							}
						}
					}
				}
			case *ast.FuncDecl:
				if typed.Recv != nil || typed.Name == nil || !typed.Name.IsExported() {
					continue
				}
				summary.Funcs = append(summary.Funcs, typed.Name.Name)
				rootFuncs = append(rootFuncs, GoFunc{
					Name:      typed.Name.Name,
					Signature: signatureText(fset, typed.Type),
					Doc:       firstSentence(docText(typed.Doc)),
					Source:    filepath.Base(path),
				})
			}
		}
		sort.Strings(summary.Types)
		sort.Strings(summary.Funcs)
		sort.Strings(summary.Consts)
		sort.Strings(summary.Vars)
		api.RootTypeCount += len(summary.Types)
		api.RootFuncCount += len(summary.Funcs)
		if len(summary.Types)+len(summary.Funcs)+len(summary.Consts)+len(summary.Vars) > 0 {
			api.RootFiles = append(api.RootFiles, summary)
		}
		api.RootFuncs = append(api.RootFuncs, rootFuncs...)
	}
	sort.Slice(api.RootFuncs, func(i, j int) bool { return api.RootFuncs[i].Name < api.RootFuncs[j].Name })
	sort.Slice(api.RootFiles, func(i, j int) bool { return api.RootFiles[i].File < api.RootFiles[j].File })
	if api.RootTypeCount == 0 || len(api.RootFuncs) == 0 {
		return nil, fmt.Errorf("根包公开 API 扫描结果为空（类型=%d、函数=%d）", api.RootTypeCount, len(api.RootFuncs))
	}
	return api, nil
}
