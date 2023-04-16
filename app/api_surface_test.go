package app

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestPublicAPISurfaceHasNoInternalTypes 断言 app 公开 API 的签名不暴露 internal 类型。
func TestPublicAPISurfaceHasNoInternalTypes(t *testing.T) {
	runtimeType := reflect.TypeOf((*Runtime)(nil))
	for index := 0; index < runtimeType.NumMethod(); index++ {
		method := runtimeType.Method(index)
		if !ast.IsExported(method.Name) {
			continue
		}
		checkSignature(t, "Runtime."+method.Name, method.Func.Type())
		for arg := 0; arg < method.Type.NumIn(); arg++ {
			checkType(t, "Runtime."+method.Name+" 参数", method.Type.In(arg))
		}
		for result := 0; result < method.Type.NumOut(); result++ {
			checkType(t, "Runtime."+method.Name+" 返回值", method.Type.Out(result))
		}
	}
	facadeTypes := []reflect.Type{
		reflect.TypeOf((*BootstrapService)(nil)).Elem(),
		reflect.TypeOf((*UserService)(nil)).Elem(),
		reflect.TypeOf((*AuthService)(nil)).Elem(),
		reflect.TypeOf((*AccessService)(nil)).Elem(),
		reflect.TypeOf((*SessionService)(nil)).Elem(),
		reflect.TypeOf((*AdminService)(nil)).Elem(),
	}
	for _, facade := range facadeTypes {
		for index := 0; index < facade.NumMethod(); index++ {
			method := facade.Method(index)
			for arg := 0; arg < method.Type.NumIn(); arg++ {
				checkType(t, facade.String()+"."+method.Name+" 参数", method.Type.In(arg))
			}
			for result := 0; result < method.Type.NumOut(); result++ {
				checkType(t, facade.String()+"."+method.Name+" 返回值", method.Type.Out(result))
			}
		}
	}
}

func checkSignature(t *testing.T, name string, typ reflect.Type) {
	t.Helper()
	if typ == nil {
		t.Fatalf("%s 类型为空", name)
	}
}

func checkType(t *testing.T, context string, typ reflect.Type) {
	t.Helper()
	if typ == nil {
		return
	}
	pkg := typ.PkgPath()
	if strings.Contains(pkg, "/internal/") {
		t.Fatalf("%s 暴露 internal 类型 %s (%s)", context, typ.String(), pkg)
	}
	switch typ.Kind() {
	case reflect.Ptr, reflect.Slice, reflect.Array, reflect.Map:
		checkType(t, context, typ.Elem())
	case reflect.Struct:
		for index := 0; index < typ.NumField(); index++ {
			field := typ.Field(index)
			if field.PkgPath != "" {
				continue // 非导出字段不属于公开表面
			}
			checkType(t, context+"."+field.Name, field.Type)
		}
	}
}

// TestExampleOnlyImportsPublicPackages 断言独立示例源码不直接导入 internal。
func TestExampleOnlyImportsPublicPackages(t *testing.T) {
	root := filepath.Join("..", "examples", "embedded-runtime")
	files, err := filepath.Glob(filepath.Join(root, "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("未找到示例源码: %v", err)
	}
	fset := token.NewFileSet()
	for _, file := range files {
		parsed, err := parser.ParseFile(fset, file, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("解析 %s 失败: %v", file, err)
		}
		for _, spec := range parsed.Imports {
			path := strings.Trim(spec.Path.Value, "\"")
			if strings.Contains(path, "/internal/") {
				t.Fatalf("示例 %s 直接导入了 internal 包 %s", file, path)
			}
		}
	}
}

// TestRootPackageDoesNotImportApp 防止公开 app 包被根包反向导入形成循环。
func TestRootPackageDoesNotImportApp(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("未找到根包源码: %v", err)
	}
	fset := token.NewFileSet()
	for _, file := range files {
		parsed, err := parser.ParseFile(fset, file, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("解析 %s 失败: %v", file, err)
		}
		for _, spec := range parsed.Imports {
			path := strings.Trim(spec.Path.Value, "\"")
			if path == "github.com/kagurazakayashi/EvernightLogin/app" ||
				strings.Contains(path, "/internal/appcore") {
				t.Fatalf("根包 %s 不得反向导入 %s", file, path)
			}
		}
	}
}
