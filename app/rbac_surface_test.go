// Copyright (c) Kagurazakayashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package app

// 步骤 224：新增 RBAC 公开接口不得暴露 internal 类型。使用独立测试文件，
// 不修改既有 api_surface_test.go（避免并行步骤写冲突）。

import (
	"reflect"
	"strings"
	"testing"
)

func rbacCheckType(t *testing.T, context string, typ reflect.Type) {
	t.Helper()
	if typ == nil {
		return
	}
	if pkg := typ.PkgPath(); strings.Contains(pkg, "/internal/") {
		t.Fatalf("%s 暴露 internal 类型 %s (%s)", context, typ.String(), pkg)
	}
	switch typ.Kind() {
	case reflect.Ptr, reflect.Slice, reflect.Array, reflect.Map:
		rbacCheckType(t, context, typ.Elem())
	case reflect.Struct:
		for index := 0; index < typ.NumField(); index++ {
			field := typ.Field(index)
			if field.PkgPath != "" {
				continue // 非导出字段不属于公开表面
			}
			rbacCheckType(t, context+"."+field.Name, field.Type)
		}
	}
}

// TestRBACPublicSurfaceHasNoInternalTypes 断言 RBAC 入口与各分组服务签名只使用公开类型。
func TestRBACPublicSurfaceHasNoInternalTypes(t *testing.T) {
	interfaces := []reflect.Type{
		reflect.TypeOf((*RBACService)(nil)).Elem(),
		reflect.TypeOf((*RBACRoleService)(nil)).Elem(),
		reflect.TypeOf((*RBACGroupService)(nil)).Elem(),
		reflect.TypeOf((*RBACPermissionService)(nil)).Elem(),
		reflect.TypeOf((*RBACAuthorizationService)(nil)).Elem(),
		reflect.TypeOf((*RBACDelegationService)(nil)).Elem(),
		reflect.TypeOf((*RBACPresetService)(nil)).Elem(),
	}
	for _, facade := range interfaces {
		for index := 0; index < facade.NumMethod(); index++ {
			method := facade.Method(index)
			for arg := 0; arg < method.Type.NumIn(); arg++ {
				rbacCheckType(t, facade.String()+"."+method.Name+" 参数",
					method.Type.In(arg))
			}
			for result := 0; result < method.Type.NumOut(); result++ {
				rbacCheckType(t, facade.String()+"."+method.Name+" 返回值",
					method.Type.Out(result))
			}
		}
	}
	// 同时检查 Runtime.RBAC 的返回类型，防止未来把 internal 类型接入访问器。
	runtimeType := reflect.TypeOf((*Runtime)(nil))
	method, ok := runtimeType.MethodByName("RBAC")
	if !ok {
		t.Fatal("缺少 Runtime.RBAC() 访问器")
	}
	for result := 0; result < method.Type.NumOut(); result++ {
		rbacCheckType(t, "Runtime.RBAC 返回值", method.Type.Out(result))
	}
}
