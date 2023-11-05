package app

// 步骤 220：公开分页遍历辅助的公开签名检查（不暴露 internal 类型），独立文件
// 避免修改 216/217 已有的 api_surface_test.go。

import (
	"reflect"
	"testing"
)

// TestPublicAPISurfacePaginationHelpers 断言迭代辅助的公开类型与泛型函数签名
// 不引用 internal 包类型（真实宿主只能看到公开声明）。
func TestPublicAPISurfacePaginationHelpers(t *testing.T) {
	for _, typ := range []reflect.Type{
		reflect.TypeOf(IterationOptions{}),
		reflect.TypeOf(IterationResult{}),
	} {
		checkType(t, "pagination helper "+typ.String(), typ)
	}
	// 泛型函数用具体类型实例化后检查参数/返回值；类型参数本身由编译器约束。
	functionType := reflect.TypeOf(IterateAdminPages[int])
	if functionType.Kind() != reflect.Func {
		t.Fatalf("IterateAdminPages 不是函数类型: %v", functionType)
	}
	for index := 0; index < functionType.NumIn(); index++ {
		checkType(t, "IterateAdminPages 参数", functionType.In(index))
	}
	for index := 0; index < functionType.NumOut(); index++ {
		checkType(t, "IterateAdminPages 返回值", functionType.Out(index))
	}
	if ErrPageNotAdvancing == nil || ErrPageNotAdvancing.Error() == "" {
		t.Fatal("ErrPageNotAdvancing 必须是非空哨兵错误")
	}
}
