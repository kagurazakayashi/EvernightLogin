package login

// 扩展注册的内部校验实现（公开契约在 extension/，类型别名见 alias_contracts.go）。
// 这里只保留“把宿主扩展列表规整为实例可管理列表”的根实现，不复制公共契约。

import (
	"fmt"
	"reflect"
)

// normalizeExtensions 校验并复制扩展注册信息，构造注册顺序的扩展列表、元数据
// 快照与可选健康检查列表。它拒绝 nil、typed-nil、非法元数据、超上限与重复的
// 「分类 + 名称」；任何一项非法都整体拒绝，不做部分注册。
func normalizeExtensions(extensions []Extension) ([]Extension, []ExtensionInfo, []ReadyChecker, error) {
	if len(extensions) > MaxExtensions {
		return nil, nil, nil, fmt.Errorf("扩展数量 %d 超过上限 %d", len(extensions), MaxExtensions)
	}
	registered := make([]Extension, 0, len(extensions))
	infos := make([]ExtensionInfo, 0, len(extensions))
	checkers := make([]ReadyChecker, 0, len(extensions))
	seen := make(map[string]struct{}, len(extensions))
	for index, extension := range extensions {
		if extension == nil || isNilInterface(extension) {
			return nil, nil, nil, fmt.Errorf("Options.Extensions[%d] 为 nil", index)
		}
		info := extension.ExtensionInfo()
		if err := info.Validate(); err != nil {
			return nil, nil, nil, fmt.Errorf("Options.Extensions[%d] 元数据无效: %w", index, err)
		}
		key := extensionKey(info)
		if _, duplicate := seen[key]; duplicate {
			return nil, nil, nil, fmt.Errorf("扩展 %q 重复注册", key)
		}
		seen[key] = struct{}{}
		registered = append(registered, extension)
		infos = append(infos, info)
		if checker, ok := extension.(ReadyChecker); ok && !isNilInterface(checker) {
			checkers = append(checkers, checker)
		}
	}
	return registered, infos, checkers, nil
}

// isNilInterface 报告接口值是否为 nil 或持有 typed-nil。接口持有 typed-nil 时
// 直接比较 == nil 为假，但调用方法会 panic，因此注册与注入入口统一拒绝。
func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Ptr, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

// extensionKey 返回扩展注册去重键（分类 + 名称）。
func extensionKey(info ExtensionInfo) string {
	return string(info.Kind) + "/" + info.Name
}
