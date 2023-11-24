// Copyright (c) Kagurazakayashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package app

// 步骤 231：备份公开接口的公共表面检查：不暴露 internal 类型，也不在公开结构里
// 暴露任意磁盘路径（FileName/SHA256 等元数据允许；Path/BackupPath/StateDir 等不行）。

import (
	"reflect"
	"strings"
	"testing"
)

func backupCheckType(t *testing.T, context string, typ reflect.Type) {
	t.Helper()
	if typ == nil {
		return
	}
	if pkg := typ.PkgPath(); strings.Contains(pkg, "/internal/") {
		t.Fatalf("%s 暴露 internal 类型 %s (%s)", context, typ.String(), pkg)
	}
	switch typ.Kind() {
	case reflect.Ptr, reflect.Slice, reflect.Array, reflect.Map:
		backupCheckType(t, context, typ.Elem())
	case reflect.Struct:
		for index := 0; index < typ.NumField(); index++ {
			field := typ.Field(index)
			if field.PkgPath != "" {
				continue
			}
			lower := strings.ToLower(field.Name)
			// 允许宿主受控目录配置（StateDir/AttachmentsDir/BackupOutputDir）与产物
			// 文件名元数据；禁止备份文件绝对路径/任意读取路径进入公开结构。
			if lower == "path" || strings.Contains(lower, "filepath") ||
				strings.Contains(lower, "backuppath") {
				t.Fatalf("%s.%s 不得在公开结构暴露磁盘路径", context, field.Name)
			}
			backupCheckType(t, context+"."+field.Name, field.Type)
		}
	}
}

// TestBackupPublicSurfaceHasNoInternalTypesOrPaths 断言备份/恢复公开签名只使用公开
// 类型，且公开结果结构不携带磁盘路径。
func TestBackupPublicSurfaceHasNoInternalTypesOrPaths(t *testing.T) {
	interfaces := []reflect.Type{
		reflect.TypeOf((*BackupService)(nil)).Elem(),
		reflect.TypeOf((*BackupPlanService)(nil)).Elem(),
		reflect.TypeOf((*BackupJobService)(nil)).Elem(),
		reflect.TypeOf((*BackupArtifactService)(nil)).Elem(),
		reflect.TypeOf((*BackupRecoveryService)(nil)).Elem(),
	}
	for _, facade := range interfaces {
		for index := 0; index < facade.NumMethod(); index++ {
			method := facade.Method(index)
			for arg := 0; arg < method.Type.NumIn(); arg++ {
				backupCheckType(t, facade.String()+"."+method.Name+" 参数",
					method.Type.In(arg))
			}
			for result := 0; result < method.Type.NumOut(); result++ {
				backupCheckType(t, facade.String()+"."+method.Name+" 返回值",
					method.Type.Out(result))
			}
		}
	}
	runtimeType := reflect.TypeOf((*Runtime)(nil))
	for _, name := range []string{"Backup"} {
		method, ok := runtimeType.MethodByName(name)
		if !ok {
			t.Fatalf("缺少 Runtime.%s 访问器", name)
		}
		for result := 0; result < method.Type.NumOut(); result++ {
			backupCheckType(t, "Runtime."+name+" 返回值", method.Type.Out(result))
		}
	}
}
