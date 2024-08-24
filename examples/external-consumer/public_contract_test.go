// 步骤 236 外部消费合同测试。
//
// 本文件属于独立 Go 模块 examples/external-consumer：只导入公开 login/app 包，
// 用真实 app.Open（临时 SQLite + 程序生成主密钥）验证：
//   - 公开域 accessor 的成功链（诊断读取）；
//   - 零值/伪造 AdminCaller 被稳定拒绝，不出现占位成功；
//   - 关闭/未装配能力返回稳定错误（协议未启用 fail-closed）；
//   - 列表请求/结果保留分页与继续语义字段；
//   - 公开类型签名不出现 internal 类型或磁盘路径。
package main

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/app"
)

func openExternalRuntime(t *testing.T) *app.Runtime {
	t.Helper()
	config := login.Default()
	config.Registration.Enabled = true
	directory := t.TempDir()
	runtime, err := app.Open(context.Background(), app.Options{
		Config:          &config,
		DatabasePath:    filepath.Join(directory, "external-contract.db"),
		MasterKeyFile:   filepath.Join(directory, "master.key"),
		CreateMasterKey: true,
		Migrate:         true,
		OperatorID:      "external-consumer-contract",
	})
	if err != nil {
		t.Fatalf("外部模块 app.Open 失败: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if closeErr := runtime.Close(ctx); closeErr != nil {
			t.Errorf("Runtime.Close 失败: %v", closeErr)
		}
	})
	return runtime
}

func requireStableDenial(t *testing.T, context string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s 不应成功（零值/伪造 Caller 或未装配能力必须拒绝）", context)
	}
	appErr := login.FromError(err)
	if appErr == nil {
		t.Fatalf("%s 返回错误不是公开 AppError: %v", context, err)
	}
	switch string(appErr.Code()) {
	case string(login.CodeAccessDenied), string(login.CodeAuthFailed),
		string(login.CodeReqInvalid), string(login.CodeConfigInvalid):
	default:
		t.Fatalf("%s 返回错误码不在稳定拒绝集合: %s", context, appErr.Code())
	}
	if strings.Contains(appErr.Error(), "internal/") {
		t.Fatalf("%s 错误文本泄漏 internal 路径: %s", context, appErr.Error())
	}
}

// TestPublicFacadesSuccessChain 验证真实成功链：诊断读取由 LocalAdmin 授权，
// 结果只在系统范围且不包含秘密字段。
func TestPublicFacadesSuccessChain(t *testing.T) {
	runtime := openExternalRuntime(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	report, err := runtime.Diagnostics().Read(ctx, app.DiagnosticsRequest{
		Caller:    runtime.LocalAdmin(),
		ScopeID:   "system",
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		t.Fatalf("LocalAdmin 诊断读取失败: %v", err)
	}
	if report.ScopeKind == "" || report.ScopeID != "system" {
		t.Fatalf("诊断范围异常: kind=%q scope=%q", report.ScopeKind, report.ScopeID)
	}
	if report.Version.GoVersion == "" {
		t.Fatalf("诊断版本信息缺失: %+v", report.Version)
	}
}

// TestPublicFacadesRejectZeroCaller 验证零值/伪造 Caller 在所有 236 新公开域
// 都被稳定拒绝，且不会 panic 或返回“成功/空结果”。
func TestPublicFacadesRejectZeroCaller(t *testing.T) {
	runtime := openExternalRuntime(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	zero := app.AdminCaller{}

	_, err := runtime.Diagnostics().Read(ctx, app.DiagnosticsRequest{Caller: zero})
	requireStableDenial(t, "Diagnostics.Read", err)
	_, err = runtime.Settings().Status(ctx, app.SettingsStatusRequest{Caller: zero})
	requireStableDenial(t, "Settings.Status", err)
	_, err = runtime.Support().ListCases(ctx, app.SupportListCasesRequest{Caller: zero})
	requireStableDenial(t, "Support.ListCases", err)
	_, err = runtime.ManualRecovery().Create(ctx, app.ManualRecoveryCreateRequest{
		Caller: zero, TargetUserID: "usr_external_contract", Operation: "reset_password",
	})
	requireStableDenial(t, "ManualRecovery.Create", err)
	_, err = runtime.Admin().RevokeUserSessions(ctx, app.AdminRevokeSessionsRequest{
		Caller: zero, TargetUserID: "usr_external_contract",
	})
	requireStableDenial(t, "Admin.RevokeUserSessions", err)
	_, err = runtime.UserLifecycle().GetUserValidity(ctx, app.AdminUserRequest{
		Caller: zero, UserID: "usr_external_contract",
	})
	requireStableDenial(t, "UserLifecycle.GetUserValidity", err)
}

// TestProtocolDisabledFailClosed 验证协议开关未启用时内省返回稳定错误，
// 不因 JWT 可本地解析就返回成功。
func TestProtocolDisabledFailClosed(t *testing.T) {
	runtime := openExternalRuntime(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := runtime.Protocol().IntrospectToken(ctx, app.ProtocolIntrospectRequest{
		ServiceID: "external-contract-resource",
		Token:     "not-a-real-token",
		RequestID: login.NewRequestID(),
	})
	requireStableDenial(t, "Protocol.IntrospectToken（未装配）", err)
}

// TestPublicListContinuationContract 验证公开列表请求/结果保留分页与继续语义，
// 避免把“只返回第一页”当完整集合。
func TestPublicListContinuationContract(t *testing.T) {
	requestFields := map[reflect.Type][]string{
		reflect.TypeOf(app.SupportListCasesRequest{}):   {"Page"},
		reflect.TypeOf(app.ManualRecoveryListRequest{}): {"Page"},
	}
	for typ, names := range requestFields {
		for _, name := range names {
			if _, ok := typ.FieldByName(name); !ok {
				t.Fatalf("%s 缺少分页请求字段 %s", typ, name)
			}
		}
	}
	resultFields := map[reflect.Type][]string{
		reflect.TypeOf(app.SupportCasePage{}):        {"Page"},
		reflect.TypeOf(app.ManualRecoveryListPage{}): {"Page"},
		reflect.TypeOf(app.DiagnosticsErrorList{}):   {"Truncated", "Entries"},
	}
	for typ, names := range resultFields {
		for _, name := range names {
			if _, ok := typ.FieldByName(name); !ok {
				t.Fatalf("%s 缺少列表结果字段 %s", typ, name)
			}
		}
	}
	pageType := reflect.TypeOf(app.AdminPageInfo{})
	for _, name := range []string{"Limit", "Offset", "Returned", "HasMore", "NextOffset"} {
		if _, ok := pageType.FieldByName(name); !ok {
			t.Fatalf("AdminPageInfo 缺少继续语义字段 %s", name)
		}
	}
}

// TestPublicSurfaceNoInternalOrDiskPaths 验证 236 公开类型不暴露 internal 类型，
// 且备份/客服/恢复结果不携带任意磁盘路径字段。
func TestPublicSurfaceNoInternalOrDiskPaths(t *testing.T) {
	for _, typ := range publicSurfaceTypes {
		checkNoInternalType(t, typ, typ.String())
	}
	for _, typ := range []reflect.Type{
		reflect.TypeOf(app.BackupArtifact{}), reflect.TypeOf(app.BackupPlan{}),
		reflect.TypeOf(app.BackupPendingRestore{}), reflect.TypeOf(app.SupportCase{}),
		reflect.TypeOf(app.ManualRecoveryListItem{}), reflect.TypeOf(app.DiagnosticsReport{}),
	} {
		checkNoDiskPathField(t, typ, typ.String())
	}
}

func checkNoInternalType(t *testing.T, typ reflect.Type, context string) {
	t.Helper()
	if typ == nil {
		return
	}
	if pkg := typ.PkgPath(); strings.Contains(pkg, "/internal/") {
		t.Fatalf("%s 暴露 internal 类型 %s", context, pkg)
	}
	switch typ.Kind() {
	case reflect.Ptr, reflect.Slice, reflect.Array, reflect.Map:
		checkNoInternalType(t, typ.Elem(), context)
	case reflect.Struct:
		for index := 0; index < typ.NumField(); index++ {
			field := typ.Field(index)
			if field.PkgPath != "" {
				continue
			}
			checkNoInternalType(t, field.Type, context+"."+field.Name)
		}
	}
}

func checkNoDiskPathField(t *testing.T, typ reflect.Type, context string) {
	t.Helper()
	if typ.Kind() != reflect.Struct {
		return
	}
	for index := 0; index < typ.NumField(); index++ {
		field := typ.Field(index)
		if field.PkgPath != "" {
			continue
		}
		name := strings.ToLower(field.Name)
		if name == "path" || strings.Contains(name, "filepath") ||
			strings.Contains(name, "backuppath") || name == "statedir" {
			t.Fatalf("%s.%s 不得暴露磁盘路径字段", context, field.Name)
		}
	}
}
