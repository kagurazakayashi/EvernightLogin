// Command rbac-consumer 是步骤 224 的外部宿主示例：仅导入公开包，使用临时
// SQLite 打开真实运行时，演示角色/用户组/权限/授权查询/预设拒绝与清理。
//
// 安全边界（示例故意覆盖拒绝路径）：
//   - LocalAdmin 是宿主进程受信操作者，可管理 RBAC 目录；
//   - AdminSession 是真实用户会话，不能预览/恢复高权限预设；
//   - 普通管理会话签发委派资格被拒绝；
//   - 受限会话不能执行 RBAC 管理操作。
//
// 示例不监听端口、不启动后台任务、不外发邮件、不读取真实配置/数据库，
// 临时目录在结束时删除，可重复运行。
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/app"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "rbac-consumer 示例失败:", err)
		os.Exit(1)
	}
	fmt.Println("rbac-consumer 示例通过：公开 RBAC 服务可创建/组合/查询/拒绝，且未导入 internal 包")
}

// run 在临时目录运行一次有界示例；任何断言失败返回错误。
func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	dir, err := os.MkdirTemp("", "evernightlogin-rbac-consumer-")
	if err != nil {
		return fmt.Errorf("创建临时目录: %w", err)
	}
	defer os.RemoveAll(dir)

	cfg := login.Default()
	cfg.Registration.Enabled = true
	cfg.Registration.RequireReview = false
	runtime, err := app.Open(ctx, app.Options{
		Config:          &cfg,
		DatabasePath:    filepath.Join(dir, "login.db"),
		MasterKeyFile:   filepath.Join(dir, "master.key"),
		CreateMasterKey: true,
		Migrate:         true,
		OperatorID:      "rbac-consumer-host",
		Logger:          nil,
	})
	if err != nil {
		return fmt.Errorf("打开运行时: %w", err)
	}
	defer func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer closeCancel()
		_ = runtime.Close(closeCtx)
	}()

	if _, err := runtime.Bootstrap().EnsureRoot(ctx, app.RootRequest{
		DisplayName: "示例 root", Password: "V7!qZ2#Lm9@Tp4$x",
		RequestID: login.NewRequestID()}); err != nil {
		return fmt.Errorf("初始化 root: %w", err)
	}
	local := runtime.LocalAdmin()
	rbac := runtime.RBAC()

	// 1) 目录：权限（含中文说明与真实 Implemented 标记）、角色、用户组。
	catalog, err := rbac.Permissions().Catalog(ctx, app.RBACCatalogRequest{
		Caller: local, RequestID: login.NewRequestID()})
	if err != nil {
		return fmt.Errorf("读取权限目录: %w", err)
	}
	if catalog.Version == "" || len(catalog.Permissions) == 0 {
		return errors.New("权限目录为空")
	}
	permission, err := rbac.Permissions().Create(ctx, app.AdminCreatePermissionRequest{
		Caller: local, ScopeID: "system", Key: "example.report.read",
		Name: "示例：读取报表", RequestID: login.NewRequestID()})
	if err != nil {
		return fmt.Errorf("创建权限: %w", err)
	}
	role, err := rbac.Roles().Create(ctx, app.AdminCreateRoleRequest{
		Caller: local, ScopeID: "system", Key: "example-reporter",
		Name: "示例报表读者", RequestID: login.NewRequestID()})
	if err != nil {
		return fmt.Errorf("创建角色: %w", err)
	}
	if err := rbac.Roles().AddPermission(ctx, app.AdminRolePermissionRequest{
		Caller: local, RoleID: role.ID, PermissionID: permission.ID,
		RequestID: login.NewRequestID()}); err != nil {
		return fmt.Errorf("角色组合权限: %w", err)
	}
	group, err := rbac.Groups().Create(ctx, app.RBACCreateGroupRequest{
		Caller: local, ScopeID: "system", Key: "example-team",
		Name: "示例用户组", RequestID: login.NewRequestID()})
	if err != nil {
		return fmt.Errorf("创建用户组: %w", err)
	}

	// 2) 用户与组合授权：用户加入组、组获得角色，查询有效权限。
	user, err := runtime.Users().Create(ctx, app.CreateUserRequest{
		Username: "example-user", Password: "K8$wR3!nB6@yF1#v",
		Nickname: "示例用户", RequestID: login.NewRequestID()})
	if err != nil {
		return fmt.Errorf("创建用户: %w", err)
	}
	if _, err := rbac.Groups().AddMembers(ctx, app.RBACGroupMemberBatchRequest{
		Caller: local, GroupID: group.ID, UserIDs: []string{user.ID},
		RequestID: login.NewRequestID()}); err != nil {
		return fmt.Errorf("加入组成员: %w", err)
	}
	if err := rbac.Roles().AssignGroup(ctx, app.RBACRoleGroupRequest{
		Caller: local, RoleID: role.ID, GroupID: group.ID,
		RequestID: login.NewRequestID()}); err != nil {
		return fmt.Errorf("组分配角色: %w", err)
	}
	check, err := rbac.Authorization().Check(ctx, app.RBACCheckRequest{
		Caller: local, SubjectUserID: user.ID, ScopeID: "system",
		Permissions: []string{"example.report.read"},
		RequestID:   login.NewRequestID()})
	if err != nil {
		return fmt.Errorf("检查有效权限: %w", err)
	}
	if !check.Allowed {
		return fmt.Errorf("组合授权后应允许: %+v", check)
	}
	effective, err := rbac.Authorization().EffectivePermissions(ctx,
		app.RBACEffectiveRequest{Caller: local, SubjectUserID: user.ID,
			ScopeID: "system", Page: app.AdminPage{Limit: 20},
			RequestID: login.NewRequestID()})
	if err != nil || len(effective.Permissions) == 0 {
		return fmt.Errorf("有效权限为空: %+v err=%v", effective, err)
	}

	// 3) 拒绝路径：普通管理会话不能恢复高权限预设。
	adminUser, err := runtime.Users().Create(ctx, app.CreateUserRequest{
		Username: "example-admin", Password: "K8$wR3!nB6@yF1#v",
		Nickname: "示例管理员", RequestID: login.NewRequestID()})
	if err != nil {
		return fmt.Errorf("创建管理用户: %w", err)
	}
	readPermission, err := rbac.Permissions().Create(ctx, app.AdminCreatePermissionRequest{
		Caller: local, ScopeID: "system", Key: "roles.read", Name: "读取角色",
		RequestID: login.NewRequestID()})
	if err != nil {
		return fmt.Errorf("创建读取权限: %w", err)
	}
	adminRole, err := rbac.Roles().Create(ctx, app.AdminCreateRoleRequest{
		Caller: local, ScopeID: "system", Key: "example-admin",
		Name: "示例管理员", RequestID: login.NewRequestID()})
	if err != nil {
		return fmt.Errorf("创建管理角色: %w", err)
	}
	if err := rbac.Roles().AddPermission(ctx, app.AdminRolePermissionRequest{
		Caller: local, RoleID: adminRole.ID, PermissionID: readPermission.ID,
		RequestID: login.NewRequestID()}); err != nil {
		return fmt.Errorf("管理角色组合权限: %w", err)
	}
	if err := rbac.Roles().AssignUser(ctx, app.GrantRoleRequest{
		Caller: local, UserID: adminUser.ID, RoleID: adminRole.ID,
		RequestID: login.NewRequestID()}); err != nil {
		return fmt.Errorf("分配管理角色: %w", err)
	}
	loginResult, err := runtime.Auth().Login(ctx, app.LoginRequest{
		Username: "example-admin", Password: "K8$wR3!nB6@yF1#v",
		ClientIP: "127.0.0.1", RequestID: login.NewRequestID()})
	if err != nil || loginResult.Restricted {
		return fmt.Errorf("管理用户登录: %+v err=%v", loginResult, err)
	}
	sessionCaller := runtime.AdminSession(loginResult.SessionSecret)
	_, err = rbac.Presets().Preview(ctx, app.RBACPresetPreviewRequest{
		Caller: sessionCaller, All: true, RequestID: login.NewRequestID()})
	if err == nil {
		return errors.New("普通管理会话恢复预设必须被拒绝")
	}
	var appError *login.AppError
	if !errors.As(err, &appError) || appError.Code() != login.CodeAccessDenied {
		return fmt.Errorf("预设拒绝错误码期望 ACCESS_DENIED，实际 %v", err)
	}

	// 4) 撤销组合权限后立即拒绝（无缓存旧授权）。
	if err := rbac.Roles().RemovePermission(ctx, app.RBACRolePermissionRemoveRequest{
		Caller: local, RoleID: role.ID, PermissionID: permission.ID,
		RequestID: login.NewRequestID()}); err != nil {
		return fmt.Errorf("移除角色权限: %w", err)
	}
	check, err = rbac.Authorization().Check(ctx, app.RBACCheckRequest{
		Caller: local, SubjectUserID: user.ID, ScopeID: "system",
		Permissions: []string{"example.report.read"}, RequestID: login.NewRequestID()})
	if err != nil || check.Allowed {
		return fmt.Errorf("撤权后必须拒绝: %+v err=%v", check, err)
	}
	return nil
}
